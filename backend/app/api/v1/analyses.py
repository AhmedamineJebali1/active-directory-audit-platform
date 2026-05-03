"""Analysis endpoints — upload, list, detail, pipeline trigger."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, File, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import NotFoundError, ValidationError
from app.core.security import get_current_user, require_role
from app.database import get_db
from app.models.analysis import Analysis
from app.models.engagement import Engagement
from app.schemas.analysis import AnalysisListResponse, AnalysisResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["analyses"])
settings = get_settings()


@router.post("/engagements/{engagement_id}/analyses", response_model=AnalysisResponse, status_code=202)
async def upload_analysis(
    engagement_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin", "manager", "auditor")),
    file: UploadFile = File(...),
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise NotFoundError("Mission")

    if not file.filename or not file.filename.endswith(".json"):
        raise ValidationError("Le fichier doit être un JSON BloodHound (.json)")

    content = await file.read()
    if len(content) > 100 * 1024 * 1024:
        raise ValidationError("Fichier trop volumineux (max 100 MB)")

    analysis = Analysis(
        id=uuid.uuid4(),
        engagement_id=engagement_id,
        source_type="bloodhound_json",
        source_filename=file.filename,
        status="pending",
        llm_provider=settings.llm_provider,
        llm_model=settings.llm_model,
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    analysis_id = str(analysis.id)

    background_tasks.add_task(
        run_analysis_pipeline,
        analysis_id=analysis_id,
        content=content,
    )

    logger.info("analysis_queued", extra={"analysis_id": analysis_id})
    return AnalysisResponse.model_validate(analysis)


@router.get("/engagements/{engagement_id}/analyses", response_model=AnalysisListResponse)
async def list_analyses(
    engagement_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
):
    result_check = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    if not result_check.scalar_one_or_none():
        raise NotFoundError("Mission")

    result = await db.execute(
        select(Analysis)
        .where(Analysis.engagement_id == engagement_id)
        .order_by(Analysis.started_at.desc())
    )
    items = result.scalars().all()

    return AnalysisListResponse(
        items=[AnalysisResponse.model_validate(a) for a in items],
        total=len(items),
    )


@router.get("/analyses/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise NotFoundError("Analyse")
    return AnalysisResponse.model_validate(analysis)


async def run_analysis_pipeline(analysis_id: str, content: bytes) -> None:
    """Background task: ingestion → paths → mitre → agent → persist."""
    import asyncio
    import json

    from app.database import get_session_factory
    from app.models.analysis import Analysis, AttackPath, PathMitreTechnique
    from app.modules import agent, ingestion, mitre
    from app.modules.paths import extract_attack_paths

    logger.info("pipeline_start", extra={"analysis_id": analysis_id})
    factory = get_session_factory()
    # Hard cap: LLM timeout per path × max paths + 5 min overhead for ingestion/DB
    pipeline_timeout = settings.llm_timeout_seconds * settings.llm_max_paths + 300

    async def _update_status(status: str, progress: int, error: str | None = None):
        async with factory() as db:
            result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            row = result.scalar_one_or_none()
            if row:
                row.status = status
                row.progress = progress
                if error:
                    row.error_message = error
                if status == "completed":
                    row.completed_at = datetime.now(UTC)
                await db.commit()

    async def _run_core():
        await _update_status("ingesting", 5)
        _broadcast_ws(analysis_id, "ingestion", 5, "Ingestion du graphe BloodHound en cours...")

        bh_data = json.loads(content)
        graph, node_count, edge_count = ingestion.ingest_bloodhound(bh_data)

        async with factory() as db:
            result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            row = result.scalar_one_or_none()
            if row:
                row.total_nodes = node_count
                row.total_edges = edge_count
                await db.commit()

        await _update_status("extracting_paths", 25)
        _broadcast_ws(analysis_id, "extraction", 25, "Extraction des chemins d'attaque...")

        paths = extract_attack_paths(graph)

        async with factory() as db:
            result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            row = result.scalar_one_or_none()
            if row:
                row.total_paths = len(paths)
                await db.commit()

        await _update_status("analyzing", 40)
        _broadcast_ws(analysis_id, "mitre", 40, "Enrichissement MITRE ATT&CK...")

        enriched_paths = mitre.enrich_paths_with_mitre(paths)

        await _update_status("analyzing", 55)
        _broadcast_ws(analysis_id, "analysis", 55, "Analyse par l'agent IA...")

        analyzed_paths = await agent.analyze_paths_batch(enriched_paths, analysis_id)

        await _update_status("analyzing", 85)
        _broadcast_ws(analysis_id, "persisting", 85, "Sauvegarde des résultats...")

        async with factory() as db:
            for ap_data in analyzed_paths:
                ap = AttackPath(
                    id=uuid.uuid4(),
                    analysis_id=uuid.UUID(analysis_id),
                    source_node=ap_data["source_node"],
                    target_node=ap_data["target_node"],
                    hops=ap_data["hops"],
                    length=ap_data["length"],
                    exploitability_score=ap_data.get("exploitability_score"),
                    stealth_score=ap_data.get("stealth_score"),
                    global_score=ap_data.get("global_score"),
                    risk_level=ap_data.get("risk_level"),
                    explanation_fr=ap_data.get("explanation_fr"),
                    recommendation_fr=ap_data.get("recommendation_fr"),
                    llm_raw_response=ap_data.get("llm_raw_response"),
                )
                db.add(ap)

                for tech in ap_data.get("mitre_techniques", []):
                    pmt = PathMitreTechnique(
                        path_id=ap.id,
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        url=tech["url"],
                    )
                    db.add(pmt)

            await db.commit()

        await _update_status("completed", 100)
        _broadcast_ws(analysis_id, "completed", 100, "Analyse terminée avec succès !")
        logger.info("pipeline_completed", extra={"analysis_id": analysis_id, "paths": len(analyzed_paths)})

    try:
        await asyncio.wait_for(_run_core(), timeout=pipeline_timeout)
    except asyncio.TimeoutError:
        logger.error("pipeline_timeout", extra={"analysis_id": analysis_id})
        await _update_status("failed", 0, "Le pipeline a dépassé le délai maximum d'exécution")
        _broadcast_ws(analysis_id, "failed", 0, "Délai d'exécution dépassé")
    except Exception as exc:
        logger.exception("pipeline_failed", extra={"analysis_id": analysis_id, "error": str(exc)})
        await _update_status("failed", 0, str(exc))
        _broadcast_ws(analysis_id, "failed", 0, f"Erreur : {exc}")


@router.get("/analyses/{analysis_id}/graph")
async def get_analysis_graph(
    analysis_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
) -> dict:
    """Return graph data (nodes + edges + paths) for Cytoscape.js rendering."""
    from app.models.analysis import AttackPath, PathMitreTechnique

    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise NotFoundError("Analyse")

    paths_result = await db.execute(
        select(AttackPath).where(AttackPath.analysis_id == analysis_id)
    )
    attack_paths = paths_result.scalars().all()

    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    path_list = []

    for ap in attack_paths:
        hops = ap.hops or []
        path_node_ids: list[str] = []

        for hop in hops:
            src_id = hop.get("source", "")
            dst_id = hop.get("target", "")
            edge_type = hop.get("edge_type", "Unknown")

            if src_id and src_id not in nodes:
                nodes[src_id] = {
                    "id": src_id,
                    "label": hop.get("source_label", src_id),
                    "type": hop.get("source_type", "Unknown"),
                    "is_privileged": False,
                }

            if dst_id and dst_id not in nodes:
                nodes[dst_id] = {
                    "id": dst_id,
                    "label": hop.get("target_label", dst_id),
                    "type": hop.get("target_type", "Unknown"),
                    "is_privileged": False,
                }

            edge_id = f"{src_id}__{dst_id}__{edge_type}"
            if src_id and dst_id and edge_id not in edges:
                edges[edge_id] = {
                    "id": edge_id,
                    "source": src_id,
                    "target": dst_id,
                    "type": edge_type,
                }

            if src_id and src_id not in path_node_ids:
                path_node_ids.append(src_id)
            if dst_id and dst_id not in path_node_ids:
                path_node_ids.append(dst_id)

        # Mark target node as privileged
        if ap.target_node and ap.target_node in nodes:
            nodes[ap.target_node]["is_privileged"] = True

        # Attach risk to target node (upgrade to highest)
        if ap.risk_level and ap.target_node in nodes:
            existing = nodes[ap.target_node].get("risk_level")
            rank = {"faible": 1, "moyen": 2, "eleve": 3, "critique": 4}
            if not existing or rank.get(ap.risk_level, 0) > rank.get(existing, 0):
                nodes[ap.target_node]["risk_level"] = ap.risk_level

        path_list.append({
            "path_id": str(ap.id),
            "source_node": ap.source_node,
            "target_node": ap.target_node,
            "risk_level": ap.risk_level,
            "global_score": ap.global_score,
            "length": ap.length,
            "node_ids": path_node_ids,
            "edge_ids": [
                f"{hops[i].get('source')}__{hops[i].get('target')}__{hops[i].get('edge_type','Unknown')}"
                for i in range(len(hops))
                if hops[i].get("source") and hops[i].get("target")
            ],
        })

    return {
        "nodes": [{"data": n} for n in nodes.values()],
        "edges": [{"data": e} for e in edges.values()],
        "paths": path_list,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_paths": len(path_list),
        },
    }


def _broadcast_ws(analysis_id: str, stage: str, progress: int, message_fr: str) -> None:
    """Emit a WebSocket event to all subscribers of this analysis."""
    from app.api.v1.ws import manager

    import asyncio

    event = {"stage": stage, "progress": progress, "message_fr": message_fr}
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(manager.broadcast(analysis_id, event))
    except RuntimeError:
        pass
