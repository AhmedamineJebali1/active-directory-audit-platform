"""Analysis endpoints — upload, list, detail, pipeline trigger."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, File, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.engagement_access import (
    require_analysis_access,
    require_engagement_access,
)
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
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    # Uploading a new analysis requires write access on the engagement.
    engagement: Annotated[Engagement, Depends(require_engagement_access("contributor"))],
    file: UploadFile = File(...),
):
    engagement_id = engagement.id
    fname = file.filename or ""
    is_zip = fname.lower().endswith(".zip")
    is_json = fname.lower().endswith(".json")
    if not (is_zip or is_json):
        raise ValidationError("Le fichier doit être un export BloodHound (.json ou .zip)")

    content = await file.read()
    if len(content) > 200 * 1024 * 1024:
        raise ValidationError("Fichier trop volumineux (max 200 MB)")

    source_type = "bloodhound_zip" if is_zip else "bloodhound_json"

    # Resolve the LLM provider+model the way the agent will actually use them.
    # The agent reads DB overrides first (set via Settings UI) and falls back
    # to env. We mirror that here so the analysis row records what was REALLY
    # used, not what the env says.
    from app.modules.agent import _load_db_llm_config
    db_llm = await _load_db_llm_config()
    effective_provider = db_llm.get("llm_provider") or settings.llm_provider
    effective_model = db_llm.get("llm_model") or settings.llm_model

    analysis = Analysis(
        id=uuid.uuid4(),
        engagement_id=engagement_id,
        source_type=source_type,
        source_filename=fname,
        status="pending",
        llm_provider=effective_provider,
        llm_model=effective_model,
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
    db: Annotated[AsyncSession, Depends(get_db)],
    engagement: Annotated[Engagement, Depends(require_engagement_access("viewer"))],
):
    result = await db.execute(
        select(Analysis)
        .where(Analysis.engagement_id == engagement.id)
        .order_by(Analysis.started_at.desc())
    )
    items = result.scalars().all()

    return AnalysisListResponse(
        items=[AnalysisResponse.model_validate(a) for a in items],
        total=len(items),
    )


@router.get("/analyses/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
):
    return AnalysisResponse.model_validate(analysis)


async def run_analysis_pipeline(analysis_id: str, content: bytes) -> None:
    """Background task: ingestion → paths → mitre → agent → persist.

    Wraps every step so the analysis row is always moved out of "pending":
    failures are recorded as `failed` with the exception message, empty
    graphs/paths complete cleanly with an explanatory note.
    """
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
        # Status updates must NEVER raise — otherwise an analysis can stay stuck
        # in "pending" forever even when the outer try/except runs.
        try:
            async with factory() as db:
                result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
                row = result.scalar_one_or_none()
                if row:
                    row.status = status
                    row.progress = progress
                    if error:
                        row.error_message = error[:2000]
                    if status == "completed":
                        row.completed_at = datetime.now(UTC)

                    # Auto-advance the parent engagement out of "draft" as soon
                    # as an analysis runs — otherwise the dashboard keeps
                    # showing the mission in the "En attente" column forever.
                    # Only move forward, never backward: leave "completed" /
                    # "archived" engagements alone.
                    if status in ("ingesting", "extracting_paths", "analyzing",
                                  "completed", "failed"):
                        eng_q = await db.execute(
                            select(Engagement).where(Engagement.id == row.engagement_id)
                        )
                        eng = eng_q.scalar_one_or_none()
                        if eng and eng.status == "draft":
                            eng.status = "in_progress"

                    await db.commit()
        except Exception as exc:
            logger.exception(
                "status_update_failed",
                extra={"analysis_id": analysis_id, "target_status": status, "error": str(exc)},
            )

    async def _run_core():
        await _update_status("ingesting", 5)
        _broadcast_ws(analysis_id, "ingestion", 5, "Ingestion du graphe BloodHound en cours...")

        # Detect format: ZIP magic bytes are PK\x03\x04
        if content[:4] == b"PK\x03\x04":
            graph, node_count, edge_count = ingestion.ingest_bloodhound_zip(content)
        else:
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

        # No paths → finish cleanly. The graph itself is still available for
        # exploration in the "Graphe" tab; persisting an empty paths list is
        # a normal outcome (e.g. small lab AD with no obvious escalation).
        if not paths:
            msg = (
                f"Aucun chemin d'attaque trouvé. Graphe ingéré : "
                f"{node_count} nœuds, {edge_count} arêtes. "
                "Aucune cible privilégiée atteignable depuis les comptes non-privilégiés."
            )
            logger.warning(
                "pipeline_no_paths",
                extra={"analysis_id": analysis_id, "nodes": node_count, "edges": edge_count},
            )
            await _update_status("completed", 100, error=msg)
            _broadcast_ws(analysis_id, "completed", 100, msg)
            return

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


@router.post("/analyses/detect-format")
async def detect_format_endpoint(
    current_user=Depends(get_current_user),
    file: UploadFile = File(...),
) -> dict:
    """Read-only preview: inspect an uploaded BloodHound file and return what
    the platform would do with it, WITHOUT writing anything to the database
    or running the LLM pipeline.

    Returns:
      - format: detected format identifier (e.g. ``bloodhound_zip_ce_v6``)
      - version: BloodHound output version when known
      - file_types: per-section item counts
      - graph: ``{nodes, edges, privileged_nodes, source_candidates}`` —
               actual ingest result
      - sample_paths: up to 3 lowest-hop paths to a privileged target
      - errors / warnings: any parse issues
    """
    from app.modules import ingestion as ing
    from app.modules.paths import extract_attack_paths

    fname = (file.filename or "").lower()
    content = await file.read()
    if len(content) > 200 * 1024 * 1024:
        raise ValidationError("Fichier trop volumineux (max 200 MB)")

    detection = ing.detect_format(content)

    # Try a real ingest preview — bounded by the same 200MB cap.
    graph_summary: dict = {"nodes": 0, "edges": 0, "privileged_nodes": 0,
                           "source_candidates": 0}
    sample_paths: list[dict] = []
    ingest_error: str | None = None

    try:
        if content[:4] == b"PK\x03\x04":
            graph, n, e = ing.ingest_bloodhound_zip(content)
        else:
            import json as _json
            data = _json.loads(content)
            graph, n, e = ing.ingest_bloodhound(data)

        priv = sum(1 for _, d in graph.nodes(data=True) if d.get("is_privileged"))
        srcs = sum(1 for _, d in graph.nodes(data=True)
                   if not d.get("is_privileged")
                   and d.get("node_type") in ("User", "Computer", "Group"))
        graph_summary = {
            "nodes": n, "edges": e,
            "privileged_nodes": priv,
            "source_candidates": srcs,
        }

        # Sample top-3 shortest paths
        paths = extract_attack_paths(graph)
        for p in sorted(paths, key=lambda x: x.length)[:3]:
            sample_paths.append({
                "source": p.source_node,
                "target": p.target_node,
                "length": p.length,
                "edge_types": p.edge_types,
            })
    except Exception as ex:
        ingest_error = str(ex)[:300]

    return {
        "filename": file.filename,
        "size_bytes": len(content),
        "detection": detection,
        "graph": graph_summary,
        "sample_paths": sample_paths,
        "ingest_error": ingest_error,
    }


@router.get("/analyses/{analysis_id}/events")
async def get_analysis_events(
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
) -> dict:
    """Return the replay buffer of pipeline events + current status/error.

    Lets the UI reconstruct the timeline (stages, messages, error_message)
    even if the WebSocket missed the live events.
    """
    from app.api.v1.ws import manager

    analysis_id = analysis.id

    return {
        "analysis_id": str(analysis_id),
        "status": analysis.status,
        "progress": analysis.progress,
        "error_message": analysis.error_message,
        "events": manager.get_events(str(analysis_id)),
    }


@router.get("/analyses/{analysis_id}/graph")
async def get_analysis_graph(
    db: Annotated[AsyncSession, Depends(get_db)],
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
) -> dict:
    """Return graph data (nodes + edges + paths) for Cytoscape.js rendering."""
    from app.models.analysis import AttackPath, PathMitreTechnique

    analysis_id = analysis.id
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
    """Emit a WebSocket event to all subscribers of this analysis.

    Always records the event in the replay buffer so clients that connect
    after the pipeline already started still see prior stages.
    Never raises — broadcast failures shouldn't break the pipeline.
    """
    from app.api.v1.ws import manager

    import asyncio

    event = {"stage": stage, "progress": progress, "message_fr": message_fr}
    try:
        manager.record_event(analysis_id, event)
    except Exception as exc:
        logger.debug("ws_record_failed", extra={"err": str(exc)})

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(manager.broadcast(analysis_id, event))
    except RuntimeError:
        # No running loop (sync call site) — replay buffer still has the event,
        # so any client polling /api/v1/analyses/{id} will see fresh progress.
        pass
    except Exception as exc:
        logger.debug("ws_broadcast_failed", extra={"err": str(exc)})
