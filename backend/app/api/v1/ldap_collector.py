"""LDAP live collection endpoint — POST /engagements/{id}/ldap-collect."""

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.engagement_access import require_engagement_access
from app.core.exceptions import NotFoundError
from app.core.security import require_role
from app.database import get_db
from app.models.analysis import Analysis
from app.models.engagement import Engagement
from app.schemas.analysis import AnalysisResponse
from typing import Annotated

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ldap"])


class LDAPCollectRequest(BaseModel):
    dc_host: str = Field(..., min_length=1, description="IP or hostname of the domain controller")
    domain: str = Field(..., min_length=3, description="AD domain FQDN (e.g. corp.local)")
    username: str = Field(..., min_length=1, description="AD account (no domain prefix)")
    password: str = Field(..., min_length=1)
    port: int = Field(default=389, ge=1, le=65535)
    use_ssl: bool = Field(default=False)


@router.post(
    "/engagements/{engagement_id}/ldap-collect",
    response_model=AnalysisResponse,
    status_code=202,
)
async def ldap_collect(
    req: LDAPCollectRequest,
    engagement: Annotated[Engagement, Depends(require_engagement_access("contributor"))],
    db: AsyncSession = Depends(get_db),
):
    """Start a live AD collection from a domain controller."""
    engagement_id = engagement.id
    analysis = Analysis(
        id=uuid.uuid4(),
        engagement_id=engagement_id,
        source_type="ldap_live",
        source_filename=f"ldap://{req.dc_host}/{req.domain}",
        status="pending",
        progress=0,
        started_at=datetime.now(UTC),
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    analysis_id = str(analysis.id)
    loop = asyncio.get_running_loop()
    asyncio.create_task(_run_ldap_pipeline(analysis_id=analysis_id, req=req, loop=loop))

    logger.info("ldap_collect_queued", extra={"analysis_id": analysis_id, "host": req.dc_host})
    return AnalysisResponse.model_validate(analysis)


async def _run_ldap_pipeline(
    analysis_id: str,
    req: LDAPCollectRequest,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Background pipeline: LDAP collection → ingestion → paths → MITRE → LLM → persist."""
    from app.api.v1.ws import manager
    from app.database import get_session_factory
    from app.models.analysis import Analysis, AttackPath, PathMitreTechnique
    from app.modules import agent, ingestion, mitre
    from app.modules.paths import extract_attack_paths

    factory = get_session_factory()

    async def _update(status: str, progress: int, error: str | None = None) -> None:
        async with factory() as db:
            res = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            a = res.scalar_one_or_none()
            if a:
                a.status = status
                a.progress = progress
                if error:
                    a.error_message = error
                if status == "completed":
                    a.completed_at = datetime.now(UTC)
                await db.commit()

    async def _broadcast(stage: str, message: str, progress: int) -> None:
        await manager.broadcast(
            analysis_id,
            {"stage": stage, "message_fr": message, "progress": progress},
        )

    def _sync_cb(stage: str, message: str, progress: int) -> None:
        """Fire-and-forget WS broadcast from the LDAP sync thread."""
        asyncio.run_coroutine_threadsafe(_broadcast(stage, message, progress), loop)

    try:
        await _update("ingesting", 3)
        await _broadcast("ldap_connecting", "Connexion au contrôleur de domaine…", 3)

        from app.modules.ldap_collector import LDAPCollector

        collector = LDAPCollector(
            dc_host=req.dc_host,
            domain=req.domain,
            username=req.username,
            password=req.password,
            port=req.port,
            use_ssl=req.use_ssl,
            progress_callback=_sync_cb,
        )

        # Run synchronous LDAP enumeration without blocking the event loop.
        # collect_all() zeros self.password immediately after bind (inside connect()).
        bh_data = await asyncio.to_thread(collector.collect_all)
        # Belt-and-suspenders: also clear the request-level copy now that collection is done.
        req.password = ""

        await _broadcast("ingesting", "Construction du graphe en mémoire…", 88)
        await _update("ingesting", 88)

        graph, node_count, edge_count = ingestion.ingest_bloodhound(bh_data)

        async with factory() as db:
            res = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            a = res.scalar_one_or_none()
            if a:
                a.total_nodes = node_count
                a.total_edges = edge_count
                await db.commit()

        await _broadcast("extracting_paths", "Extraction des chemins d'attaque…", 91)
        await _update("extracting_paths", 91)

        paths = extract_attack_paths(graph)

        async with factory() as db:
            res = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            a = res.scalar_one_or_none()
            if a:
                a.total_paths = len(paths)
                await db.commit()

        await _broadcast("analyzing", "Enrichissement MITRE ATT&CK…", 93)
        await _update("analyzing", 93)

        enriched_paths = mitre.enrich_paths_with_mitre(paths)

        await _broadcast("analyzing", f"Agent IA — analyse de {len(paths)} chemins…", 95)

        analyzed_paths = await agent.analyze_paths_batch(enriched_paths, analysis_id)

        await _broadcast("analyzing", "Sauvegarde des résultats…", 98)
        await _update("analyzing", 98)

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
                await db.flush()
                for tech in ap_data.get("mitre_techniques", []):
                    db.add(PathMitreTechnique(
                        path_id=ap.id,
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        url=tech["url"],
                    ))
            await db.commit()

        await _update("completed", 100)
        await _broadcast("completed", "Collecte et analyse terminées avec succès !", 100)
        logger.info("ldap_pipeline_completed", extra={"analysis_id": analysis_id, "paths": len(analyzed_paths)})

    except Exception as exc:
        logger.exception("ldap_pipeline_failed", extra={"analysis_id": analysis_id})
        err = str(exc)
        await _update("failed", 0, err)
        await _broadcast("failed", f"Erreur de collecte : {err}", 0)
