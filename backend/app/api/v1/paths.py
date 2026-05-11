"""Attack paths endpoints with filtering and pagination."""

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.engagement_access import require_analysis_access
from app.core.exceptions import NotFoundError, ValidationError
from app.core.security import get_current_user
from app.database import get_db
from app.models.analysis import Analysis, AttackPath
from app.models.engagement import Engagement
from app.modules.remediation import build_bundle, build_script_for_path
from app.schemas.analysis import AttackPathListResponse, AttackPathResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["paths"])


@router.get("/analyses/{analysis_id}/paths", response_model=AttackPathListResponse)
async def list_paths(
    db: Annotated[AsyncSession, Depends(get_db)],
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
    risk: str | None = Query(None, description="Filter by risk level (critique/eleve/moyen/faible)"),
    min_score: float | None = Query(None, ge=0, le=10),
    technique: str | None = Query(None, description="Filter by MITRE technique ID (e.g. T1078)"),
    max_length: int | None = Query(None, ge=1, le=10),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    analysis_id = analysis.id

    query = (
        select(AttackPath)
        .where(AttackPath.analysis_id == analysis_id)
        .options(selectinload(AttackPath.mitre_techniques))
    )

    if risk:
        query = query.where(AttackPath.risk_level == risk.lower())
    if min_score is not None:
        query = query.where(AttackPath.global_score >= min_score)
    if max_length is not None:
        query = query.where(AttackPath.length <= max_length)

    count_query = select(func.count()).select_from(
        query.subquery()
    )
    total = (await db.execute(count_query)).scalar_one()

    query = query.order_by(AttackPath.global_score.desc().nullslast()).limit(limit).offset(offset)
    result = await db.execute(query)
    paths = result.scalars().all()

    if technique:
        from app.models.analysis import PathMitreTechnique
        tech_filter = set()
        for p in paths:
            for mt in p.mitre_techniques:
                if mt.technique_id.startswith(technique):
                    tech_filter.add(p.id)
        paths = [p for p in paths if p.id in tech_filter]

    return AttackPathListResponse(
        items=[AttackPathResponse.model_validate(p) for p in paths],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/analyses/{analysis_id}/paths/{path_id}", response_model=AttackPathResponse)
async def get_path(
    path_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
):
    result = await db.execute(
        select(AttackPath)
        .where(AttackPath.id == path_id, AttackPath.analysis_id == analysis.id)
        .options(selectinload(AttackPath.mitre_techniques))
    )
    path = result.scalar_one_or_none()
    if not path:
        raise NotFoundError("Chemin d'attaque")
    return AttackPathResponse.model_validate(path)


def _ascii_safe_filename(name: str) -> str:
    """Strip non-ASCII chars so Content-Disposition filename works in all browsers."""
    import re

    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "remediation"


@router.get("/analyses/{analysis_id}/paths/{path_id}/remediation-script")
async def download_remediation_script(
    path_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
):
    """Return the PowerShell remediation script for a single attack path."""
    result = await db.execute(
        select(AttackPath)
        .where(AttackPath.id == path_id, AttackPath.analysis_id == analysis.id)
        .options(selectinload(AttackPath.mitre_techniques))
    )
    path = result.scalar_one_or_none()
    if not path:
        raise NotFoundError("Chemin d'attaque")

    engagement = (
        await db.execute(
            select(Engagement).where(Engagement.id == analysis.engagement_id)
        )
    ).scalar_one_or_none()

    guide = build_script_for_path(path, engagement=engagement)
    eng_code = engagement.code if engagement else "mission"
    filename = _ascii_safe_filename(f"mitigation-{eng_code}-{path.id.hex[:8]}.md")

    return Response(
        content=guide,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/analyses/{analysis_id}/remediation-bundle.zip")
async def download_remediation_bundle(
    db: Annotated[AsyncSession, Depends(get_db)],
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
):
    """Return a ZIP archive with every remediation script + LISEZ-MOI.txt."""
    analysis_id = analysis.id
    if analysis.status != "completed":
        raise ValidationError("L'analyse n'est pas encore terminée")

    engagement = (
        await db.execute(select(Engagement).where(Engagement.id == analysis.engagement_id))
    ).scalar_one_or_none()

    paths_result = await db.execute(
        select(AttackPath)
        .where(AttackPath.analysis_id == analysis_id)
        .options(selectinload(AttackPath.mitre_techniques))
    )
    paths = paths_result.scalars().all()
    if not paths:
        raise ValidationError("Aucun chemin d'attaque trouvé pour cette analyse")

    zip_bytes = build_bundle(engagement, paths)
    eng_code = engagement.code if engagement else "mission"
    filename = _ascii_safe_filename(f"remediation-{eng_code}-{analysis_id.hex[:8]}.zip")

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
