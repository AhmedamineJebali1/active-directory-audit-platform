"""Engagement CRUD endpoints."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError
from app.core.security import get_current_user, require_role
from app.database import get_db
from app.models.engagement import Engagement
from app.schemas.engagement import (
    EngagementCreate,
    EngagementListResponse,
    EngagementNotesUpdate,
    EngagementResponse,
    EngagementUpdate,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/engagements", tags=["engagements"])


@router.get("", response_model=EngagementListResponse)
async def list_engagements(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    include_archived: bool = Query(False),
):
    base_q = select(Engagement)
    count_q = select(func.count()).select_from(Engagement)
    if not include_archived:
        base_q = base_q.where(Engagement.status != "archived")
        count_q = count_q.where(Engagement.status != "archived")

    count_result = await db.execute(count_q)
    total = count_result.scalar_one()

    result = await db.execute(
        base_q.order_by(Engagement.created_at.desc()).limit(limit).offset(offset)
    )
    items = result.scalars().all()

    return EngagementListResponse(
        items=[EngagementResponse.model_validate(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=EngagementResponse, status_code=201)
async def create_engagement(
    payload: EngagementCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin", "manager")),
):
    existing = await db.execute(select(Engagement).where(Engagement.code == payload.code))
    if existing.scalar_one_or_none():
        raise ConflictError(f"Le code mission '{payload.code}' est déjà utilisé")

    engagement = Engagement(
        id=uuid.uuid4(),
        client_name=payload.client_name,
        code=payload.code,
        description=payload.description,
        created_by=current_user.id,
    )
    db.add(engagement)
    await db.commit()
    await db.refresh(engagement)

    logger.info("engagement_created", extra={"code": payload.code, "user": str(current_user.id)})
    return EngagementResponse.model_validate(engagement)


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise NotFoundError("Mission")
    return EngagementResponse.model_validate(engagement)


@router.patch("/{engagement_id}", response_model=EngagementResponse)
async def update_engagement(
    engagement_id: uuid.UUID,
    payload: EngagementUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin", "manager")),
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise NotFoundError("Mission")

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(engagement, field, value)

    await db.commit()
    await db.refresh(engagement)
    return EngagementResponse.model_validate(engagement)


@router.delete("/{engagement_id}", status_code=204)
async def delete_engagement(
    engagement_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
):
    """Permanently delete an engagement and all its data (cascade)."""
    from sqlalchemy import delete

    from app.models.analysis import Analysis, AttackPath, PathMitreTechnique

    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise NotFoundError("Mission")

    # Collect analysis IDs first for cascade
    analysis_ids_q = await db.execute(
        select(Analysis.id).where(Analysis.engagement_id == engagement_id)
    )
    analysis_ids = [row[0] for row in analysis_ids_q.all()]

    if analysis_ids:
        # Collect attack path IDs
        path_ids_q = await db.execute(
            select(AttackPath.id).where(AttackPath.analysis_id.in_(analysis_ids))
        )
        path_ids = [row[0] for row in path_ids_q.all()]
        if path_ids:
            await db.execute(
                delete(PathMitreTechnique).where(PathMitreTechnique.path_id.in_(path_ids))
            )
        await db.execute(delete(AttackPath).where(AttackPath.analysis_id.in_(analysis_ids)))
        await db.execute(delete(Analysis).where(Analysis.engagement_id == engagement_id))

    db.delete(engagement)
    await db.commit()
    logger.info("engagement_deleted", extra={"id": str(engagement_id), "code": engagement.code})


@router.get("/stats/summary")
async def get_engagement_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
) -> dict[str, Any]:
    """Return per-status counts and global path totals for the dashboard."""
    from app.models.analysis import Analysis, AttackPath

    status_result = await db.execute(
        select(Engagement.status, func.count()).group_by(Engagement.status)
    )
    by_status = dict(status_result.all())

    total_paths_result = await db.execute(select(func.count()).select_from(AttackPath))
    total_paths = total_paths_result.scalar() or 0

    critical_result = await db.execute(
        select(func.count()).select_from(AttackPath).where(AttackPath.risk_level == "critique")
    )
    total_critical = critical_result.scalar() or 0

    return {
        "by_status": by_status,
        "total": sum(by_status.values()),
        "draft": by_status.get("draft", 0),
        "in_progress": by_status.get("in_progress", 0),
        "completed": by_status.get("completed", 0),
        "archived": by_status.get("archived", 0),
        "total_paths": total_paths,
        "total_critical": total_critical,
    }


@router.get("/{engagement_id}/notes")
async def get_notes(
    engagement_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
) -> dict[str, Any]:
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise NotFoundError("Mission")
    return {
        "notes": engagement.notes or "",
        "notes_updated_at": engagement.notes_updated_at.isoformat() if engagement.notes_updated_at else None,
    }


@router.patch("/{engagement_id}/notes")
async def update_notes(
    engagement_id: uuid.UUID,
    payload: EngagementNotesUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
) -> dict[str, Any]:
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise NotFoundError("Mission")

    engagement.notes = payload.notes
    engagement.notes_updated_at = datetime.now(UTC)
    await db.commit()
    logger.info("engagement_notes_updated", extra={"id": str(engagement_id)})
    return {
        "notes": engagement.notes,
        "notes_updated_at": engagement.notes_updated_at.isoformat(),
    }
