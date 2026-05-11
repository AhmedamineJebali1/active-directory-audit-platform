"""Engagement CRUD endpoints. Access is gated by per-engagement membership;
see core/engagement_access.py for the rules."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.engagement_access import (
    list_accessible_engagement_ids,
    require_engagement_access,
)
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError
from app.core.security import get_current_user, require_role
from app.database import get_db
from app.models.engagement import Engagement
from app.models.engagement_member import EngagementMember
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
    """List engagements the current user can access.

    Admins see all engagements. Everyone else sees only engagements where
    they appear in `engagement_members`.
    """
    accessible_ids = await list_accessible_engagement_ids(db, current_user)

    base_q = select(Engagement)
    count_q = select(func.count()).select_from(Engagement)
    if accessible_ids is not None:
        if not accessible_ids:
            # User has no engagement access at all — short-circuit
            return EngagementListResponse(items=[], total=0, limit=limit, offset=offset)
        base_q = base_q.where(Engagement.id.in_(accessible_ids))
        count_q = count_q.where(Engagement.id.in_(accessible_ids))
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
    # Auto-add the creator as `lead` so they keep access without an extra step.
    db.add(EngagementMember(
        id=uuid.uuid4(),
        engagement_id=engagement.id,
        user_id=current_user.id,
        role_on_engagement="lead",
        added_by=current_user.id,
    ))
    await db.commit()
    await db.refresh(engagement)

    logger.info("engagement_created", extra={"code": payload.code, "user": str(current_user.id)})
    return EngagementResponse.model_validate(engagement)


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement: Annotated[Engagement, Depends(require_engagement_access("viewer"))],
):
    return EngagementResponse.model_validate(engagement)


@router.patch("/{engagement_id}", response_model=EngagementResponse)
async def update_engagement(
    payload: EngagementUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    # Lead-on-engagement OR global admin can modify
    engagement: Annotated[Engagement, Depends(require_engagement_access("lead"))],
):
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
    engagement: Annotated[Engagement, Depends(require_engagement_access("viewer"))],
) -> dict[str, Any]:
    return {
        "notes": engagement.notes or "",
        "notes_updated_at": engagement.notes_updated_at.isoformat() if engagement.notes_updated_at else None,
    }


@router.patch("/{engagement_id}/notes")
async def update_notes(
    payload: EngagementNotesUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    # Contributor or higher — viewers shouldn't write notes
    engagement: Annotated[Engagement, Depends(require_engagement_access("contributor"))],
) -> dict[str, Any]:
    engagement.notes = payload.notes
    engagement.notes_updated_at = datetime.now(UTC)
    await db.commit()
    logger.info("engagement_notes_updated", extra={"id": str(engagement.id)})
    return {
        "notes": engagement.notes,
        "notes_updated_at": engagement.notes_updated_at.isoformat(),
    }


# ── Member management ─────────────────────────────────────────────────────


@router.get("/{engagement_id}/members")
async def list_engagement_members(
    db: Annotated[AsyncSession, Depends(get_db)],
    engagement: Annotated[Engagement, Depends(require_engagement_access("viewer"))],
) -> dict[str, Any]:
    """List members of this engagement with their per-engagement role."""
    from app.models.user import User

    result = await db.execute(
        select(EngagementMember, User)
        .join(User, EngagementMember.user_id == User.id)
        .where(EngagementMember.engagement_id == engagement.id)
        .order_by(EngagementMember.created_at)
    )
    items = []
    for member, user in result.all():
        items.append({
            "id": str(member.id),
            "user_id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "global_role": user.role,
            "role_on_engagement": member.role_on_engagement,
            "added_at": member.created_at.isoformat(),
        })
    return {"items": items, "total": len(items), "your_role": engagement.user_role}


@router.post("/{engagement_id}/members", status_code=201)
async def add_engagement_member(
    db: Annotated[AsyncSession, Depends(get_db)],
    engagement: Annotated[Engagement, Depends(require_engagement_access("lead"))],
    current_user=Depends(get_current_user),
    *, payload: dict,
) -> dict[str, Any]:
    """Add a user to this engagement. Lead role or global admin only."""
    from app.models.user import User

    user_email = (payload.get("email") or "").strip().lower()
    role = payload.get("role_on_engagement", "contributor")
    if role not in ("lead", "contributor", "viewer"):
        raise ValueError("role_on_engagement must be lead, contributor or viewer")
    if not user_email:
        raise ValueError("email is required")

    user_q = await db.execute(select(User).where(User.email == user_email))
    user = user_q.scalar_one_or_none()
    if not user:
        raise NotFoundError("Utilisateur")

    # Already a member?
    existing_q = await db.execute(
        select(EngagementMember).where(
            EngagementMember.engagement_id == engagement.id,
            EngagementMember.user_id == user.id,
        )
    )
    if existing_q.scalar_one_or_none():
        raise ConflictError(f"{user.email} est déjà membre de cette mission")

    member = EngagementMember(
        id=uuid.uuid4(),
        engagement_id=engagement.id,
        user_id=user.id,
        role_on_engagement=role,
        added_by=current_user.id,
    )
    db.add(member)
    await db.commit()
    logger.info("engagement_member_added",
                extra={"engagement": str(engagement.id), "user": user_email, "role": role})
    return {"id": str(member.id), "email": user.email, "role_on_engagement": role}


@router.delete("/{engagement_id}/members/{user_id}", status_code=204)
async def remove_engagement_member(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    engagement: Annotated[Engagement, Depends(require_engagement_access("lead"))],
    current_user=Depends(get_current_user),
):
    """Remove a member from this engagement. Lead or global admin only.
    A lead cannot remove themselves if they're the last lead."""
    result = await db.execute(
        select(EngagementMember).where(
            EngagementMember.engagement_id == engagement.id,
            EngagementMember.user_id == user_id,
        )
    )
    member = result.scalar_one_or_none()
    if not member:
        raise NotFoundError("Membre")

    # Prevent orphaning: don't let the last lead remove themselves
    if member.role_on_engagement == "lead":
        leads_q = await db.execute(
            select(func.count()).select_from(EngagementMember)
            .where(
                EngagementMember.engagement_id == engagement.id,
                EngagementMember.role_on_engagement == "lead",
            )
        )
        if (leads_q.scalar() or 0) <= 1 and current_user.role != "admin":
            raise AuthorizationError(
                "Impossible de supprimer le dernier lead. Désignez d'abord un autre lead."
            )

    await db.delete(member)
    await db.commit()
    logger.info("engagement_member_removed",
                extra={"engagement": str(engagement.id), "user": str(user_id)})
