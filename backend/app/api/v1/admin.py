"""Admin-only endpoints: audit log viewer + user management."""

import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.core.security import get_current_user, hash_password, require_role
from app.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/audit-logs")
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_role("admin")),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user_id: uuid.UUID | None = Query(None, description="Filter by user"),
    action_prefix: str | None = Query(None, description="Filter by action prefix, e.g. 'POST /api/v1/engagements'"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
) -> dict[str, Any]:
    """Return paginated audit-log entries, newest first."""
    base = select(AuditLog)
    count_q = select(func.count()).select_from(AuditLog)

    if user_id:
        base = base.where(AuditLog.user_id == user_id)
        count_q = count_q.where(AuditLog.user_id == user_id)
    if action_prefix:
        like = f"{action_prefix}%"
        base = base.where(AuditLog.action.like(like))
        count_q = count_q.where(AuditLog.action.like(like))
    if resource_type:
        base = base.where(AuditLog.resource_type == resource_type)
        count_q = count_q.where(AuditLog.resource_type == resource_type)

    total = (await db.execute(count_q)).scalar_one()
    rows = (
        await db.execute(
            base.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()

    # Fetch user emails in one query for display
    user_ids = {r.user_id for r in rows if r.user_id}
    user_map: dict[uuid.UUID, str] = {}
    if user_ids:
        users = (
            await db.execute(select(User.id, User.email).where(User.id.in_(user_ids)))
        ).all()
        user_map = {uid: email for uid, email in users}

    return {
        "items": [
            {
                "id": r.id,
                "user_id": str(r.user_id) if r.user_id else None,
                "user_email": user_map.get(r.user_id) if r.user_id else None,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "ip_address": r.ip_address,
                "metadata": r.meta,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ──────────────────────────────────────────────────────────────────────────
# User management — listed/created/disabled by admin
# ──────────────────────────────────────────────────────────────────────────


@router.get("/users")
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_role("admin")),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    include_disabled: bool = Query(True),
    q: str | None = Query(None, description="Email/name search"),
) -> dict[str, Any]:
    base = select(User)
    count_q = select(func.count()).select_from(User)
    if not include_disabled:
        base = base.where(User.is_active.is_(True))
        count_q = count_q.where(User.is_active.is_(True))
    if q:
        like = f"%{q.lower()}%"
        base = base.where(
            (func.lower(User.email).like(like)) | (func.lower(User.full_name).like(like))
        )
        count_q = count_q.where(
            (func.lower(User.email).like(like)) | (func.lower(User.full_name).like(like))
        )

    total = (await db.execute(count_q)).scalar_one()
    rows = (
        await db.execute(base.order_by(User.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    return {
        "items": [
            {
                "id": str(u.id),
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat(),
                "updated_at": u.updated_at.isoformat() if u.updated_at else None,
                "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            }
            for u in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.patch("/users/{user_id}")
async def update_user(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
    *, payload: dict,
) -> dict[str, Any]:
    """Update role, full_name, or is_active. Cannot edit your own active flag
    (you'd lock yourself out)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("Utilisateur")

    if "role" in payload:
        new_role = payload["role"]
        if new_role not in ("admin", "manager", "auditor"):
            raise ValidationError("Rôle invalide")
        user.role = new_role
    if "full_name" in payload and payload["full_name"]:
        user.full_name = str(payload["full_name"])[:255]
    if "is_active" in payload:
        if user.id == current_user.id:
            raise ValidationError("Vous ne pouvez pas désactiver votre propre compte")
        user.is_active = bool(payload["is_active"])

    await db.commit()
    await db.refresh(user)
    logger.info("user_updated", extra={"id": str(user.id), "by": str(current_user.id)})
    return {
        "id": str(user.id), "email": user.email, "full_name": user.full_name,
        "role": user.role, "is_active": user.is_active,
    }


@router.post("/users/{user_id}/disable", status_code=204)
async def disable_user(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
):
    """Soft-disable: user can't log in but data is preserved."""
    if user_id == current_user.id:
        raise ValidationError("Vous ne pouvez pas désactiver votre propre compte")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("Utilisateur")
    user.is_active = False
    await db.commit()
    logger.info("user_disabled", extra={"id": str(user_id), "by": str(current_user.id)})


@router.post("/users/{user_id}/enable", status_code=204)
async def enable_user(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("Utilisateur")
    user.is_active = True
    await db.commit()
    logger.info("user_enabled", extra={"id": str(user_id), "by": str(current_user.id)})


@router.get("/users/{user_id}/impact")
async def get_user_delete_impact(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_role("admin")),
) -> dict[str, Any]:
    """Return the impact of permanently deleting a user:
    how many missions they belong to, lead, or created.
    """
    from app.models.engagement import Engagement
    from app.models.engagement_member import EngagementMember

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("Utilisateur")

    missions_member = (
        await db.execute(
            select(func.count()).select_from(EngagementMember)
            .where(EngagementMember.user_id == user_id)
        )
    ).scalar_one()

    missions_lead = (
        await db.execute(
            select(func.count()).select_from(EngagementMember)
            .where(
                EngagementMember.user_id == user_id,
                EngagementMember.role_on_engagement == "lead",
            )
        )
    ).scalar_one()

    missions_created = (
        await db.execute(
            select(func.count()).select_from(Engagement)
            .where(Engagement.created_by == user_id)
        )
    ).scalar_one()

    return {
        "user_id": str(user_id),
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "missions_member": missions_member,
        "missions_lead": missions_lead,
        "missions_created": missions_created,
    }


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
):
    """Permanently delete a user account.

    Cascade behaviour:
    - engagement_members rows are deleted via DB CASCADE (ondelete=CASCADE on user_id FK).
    - Engagements the user created are re-attributed to the deleting admin so the FK
      constraint is satisfied and missions are not lost.
    - Audit logs are preserved for traceability (user_id becomes orphaned but that is
      acceptable for historical records).
    - The user themselves cannot be deleted (use deactivate for self-management).
    - Admin accounts cannot be deleted; deactivate them instead.
    """
    from sqlalchemy import update as sa_update
    from app.models.engagement import Engagement

    if user_id == current_user.id:
        raise ValidationError("Vous ne pouvez pas supprimer votre propre compte.")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("Utilisateur")

    if user.role == "admin":
        raise ValidationError(
            "Les comptes administrateurs ne peuvent pas être supprimés. "
            "Désactivez le compte ou rétrogradez-le d'abord."
        )

    # Re-attribute missions created by this user to the deleting admin.
    # The FK engagements.created_by is NOT NULL so we cannot nullify it.
    await db.execute(
        sa_update(Engagement)
        .where(Engagement.created_by == user_id)
        .values(created_by=current_user.id)
    )

    # Hard-delete the user. The DB cascades handle:
    #   engagement_members.user_id  → DELETE CASCADE
    #   engagement_members.added_by → SET NULL
    await db.delete(user)
    await db.commit()

    logger.info(
        "user_permanently_deleted",
        extra={"deleted_user": str(user_id), "by_admin": str(current_user.id)},
    )
