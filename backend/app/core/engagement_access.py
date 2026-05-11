"""Engagement-level access control.

Single source of truth for "can this user see this engagement?". All
engagement-scoped endpoints (engagements, analyses, paths, stats, reports,
remediation, mitre, graph, …) should go through these helpers.

Global RBAC roles vs per-engagement membership:
  - admin (global)   → bypasses membership, sees everything
  - manager (global) → can create engagements; on their own engagements they
                       are auto-added as lead, otherwise they need explicit
                       membership like an auditor
  - auditor (global) → only sees engagements where they are a member
"""

import uuid
from typing import Annotated

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthorizationError, NotFoundError
from app.core.security import get_current_user
from app.database import get_db
from app.models.engagement import Engagement
from app.models.engagement_member import EngagementMember


# Role hierarchy on an engagement — higher number = more rights.
_ENGAGEMENT_ROLE_RANK = {"viewer": 1, "contributor": 2, "lead": 3}


def _rank(role: str) -> int:
    return _ENGAGEMENT_ROLE_RANK.get(role, 0)


async def get_user_engagement_role(
    db: AsyncSession, user, engagement_id: uuid.UUID,
) -> str | None:
    """Return the user's role on this engagement, or None if no access.

    Global admins always return 'lead' (effective full control).
    """
    if user.role == "admin":
        return "lead"
    result = await db.execute(
        select(EngagementMember).where(
            EngagementMember.engagement_id == engagement_id,
            EngagementMember.user_id == user.id,
        )
    )
    member = result.scalar_one_or_none()
    return member.role_on_engagement if member else None


def require_engagement_access(min_role: str = "viewer"):
    """FastAPI dependency factory: load an engagement and verify access.

    Usage:
        @router.get("/engagements/{engagement_id}")
        async def get_engagement(
            engagement_id: uuid.UUID,
            engagement: Engagement = Depends(require_engagement_access("viewer")),
        ): ...

    Raises:
        NotFoundError    if the engagement does not exist
        AuthorizationError if the user is not allowed at this role level
    """
    min_rank = _rank(min_role)
    if not min_rank:
        raise ValueError(f"Unknown engagement role: {min_role}")

    async def _check(
        engagement_id: uuid.UUID,
        db: Annotated[AsyncSession, Depends(get_db)],
        current_user=Depends(get_current_user),
    ) -> Engagement:
        result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise NotFoundError("Mission")

        eng_role = await get_user_engagement_role(db, current_user, engagement_id)
        if eng_role is None or _rank(eng_role) < min_rank:
            raise AuthorizationError(
                "Vous n'avez pas accès à cette mission. "
                "Demandez à un lead ou un administrateur de vous y ajouter."
            )
        # Stash the per-engagement role on the engagement object so the endpoint
        # can fork on it without re-querying.
        engagement.user_role = eng_role  # type: ignore[attr-defined]
        return engagement

    return _check


def require_analysis_access(min_role: str = "viewer"):
    """FastAPI dependency factory: load an Analysis and verify access to its
    parent engagement.

    Returns the Analysis (not the engagement) so endpoints can use it directly.
    Stashes the user's per-engagement role at `analysis.user_role`.
    """
    min_rank = _rank(min_role)
    if not min_rank:
        raise ValueError(f"Unknown engagement role: {min_role}")

    async def _check(
        analysis_id: uuid.UUID,
        db: Annotated[AsyncSession, Depends(get_db)],
        current_user=Depends(get_current_user),
    ):
        from app.models.analysis import Analysis  # circular-import safe

        result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
        analysis = result.scalar_one_or_none()
        if not analysis:
            raise NotFoundError("Analyse")

        eng_role = await get_user_engagement_role(db, current_user, analysis.engagement_id)
        if eng_role is None or _rank(eng_role) < min_rank:
            raise AuthorizationError(
                "Vous n'avez pas accès à cette analyse. "
                "Demandez à un lead ou un administrateur de vous ajouter à la mission parente."
            )
        analysis.user_role = eng_role  # type: ignore[attr-defined]
        return analysis

    return _check


async def list_accessible_engagement_ids(
    db: AsyncSession, user, include_archived: bool = False,
) -> set[uuid.UUID] | None:
    """Return the set of engagement IDs the user can see.

    Returns None for admins (meaning "no filter — show all"). This is a small
    optimization so list endpoints don't have to JOIN members for admins.
    """
    if user.role == "admin":
        return None
    q = (
        select(EngagementMember.engagement_id)
        .where(EngagementMember.user_id == user.id)
    )
    result = await db.execute(q)
    return {row[0] for row in result.all()}
