"""EngagementMember — explicit grant of access to a mission.

A user can access an engagement they did not create only if they appear in
this table. Admins bypass this check entirely (see api/v1/engagements.py).

Role on engagement:
  - lead         — full control (rename, archive, add/remove members)
  - contributor  — can upload analyses, write notes
  - viewer       — read-only

This sits ABOVE the global RBAC role:
  - global admin  → sees everything, no membership needed
  - global manager → can create engagements; on those they create, they are auto-added as lead
  - global auditor → must be invited to an engagement to see it
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Enum, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EngagementMember(Base):
    __tablename__ = "engagement_members"
    __table_args__ = (
        UniqueConstraint("engagement_id", "user_id", name="uq_engagement_member"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    role_on_engagement: Mapped[str] = mapped_column(
        Enum("lead", "contributor", "viewer", name="engagement_member_role"),
        nullable=False,
        default="contributor",
    )
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    engagement: Mapped["Engagement"] = relationship(
        "Engagement", back_populates="members", foreign_keys=[engagement_id]
    )
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<EngagementMember eng={self.engagement_id} user={self.user_id} role={self.role_on_engagement}>"
