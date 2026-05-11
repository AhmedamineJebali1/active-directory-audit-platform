"""User model."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Enum, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum("admin", "manager", "auditor", name="user_role"),
        nullable=False,
        default="auditor",
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Incremented every time the user logs out or admin force-logs-them-out.
    # The current value is embedded in every issued JWT; tokens whose `tv`
    # claim doesn't match the user's current token_version are rejected.
    # This is how server-side session invalidation works without storing
    # every issued token in a DB. See app/core/security.py.
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0",
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    engagements: Mapped[list["Engagement"]] = relationship(back_populates="creator")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")

    def __repr__(self) -> str:
        return f"<User {self.email} role={self.role}>"
