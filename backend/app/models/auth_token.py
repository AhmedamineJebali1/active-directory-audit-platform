"""Single-use auth tokens — used for both password-reset and invite flows.

Tokens are stored as SHA-256 hashes (not plaintext). Each token has:
  - purpose: "password_reset" | "invite"
  - one-shot: consumed_at marks it used
  - expires_at: TTL enforcement
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    purpose: Mapped[str] = mapped_column(
        Enum("password_reset", "invite", name="auth_token_purpose"),
        nullable=False, index=True,
    )
    # SHA-256 hex of the actual token string. Never stored in plaintext.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    user = relationship("User")

    def is_valid_now(self) -> bool:
        return (
            self.consumed_at is None
            and self.expires_at > datetime.now(UTC)
        )
