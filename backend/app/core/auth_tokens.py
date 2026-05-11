"""Helpers for issuing + verifying single-use auth tokens.

Tokens are random 32-byte URL-safe strings. Only their SHA-256 hash is stored,
so even a DB dump doesn't leak working tokens.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth_token import AuthToken

# TTLs
INVITE_TTL_HOURS = 72         # 3 days — gives an admin time to convey it
PASSWORD_RESET_TTL_HOURS = 1


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def issue_token(
    db: AsyncSession, user_id: uuid.UUID, purpose: str, ttl_hours: int,
) -> tuple[str, AuthToken]:
    """Generate a fresh token string + persist its hash. Returns (plaintext, row).

    Caller MUST use the plaintext only for the outgoing email/link — never
    log it, never put it in the response body except in the immediate flow.
    """
    plaintext = secrets.token_urlsafe(32)
    row = AuthToken(
        id=uuid.uuid4(),
        user_id=user_id,
        purpose=purpose,
        token_hash=_hash(plaintext),
        expires_at=datetime.now(UTC) + timedelta(hours=ttl_hours),
    )
    db.add(row)
    await db.flush()
    return plaintext, row


async def consume_token(
    db: AsyncSession, token: str, purpose: str,
) -> AuthToken | None:
    """Look up + atomically mark consumed. Returns the row if valid, else None."""
    th = _hash(token)
    result = await db.execute(
        select(AuthToken).where(
            AuthToken.token_hash == th, AuthToken.purpose == purpose
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        return None
    if row.consumed_at is not None:
        return None
    if row.expires_at <= datetime.now(UTC):
        return None
    row.consumed_at = datetime.now(UTC)
    await db.flush()
    return row
