"""JWT authentication, password hashing, and RBAC dependencies."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.database import get_db

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, role: str, token_version: int = 0) -> str:
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": subject, "role": role, "exp": expire,
        "type": "access", "tv": token_version,
    }
    return jwt.encode(payload, settings.app_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str, role: str, token_version: int = 0) -> str:
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub": subject, "role": role, "exp": expire,
        "type": "refresh", "tv": token_version,
    }
    return jwt.encode(payload, settings.app_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.app_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError as exc:
        raise AuthenticationError("Token invalide ou expiré") from exc


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Dependency: extract and validate current authenticated user."""
    from app.models.user import User
    from sqlalchemy import select

    if credentials is None:
        raise AuthenticationError()

    payload = decode_token(credentials.credentials)
    user_id: str | None = payload.get("sub")
    if not user_id:
        raise AuthenticationError()

    import uuid as _uuid
    try:
        user_uuid = _uuid.UUID(user_id)
    except ValueError:
        raise AuthenticationError()

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthenticationError("Compte introuvable ou désactivé")

    # Server-side session revocation: when a user logs out (or admin force-
    # logout), users.token_version is incremented. JWTs issued before that
    # carry an older `tv` claim and are rejected here, so they cannot be used
    # again even though they're still cryptographically valid.
    #
    # `token_version` may not exist on the user row yet if migration 0005
    # hasn't been applied — treat it as 0 in that case so existing sessions
    # keep working through the transition.
    token_tv = payload.get("tv")
    if token_tv is not None:
        user_tv = getattr(user, "token_version", 0) or 0
        if token_tv != user_tv:
            raise AuthenticationError("Session révoquée — veuillez vous reconnecter")

    return user


def require_role(*roles: str):
    """Factory: returns a FastAPI dependency that enforces role membership."""

    async def _check(
        current_user=Depends(get_current_user),
    ):
        if current_user.role not in roles:
            raise AuthorizationError(
                f"Rôle requis : {', '.join(roles)}. Votre rôle : {current_user.role}"
            )
        return current_user

    return _check
