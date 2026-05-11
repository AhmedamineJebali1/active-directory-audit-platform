"""Authentication endpoints: /login, /register, /me, /refresh, /logout,
/invite, /accept-invite, /forgot-password, /reset-password."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.auth_tokens import (
    INVITE_TTL_HOURS,
    PASSWORD_RESET_TTL_HOURS,
    consume_token,
    issue_token,
)
from app.core.exceptions import AuthenticationError, ConflictError, NotFoundError, ValidationError
from app.core.notifications import send_email
from app.core.password_policy import validate_password
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    # Per-(email, ip) rate-limit. See app/core/rate_limit.py.
    from app.core.rate_limit import check_login_attempt, record_login_failure, record_login_success

    client_ip = (request.client.host if request.client else "0.0.0.0")
    check_login_attempt(payload.email, client_ip)

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        record_login_failure(payload.email, client_ip)
        raise AuthenticationError("Email ou mot de passe incorrect")

    if not user.is_active:
        record_login_failure(payload.email, client_ip)
        raise AuthenticationError("Compte désactivé")

    record_login_success(payload.email, client_ip)

    # Defensive: in case migration 0005 hasn't been applied yet on this DB,
    # `last_login_at` / `token_version` might not exist. Wrap so login never
    # 500s on a transitional schema.
    try:
        user.last_login_at = datetime.now(UTC)
        await db.commit()
    except Exception as exc:
        logger.warning("login_last_login_update_failed", extra={"error": str(exc)})
        await db.rollback()

    tv = getattr(user, "token_version", 0) or 0
    access_token = create_access_token(str(user.id), user.role, tv)
    refresh_token = create_refresh_token(str(user.id), user.role, tv)

    logger.info("user_login", extra={"user_id": str(user.id), "email": user.email})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    payload: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_role("admin")),
):
    validate_password(payload.password, user_email=payload.email)
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise ConflictError(f"Un utilisateur avec l'email {payload.email} existe déjà")

    user = User(
        id=uuid.uuid4(),
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    logger.info("user_registered", extra={"email": payload.email, "role": payload.role})

    return UserResponse.model_validate(user)


@router.get("/me", response_model=UserResponse)
async def me(current_user=Depends(get_current_user)):
    return UserResponse.model_validate(current_user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    token_data = decode_token(payload.refresh_token)
    if token_data.get("type") != "refresh":
        raise AuthenticationError("Token de rafraîchissement invalide")

    user_id = token_data.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise AuthenticationError("Utilisateur introuvable ou désactivé")

    # Reject refresh tokens issued before the last logout / force-logout.
    token_tv = token_data.get("tv")
    if token_tv is not None and token_tv != user.token_version:
        raise AuthenticationError("Session révoquée — veuillez vous reconnecter")

    access_token = create_access_token(str(user.id), user.role, user.token_version)
    refresh_token = create_refresh_token(str(user.id), user.role, user.token_version)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/logout", status_code=204)
async def logout(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
):
    """Invalidate ALL active sessions for the current user.

    Bumps token_version, which makes every previously-issued access AND
    refresh token unusable. Client should clear local tokens too.
    """
    current_user.token_version = (current_user.token_version or 0) + 1
    await db.commit()
    logger.info("user_logout", extra={"user_id": str(current_user.id)})


@router.post("/admin/users/{user_id}/force-logout", status_code=204)
async def force_logout_user(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_role("admin")),
):
    """Admin: invalidate ALL sessions of another user (e.g. on compromise)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("Utilisateur")
    user.token_version = (user.token_version or 0) + 1
    await db.commit()
    logger.info("user_force_logout", extra={"user_id": str(user.id)})


# ──────────────────────────────────────────────────────────────────────────
# Invite flow — admin sends an invite email; recipient sets their password
# ──────────────────────────────────────────────────────────────────────────


class InviteRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    role: str = Field(default="auditor")


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=10)
    new_password: str = Field(min_length=12, max_length=72)


@router.post("/invite", status_code=202)
async def invite_user(
    payload: InviteRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
):
    """Create a placeholder account + send an invite email with a one-shot link.

    The user receives an email with a URL like:
        {APP_BASE_URL}/accept-invite.html?token=…
    Where they pick their own password (validated against the policy).
    """
    if payload.role not in ("admin", "manager", "auditor"):
        raise ValidationError("Rôle invalide")

    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise ConflictError(f"Un utilisateur avec l'email {payload.email} existe déjà")

    # Random throwaway password — user MUST change it via the invite link.
    import secrets
    placeholder_pw = secrets.token_urlsafe(40)
    user = User(
        id=uuid.uuid4(),
        email=str(payload.email),
        hashed_password=hash_password(placeholder_pw),
        full_name=payload.full_name,
        role=payload.role,
        is_active=False,   # disabled until they accept the invite
    )
    db.add(user)
    await db.flush()

    token, _ = await issue_token(db, user.id, "invite", INVITE_TTL_HOURS)
    await db.commit()

    # Build link
    base = settings.app_base_url.rstrip("/")
    link = f"{base}/accept-invite.html?token={token}"

    body = (
        f"Bonjour {payload.full_name},\n\n"
        f"Vous avez été invité(e) sur AD Audit AI par {current_user.email}.\n\n"
        f"Pour activer votre compte et choisir votre mot de passe, "
        f"cliquez sur le lien ci-dessous (valide {INVITE_TTL_HOURS} heures) :\n\n"
        f"  {link}\n\n"
        f"Votre rôle : {payload.role}\n\n"
        f"Si vous n'attendiez pas cette invitation, ignorez cet email.\n"
    )
    send_email(str(payload.email), "Invitation à AD Audit AI", body)
    logger.info("invite_sent", extra={"email": str(payload.email), "by": str(current_user.id)})
    return {"email": str(payload.email), "expires_in_hours": INVITE_TTL_HOURS}


@router.post("/accept-invite", response_model=TokenResponse)
async def accept_invite(
    payload: AcceptInviteRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Consume the invite token, set the chosen password, activate account,
    and immediately log the user in (returns access + refresh tokens)."""
    row = await consume_token(db, payload.token, "invite")
    if not row:
        raise AuthenticationError("Lien d'invitation invalide ou expiré")

    user = (await db.execute(select(User).where(User.id == row.user_id))).scalar_one_or_none()
    if not user:
        raise AuthenticationError("Compte introuvable")

    validate_password(payload.new_password, user_email=user.email)
    user.hashed_password = hash_password(payload.new_password)
    user.is_active = True
    user.token_version = (user.token_version or 0) + 1   # invalidate any leftover sessions
    user.last_login_at = datetime.now(UTC)
    await db.commit()

    access = create_access_token(str(user.id), user.role, user.token_version)
    refresh = create_refresh_token(str(user.id), user.role, user.token_version)
    logger.info("invite_accepted", extra={"user_id": str(user.id)})
    return TokenResponse(
        access_token=access, refresh_token=refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


# ──────────────────────────────────────────────────────────────────────────
# Password reset — never confirms whether an email exists
# ──────────────────────────────────────────────────────────────────────────


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=10)
    new_password: str = Field(min_length=12, max_length=72)


@router.post("/forgot-password", status_code=202)
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Send a password-reset email IF the address exists. Always returns 202
    so an attacker can't enumerate accounts."""
    # Loose rate limit — 3 requests per (email, IP) per 15 min
    from app.core.rate_limit import _BUCKET   # reuse the same bucket
    client_ip = request.client.host if request.client else "0.0.0.0"
    # Reuse the failure-tracking semantic to throttle reset spam
    _BUCKET.record_failure(str(payload.email), client_ip)
    try:
        _BUCKET.check(str(payload.email), client_ip)
    except AuthenticationError:
        # Still return 202 — don't tell the attacker we throttled
        logger.warning("password_reset_throttled", extra={"email": str(payload.email)})
        return {"status": "ok"}

    user = (
        await db.execute(select(User).where(User.email == str(payload.email)))
    ).scalar_one_or_none()

    if user and user.is_active:
        token, _ = await issue_token(db, user.id, "password_reset", PASSWORD_RESET_TTL_HOURS)
        await db.commit()
        base = settings.app_base_url.rstrip("/")
        link = f"{base}/reset-password.html?token={token}"
        body = (
            f"Bonjour,\n\n"
            f"Vous avez demandé une réinitialisation de mot de passe pour AD Audit AI.\n\n"
            f"Cliquez sur le lien ci-dessous (valide {PASSWORD_RESET_TTL_HOURS} heure) :\n\n"
            f"  {link}\n\n"
            f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
            f"Votre mot de passe actuel reste valide tant qu'il n'est pas changé.\n"
        )
        send_email(user.email, "Réinitialisation de votre mot de passe", body)
        logger.info("password_reset_requested", extra={"user_id": str(user.id)})

    # Always return the same response, regardless of whether the email exists
    return {"status": "ok"}


@router.post("/reset-password", response_model=TokenResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    row = await consume_token(db, payload.token, "password_reset")
    if not row:
        raise AuthenticationError("Lien de réinitialisation invalide ou expiré")

    user = (await db.execute(select(User).where(User.id == row.user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise AuthenticationError("Compte introuvable ou désactivé")

    validate_password(payload.new_password, user_email=user.email)
    user.hashed_password = hash_password(payload.new_password)
    user.token_version = (user.token_version or 0) + 1   # invalidate every other session
    user.last_login_at = datetime.now(UTC)
    await db.commit()

    access = create_access_token(str(user.id), user.role, user.token_version)
    refresh = create_refresh_token(str(user.id), user.role, user.token_version)
    logger.info("password_reset_completed", extra={"user_id": str(user.id)})
    return TokenResponse(
        access_token=access, refresh_token=refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )
