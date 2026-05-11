"""Audit log middleware — records every authenticated mutating request.

Hooks into the FastAPI ASGI dispatch chain. For each POST/PATCH/PUT/DELETE,
after the response is generated, we extract:

  - user_id  : from the JWT (None if anonymous, e.g. /auth/login attempts)
  - action   : "<METHOD> <route_template>"  e.g. "POST /api/v1/engagements"
  - resource_id : the last path-parameter UUID/int we see (best-effort)
  - ip_address : X-Forwarded-For (first hop) or client.host
  - metadata : {status_code, route, query_params (no auth tokens),
                response_size, latency_ms}

We DO NOT log request bodies — they often contain passwords, API keys, files.

Failures here are swallowed (logged as warnings). An auditing crash must
never break a real user request.
"""

import logging
import re
import time
import uuid
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.security import decode_token

logger = logging.getLogger(__name__)

# Methods we audit. GETs are not audited (would 10x the row count, and
# read-access tracking belongs in app logs not audit logs).
_AUDITED_METHODS = {"POST", "PATCH", "PUT", "DELETE"}

# Skip noisy/sensitive paths that don't need audit-log rows.
_SKIP_PATHS = (
    "/healthz", "/readyz",
    "/docs", "/openapi.json", "/redoc",
    # Auth refresh churn: useful as a metric but pollutes the audit table.
    "/api/v1/auth/refresh",
)

# Match a UUID at the end of a path so we can pull "resource_id" for free.
_UUID_RE = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE
)


def _client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:45]
    return request.client.host if request.client else None


def _extract_user_id(request: Request) -> uuid.UUID | None:
    """Best-effort: pull the user id from the bearer token without re-querying."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(None, 1)[1].strip()
    try:
        payload = decode_token(token)
        sub = payload.get("sub")
        if sub:
            return uuid.UUID(sub)
    except Exception:
        pass
    return None


def _extract_resource_id(path: str) -> str | None:
    m = _UUID_RE.findall(path)
    if m:
        return m[-1]  # last UUID — typically the "resource" the request acts on
    return None


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        path = request.url.path

        # Fast path: no audit for reads and skipped routes
        if method not in _AUDITED_METHODS or any(path.startswith(s) for s in _SKIP_PATHS):
            return await call_next(request)

        start = time.monotonic()
        try:
            response: Response = await call_next(request)
        except Exception:
            # Don't try to write audit if the request itself blew up — let the
            # exception handler do its thing.
            raise

        latency_ms = int((time.monotonic() - start) * 1000)

        # Best-effort persist; never let audit failures impact the request.
        try:
            await _persist(request, response, latency_ms)
        except Exception as exc:
            logger.warning("audit_persist_failed", extra={"error": str(exc), "path": path})

        return response


async def _persist(request: Request, response: Response, latency_ms: int) -> None:
    from sqlalchemy.exc import SQLAlchemyError

    from app.database import get_session_factory
    from app.models.audit_log import AuditLog

    user_id = _extract_user_id(request)
    method = request.method.upper()
    path = request.url.path
    action = f"{method} {path}"
    resource_id = _extract_resource_id(path)

    # Pull route template if FastAPI matched a route — gives us a stable
    # action name without the UUID in it (better for grouping).
    route = request.scope.get("route")
    route_path = getattr(route, "path", path) if route else path
    if route_path != path:
        action = f"{method} {route_path}"

    metadata: dict = {
        "status_code": response.status_code,
        "latency_ms": latency_ms,
        "ua": (request.headers.get("user-agent") or "")[:200],
    }
    # Lightly capture query keys (NEVER values — they can carry tokens)
    if request.url.query:
        metadata["query_keys"] = sorted({
            k for k, _ in request.query_params.multi_items()
        })

    log = AuditLog(
        user_id=user_id,
        action=action[:100],
        resource_type=_resource_type_from_path(path),
        resource_id=resource_id,
        ip_address=_client_ip(request),
        meta=metadata,
        created_at=datetime.now(UTC),
    )
    factory = get_session_factory()
    async with factory() as db:
        try:
            db.add(log)
            await db.commit()
        except SQLAlchemyError as exc:
            await db.rollback()
            logger.warning("audit_db_error", extra={"error": str(exc)})


def _resource_type_from_path(path: str) -> str | None:
    """Heuristic: '/api/v1/engagements/.../analyses/...' → 'analysis'.

    Returns the LAST plural-noun segment seen before a UUID. Keeps the audit
    log queryable by resource type.
    """
    parts = [p for p in path.strip("/").split("/") if p]
    plural_to_singular = {
        "engagements": "engagement",
        "analyses": "analysis",
        "paths": "attack_path",
        "users": "user",
        "members": "engagement_member",
        "llm": "llm_config",
        "auth": "auth",
    }
    last_resource = None
    for p in parts:
        if p in plural_to_singular:
            last_resource = plural_to_singular[p]
    return last_resource


def install(app: FastAPI) -> None:
    """Register the audit middleware on the FastAPI app."""
    app.add_middleware(AuditLogMiddleware)
