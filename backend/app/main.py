"""FastAPI application entrypoint."""

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import configure_logging

settings = get_settings()
configure_logging(settings.log_level, json_output=settings.app_env == "production")

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown."""
    logger.info("app_starting", extra={"env": settings.app_env})
    await _init_db_schema()
    await _ensure_admin_user()
    if settings.seed_admin_password in ("ChangeMeNow!2026",):
        logger.warning("default_admin_password_in_use — change SEED_ADMIN_PASSWORD in production")
    yield
    logger.info("app_shutting_down")


app = FastAPI(
    title="AD Audit AI",
    description="Active Directory Security Audit Automation Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

_cors_origins = [
    "http://localhost",
    "http://localhost:80",
    "http://localhost:3000",
    "https://localhost",
    settings.app_base_url,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(AuthenticationError)
async def auth_error_handler(request: Request, exc: AuthenticationError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": exc.detail},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(AuthorizationError)
async def authz_error_handler(request: Request, exc: AuthorizationError):
    return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": exc.detail})


@app.exception_handler(NotFoundError)
async def not_found_handler(request: Request, exc: NotFoundError):
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": exc.detail})


@app.exception_handler(ValidationError)
async def validation_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": exc.detail}
    )


# Register routers
from app.api.v1 import auth, engagements, analyses, paths, stats, mitre, reports, ws, llm_settings, ldap_collector  # noqa: E402

app.include_router(auth.router, prefix="/api/v1")
app.include_router(engagements.router, prefix="/api/v1")
app.include_router(analyses.router, prefix="/api/v1")
app.include_router(paths.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")
app.include_router(mitre.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(llm_settings.router, prefix="/api/v1")
app.include_router(ldap_collector.router, prefix="/api/v1")
app.include_router(ws.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}


@app.get("/readyz")
async def readyz():
    checks = {}

    try:
        from app.database import get_session_factory
        from sqlalchemy import text

        factory = get_session_factory()
        async with factory() as db:
            await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"

    try:
        from neo4j import AsyncGraphDatabase

        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        await driver.verify_connectivity()
        await driver.close()
        checks["neo4j"] = "ok"
    except Exception as exc:
        checks["neo4j"] = f"error: {exc}"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ok" if all_ok else "degraded", "checks": checks},
    )


async def _init_db_schema() -> None:
    """Create all tables (idempotent). Handles first-boot schema creation."""
    from app.database import Base, get_engine
    import app.models  # noqa: F401 — register all models

    engine = get_engine()
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("db_schema_ready")
    except Exception as exc:
        logger.error("db_schema_init_failed", extra={"error": str(exc)})


async def _ensure_admin_user() -> None:
    """Seed the default admin user if it doesn't exist."""
    from app.core.security import hash_password
    from app.database import get_session_factory
    from app.models.user import User
    from sqlalchemy import select

    try:
        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(select(User).where(User.email == settings.seed_admin_email))
            if result.scalar_one_or_none() is None:
                admin = User(
                    id=uuid.uuid4(),
                    email=settings.seed_admin_email,
                    hashed_password=hash_password(settings.seed_admin_password),
                    full_name=settings.seed_admin_name,
                    role="admin",
                )
                db.add(admin)
                await db.commit()
                logger.info("admin_user_seeded", extra={"email": settings.seed_admin_email})
    except Exception as exc:
        logger.warning("admin_seed_failed", extra={"error": str(exc)})
