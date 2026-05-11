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

# Audit log middleware — records every authenticated mutating request.
from app.core import audit as _audit
_audit.install(app)


# Security response headers — applied to every response.
@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    # Defense-in-depth headers. CSP is intentionally permissive for inline-script
    # pages (Alpine.js); tighten if those pages move to external JS.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=()",
    )
    if settings.app_env == "production":
        # HSTS only in production — never on plain-HTTP localhost dev.
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    return response


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
from app.api.v1 import auth, engagements, analyses, paths, stats, mitre, reports, ws, llm_settings, ldap_collector, admin  # noqa: E402

app.include_router(auth.router, prefix="/api/v1")
app.include_router(engagements.router, prefix="/api/v1")
app.include_router(analyses.router, prefix="/api/v1")
app.include_router(paths.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")
app.include_router(mitre.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(llm_settings.router, prefix="/api/v1")
app.include_router(ldap_collector.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
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
    """Bring the schema up-to-date on boot.

    Strategy:
      1. Run Alembic FIRST. If the DB is fresh, it creates everything via the
         migration scripts. If the DB is mid-revision, alembic catches it up.
      2. Then a defensive `create_all` only as a safety net for tables that
         exist as SQLAlchemy models but lack a migration (very rare).

    Why not just `create_all`?
      `create_all` is a no-op for existing tables: it never adds new columns,
      never alters existing schema. A pre-existing DB plus a new model field
      means the column is silently missing and every query crashes — which
      is exactly the bug that hit Phase 1.
    """
    import app.models  # noqa: F401 — register all models

    # 1. Alembic — source of truth for schema changes.
    try:
        await _run_alembic_upgrade()
        logger.info("db_schema_ready_alembic")
    except Exception as exc:
        logger.exception("db_schema_alembic_failed", extra={"error": str(exc)})

    # 2. Safety net: create_all picks up any model that lacks a migration.
    #    Idempotent and won't damage anything alembic already managed.
    from app.database import Base, get_engine
    engine = get_engine()
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("db_schema_ready_create_all")
    except Exception as exc:
        logger.error("db_schema_create_all_failed", extra={"error": str(exc)})


async def _run_alembic_upgrade() -> None:
    """Run `alembic upgrade head` programmatically inside this process.

    Handles three cases:
      A. Fresh DB              → create_all (above) just made everything.
                                 We stamp the DB to head so future migrations
                                 don't try to re-create tables.
      B. DB at a known revision → upgrade head applies anything newer.
      C. DB has tables but no   → bootstrap stamp to the most-recent revision
         alembic_version row     whose schema matches what's there, then upgrade.

    Synchronous Alembic call wrapped in a thread so we don't block the loop.
    """
    import asyncio
    from pathlib import Path

    def _do_upgrade() -> None:
        from alembic import command
        from alembic.config import Config
        from sqlalchemy import create_engine, inspect, text

        ini_path = Path(__file__).resolve().parent.parent / "alembic.ini"
        if not ini_path.exists():
            logger.warning("alembic_ini_missing", extra={"path": str(ini_path)})
            return

        cfg = Config(str(ini_path))
        cfg.set_main_option("sqlalchemy.url", settings.database_url)
        cfg.set_main_option("script_location", str(ini_path.parent / "alembic"))
        cfg.attributes["configure_logger"] = False

        # Inspect the existing DB to decide whether we need a bootstrap stamp.
        sync_engine = create_engine(settings.database_url)
        try:
            insp = inspect(sync_engine)
            tables = set(insp.get_table_names())
            has_alembic = "alembic_version" in tables
            has_core = "users" in tables and "engagements" in tables

            if not has_alembic and has_core:
                # Case C — schema was bootstrapped by create_all on an older
                # code revision. Figure out the highest migration whose schema
                # is already present, then stamp.
                user_cols = {c["name"] for c in insp.get_columns("users")}
                bootstrap_rev = "0003"  # baseline before this phase
                if "token_version" in user_cols:
                    # 0005 columns are present → bootstrap is at 0005
                    bootstrap_rev = "0005"
                elif "engagement_members" in tables:
                    bootstrap_rev = "0004"
                # auth_tokens table is created by 0006
                if "auth_tokens" in tables and bootstrap_rev < "0006":
                    bootstrap_rev = "0006"
                logger.warning(
                    "alembic_bootstrap_stamp",
                    extra={"rev": bootstrap_rev,
                           "reason": "tables exist without alembic_version"},
                )
                command.stamp(cfg, bootstrap_rev)
            elif not has_alembic and not has_core:
                # Case A — fresh DB. create_all already built everything;
                # stamp to head so future migrations work cleanly.
                logger.info("alembic_bootstrap_fresh_db")
                command.stamp(cfg, "head")
                return

            # Case B (and tail end of A/C) — apply anything newer than what
            # the DB currently knows about.
            command.upgrade(cfg, "head")
        finally:
            sync_engine.dispose()

    await asyncio.to_thread(_do_upgrade)


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
