"""Integration test fixtures: in-memory SQLite DB + FastAPI test client."""

import os
import uuid
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# These must be set BEFORE importing the app.
os.environ.setdefault("APP_SECRET_KEY", "integration-test-secret-key-not-for-prod-use-only")
os.environ.setdefault("LLM_PROVIDER", "mock")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest_asyncio.fixture
async def test_engine():
    """In-memory SQLite engine that creates the schema on startup."""
    from app.database import Base
    from app.models import audit_log, engagement, user, analysis  # noqa: F401  — register tables

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def test_session_factory(test_engine):
    return async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def client(test_session_factory) -> AsyncGenerator[AsyncClient, None]:
    """HTTPX async client with DB dependency overridden to use the in-memory engine."""
    from app.main import app
    from app.database import get_db

    async def _override_get_db():
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def admin_user(test_session_factory):
    """Seed an admin user; returns (user, plaintext_password)."""
    from app.core.security import hash_password
    from app.models.user import User

    plain = "AdminPass!123"
    user = User(
        id=uuid.uuid4(),
        email="testadmin@example.com",
        hashed_password=hash_password(plain),
        full_name="Test Admin",
        role="admin",
    )
    async with test_session_factory() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user, plain


@pytest_asyncio.fixture
async def auditor_user(test_session_factory):
    from app.core.security import hash_password
    from app.models.user import User

    plain = "AuditorPass!123"
    user = User(
        id=uuid.uuid4(),
        email="auditor@example.com",
        hashed_password=hash_password(plain),
        full_name="Test Auditor",
        role="auditor",
    )
    async with test_session_factory() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user, plain


@pytest_asyncio.fixture
async def admin_token(client, admin_user):
    user, plain = admin_user
    res = await client.post("/api/v1/auth/login", json={"email": user.email, "password": plain})
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest_asyncio.fixture
async def auditor_token(client, auditor_user):
    user, plain = auditor_user
    res = await client.post("/api/v1/auth/login", json={"email": user.email, "password": plain})
    assert res.status_code == 200
    return res.json()["access_token"]
