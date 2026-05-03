"""Shared pytest fixtures."""

import json
import os
from pathlib import Path
from typing import Any

import pytest

# Use mock LLM provider in all tests to avoid network calls.
os.environ.setdefault("LLM_PROVIDER", "mock")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-pytest-only-not-prod")

DATA_DIR = Path(__file__).parent.parent / "data"
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sample_bh_data() -> dict[str, Any]:
    """Load the realistic BloodHound sample graph."""
    path = DATA_DIR / "sample_graph.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def minimal_bh_fixture() -> dict[str, Any]:
    """A tiny synthetic graph: regular user → group → admin user (DA)."""
    return {
        "data": [
            {
                "nodes": [
                    {
                        "id": "S-1-5-21-1234-1001",
                        "label": "alice@corp.local",
                        "type": "User",
                        "properties": {"name": "alice@corp.local"},
                    },
                    {
                        "id": "S-1-5-21-1234-1100",
                        "label": "IT_SUPPORT@CORP.LOCAL",
                        "type": "Group",
                        "properties": {"name": "IT_SUPPORT@CORP.LOCAL"},
                    },
                    {
                        "id": "S-1-5-21-1234-2001",
                        "label": "DEV-WS01.CORP.LOCAL",
                        "type": "Computer",
                        "properties": {"name": "DEV-WS01"},
                    },
                    {
                        "id": "S-1-5-21-1234-1500",
                        "label": "BOB_ADMIN@CORP.LOCAL",
                        "type": "User",
                        "properties": {"name": "BOB_ADMIN@CORP.LOCAL"},
                    },
                    {
                        "id": "S-1-5-21-1234-512",
                        "label": "DOMAIN ADMINS@CORP.LOCAL",
                        "type": "Group",
                        "properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"},
                    },
                ],
                "edges": [
                    {"source": "S-1-5-21-1234-1001", "target": "S-1-5-21-1234-1100", "label": "MemberOf"},
                    {"source": "S-1-5-21-1234-1100", "target": "S-1-5-21-1234-2001", "label": "AdminTo"},
                    {"source": "S-1-5-21-1234-2001", "target": "S-1-5-21-1234-1500", "label": "HasSession"},
                    {"source": "S-1-5-21-1234-1500", "target": "S-1-5-21-1234-512", "label": "MemberOf"},
                ],
            }
        ]
    }


@pytest.fixture
def corrupt_bh_fixture() -> str:
    """Malformed BloodHound JSON string."""
    return '{"data": [{"nodes": [{"id"'


@pytest.fixture(autouse=True)
def reset_agent_cache():
    """Clear the in-memory LLM cache between tests."""
    from app.modules import agent

    agent._in_memory_cache.clear()
    yield
    agent._in_memory_cache.clear()
