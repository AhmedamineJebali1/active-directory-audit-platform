"""Tests for the LLM agent module (with MockProvider)."""

import json

import pytest

from app.modules import agent
from app.modules.llm_providers.base import LLMProvider
from app.modules.paths import AttackPathData


def _path(name: str = "alice", target: str = "DA", key_suffix: str = "") -> AttackPathData:
    hops = [{
        "source": "S-1", "source_label": name, "source_type": "User",
        "target": "S-2", "target_label": target, "target_type": "Group",
        "edge_type": "MemberOf",
    }]
    return AttackPathData(
        source_node=name,
        target_node=target,
        hops=hops,
        length=1,
        edge_types=["MemberOf"],
        source_type="User",
        target_type="Group",
        canonical_key=f"{name}->{target}-{key_suffix}",
        mitre_techniques=[
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1078/"}
        ],
    )


class _BadJsonProvider(LLMProvider):
    @property
    def provider_name(self) -> str:
        return "test_bad"

    async def invoke(self, prompt: str, system: str = "") -> str:
        return "this is definitely not JSON"


class _CountingProvider(LLMProvider):
    def __init__(self, payloads: list[str]):
        self._payloads = payloads
        self.calls = 0

    @property
    def provider_name(self) -> str:
        return "counting"

    async def invoke(self, prompt: str, system: str = "") -> str:
        idx = min(self.calls, len(self._payloads) - 1)
        self.calls += 1
        return self._payloads[idx]


class TestAgentHappyPath:
    @pytest.mark.asyncio
    async def test_mock_provider_returns_validated_result(self):
        result = await agent.analyze_paths_batch([_path(key_suffix="happy1")], analysis_id="test-id")
        assert len(result) == 1
        r = result[0]
        assert r["risk_level"] in ("faible", "moyen", "eleve", "critique")
        # Real LLM result populates scores; analyse_echec sets them to None.
        assert r["global_score"] is not None, "LLM was not actually invoked (analyse_echec fallback)"
        assert "analyse_echec" not in (r["explanation_fr"] or "")
        assert isinstance(r["explanation_fr"], str)
        assert isinstance(r["recommendation_fr"], str)
        assert r["mitre_techniques"]

    @pytest.mark.asyncio
    async def test_results_cached_by_canonical_key(self):
        p1 = _path("alice", key_suffix="cache_test")
        p2 = _path("alice", key_suffix="cache_test")
        results = await agent.analyze_paths_batch([p1, p2], "id1")
        assert len(results) == 2
        assert results[0]["explanation_fr"] == results[1]["explanation_fr"]


class TestAgentRetryAndFailure:
    @pytest.mark.asyncio
    async def test_returns_analyse_echec_when_provider_always_fails(self, monkeypatch):
        monkeypatch.setattr(agent, "_get_provider", lambda: _BadJsonProvider())
        result = await agent.analyze_paths_batch([_path(key_suffix="always_fail")], "id-fail")
        assert len(result) == 1
        r = result[0]
        assert r["global_score"] is None
        assert "analyse_echec" in (r["explanation_fr"] or "")

    @pytest.mark.asyncio
    async def test_recovers_on_second_attempt(self, monkeypatch):
        good = json.dumps({
            "exploitability_score": 7,
            "stealth_score": 5,
            "global_score": 8,
            "risk_level": "Élevé",
            "explanation": "x" * 80,
            "recommendation": "y" * 60,
        })
        provider = _CountingProvider(["junk", good])
        monkeypatch.setattr(agent, "_get_provider", lambda: provider)
        result = await agent.analyze_paths_batch([_path(key_suffix="recovers")], "id-retry")
        assert provider.calls == 2
        assert result[0]["global_score"] == 8.0
