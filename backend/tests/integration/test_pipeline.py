"""End-to-end pipeline test: ingestion → paths → MITRE → mock LLM analysis."""

import pytest

from app.modules import agent, ingestion, mitre
from app.modules.paths import extract_attack_paths


class TestEndToEndPipeline:
    @pytest.mark.asyncio
    async def test_full_pipeline_on_sample_graph(self, sample_bh_data):
        # Phase 1: Ingestion
        graph, n_nodes, n_edges = ingestion.ingest_bloodhound(sample_bh_data)
        assert n_nodes >= 50
        assert n_edges >= 70

        # Phase 2: Path extraction
        paths = extract_attack_paths(graph)
        assert len(paths) >= 3, f"Expected ≥3 paths, got {len(paths)}"

        # Phase 3: MITRE enrichment
        enriched = mitre.enrich_paths_with_mitre(paths)
        techniques_found = sum(1 for p in enriched if p.mitre_techniques)
        assert techniques_found >= 1

        # Phase 4: LLM analysis (mock)
        results = await agent.analyze_paths_batch(enriched[:5], "test-pipeline-id")
        assert len(results) == 5
        for r in results:
            assert "risk_level" in r
            assert "explanation_fr" in r
            assert "recommendation_fr" in r
            assert isinstance(r["mitre_techniques"], list)

    @pytest.mark.asyncio
    async def test_pipeline_produces_at_least_one_critical_or_high(self, sample_bh_data):
        graph, _, _ = ingestion.ingest_bloodhound(sample_bh_data)
        paths = extract_attack_paths(graph)
        enriched = mitre.enrich_paths_with_mitre(paths[:10])
        results = await agent.analyze_paths_batch(enriched, "id")
        assert len(results) >= 1
        levels = {r["risk_level"] for r in results}
        assert levels.intersection({"critique", "eleve", "moyen", "faible"})
