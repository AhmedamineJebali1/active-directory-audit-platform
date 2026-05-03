"""Tests for the MITRE ATT&CK enrichment module."""

import pytest

from app.modules.ingestion import ingest_bloodhound
from app.modules.mitre import (
    compute_coverage,
    enrich_path_with_mitre,
    enrich_paths_with_mitre,
)
from app.modules.paths import AttackPathData, extract_attack_paths


def _make_path(edge_types: list[str]) -> AttackPathData:
    return AttackPathData(
        source_node="alice",
        target_node="DA",
        hops=[],
        length=len(edge_types),
        edge_types=edge_types,
        source_type="User",
        target_type="Group",
        canonical_key="-".join(edge_types),
    )


class TestEnrichSingle:
    def test_member_of_yields_at_least_one_technique(self):
        path = _make_path(["MemberOf"])
        techs = enrich_path_with_mitre(path)
        assert len(techs) >= 1
        assert all("id" in t and "name" in t and "tactic" in t and "url" in t for t in techs)

    def test_dcsync_returns_t1003_technique(self):
        path = _make_path(["DCSync"])
        techs = enrich_path_with_mitre(path)
        ids = {t["id"] for t in techs}
        assert any(tid.startswith("T1003") for tid in ids)

    def test_techniques_are_deduplicated_within_path(self):
        path = _make_path(["GenericAll", "GenericAll", "WriteOwner"])
        techs = enrich_path_with_mitre(path)
        ids = [t["id"] for t in techs]
        assert len(ids) == len(set(ids))

    def test_unknown_edge_returns_empty(self):
        path = _make_path(["TotallyMadeUpEdge"])
        techs = enrich_path_with_mitre(path)
        assert techs == []


class TestEnrichPaths:
    def test_in_place_enrichment(self):
        paths = [_make_path(["MemberOf"]), _make_path(["DCSync"])]
        result = enrich_paths_with_mitre(paths)
        assert result is paths
        for p in paths:
            assert p.mitre_techniques


class TestCoverage:
    def test_coverage_aggregates_across_paths(self):
        paths = [_make_path(["MemberOf"]), _make_path(["DCSync"])]
        enrich_paths_with_mitre(paths)
        coverage = compute_coverage(paths)

        assert "techniques" in coverage
        assert "count_by_tactic" in coverage
        assert "top_10_techniques" in coverage
        assert len(coverage["techniques"]) >= 2

    def test_top_techniques_are_sorted(self):
        paths = [_make_path(["GenericAll"]) for _ in range(5)] + [_make_path(["DCSync"])]
        enrich_paths_with_mitre(paths)
        coverage = compute_coverage(paths)
        if len(coverage["top_10_techniques"]) >= 2:
            counts = [t["count"] for t in coverage["top_10_techniques"]]
            assert counts == sorted(counts, reverse=True)


class TestRealSampleEnrichment:
    def test_enriches_paths_from_real_sample(self, sample_bh_data):
        graph, _, _ = ingest_bloodhound(sample_bh_data)
        paths = extract_attack_paths(graph)
        enriched = enrich_paths_with_mitre(paths)
        with_techs = [p for p in enriched if p.mitre_techniques]
        assert len(with_techs) >= 1
