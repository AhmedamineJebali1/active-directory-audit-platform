"""Tests for the attack path extraction module."""

import pytest

from app.modules.ingestion import ingest_bloodhound
from app.modules.paths import MAX_PATH_LENGTH, AttackPathData, extract_attack_paths


class TestPathExtraction:
    def test_finds_path_in_minimal_graph(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        paths = extract_attack_paths(graph)
        assert len(paths) >= 1
        assert all(isinstance(p, AttackPathData) for p in paths)

    def test_each_path_has_at_least_one_hop(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        paths = extract_attack_paths(graph)
        for p in paths:
            assert p.length >= 1
            assert len(p.hops) == p.length
            assert len(p.edge_types) == p.length

    def test_no_duplicate_paths(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        paths = extract_attack_paths(graph)
        keys = [p.canonical_key for p in paths]
        assert len(keys) == len(set(keys))

    def test_paths_terminate_at_privileged_targets(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        paths = extract_attack_paths(graph)
        privileged_labels = {
            d.get("label") for _, d in graph.nodes(data=True) if d.get("is_privileged")
        }
        for p in paths:
            assert p.target_node in privileged_labels

    def test_max_length_respected(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        paths = extract_attack_paths(graph)
        for p in paths:
            assert p.length <= MAX_PATH_LENGTH

    def test_finds_multiple_paths_in_real_sample(self, sample_bh_data):
        graph, _, _ = ingest_bloodhound(sample_bh_data)
        paths = extract_attack_paths(graph)
        assert len(paths) >= 3, f"Expected ≥3 paths, found {len(paths)}"

    def test_returns_empty_when_no_privileged_targets(self):
        data = {
            "data": [
                {
                    "nodes": [
                        {"id": "S-1-5-21-1-1001", "label": "u1", "type": "User"},
                        {"id": "S-1-5-21-1-1002", "label": "u2", "type": "User"},
                    ],
                    "edges": [
                        {"source": "S-1-5-21-1-1001", "target": "S-1-5-21-1-1002", "label": "MemberOf"},
                    ],
                }
            ]
        }
        graph, _, _ = ingest_bloodhound(data)
        paths = extract_attack_paths(graph)
        assert paths == []
