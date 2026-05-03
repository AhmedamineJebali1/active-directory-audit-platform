"""Tests for the BloodHound ingestion module."""

import json

import pytest

from app.core.exceptions import IngestionError
from app.modules.ingestion import ingest_bloodhound


class TestIngestionHappyPath:
    def test_ingests_minimal_graph_v5(self, minimal_bh_fixture):
        graph, n_nodes, n_edges = ingest_bloodhound(minimal_bh_fixture)
        assert n_nodes == 5
        assert n_edges == 4
        assert graph.number_of_nodes() == 5
        assert graph.number_of_edges() == 4

    def test_marks_domain_admins_as_privileged(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        da_node = "S-1-5-21-1234-512"
        assert graph.nodes[da_node]["is_privileged"] is True

    def test_marks_regular_user_as_non_privileged(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        regular = "S-1-5-21-1234-1001"
        assert graph.nodes[regular]["is_privileged"] is False

    def test_preserves_edge_types(self, minimal_bh_fixture):
        graph, _, _ = ingest_bloodhound(minimal_bh_fixture)
        edge = graph.get_edge_data("S-1-5-21-1234-1001", "S-1-5-21-1234-1100")
        assert edge["edge_type"] == "MemberOf"

    def test_ingests_real_sample_graph(self, sample_bh_data):
        graph, n_nodes, n_edges = ingest_bloodhound(sample_bh_data)
        assert n_nodes >= 50
        assert n_edges >= 70
        privileged = [n for n, d in graph.nodes(data=True) if d.get("is_privileged")]
        assert len(privileged) >= 1


class TestIngestionErrors:
    def test_raises_on_empty_data(self):
        with pytest.raises(IngestionError, match="vide"):
            ingest_bloodhound({})

    def test_raises_on_none(self):
        with pytest.raises(IngestionError):
            ingest_bloodhound(None)

    def test_raises_on_unrecognized_format(self):
        with pytest.raises(IngestionError, match="non reconnu"):
            ingest_bloodhound(42)


class TestIngestionResilience:
    def test_unknown_edge_types_are_skipped_not_crashed(self):
        data = {
            "data": [
                {
                    "nodes": [
                        {"id": "S-1-5-21-1-1001", "label": "u1", "type": "User"},
                        {"id": "S-1-5-21-1-1002", "label": "u2", "type": "User"},
                        {"id": "S-1-5-21-1-512", "label": "DA", "type": "Group"},
                    ],
                    "edges": [
                        {"source": "S-1-5-21-1-1001", "target": "S-1-5-21-1-512", "label": "MemberOf"},
                        {"source": "S-1-5-21-1-1002", "target": "S-1-5-21-1-512", "label": "MadeUpEdgeType"},
                    ],
                }
            ]
        }
        graph, n_nodes, n_edges = ingest_bloodhound(data)
        assert n_nodes == 3
        assert n_edges == 2

    def test_missing_target_node_added_as_unknown(self):
        data = {
            "data": [
                {
                    "nodes": [{"id": "S-1-5-21-1-1001", "label": "alice", "type": "User"}],
                    "edges": [
                        {"source": "S-1-5-21-1-1001", "target": "S-1-5-21-1-512", "label": "MemberOf"},
                    ],
                }
            ]
        }
        graph, _, _ = ingest_bloodhound(data)
        assert "S-1-5-21-1-512" in graph.nodes
        assert graph.nodes["S-1-5-21-1-512"]["node_type"] == "Unknown"
