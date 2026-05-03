"""Module 2 — Attack path extraction from NetworkX DiGraph.

Finds all simple paths from non-privileged nodes to privileged targets (max 6 hops).
"""

import hashlib
import itertools
import logging
from dataclasses import dataclass, field

import networkx as nx

logger = logging.getLogger(__name__)

MAX_PATH_LENGTH = 6
MAX_PATHS_PER_PAIR = 10   # max simple paths per (source, target) pair
MAX_TOTAL_PATHS = 1000    # hard global cap to prevent unbounded DB growth


@dataclass
class AttackPathData:
    """Represents a single attack path in the graph."""

    source_node: str
    target_node: str
    hops: list[dict]
    length: int
    edge_types: list[str]
    source_type: str
    target_type: str
    canonical_key: str
    mitre_techniques: list[dict] = field(default_factory=list)


def _make_canonical_key(path: list[str], graph: nx.DiGraph) -> str:
    """Deduplicate paths by their canonical edge sequence."""
    parts = []
    for i in range(len(path) - 1):
        edge_data = graph.get_edge_data(path[i], path[i + 1]) or {}
        parts.append(f"{path[i]}→[{edge_data.get('edge_type', '?')}]→{path[i + 1]}")
    key = "|".join(parts)
    return hashlib.sha256(key.encode()).hexdigest()


def _build_hop(src: str, dst: str, graph: nx.DiGraph) -> dict:
    edge_data = graph.get_edge_data(src, dst) or {}
    src_data = graph.nodes.get(src, {})
    dst_data = graph.nodes.get(dst, {})
    return {
        "source": src,
        "source_label": src_data.get("label", src),
        "source_type": src_data.get("node_type", "Unknown"),
        "target": dst,
        "target_label": dst_data.get("label", dst),
        "target_type": dst_data.get("node_type", "Unknown"),
        "edge_type": edge_data.get("edge_type", "Unknown"),
    }


def extract_attack_paths(graph: nx.DiGraph) -> list[AttackPathData]:
    """Extract all attack paths from non-privileged to privileged nodes.

    Args:
        graph: NetworkX DiGraph from ingestion module.

    Returns:
        List of AttackPathData (deduplicated, max length 6).
    """
    privileged_targets = [n for n, d in graph.nodes(data=True) if d.get("is_privileged")]
    # Only User and Computer nodes can be attacker-controlled starting points.
    # Domain and Group nodes are containers/targets, not lateral movement origins.
    non_privileged_sources = [
        n for n, d in graph.nodes(data=True)
        if not d.get("is_privileged") and d.get("node_type") in ("User", "Computer")
    ]

    if not privileged_targets:
        logger.warning("no_privileged_targets_found")
        return []

    logger.info(
        "path_extraction_start",
        extra={
            "sources": len(non_privileged_sources),
            "targets": len(privileged_targets),
        },
    )

    seen_keys: set[str] = set()
    paths: list[AttackPathData] = []

    for target in privileged_targets:
        if len(paths) >= MAX_TOTAL_PATHS:
            break
        for source in non_privileged_sources:
            if len(paths) >= MAX_TOTAL_PATHS:
                break
            if source == target:
                continue

            try:
                raw_paths = list(
                    itertools.islice(
                        nx.all_simple_paths(graph, source=source, target=target, cutoff=MAX_PATH_LENGTH),
                        MAX_PATHS_PER_PAIR,
                    )
                )
            except (nx.NodeNotFound, nx.NetworkXError):
                continue

            for raw_path in raw_paths:
                if len(raw_path) < 2:
                    continue

                key = _make_canonical_key(raw_path, graph)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                hops = [_build_hop(raw_path[i], raw_path[i + 1], graph) for i in range(len(raw_path) - 1)]
                edge_types = [h["edge_type"] for h in hops]

                src_data = graph.nodes.get(source, {})
                dst_data = graph.nodes.get(target, {})

                paths.append(
                    AttackPathData(
                        source_node=src_data.get("label", source),
                        target_node=dst_data.get("label", target),
                        hops=hops,
                        length=len(hops),
                        edge_types=edge_types,
                        source_type=src_data.get("node_type", "Unknown"),
                        target_type=dst_data.get("node_type", "Unknown"),
                        canonical_key=key,
                    )
                )

    # Sort by length (shortest first), then limit to most interesting
    paths.sort(key=lambda p: p.length)

    logger.info("path_extraction_done", extra={"total_paths": len(paths)})
    return paths
