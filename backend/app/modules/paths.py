"""Module 2 — Attack path extraction from NetworkX DiGraph.

Finds attack paths from non-privileged nodes to privileged targets (max 6 hops).
Uses BFS with a per-pair time budget so large graphs don't hang.

Edges are split into "traversable" (count toward attack-path length) and
"non-traversable" (sub-rights or descriptive edges that don't represent an
attack step on their own). The split mirrors SpecterOps' BloodHound CE
classification:
https://bloodhound.specterops.io/resources/edges/traversable-edges
"""

import hashlib
import logging
import time
from collections import deque
from dataclasses import dataclass, field

import networkx as nx

logger = logging.getLogger(__name__)

MAX_PATH_LENGTH = 6
MAX_PATHS_PER_PAIR = 10   # max simple paths per (source, target) pair
MAX_TOTAL_PATHS = 1000    # hard global cap to prevent unbounded DB growth
PER_PAIR_TIMEOUT = 2.0    # seconds — wall-clock budget per (source,target)
SOURCE_NODE_TYPES = {"User", "Computer", "Group"}

# Edges BloodHound CE marks NON-traversable. These exist in the graph for
# context (visualisation, MITRE mapping) but must not count as attack hops.
# A path of "user --GetChanges--> domain" is meaningless on its own — only
# the SYNTHETIC `DCSync` (= GetChanges ∧ GetChangesAll) is an attack edge.
NON_TRAVERSABLE_EDGES = frozenset({
    # Replication primitives — combine into DCSync (synthesized in ingestion)
    "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
    # ADCS sub-rights — combine into ADCSESC* synthetic edges upstream
    "Enroll", "DelegatedEnrollmentAgent", "EnrollOnBehalfOf",
    "EnterpriseCAFor", "IssuedSignedBy", "RootCAFor",
    "NTAuthStoreFor", "HostsCAService",
    "OIDGroupLink", "ExtendedByPolicy", "PublishedTo",
    "WritePKIEnrollmentFlag", "WritePKINameFlag",
    "TrustedForNTAuth",
    # Raw counterparts of materialized edges
    "OwnsRaw", "WriteOwnerRaw",
    # Descriptive / structural — useful for context, not an attack step
    "ProtectAdminGroups", "RemoteInteractiveLogonRight",
    "MemberOfLocalGroup", "LocalToComputer",
})


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


def _is_traversable(graph: nx.DiGraph, src: str, dst: str) -> bool:
    """True if the edge (src→dst) is a traversable attack-path step."""
    edata = graph.get_edge_data(src, dst) or {}
    return edata.get("edge_type") not in NON_TRAVERSABLE_EDGES


def _bfs_paths(
    graph: nx.DiGraph,
    source: str,
    target: str,
    cutoff: int,
    max_paths: int,
    deadline: float,
) -> list[list[str]]:
    """BFS-based simple-path enumeration with a wall-clock deadline.

    Only follows edges flagged traversable. Faster than nx.all_simple_paths
    on dense graphs because we bail out immediately when the deadline passes
    or once max_paths are collected.
    """
    if source not in graph or target not in graph:
        return []
    if source == target:
        return []

    found: list[list[str]] = []
    queue: deque = deque([(source, [source], {source})])
    while queue:
        if time.monotonic() > deadline:
            break
        node, path, visited = queue.popleft()
        if len(path) > cutoff:
            continue
        for nbr in graph.successors(node):
            if nbr in visited:
                continue
            if not _is_traversable(graph, node, nbr):
                continue
            new_path = path + [nbr]
            if nbr == target:
                found.append(new_path)
                if len(found) >= max_paths:
                    return found
            elif len(new_path) <= cutoff:
                queue.append((nbr, new_path, visited | {nbr}))
    return found


def extract_attack_paths(graph: nx.DiGraph) -> list[AttackPathData]:
    """Extract attack paths from non-privileged to privileged nodes.

    Uses BFS with a wall-clock budget per (source,target) so large domains
    don't hang. Sources include Users, Computers, and non-privileged Groups
    (group abuse is a real attack vector, e.g. AddMember to a Tier-0 group).
    """
    privileged_targets = [n for n, d in graph.nodes(data=True) if d.get("is_privileged")]
    non_privileged_sources = [
        n for n, d in graph.nodes(data=True)
        if not d.get("is_privileged") and d.get("node_type") in SOURCE_NODE_TYPES
    ]

    if not privileged_targets:
        logger.warning(
            "no_privileged_targets_found",
            extra={"total_nodes": graph.number_of_nodes()},
        )
        return []

    logger.info(
        "path_extraction_start",
        extra={
            "sources": len(non_privileged_sources),
            "targets": len(privileged_targets),
            "edges": graph.number_of_edges(),
        },
    )

    # Optimization: only iterate over sources that can actually reach a
    # privileged target via TRAVERSABLE edges. Build a subgraph view that
    # excludes non-traversable edges, then reverse-BFS from each target.
    # Much cheaper than O(sources × targets) full searches.
    def _filter_edge(u: str, v: str) -> bool:
        return graph[u][v].get("edge_type") not in NON_TRAVERSABLE_EDGES

    traversable_view = nx.subgraph_view(graph, filter_edge=_filter_edge)

    reachable_sources: set[str] = set()
    for target in privileged_targets:
        try:
            ancestors = nx.ancestors(traversable_view, target)
        except nx.NodeNotFound:
            continue
        reachable_sources |= ancestors

    candidate_sources = [s for s in non_privileged_sources if s in reachable_sources]
    logger.info(
        "path_extraction_candidates",
        extra={"reachable_sources": len(candidate_sources)},
    )

    seen_keys: set[str] = set()
    paths: list[AttackPathData] = []

    for target in privileged_targets:
        if len(paths) >= MAX_TOTAL_PATHS:
            break
        for source in candidate_sources:
            if len(paths) >= MAX_TOTAL_PATHS:
                break
            if source == target:
                continue

            deadline = time.monotonic() + PER_PAIR_TIMEOUT
            try:
                raw_paths = _bfs_paths(
                    graph, source, target,
                    cutoff=MAX_PATH_LENGTH,
                    max_paths=MAX_PATHS_PER_PAIR,
                    deadline=deadline,
                )
            except Exception as exc:
                logger.debug("path_pair_error", extra={"err": str(exc)[:80]})
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

    paths.sort(key=lambda p: p.length)
    logger.info("path_extraction_done", extra={"total_paths": len(paths)})
    return paths
