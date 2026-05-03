"""Module 4 — MITRE ATT&CK mapping and enrichment."""

import json
import logging
from collections import Counter
from pathlib import Path

from app.modules.paths import AttackPathData

logger = logging.getLogger(__name__)

_MAPPING_PATH = Path(__file__).parent.parent.parent / "data" / "mitre_mapping.json"
_mapping_cache: dict | None = None


def _load_mapping() -> dict:
    global _mapping_cache
    if _mapping_cache is None:
        with open(_MAPPING_PATH, encoding="utf-8") as f:
            _mapping_cache = json.load(f)
        logger.info("mitre_mapping_loaded", extra={"edge_types": len(_mapping_cache)})
    return _mapping_cache


def enrich_path_with_mitre(path: AttackPathData) -> list[dict]:
    """Return deduplicated MITRE techniques for all edges in the path.

    Args:
        path: An AttackPathData instance with edge_types populated.

    Returns:
        List of unique technique dicts (id, name, tactic, url).
    """
    mapping = _load_mapping()
    seen: dict[str, dict] = {}

    for edge_type in path.edge_types:
        for tech in mapping.get(edge_type, []):
            tech_id = tech["id"]
            if tech_id not in seen:
                seen[tech_id] = tech

    return list(seen.values())


def enrich_paths_with_mitre(paths: list[AttackPathData]) -> list[AttackPathData]:
    """Enrich all paths with their MITRE techniques in-place.

    Args:
        paths: List of AttackPathData instances.

    Returns:
        Same list with mitre_techniques populated.
    """
    for path in paths:
        path.mitre_techniques = enrich_path_with_mitre(path)
    return paths


def compute_coverage(paths: list[AttackPathData]) -> dict:
    """Compute MITRE coverage stats across all paths.

    Args:
        paths: List of AttackPathData with mitre_techniques populated.

    Returns:
        Dict with techniques, count_by_tactic, top_10_techniques.
    """
    all_techniques: dict[str, dict] = {}
    tactic_counter: Counter = Counter()
    tech_counter: Counter = Counter()

    for path in paths:
        for tech in path.mitre_techniques:
            tid = tech["id"]
            if tid not in all_techniques:
                all_techniques[tid] = tech
            tactic_counter[tech["tactic"]] += 1
            tech_counter[tid] += 1

    return {
        "techniques": list(all_techniques.values()),
        "count_by_tactic": dict(tactic_counter),
        "top_10_techniques": [
            {"id": tid, "count": cnt, "name": all_techniques[tid]["name"]}
            for tid, cnt in tech_counter.most_common(10)
        ],
    }
