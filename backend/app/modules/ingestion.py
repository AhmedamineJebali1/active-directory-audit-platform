"""Module 1 — BloodHound JSON ingestion → NetworkX DiGraph.

Supports BloodHound v4 and v5 export schemas.
"""

import logging
from typing import Any

import networkx as nx

from app.core.exceptions import IngestionError

logger = logging.getLogger(__name__)

PRIVILEGED_GROUP_SIDS = {
    "512",  # Domain Admins
    "519",  # Enterprise Admins
    "518",  # Schema Admins
}
PRIVILEGED_BUILTIN_SIDS = {"S-1-5-32-544"}  # Administrators

KNOWN_EDGE_TYPES = {
    # ── BloodHound 4.x standard edges ────────────────────────────────────────
    "AdminTo", "MemberOf", "HasSession", "DCSync", "WriteOwner", "GenericAll",
    "ForceChangePassword", "Owns", "WriteDACL", "AllowedToDelegate", "AddMember",
    "ReadLAPSPassword", "ReadGMSAPassword", "GPLink", "Contains", "TrustedBy",
    "CanRDP", "CanPSRemote", "ExecuteDCOM", "AllowedToAct", "SQLAdmin",
    "HasSIDHistory", "WriteAccountRestrictions", "AddSelf", "GenericWrite",
    # ── DCSync / replication rights ──────────────────────────────────────────
    "GetChangesAll", "GetChanges", "GetChangesInFilteredSet",
    # ── BloodHound CE / newer edges ───────────────────────────────────────────
    "AddKeyCredentialLink",   # Shadow Credentials attack
    "WriteGPLink",            # link a malicious GPO to an OU
    "SyncLAPSPassword",       # sync LAPS password without ReadLAPSPassword
    "DumpSMSAPassword",       # dump standalone MSA password
    "CoerceToTGT",            # RBCD / coercion to obtain a TGT
    "DCFor",                  # host is DC for a domain
    "AbuseElevatedSessionToken",
    # ── Active Directory Certificate Services (ADCS) ──────────────────────────
    "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5",
    "ADCSESC6a", "ADCSESC6b", "ADCSESC7",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
    "TrustedForNTAuth", "EnterpriseCAFor", "IssuedSignedBy",
    "RootCAFor", "NTAuthStoreFor", "HostsCAService",
    "ManageCA", "ManageCertificates", "Enroll", "OIDGroupLink",
    "ExtendedByPolicy", "GoldenCert",
    # ── Synthetic edges from ldap_collector ───────────────────────────────────
    "Kerberoastable",    # any domain user can request TGS for SPN accounts
    "ASREPRoastable",    # accounts with DONT_REQ_PREAUTH — no auth needed to attack
}


def _is_privileged(node_id: str, node_props: dict) -> bool:
    """Return True if the node is a Domain Admin, Enterprise Admin, etc."""
    sid = str(node_id)
    # Builtin Administrators (S-1-5-32-544)
    if sid in PRIVILEGED_BUILTIN_SIDS:
        return True
    # Domain suffix patterns: S-1-5-21-*-512, *-519, *-518
    for suffix in PRIVILEGED_GROUP_SIDS:
        if sid.endswith(f"-{suffix}"):
            return True
    # admincount flag
    props = node_props.get("properties", {})
    if props.get("admincount") and node_props.get("type") in ("Group", "User"):
        return True
    return False


def _parse_nodes_v5(data: list[dict]) -> dict[str, dict]:
    """Parse BloodHound v5 node array."""
    nodes: dict[str, dict] = {}
    for item in data:
        node_id = item.get("id") or item.get("ObjectIdentifier", "")
        if not node_id:
            continue
        nodes[str(node_id)] = {
            "label": item.get("label", str(node_id)),
            "type": item.get("type", "Unknown"),
            "properties": item.get("properties", {}),
        }
    return nodes


def _parse_edges_v5(data: list[dict]) -> list[dict]:
    """Parse BloodHound v5 edge array."""
    edges = []
    for item in data:
        src = str(item.get("source", ""))
        dst = str(item.get("target", ""))
        label = item.get("label", "")
        if src and dst and label:
            edges.append({"source": src, "target": dst, "type": label, "properties": item.get("properties", {})})
    return edges


def _extract_from_v4_section(section: dict) -> tuple[dict[str, dict], list[dict]]:
    """Extract nodes and edges from a v4 BloodHound section (e.g. users, computers)."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    for item in section.get("data", []):
        obj = item.get("Properties", item)
        oid = obj.get("objectid") or item.get("ObjectIdentifier", "")
        if not oid:
            continue
        node_type = _infer_type_from_keys(item)
        nodes[str(oid)] = {
            "label": obj.get("name", str(oid)),
            "type": node_type,
            "properties": obj,
        }
        for ace in item.get("Aces", []):
            right = ace.get("RightName", "")
            principal_id = ace.get("PrincipalSID", "")
            if right and principal_id:
                edges.append({
                    "source": str(principal_id),
                    "target": str(oid),
                    "type": right,
                    "properties": {},
                })

    return nodes, edges


def _infer_type_from_keys(item: dict) -> str:
    if "IsDC" in item or "DomainSID" in item:
        return "Computer" if "IsWorkstation" in item else "Computer"
    if "Members" in item:
        return "Group"
    if "PrimaryGroupSID" in item:
        return "User"
    return "Unknown"


def ingest_bloodhound(data: Any) -> tuple[nx.DiGraph, int, int]:
    """Parse BloodHound JSON and return a NetworkX DiGraph.

    Args:
        data: Parsed BloodHound JSON (dict or list).

    Returns:
        Tuple of (DiGraph, node_count, edge_count).

    Raises:
        IngestionError: If the data is malformed or empty.
    """
    if not data:
        raise IngestionError("Le fichier BloodHound est vide")

    graph = nx.DiGraph()
    all_nodes: dict[str, dict] = {}
    all_edges: list[dict] = []

    # Detect format
    if isinstance(data, list):
        # Raw array (rare)
        all_edges = _parse_edges_v5(data)
    elif isinstance(data, dict):
        # v5 format: {"meta": {...}, "data": [{"nodes": [...], "edges": [...]}]}
        if "data" in data and isinstance(data["data"], list):
            for section in data["data"]:
                if isinstance(section, dict):
                    if "nodes" in section:
                        all_nodes.update(_parse_nodes_v5(section["nodes"]))
                        all_edges.extend(_parse_edges_v5(section.get("edges", [])))
                    else:
                        # v4-style section
                        n, e = _extract_from_v4_section(section)
                        all_nodes.update(n)
                        all_edges.extend(e)
        # v4 format: {"computers": {...}, "users": {...}, ...}
        for key in ("computers", "users", "groups", "domains", "gpos", "ous"):
            if key in data:
                n, e = _extract_from_v4_section(data[key])
                all_nodes.update(n)
                all_edges.extend(e)
    else:
        raise IngestionError("Format BloodHound non reconnu")

    if not all_nodes and not all_edges:
        raise IngestionError("Aucun nœud ou relation trouvé dans le fichier")

    # Add nodes
    for node_id, attrs in all_nodes.items():
        graph.add_node(
            node_id,
            label=attrs["label"],
            node_type=attrs["type"],
            is_privileged=_is_privileged(node_id, attrs),
            properties=attrs.get("properties", {}),
        )

    # Add edges
    skipped = 0
    for edge in all_edges:
        src, dst, etype = edge["source"], edge["target"], edge["type"]
        if etype not in KNOWN_EDGE_TYPES:
            logger.debug("unknown_edge_type", extra={"type": etype, "src": src[:20]})
            skipped += 1
        # Ensure nodes exist even if not in node list
        if src not in graph:
            graph.add_node(src, label=src, node_type="Unknown", is_privileged=False, properties={})
        if dst not in graph:
            graph.add_node(dst, label=dst, node_type="Unknown", is_privileged=False, properties={})
        graph.add_edge(src, dst, edge_type=etype, properties=edge.get("properties", {}))

    if skipped > 0:
        logger.warning("edges_skipped", extra={"count": skipped, "reason": "unknown_type"})

    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()

    logger.info(
        "ingestion_complete",
        extra={"nodes": node_count, "edges": edge_count, "skipped_edges": skipped},
    )

    if node_count == 0:
        raise IngestionError("Le graphe est vide après ingestion")

    return graph, node_count, edge_count
