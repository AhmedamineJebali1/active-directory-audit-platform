"""Module 1 — BloodHound JSON ingestion → NetworkX DiGraph.

Supports BloodHound v4, v5, and v6 (CE multi-file ZIP) export schemas.
"""

import io
import json
import logging
import zipfile
from typing import Any

import networkx as nx

from app.core.exceptions import IngestionError

logger = logging.getLogger(__name__)

# Domain-relative RIDs that identify privileged groups (S-1-5-21-<domain>-<RID>)
PRIVILEGED_GROUP_SIDS = {
    "512",  # Domain Admins
    "519",  # Enterprise Admins
    "518",  # Schema Admins
    "516",  # Domain Controllers
    "521",  # Read-only Domain Controllers
    "520",  # Group Policy Creator Owners
    "498",  # Enterprise Read-only Domain Controllers
    "526",  # Key Admins
    "527",  # Enterprise Key Admins
}
# Builtin SIDs (also seen prefixed with domain like "DOMAIN.LOCAL-S-1-5-32-544")
PRIVILEGED_BUILTIN_SIDS = {
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-32-552",  # Replicators
    # Well-known synthetic groups (not RID-relative — assigned at runtime)
    "S-1-5-9",       # Enterprise Domain Controllers
}

# Canonical edge spellings come from SharpHoundCommon EdgeNames.cs.
# Some real-world exports (older SharpHound, BloodHound v4 dumps, hand-rolled
# samples) use slightly different casing. We normalize at ingest time.
_EDGE_ALIAS = {
    # SharpHoundCommon canonical is "WriteDacl" — accept the common misspelling.
    "WRITEDACL": "WriteDacl",
    "WRITE_DACL": "WriteDacl",
    # Some tools emit "GpLink" (camelCase variation)
    "GPLINK": "GPLink",
    "GP_LINK": "GPLink",
    # Older tools / our own samples
    "WRITESPN": "WriteSPN",
    # ASREPRoastable variants
    "AS-REPROASTABLE": "ASREPRoastable",
    "ASREP_ROASTABLE": "ASREPRoastable",
    # CoerceAndRelay variants — collapse the four NTLM relay sub-edges to one
    # bucket only when the caller can't disambiguate. We keep the four real
    # edges separately in KNOWN_EDGE_TYPES below; this alias is only used when
    # someone literally writes "CoerceAndRelayNTLM" with no target.
}


def _canon_edge(raw: str) -> str:
    """Normalize an edge type to BloodHound's canonical spelling."""
    if not raw:
        return raw
    return _EDGE_ALIAS.get(raw.upper(), raw)


# All AD edges BloodHound CE recognises (traversable + non-traversable union).
# Source: https://bloodhound.specterops.io/resources/edges/traversable-edges
KNOWN_EDGE_TYPES = {
    # ── Generic ACL rights ─────────────────────────────────────────────────
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteOwnerLimitedRights",
    "Owns", "OwnsLimitedRights", "AllExtendedRights", "ReadLAPSPassword",
    "ReadGMSAPassword", "ForceChangePassword", "AddMember", "AddSelf",
    "AddKeyCredentialLink", "WriteSPN", "WriteAccountRestrictions",
    "WriteGPLink",
    # ── Replication primitives (NON-traversable on their own; combine to DCSync) ──
    "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
    # ── Synthetic combined edge ─────────────────────────────────────────────
    "DCSync",
    # ── Containment / structure ─────────────────────────────────────────────
    "MemberOf", "Contains", "GPLink", "DCFor",
    # ── Local rights (require SMB/RPC to collect) ──────────────────────────
    "AdminTo", "HasSession", "CanRDP", "CanPSRemote", "ExecuteDCOM", "SQLAdmin",
    # ── Delegation / impersonation ──────────────────────────────────────────
    "AllowedToDelegate", "AllowedToAct", "AddAllowedToAct",
    "AbuseTGTDelegation", "CoerceToTGT", "ClaimSpecialIdentity",
    "CoerceAndRelayNTLMToADCS", "CoerceAndRelayNTLMToLDAP",
    "CoerceAndRelayNTLMToLDAPS", "CoerceAndRelayNTLMToSMB",
    # ── Identity / migration ────────────────────────────────────────────────
    "HasSIDHistory", "SpoofSIDHistory", "DumpSMSAPassword", "SyncLAPSPassword",
    "SyncedToADUser", "SyncedToEntraUser",
    # ── Trusts ──────────────────────────────────────────────────────────────
    "TrustedBy", "CrossForestTrust", "SameForestTrust", "HasTrustKeys",
    # ── ADCS ────────────────────────────────────────────────────────────────
    "ADCSESC1", "ADCSESC3", "ADCSESC4",
    "ADCSESC6a", "ADCSESC6b", "ADCSESC7",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
    "GoldenCert", "ManageCA", "ManageCertificates", "Enroll",
    "DelegatedEnrollmentAgent", "EnrollOnBehalfOf",
    "TrustedForNTAuth", "EnterpriseCAFor", "IssuedSignedBy",
    "RootCAFor", "NTAuthStoreFor", "HostsCAService",
    "OIDGroupLink", "ExtendedByPolicy", "PublishedTo",
    "WritePKIEnrollmentFlag", "WritePKINameFlag",
    # ── Misc / non-traversable raw counterparts ─────────────────────────────
    "OwnsRaw", "WriteOwnerRaw", "ProtectAdminGroups",
    "RemoteInteractiveLogonRight", "MemberOfLocalGroup", "LocalToComputer",
    # ── Synthetic edges produced by our LDAP collector ──────────────────────
    "Kerberoastable", "ASREPRoastable",
    # ── Legacy / kept for backward compatibility with older sample data ─────
    "AbuseElevatedSessionToken",
    # The misspelling stays known so older fixtures still ingest cleanly;
    # _canon_edge() rewrites it to "WriteDacl" before it ever reaches paths.py.
    "WriteDACL",
}


def _is_privileged(node_id: str, node_props: dict) -> bool:
    """Return True if the node is a privileged group/user/computer.

    Detection is SID-based (locale-independent). Group names like "Domain Admins"
    vs "Admins du domaine" vs "Domänen-Admins" all share the same SID — that's
    the only reliable signal.

    Sources of truth:
      - Builtin RIDs: ``S-1-5-32-{544,548,549,550,551,552}``
        (also seen domain-prefixed: ``CONTOSO.LOCAL-S-1-5-32-544``)
      - Domain-relative privileged RIDs ``-{512,516,518,519,520,521,526,527,498}``
      - ``adminCount=1`` flag (AdminSDHolder-protected accounts)
    """
    sid = str(node_id).upper()
    # Builtin SIDs — may appear bare ("S-1-5-32-544") or domain-prefixed
    # ("CONTOSO.LOCAL-S-1-5-32-544"). Accept both forms.
    for builtin in PRIVILEGED_BUILTIN_SIDS:
        if sid == builtin or sid.endswith("-" + builtin):
            return True
    # Domain-relative RIDs: S-1-5-21-<domain>-<RID>
    for suffix in PRIVILEGED_GROUP_SIDS:
        if sid.endswith(f"-{suffix}"):
            return True
    # adminCount flag — protected accounts (AdminSDHolder).
    # SharpHound emits booleans; some tools emit "1"/"0" strings — handle both.
    props = node_props.get("properties", {}) or {}
    admin_count = props.get("admincount") or props.get("adminCount")
    if node_props.get("type") in ("Group", "User"):
        if admin_count is True or admin_count == 1 or admin_count == "1":
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


def _extract_from_v4_section(section: dict, default_type: str = "") -> tuple[dict[str, dict], list[dict]]:
    """Extract nodes and edges from a v4 BloodHound section (e.g. users, computers).

    Covers ALL relation fields a real SharpHound export carries — not just Aces.
    Otherwise large domains end up with rich node sets but zero edges, which
    means zero attack paths.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    for item in section.get("data", []):
        obj = item.get("Properties", item)
        oid = obj.get("objectid") or item.get("ObjectIdentifier", "")
        if not oid:
            continue
        node_type = default_type or _infer_type_from_keys(item)
        nodes[str(oid)] = {
            "label": obj.get("name", str(oid)),
            "type": node_type,
            "properties": obj,
        }

        # ── Aces → ACE right name (principal → object) ───────────────────
        for ace in item.get("Aces", []) or []:
            right = ace.get("RightName", "")
            principal_id = ace.get("PrincipalSID", "")
            if right and principal_id:
                edges.append({"source": str(principal_id), "target": str(oid),
                              "type": right, "properties": {}})

        # ── Members → MemberOf (member → group) ───────────────────────────
        for member in item.get("Members", []) or []:
            mid = member.get("ObjectIdentifier", "")
            if mid and mid != oid:
                edges.append({"source": str(mid), "target": str(oid),
                              "type": "MemberOf", "properties": {}})

        # ── PrimaryGroupSID → MemberOf (user/computer → primary group) ───
        primary = item.get("PrimaryGroupSID") or obj.get("primarygroupsid")
        if primary and primary != oid:
            edges.append({"source": str(oid), "target": str(primary),
                          "type": "MemberOf", "properties": {}})

        # ── AllowedToDelegate → AllowedToDelegate ────────────────────────
        for tgt in item.get("AllowedToDelegate", []) or []:
            tid = tgt.get("ObjectIdentifier", "") if isinstance(tgt, dict) else str(tgt)
            if tid and tid != oid:
                edges.append({"source": str(oid), "target": str(tid),
                              "type": "AllowedToDelegate", "properties": {}})

        # ── AllowedToAct (RBCD) ──────────────────────────────────────────
        for src in item.get("AllowedToAct", []) or []:
            sid = src.get("ObjectIdentifier", "") if isinstance(src, dict) else str(src)
            if sid and sid != oid:
                edges.append({"source": str(sid), "target": str(oid),
                              "type": "AllowedToAct", "properties": {}})

        # ── Sessions → HasSession (computer → user) ──────────────────────
        for sess_key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
            sess_block = item.get(sess_key) or {}
            if isinstance(sess_block, dict):
                for sess in sess_block.get("Results", []) or []:
                    user_sid = sess.get("UserSID", "")
                    if user_sid and user_sid != oid:
                        edges.append({"source": str(oid), "target": str(user_sid),
                                      "type": "HasSession", "properties": {}})
            elif isinstance(sess_block, list):
                for sess in sess_block:
                    user_sid = sess.get("UserSID", "") if isinstance(sess, dict) else ""
                    if user_sid and user_sid != oid:
                        edges.append({"source": str(oid), "target": str(user_sid),
                                      "type": "HasSession", "properties": {}})

        # ── LocalGroups → AdminTo / CanRDP / etc. (RID-based, locale-safe) ─
        for lg in item.get("LocalGroups", []) or []:
            edge_type = _classify_local_group(lg)
            if not edge_type:
                continue
            for member in lg.get("Results", []) or []:
                mid = member.get("ObjectIdentifier", "")
                if mid and mid != oid:
                    edges.append({"source": str(mid), "target": str(oid),
                                  "type": edge_type, "properties": {}})

        # ── Trusts → TrustedBy (domain → trusted domain) ────────────────
        for trust in item.get("Trusts", []) or []:
            tid = trust.get("TargetDomainSid", "")
            if tid and tid != oid:
                edges.append({"source": str(oid), "target": str(tid),
                              "type": "TrustedBy", "properties": {}})

        # ── Links (domain/OU → GPO) ─────────────────────────────────────
        for link in item.get("Links", []) or []:
            gpo_sid = link.get("GUID", "") or link.get("ObjectIdentifier", "")
            if gpo_sid and gpo_sid != oid:
                edges.append({"source": str(oid), "target": str(gpo_sid),
                              "type": "GPLink", "properties": {}})

        # ── HasSIDHistory ───────────────────────────────────────────────
        for hist in item.get("HasSIDHistory", []) or []:
            hid = hist.get("ObjectIdentifier", "") if isinstance(hist, dict) else str(hist)
            if hid and hid != oid:
                edges.append({"source": str(oid), "target": str(hid),
                              "type": "HasSIDHistory", "properties": {}})

        # ── ContainedBy → Contains (parent → this) ───────────────────────
        contained_by = item.get("ContainedBy") or {}
        if isinstance(contained_by, dict):
            parent_id = contained_by.get("ObjectIdentifier", "")
            if parent_id and parent_id != oid:
                edges.append({"source": str(parent_id), "target": str(oid),
                              "type": "Contains", "properties": {}})

        # ── ChildObjects → Contains (this → children) ────────────────────
        for child in item.get("ChildObjects", []) or []:
            cid = child.get("ObjectIdentifier", "") if isinstance(child, dict) else ""
            if cid and cid != oid:
                edges.append({"source": str(oid), "target": str(cid),
                              "type": "Contains", "properties": {}})

    return nodes, edges


def detect_format(content: bytes) -> dict:
    """Inspect raw bytes and return what format we think this is.

    Used by the `/detect-format` preview endpoint so the user can see what
    the platform sees before kicking off the full pipeline. Read-only:
    never raises, returns ``{"format": "unknown", "error": "..."}`` on failure.

    Returns:
        dict with keys:
          - format: one of "bloodhound_zip_ce_v6", "bloodhound_v5",
                   "bloodhound_v4_sections", "simple_nodes_edges", "unknown"
          - version: integer (when known) or None
          - file_types: dict {section_name: count}  (e.g. {"users": 8, "groups": 55})
          - error: str | None
    """
    try:
        if not content:
            return {"format": "unknown", "version": None, "file_types": {},
                    "error": "Fichier vide"}

        # ZIP magic bytes — BloodHound CE multi-file archive
        if content[:4] == b"PK\x03\x04":
            return _detect_zip_format(content)

        # JSON — try to parse and classify
        try:
            data = json.loads(content)
        except json.JSONDecodeError as ex:
            return {"format": "unknown", "version": None, "file_types": {},
                    "error": f"JSON invalide : {ex.msg}"}

        return _detect_json_format(data)
    except Exception as ex:
        return {"format": "unknown", "version": None, "file_types": {},
                "error": f"Erreur d'analyse : {ex}"}


def _detect_zip_format(zip_bytes: bytes) -> dict:
    """Look inside a BloodHound CE ZIP and return per-file metadata."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as ex:
        return {"format": "unknown", "version": None, "file_types": {},
                "error": f"Archive ZIP invalide : {ex}"}

    file_types: dict[str, int] = {}
    version = None
    methods = None
    with zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                raw = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            meta = raw.get("meta", {}) if isinstance(raw, dict) else {}
            ftype = meta.get("type", "").lower()
            count = meta.get("count", len(raw.get("data", []) or []))
            if ftype:
                file_types[ftype] = count
            if version is None:
                version = meta.get("version")
            if methods is None:
                methods = meta.get("methods")
    return {
        "format": "bloodhound_zip_ce_v6" if (version and version >= 6) else "bloodhound_zip",
        "version": version,
        "file_types": file_types,
        "collection_methods": methods,
        "error": None if file_types else "Aucun fichier JSON BloodHound trouvé dans le ZIP",
    }


def _detect_json_format(data) -> dict:
    """Classify a parsed JSON document into a known BloodHound shape."""
    if not isinstance(data, dict):
        if isinstance(data, list):
            return {"format": "simple_nodes_edges", "version": None,
                    "file_types": {}, "error": None}
        return {"format": "unknown", "version": None, "file_types": {},
                "error": f"Type racine non supporté : {type(data).__name__}"}

    meta = data.get("meta") or {}
    version = meta.get("version") if isinstance(meta, dict) else None

    # v4 sections format: top-level keys like "users", "computers", "groups"
    v4_sections = {k for k in ("computers", "users", "groups", "domains",
                                "gpos", "ous", "containers") if k in data}
    if v4_sections:
        file_types = {k: len((data[k] or {}).get("data", []) or [])
                      for k in v4_sections}
        return {"format": "bloodhound_v4_sections", "version": version,
                "file_types": file_types, "error": None}

    # v5: {meta, data: [{nodes:[], edges:[]}]}
    inner = data.get("data")
    if isinstance(inner, list) and inner and isinstance(inner[0], dict):
        first = inner[0]
        if "nodes" in first or "edges" in first:
            file_types = {
                "nodes": sum(len(s.get("nodes", [])) for s in inner if isinstance(s, dict)),
                "edges": sum(len(s.get("edges", [])) for s in inner if isinstance(s, dict)),
            }
            return {"format": "bloodhound_v5", "version": version,
                    "file_types": file_types, "error": None}

    # Plain {nodes:[], edges:[]} — our simple custom format
    if "nodes" in data or "edges" in data:
        return {"format": "simple_nodes_edges", "version": None,
                "file_types": {"nodes": len(data.get("nodes", []) or []),
                               "edges": len(data.get("edges", []) or [])},
                "error": None}

    return {"format": "unknown", "version": version, "file_types": {},
            "error": "Format BloodHound non reconnu"}


def _infer_type_from_keys(item: dict) -> str:
    if "IsDC" in item or "DomainSID" in item:
        return "Computer" if "IsWorkstation" in item else "Computer"
    if "Members" in item:
        return "Group"
    if "PrimaryGroupSID" in item:
        return "User"
    return "Unknown"


def _synthesize_dcsync_edges(
    graph: nx.DiGraph,
    rights_observed: dict[tuple[str, str], set[str]] | None = None,
) -> int:
    """Emit synthetic DCSync edges where a principal has BOTH GetChanges AND
    GetChangesAll on the same Domain object. Mirrors how BloodHound CE derives
    the DCSync edge — it is not a primary right but a combination.

    Reference: https://bloodhound.specterops.io/resources/edges/dc-sync

    NetworkX DiGraph keeps at most one edge per (src, dst), so by the time
    both GetChanges and GetChangesAll have been ingested, only one survives in
    the graph. Callers MUST pass `rights_observed` — a side-table built during
    ingestion that records which rights were seen per (principal, domain) pair.

    Args:
        graph: DiGraph with raw ACE edges already inserted.
        rights_observed: dict {(principal_sid, domain_sid): {"GetChanges",...}}.
            If None, falls back to scanning current graph edges (lossy on
            DiGraph but still works for fixtures with no edge collision).

    Returns:
        Number of DCSync edges added.
    """
    rights: dict[tuple[str, str], set[str]] = {}
    if rights_observed is not None:
        rights = rights_observed
    else:
        for src, dst, edata in graph.edges(data=True):
            et = edata.get("edge_type")
            if et in ("GetChanges", "GetChangesAll"):
                rights.setdefault((src, dst), set()).add(et)

    added = 0
    for (src, dst), names in rights.items():
        if not ({"GetChanges", "GetChangesAll"} <= names):
            continue
        # DCSync requires both rights. Only emit on Domain nodes (BH semantics).
        node_type = graph.nodes[dst].get("node_type", "Unknown") if dst in graph else "Unknown"
        if node_type != "Domain":
            sid = str(dst)
            looks_like_domain = sid.startswith("S-1-5-21-") and sid.count("-") == 4
            if not looks_like_domain:
                continue

        existing = graph.get_edge_data(src, dst)
        if existing and existing.get("edge_type") == "DCSync":
            continue
        # Overwriting any prior GetChanges/GetChangesAll edge between the same
        # pair is desired — they are non-traversable on their own; DCSync is
        # the meaningful attack edge. (See SpecterOps DCSync docs.)
        graph.add_edge(src, dst, edge_type="DCSync", properties={"synthetic": True})
        added += 1

    if added:
        logger.info("dcsync_edges_synthesized", extra={"count": added})
    return added


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
        _v4_section_type = {
            "computers": "Computer", "users": "User", "groups": "Group",
            "domains": "Domain", "gpos": "GPO", "ous": "OU",
            "containers": "Container",
        }
        for key, ntype in _v4_section_type.items():
            if key in data:
                n, e = _extract_from_v4_section(data[key], default_type=ntype)
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

    # Add edges (canonicalize spelling at boundary — see _EDGE_ALIAS / _canon_edge)
    skipped = 0
    unknown_seen: set[str] = set()
    # Track raw rights per (principal, target) pair so we can synthesize
    # combination edges (DCSync = GetChanges + GetChangesAll). Must be done
    # BEFORE the DiGraph deduplicates edges between the same pair.
    rights_observed: dict[tuple[str, str], set[str]] = {}
    for edge in all_edges:
        src, dst = edge["source"], edge["target"]
        etype = _canon_edge(edge["type"])
        if etype not in KNOWN_EDGE_TYPES:
            unknown_seen.add(etype)
            skipped += 1
        if etype in ("GetChanges", "GetChangesAll"):
            rights_observed.setdefault((src, dst), set()).add(etype)
        # Ensure nodes exist even if not in node list
        if src not in graph:
            graph.add_node(src, label=src, node_type="Unknown", is_privileged=False, properties={})
        if dst not in graph:
            graph.add_node(dst, label=dst, node_type="Unknown", is_privileged=False, properties={})
        graph.add_edge(src, dst, edge_type=etype, properties=edge.get("properties", {}))

    if unknown_seen:
        # Log a sample of unknown edge types so we know what new BH versions emit.
        logger.warning(
            "unknown_edge_types_seen",
            extra={"types": sorted(unknown_seen)[:10], "skipped_count": skipped},
        )

    # Synthesize DCSync edges from co-occurring GetChanges + GetChangesAll
    _synthesize_dcsync_edges(graph, rights_observed=rights_observed)

    if skipped > 0:
        logger.warning("edges_skipped", extra={"count": skipped, "reason": "unknown_type"})

    # Recompute is_privileged for every node (including stubs added from edge
    # endpoints whose privilege status couldn't be determined at insertion time).
    privileged_count = 0
    for nid, ndata in graph.nodes(data=True):
        is_priv = _is_privileged(
            nid,
            {
                "properties": ndata.get("properties", {}),
                "type": ndata.get("node_type", "Unknown"),
                "label": ndata.get("label", ""),
            },
        )
        ndata["is_privileged"] = is_priv
        if is_priv:
            privileged_count += 1

    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()

    logger.info(
        "ingestion_complete",
        extra={
            "nodes": node_count,
            "edges": edge_count,
            "skipped_edges": skipped,
            "privileged_nodes": privileged_count,
        },
    )

    if node_count == 0:
        raise IngestionError("Le graphe est vide après ingestion")

    return graph, node_count, edge_count


# BloodHound v6 CE ZIP format — maps file type to NetworkX node_type
_ZIP_TYPE_MAP = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "domains": "Domain",
    "gpos": "GPO",
    "ous": "OU",
    "containers": "Container",
    "cas": "CertAuthority",
    "certtemplates": "CertTemplate",
    "aiacas": "CertAuthority",
    "rootcas": "CertAuthority",
    "enterprisecas": "CertAuthority",
    "ntauthstores": "NTAuthStore",
}

# RID-based map for computer LocalGroups (preferred — locale-independent).
# Mirrors how bloodhound-python's enumeration/computers.py classifies groups.
# Source: https://github.com/dirkjanm/BloodHound.py — c.rpc_get_group_members(<RID>)
_LOCAL_GROUP_RID_MAP: dict[int, str] = {
    544: "AdminTo",       # BUILTIN\Administrators
    555: "CanRDP",        # BUILTIN\Remote Desktop Users
    562: "ExecuteDCOM",   # BUILTIN\Distributed COM Users
    580: "CanPSRemote",   # BUILTIN\Remote Management Users
}

# Fallback name-substring map (English only). Used ONLY when RID is missing
# from the LocalGroupAPIResult item — older SharpHound versions, hand-rolled
# fixtures. On a French DC the SID/RID path always wins, so this is harmless.
_LOCAL_GROUP_NAME_MAP: dict[str, str] = {
    "Administrators": "AdminTo",
    "Remote Desktop": "CanRDP",
    "Distributed COM": "ExecuteDCOM",
    "Remote Management": "CanPSRemote",
}


def _classify_local_group(lg: dict) -> str | None:
    """Map a SharpHound LocalGroupAPIResult to a BloodHound edge type.

    Strategy: try RID first (`Rid` field, or last segment of `ObjectIdentifier`),
    fall back to English name substring match. Returns None if unrecognised.
    """
    if not isinstance(lg, dict):
        return None
    # Direct Rid field (newer SharpHound)
    rid = lg.get("Rid")
    if isinstance(rid, int) and rid in _LOCAL_GROUP_RID_MAP:
        return _LOCAL_GROUP_RID_MAP[rid]
    # ObjectID is "S-1-5-32-544" etc; last segment is the RID
    obj_id = lg.get("ObjectID") or lg.get("ObjectIdentifier") or ""
    if isinstance(obj_id, str) and "-" in obj_id:
        try:
            tail = int(obj_id.rsplit("-", 1)[-1])
            if tail in _LOCAL_GROUP_RID_MAP:
                return _LOCAL_GROUP_RID_MAP[tail]
        except ValueError:
            pass
    # Locale-dependent fallback (English)
    name = lg.get("Name", "") or ""
    for kw, et in _LOCAL_GROUP_NAME_MAP.items():
        if kw in name:
            return et
    return None


def ingest_bloodhound_zip(zip_bytes: bytes) -> tuple[nx.DiGraph, int, int]:
    """Parse a BloodHound ZIP archive (v6 CE / SharpHound 2.x format).

    Each JSON file in the archive represents one object type (users, groups,
    computers, etc.). Nodes are built from ObjectIdentifier + Properties, and
    edges are derived from Members, Aces, Sessions, LocalGroups, and delegation
    relationships.

    Args:
        zip_bytes: Raw bytes of the ZIP archive.

    Returns:
        Tuple of (DiGraph, node_count, edge_count).

    Raises:
        IngestionError: If the archive is invalid or empty.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise IngestionError(f"Archive ZIP invalide : {exc}") from exc

    graph = nx.DiGraph()
    # (object_id, raw_item, node_type)
    all_items: list[tuple[str, dict, str]] = []

    with zf:
        json_files = [n for n in zf.namelist() if n.endswith(".json")]
        if not json_files:
            raise IngestionError("Aucun fichier JSON trouvé dans l'archive ZIP")

        for filename in json_files:
            try:
                raw = json.loads(zf.read(filename))
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("zip_file_parse_error", extra={"filename": filename, "error": str(exc)})
                continue

            meta = raw.get("meta", {})
            file_type = meta.get("type", "").lower()
            items = raw.get("data", [])
            if not isinstance(items, list):
                continue

            node_type = _ZIP_TYPE_MAP.get(file_type, "Unknown")

            for item in items:
                obj_id = item.get("ObjectIdentifier", "")
                if not obj_id:
                    continue
                props = item.get("Properties", {})
                label = props.get("name", obj_id)
                is_priv = _is_privileged(obj_id, {"properties": props, "type": node_type})

                graph.add_node(
                    obj_id,
                    label=label,
                    node_type=node_type,
                    is_privileged=is_priv,
                    properties=props,
                )
                all_items.append((obj_id, item, node_type))

    if not all_items:
        raise IngestionError("Aucun objet AD trouvé dans l'archive ZIP")

    edge_count = 0
    # Track raw rights per (principal, target) so DCSync synthesis can detect
    # the GetChanges + GetChangesAll combination before DiGraph dedupes them.
    rights_observed: dict[tuple[str, str], set[str]] = {}

    def _ensure_node(nid: str, ntype: str = "Unknown") -> None:
        if not graph.has_node(nid):
            graph.add_node(nid, label=nid, node_type=ntype, is_privileged=False, properties={})

    def _add_edge(src: str, dst: str, etype: str) -> None:
        nonlocal edge_count
        etype = _canon_edge(etype)
        if etype in ("GetChanges", "GetChangesAll"):
            rights_observed.setdefault((src, dst), set()).add(etype)
        _ensure_node(src)
        _ensure_node(dst)
        # Allow parallel edges of different types via key
        if not graph.has_edge(src, dst) or graph[src][dst].get("edge_type") != etype:
            graph.add_edge(src, dst, edge_type=etype)
            edge_count += 1

    for obj_id, item, node_type in all_items:
        props = item.get("Properties", {}) or {}

        # PrimaryGroupSID → MemberOf (every domain user/computer is a member of
        # its primary group, but BloodHound stores it as a property, not as a
        # Members entry on the group object).
        primary_group = item.get("PrimaryGroupSID") or props.get("primarygroupsid")
        if primary_group and primary_group != obj_id:
            _ensure_node(primary_group, "Group")
            _add_edge(obj_id, primary_group, "MemberOf")

        # Kerberoastable: any user with a non-empty SPN
        if node_type == "User":
            spns = (
                props.get("serviceprincipalnames")
                or props.get("ServicePrincipalNames")
                or []
            )
            has_spn = bool(spns) or bool(props.get("hasspn"))
            if has_spn and not props.get("name", "").upper().startswith("KRBTGT"):
                # Synthetic edge from "any authenticated user" abstraction
                # (modelled as a self-flag for downstream analysis)
                graph.nodes[obj_id]["kerberoastable"] = True
            if props.get("dontreqpreauth"):
                graph.nodes[obj_id]["asreproastable"] = True
            if props.get("unconstraineddelegation"):
                graph.nodes[obj_id]["unconstrained"] = True

        # Members → MemberOf (member SID → group)
        for member in item.get("Members", []) or []:
            mid = member.get("ObjectIdentifier", "")
            if mid and mid != obj_id:
                _ensure_node(mid, member.get("ObjectType", "Unknown"))
                _add_edge(mid, obj_id, "MemberOf")

        # Aces → ACE right name (principal → object)
        for ace in item.get("Aces", []) or []:
            psid = ace.get("PrincipalSID", "")
            right = ace.get("RightName", "")
            if psid and right and psid != obj_id:
                _ensure_node(psid, ace.get("PrincipalType", "Unknown"))
                _add_edge(psid, obj_id, right)

        # AllowedToDelegate → AllowedToDelegate
        for target in item.get("AllowedToDelegate", []) or []:
            tid = target.get("ObjectIdentifier", "")
            if tid and tid != obj_id:
                _ensure_node(tid, target.get("ObjectType", "Unknown"))
                _add_edge(obj_id, tid, "AllowedToDelegate")

        # AllowedToAct → AllowedToAct (RBCD)
        for target in item.get("AllowedToAct", []) or []:
            tid = target.get("ObjectIdentifier", "")
            if tid and tid != obj_id:
                _ensure_node(tid, target.get("ObjectType", "Unknown"))
                _add_edge(tid, obj_id, "AllowedToAct")

        # Sessions → HasSession (computer → user)
        for sess_key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
            sess_block = item.get(sess_key) or {}
            if isinstance(sess_block, dict):
                for sess in sess_block.get("Results", []) or []:
                    user_sid = sess.get("UserSID", "")
                    if user_sid and user_sid != obj_id:
                        _ensure_node(user_sid, "User")
                        _add_edge(obj_id, user_sid, "HasSession")

        # LocalGroups → AdminTo / CanRDP / ExecuteDCOM / CanPSRemote (RID-based)
        for lg in item.get("LocalGroups", []) or []:
            edge_type = _classify_local_group(lg)
            if not edge_type:
                continue
            for member in lg.get("Results", []) or []:
                mid = member.get("ObjectIdentifier", "")
                if mid and mid != obj_id:
                    _ensure_node(mid, member.get("ObjectType", "Unknown"))
                    _add_edge(mid, obj_id, edge_type)

        # Trusts → TrustedBy (domain → trusted domain)
        for trust in item.get("Trusts", []) or []:
            tid = trust.get("TargetDomainSid", "")
            tname = trust.get("TargetDomainName", tid)
            if tid and tid != obj_id:
                if not graph.has_node(tid):
                    graph.add_node(tid, label=tname, node_type="Domain", is_privileged=False, properties={})
                _add_edge(obj_id, tid, "TrustedBy")

        # Links (domain/OU → GPO)
        for link in item.get("Links", []) or []:
            gpo_sid = link.get("GUID", "") or link.get("ObjectIdentifier", "")
            if gpo_sid and gpo_sid != obj_id:
                _ensure_node(gpo_sid, "GPO")
                _add_edge(obj_id, gpo_sid, "GPLink")

        # ContainedBy → Contains (parent container → this object)
        contained_by = item.get("ContainedBy") or {}
        if isinstance(contained_by, dict):
            parent_id = contained_by.get("ObjectIdentifier", "")
            if parent_id and parent_id != obj_id:
                _ensure_node(parent_id, contained_by.get("ObjectType", "Unknown"))
                _add_edge(parent_id, obj_id, "Contains")

        # ChildObjects → Contains (this container → child).
        # SharpHoundCommon emits this on Domain, OU, and Container objects;
        # children may live in a different JSON file (e.g. computers.json),
        # so we need both directions to capture the full hierarchy.
        for child in item.get("ChildObjects", []) or []:
            cid = child.get("ObjectIdentifier", "") if isinstance(child, dict) else ""
            if cid and cid != obj_id:
                _ensure_node(cid, child.get("ObjectType", "Unknown"))
                _add_edge(obj_id, cid, "Contains")

        # HasSIDHistory
        for hist in item.get("HasSIDHistory", []) or []:
            hid = hist.get("ObjectIdentifier", "")
            if hid and hid != obj_id:
                _ensure_node(hid, hist.get("ObjectType", "Unknown"))
                _add_edge(obj_id, hid, "HasSIDHistory")

    # Synthesize DCSync edges from co-occurring GetChanges + GetChangesAll
    _synthesize_dcsync_edges(graph, rights_observed=rights_observed)

    # Final pass: recompute is_privileged for every node, including stubs
    # whose privilege status was unknown at insertion time. Also add synthetic
    # Kerberoast / ASREP edges (any User → kerberoastable User).
    privileged_count = 0
    for nid, ndata in graph.nodes(data=True):
        is_priv = _is_privileged(
            nid,
            {
                "properties": ndata.get("properties", {}),
                "type": ndata.get("node_type", "Unknown"),
                "label": ndata.get("label", ""),
            },
        )
        ndata["is_privileged"] = is_priv
        if is_priv:
            privileged_count += 1

    node_count = graph.number_of_nodes()
    logger.info(
        "zip_ingestion_complete",
        extra={
            "nodes": node_count,
            "edges": edge_count,
            "items_parsed": len(all_items),
            "privileged_nodes": privileged_count,
        },
    )

    if node_count == 0:
        raise IngestionError("Le graphe ZIP est vide après ingestion")

    return graph, node_count, edge_count
