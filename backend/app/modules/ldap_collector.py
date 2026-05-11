"""Module LDAP — Live Active Directory data collection.

Connects to a domain controller, enumerates users, computers, groups,
ACL/DACL entries, and their relationships, then returns a BloodHound-
compatible graph that feeds directly into the existing ingestion pipeline.
"""

import logging
import struct
from typing import Callable

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, str, int], None]

# ── Known DACL GUID bytes (Windows mixed-endian: parts 1-3 LE, part 4 BE) ──
# DS-Replication-Get-Changes      1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
_GUID_DS_REPL_GET_CHANGES     = b'\xaa\xf6\x31\x11\x07\x9c\xd1\x11\xf7\x9f\x00\xc0\x4f\xc2\xdc\xd2'
# DS-Replication-Get-Changes-All  1131f6ab-9c07-11d1-f79f-00c04fc2dcd2
_GUID_DS_REPL_GET_CHANGES_ALL = b'\xab\xf6\x31\x11\x07\x9c\xd1\x11\xf7\x9f\x00\xc0\x4f\xc2\xdc\xd2'
# User-Force-Change-Password      00299570-246d-11d0-a768-00aa006e0529
_GUID_USER_FORCE_CHANGE_PWD   = b'\x70\x95\x29\x00\x6d\x24\xd0\x11\xa7\x68\x00\xaa\x00\x6e\x05\x29'
# member attribute write          bf9679c0-0de6-11d0-a285-00aa003049e2
_GUID_MEMBER_ATTR             = b'\xc0\x79\x96\xbf\xe6\x0d\xd0\x11\xa2\x85\x00\xaa\x00\x30\x49\xe2'

# Access mask bits relevant to BloodHound
_GENERIC_ALL    = 0x10000000
_WRITE_DAC      = 0x00040000
_WRITE_OWNER    = 0x00080000
_DS_WRITE_PROP  = 0x00000020
_DS_CTRL_ACCESS = 0x00000100
_GENERIC_WRITE  = 0x40000000


def _as_list(val) -> list:
    """Normalize a single value / list / None to always return a list."""
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [v for v in val if v is not None]
    return [val]


def _sid_to_str(raw) -> str:
    """Convert objectSid (raw bytes or already-formatted string) → 'S-1-5-…' string."""
    if isinstance(raw, str):
        return raw if raw.startswith("S-") else ""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        return ""
    try:
        revision = raw[0]
        sub_count = raw[1]
        authority = int.from_bytes(raw[2:8], "big")
        subs = struct.unpack(f"<{sub_count}I", raw[8: 8 + sub_count * 4])
        return f"S-{revision}-{authority}-{'-'.join(str(s) for s in subs)}"
    except Exception:
        return ""


def _mask_to_bh_edges(mask: int, obj_guid: bytes | None, object_type: str) -> list[str]:
    """Map an ACCESS_MASK + optional ObjectType GUID to BloodHound edge labels."""
    edges: list[str] = []

    if mask & _GENERIC_ALL:
        edges.append("GenericAll")
        return edges  # GenericAll implies everything below

    if mask & _WRITE_DAC:
        edges.append("WriteDacl")
    if mask & _WRITE_OWNER:
        edges.append("WriteOwner")
    if mask & _GENERIC_WRITE:
        edges.append("GenericWrite")

    if mask & _DS_CTRL_ACCESS:
        if object_type == "Domain" and obj_guid in (
            _GUID_DS_REPL_GET_CHANGES,
            _GUID_DS_REPL_GET_CHANGES_ALL,
        ):
            edges.append("GetChangesAll")
        elif object_type == "User" and obj_guid == _GUID_USER_FORCE_CHANGE_PWD:
            edges.append("ForceChangePassword")

    if (mask & _DS_WRITE_PROP) and object_type == "Group":
        if obj_guid is None or obj_guid == _GUID_MEMBER_ATTR:
            edges.append("AddMember")

    return list(set(edges))


def _parse_dacl_edges(sd_bytes: bytes, object_sid: str, object_type: str) -> list[dict]:
    """Parse a Windows Security Descriptor binary blob and return BH-style edges.

    Handles ACE types 0x00 (ACCESS_ALLOWED) and 0x05 (ACCESS_ALLOWED_OBJECT).
    All parse errors are silently discarded to keep the collection robust.
    """
    try:
        if len(sd_bytes) < 20:
            return []

        # SECURITY_DESCRIPTOR header (20 bytes)
        _rev, _sbz1, _ctrl = struct.unpack_from("<BBH", sd_bytes, 0)
        _off_owner, _off_group, _off_sacl, off_dacl = struct.unpack_from("<IIII", sd_bytes, 4)

        if off_dacl == 0 or off_dacl + 8 > len(sd_bytes):
            return []

        # ACL header (8 bytes)
        _acl_rev, _acl_sbz1, _acl_size, ace_count, _acl_sbz2 = struct.unpack_from(
            "<BBHHH", sd_bytes, off_dacl
        )

        edges: list[dict] = []
        pos = off_dacl + 8  # first ACE

        for _ in range(ace_count):
            if pos + 4 > len(sd_bytes):
                break

            ace_type, _ace_flags, ace_size = struct.unpack_from("<BBH", sd_bytes, pos)

            if ace_size < 4 or pos + ace_size > len(sd_bytes):
                break

            try:
                if ace_type == 0x00:  # ACCESS_ALLOWED_ACE
                    if ace_size >= 12:
                        access_mask = struct.unpack_from("<I", sd_bytes, pos + 4)[0]
                        trustee_sid = _sid_to_str(bytes(sd_bytes[pos + 8: pos + ace_size]))
                        if trustee_sid and trustee_sid != object_sid:
                            for et in _mask_to_bh_edges(access_mask, None, object_type):
                                edges.append({"source": trustee_sid, "target": object_sid, "label": et})

                elif ace_type == 0x05:  # ACCESS_ALLOWED_OBJECT_ACE
                    if ace_size >= 16:
                        access_mask, obj_flags = struct.unpack_from("<II", sd_bytes, pos + 4)
                        sub = pos + 12
                        obj_guid: bytes | None = None
                        if obj_flags & 0x1 and sub + 16 <= pos + ace_size:
                            obj_guid = bytes(sd_bytes[sub: sub + 16])
                            sub += 16
                        if obj_flags & 0x2 and sub + 16 <= pos + ace_size:
                            sub += 16  # skip inherited object type
                        trustee_sid = _sid_to_str(bytes(sd_bytes[sub: pos + ace_size]))
                        if trustee_sid and trustee_sid != object_sid:
                            for et in _mask_to_bh_edges(access_mask, obj_guid, object_type):
                                edges.append({"source": trustee_sid, "target": object_sid, "label": et})
            except Exception:
                pass

            pos += ace_size

        return edges

    except Exception as exc:
        logger.debug("dacl_parse_error", extra={"error": str(exc)[:80]})
        return []


class LDAPCollector:
    """Synchronous LDAP collector for Active Directory environments.

    Enumerates users, computers, groups, and ACL/DACL entries.
    Returns a BloodHound v5-compatible JSON dict for the ingestion pipeline.
    """

    CONNECT_TIMEOUT = 10   # seconds until TCP connection fails
    RECEIVE_TIMEOUT = 30   # seconds until an LDAP response times out

    def __init__(
        self,
        dc_host: str,
        domain: str,
        username: str,
        password: str,
        port: int = 389,
        use_ssl: bool = False,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.dc_host = dc_host
        self.domain = domain
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self._cb: ProgressCallback = progress_callback or (lambda stage, msg, pct: None)
        self.conn = None
        # Build base DN from FQDN; if only a short name is given (no dots)
        # we'll auto-detect the real base DN after connecting via server info.
        self.base_dn = ",".join(f"DC={p}" for p in domain.split(".")) if "." in domain else ""
        self._dn_sid: dict[str, str] = {}

    # ── Connection ──────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Establish LDAP connection using NTLM with simple-bind fallback."""
        try:
            from ldap3 import ALL, NTLM, SIMPLE, Connection, Server
        except ImportError as exc:
            raise RuntimeError(
                "La bibliothèque ldap3 n'est pas installée. "
                "Ajoutez ldap3>=3.4.0 aux dépendances du backend."
            ) from exc

        server = Server(
            self.dc_host,
            port=self.port,
            use_ssl=self.use_ssl,
            get_info=ALL,
            connect_timeout=self.CONNECT_TIMEOUT,
        )
        ntlm_user = f"{self.domain}\\{self.username}"
        try:
            self.conn = Connection(
                server,
                user=ntlm_user,
                password=self.password,
                authentication=NTLM,
                auto_bind=True,
                auto_referrals=False,
                receive_timeout=self.RECEIVE_TIMEOUT,
            )
        except Exception:
            # Fallback: UPN format + simple bind (less secure but wider support)
            upn = f"{self.username}@{self.domain}"
            self.conn = Connection(
                server,
                user=upn,
                password=self.password,
                authentication=SIMPLE,
                auto_bind=True,
                auto_referrals=False,
                receive_timeout=self.RECEIVE_TIMEOUT,
            )
        # Zero out the password from memory immediately after bind.
        self.password = ""

        # Auto-detect base DN from server info when domain had no dots (e.g. "CONTROLLER").
        if not self.base_dn and server.info:
            try:
                ctx = server.info.other.get("defaultNamingContext", [])
                if ctx:
                    self.base_dn = ctx[0] if isinstance(ctx, list) else ctx
            except Exception:
                pass
        if not self.base_dn:
            self.base_dn = ",".join(f"DC={p}" for p in self.domain.split("."))

        logger.info("ldap_connected", extra={"host": self.dc_host, "base_dn": self.base_dn})

    def disconnect(self) -> None:
        if self.conn:
            try:
                self.conn.unbind()
            except Exception:
                pass

    # ── Search ──────────────────────────────────────────────────────────────

    def _search_all(self, filter_str: str, attrs: list[str]) -> list[dict]:
        """Execute a fully-paged subtree search and return ALL matching entries.

        Uses ldap3's paged_search extension so production ADs with thousands of
        objects are handled correctly — a single conn.search(paged_size=500) only
        returns the first page and silently drops the rest.
        """
        from ldap3 import SUBTREE

        # Multi-value DN attributes need the list of all values, not just the first.
        _multi_dn = {"memberOf", "member", "servicePrincipalName"}

        results: list[dict] = []
        try:
            for entry in self.conn.extend.standard.paged_search(
                search_base=self.base_dn,
                search_filter=filter_str,
                search_scope=SUBTREE,
                attributes=attrs,
                paged_size=500,
                generator=True,
            ):
                if entry.get("type") != "searchResEntry":
                    continue

                d: dict = {"dn": entry["dn"]}
                raw_attrs = entry.get("raw_attributes", {})
                cooked_attrs = entry.get("attributes", {})

                for attr in attrs:
                    try:
                        if attr in _multi_dn:
                            val = cooked_attrs.get(attr, [])
                            d[attr] = _as_list(val)
                        elif attr == "objectSid":
                            # Prefer raw bytes so _sid_to_str can parse them;
                            # fall back to the already-decoded string value.
                            raw_list = raw_attrs.get(attr, [])
                            if raw_list:
                                d[attr] = raw_list[0]
                            else:
                                d[attr] = cooked_attrs.get(attr) or b""
                        else:
                            d[attr] = cooked_attrs.get(attr)
                    except Exception:
                        d[attr] = None

                results.append(d)
        except Exception as exc:
            logger.warning(
                "ldap_search_error",
                extra={"filter": filter_str[:80], "error": str(exc)[:120]},
            )
        return results

    # ── Collectors ──────────────────────────────────────────────────────────

    def collect_domain_info(self) -> dict:
        rows = self._search_all("(objectClass=domain)", ["objectSid", "name"])
        for row in rows:
            sid = _sid_to_str(row.get("objectSid") or b"")
            name = row.get("name") or self.domain
            if sid:
                self._dn_sid[row["dn"]] = sid
                return {"sid": sid, "name": name, "dn": row["dn"]}
        return {"sid": self.base_dn, "name": self.domain, "dn": self.base_dn}

    def collect_users(self) -> list[dict]:
        # Attribute set mirrors bloodhound-python/bloodhound/ad/domain.py
        # get_users(include_properties=True). All fields are LDAP-derivable
        # (no SMB/RPC), so they are honest to collect over LDAP only.
        attrs = [
            "sAMAccountName", "objectSid", "distinguishedName",
            "memberOf", "adminCount", "userAccountControl",
            "servicePrincipalName", "primaryGroupID",
            "msDS-AllowedToDelegateTo", "sIDHistory",
        ]
        rows = self._search_all("(&(objectClass=user)(!(objectClass=computer)))", attrs)
        users = []
        for row in rows:
            sid = _sid_to_str(row.get("objectSid") or b"")
            if not sid:
                continue
            name = row.get("sAMAccountName") or row["dn"]
            self._dn_sid[row["dn"]] = sid
            uac = row.get("userAccountControl") or 0
            try:
                uac_int = int(str(uac))
                disabled = bool(uac_int & 2)
                asrep_roastable = bool(uac_int & 0x400000)  # DONT_REQ_PREAUTH
                unconstrained = bool(uac_int & 0x80000)     # TRUSTED_FOR_DELEGATION
            except Exception:
                disabled = False
                asrep_roastable = False
                unconstrained = False
            has_spn = bool(_as_list(row.get("servicePrincipalName")))
            # primaryGroupID is a numeric RID — must be combined with the
            # domain SID to produce the actual group SID (S-1-5-21-X-<RID>).
            primary_rid = row.get("primaryGroupID")
            try:
                primary_rid = int(str(primary_rid)) if primary_rid is not None else None
            except (TypeError, ValueError):
                primary_rid = None
            # Resolve sIDHistory — list of binary SIDs
            sid_history = []
            for h in _as_list(row.get("sIDHistory")):
                hs = _sid_to_str(h)
                if hs:
                    sid_history.append(hs)
            users.append({
                "sid": sid,
                "name": name,
                "dn": row["dn"],
                "member_of": _as_list(row.get("memberOf")),
                "admin_count": bool(row.get("adminCount")),
                "enabled": not disabled,
                "has_spn": has_spn,
                "asrep_roastable": asrep_roastable,
                "unconstrained_delegation": unconstrained,
                "primary_group_rid": primary_rid,
                "allowed_to_delegate": _as_list(row.get("msDS-AllowedToDelegateTo")),
                "sid_history": sid_history,
            })
        logger.info("users_collected", extra={"count": len(users)})
        return users

    def collect_computers(self) -> list[dict]:
        attrs = [
            "sAMAccountName", "objectSid", "distinguishedName",
            "memberOf", "operatingSystem", "dNSHostName",
            "userAccountControl", "primaryGroupID",
            "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "sIDHistory",
        ]
        rows = self._search_all("(objectClass=computer)", attrs)
        computers = []
        for row in rows:
            sid = _sid_to_str(row.get("objectSid") or b"")
            if not sid:
                continue
            dns = row.get("dNSHostName") or ""
            sam = (row.get("sAMAccountName") or "").rstrip("$")
            name = dns or sam or row["dn"]
            self._dn_sid[row["dn"]] = sid
            uac = row.get("userAccountControl") or 0
            try:
                uac_int = int(str(uac))
                unconstrained = bool(uac_int & 0x80000)  # TRUSTED_FOR_DELEGATION
            except Exception:
                unconstrained = False
            primary_rid = row.get("primaryGroupID")
            try:
                primary_rid = int(str(primary_rid)) if primary_rid is not None else None
            except (TypeError, ValueError):
                primary_rid = None
            sid_history = []
            for h in _as_list(row.get("sIDHistory")):
                hs = _sid_to_str(h)
                if hs:
                    sid_history.append(hs)
            # msDS-AllowedToActOnBehalfOfOtherIdentity is a Security Descriptor
            # blob. Each ACE's PrincipalSID is a "controller" able to perform
            # RBCD against this computer (AllowedToAct edge: principal -> this).
            rbcd_principals: list[str] = []
            sd_blob = row.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
            if isinstance(sd_blob, (bytes, bytearray)) and len(sd_blob) > 20:
                for e in _parse_dacl_edges(bytes(sd_blob), sid, "Computer"):
                    if e.get("source"):
                        rbcd_principals.append(e["source"])
            computers.append({
                "sid": sid,
                "name": name,
                "dn": row["dn"],
                "member_of": _as_list(row.get("memberOf")),
                "os": row.get("operatingSystem"),
                "unconstrained_delegation": unconstrained,
                "primary_group_rid": primary_rid,
                "allowed_to_delegate": _as_list(row.get("msDS-AllowedToDelegateTo")),
                "rbcd_principals": rbcd_principals,
                "sid_history": sid_history,
            })
        logger.info("computers_collected", extra={"count": len(computers)})
        return computers

    def collect_groups(self) -> list[dict]:
        attrs = [
            "sAMAccountName", "objectSid", "distinguishedName",
            "member", "memberOf", "adminCount",
        ]
        rows = self._search_all("(objectClass=group)", attrs)
        groups = []
        for row in rows:
            sid = _sid_to_str(row.get("objectSid") or b"")
            if not sid:
                continue
            name = row.get("sAMAccountName") or row["dn"]
            self._dn_sid[row["dn"]] = sid
            groups.append({
                "sid": sid,
                "name": name,
                "dn": row["dn"],
                "members": _as_list(row.get("member")),
                "member_of": _as_list(row.get("memberOf")),
                "admin_count": bool(row.get("adminCount")),
            })
        logger.info("groups_collected", extra={"count": len(groups)})
        return groups

    def collect_acls(self) -> list[dict]:
        """Read nTSecurityDescriptor from AD objects and extract DACL-based edges.

        Queries users, computers, groups, and domain objects. Parses binary
        Security Descriptors to find BloodHound-relevant ACE rights:
        GenericAll, WriteDacl, WriteOwner, GenericWrite, GetChangesAll (DCSync),
        ForceChangePassword, AddMember.

        Returns a list of {"source": sid, "target": sid, "label": edge_type} dicts.
        """
        try:
            from ldap3 import SUBTREE
            from ldap3.protocol.microsoft import security_descriptor_control
        except ImportError:
            logger.warning("acl_collection_skipped: ldap3 or security_descriptor_control unavailable")
            return []

        # DACL_SECURITY_INFORMATION = 4 (read only the DACL, not SACL)
        try:
            sd_ctrl = security_descriptor_control(sdflags=4)
        except Exception:
            # Fallback: build the control manually
            from binascii import unhexlify
            from ldap3.core.results import RESULT_SUCCESS
            sd_ctrl = [("1.2.840.113556.1.4.801", True, unhexlify("3003020104"))]

        acl_edges: list[dict] = []

        type_map = [
            ("(&(objectClass=user)(!(objectClass=computer)))", "User"),
            ("(objectClass=computer)", "Computer"),
            ("(objectClass=group)", "Group"),
            ("(objectClass=domain)", "Domain"),
        ]

        for filter_str, obj_type in type_map:
            try:
                self.conn.search(
                    search_base=self.base_dn,
                    search_filter=filter_str,
                    search_scope=SUBTREE,
                    attributes=["objectSid", "nTSecurityDescriptor"],
                    controls=sd_ctrl,
                    paged_size=200,
                )
                for entry in self.conn.entries:
                    try:
                        raw_sids = entry["objectSid"].raw_values
                        obj_sid = _sid_to_str(raw_sids[0] if raw_sids else b"")
                        if not obj_sid:
                            continue
                        raw_sds = entry["nTSecurityDescriptor"].raw_values
                        if not raw_sds:
                            continue
                        parsed = _parse_dacl_edges(raw_sds[0], obj_sid, obj_type)
                        acl_edges.extend(parsed)
                    except Exception as exc:
                        logger.debug("acl_entry_skip", extra={"error": str(exc)[:60]})
            except Exception as exc:
                logger.warning("acl_query_error", extra={"type": obj_type, "error": str(exc)[:100]})

        # Deduplicate
        seen: set[tuple] = set()
        unique: list[dict] = []
        for e in acl_edges:
            key = (e["source"], e["target"], e["label"])
            if key not in seen:
                seen.add(key)
                unique.append(e)

        logger.info("acls_collected", extra={"acl_edges": len(unique)})
        return unique

    # ── Graph builder ───────────────────────────────────────────────────────

    def _privileged_group_sids(self, groups: list[dict]) -> set[str]:
        """Return SIDs of groups whose members are AUTO-LOCAL-ADMIN on every
        domain-joined computer in default AD configurations.

        Used only by the LDAP `AdminTo` heuristic (we cannot enumerate local
        Administrators groups via LDAP — that requires SMB/SAMR). Restricted
        to genuinely auto-admin groups:
          - Domain Admins (-512): added to local Administrators on join
          - Enterprise Admins (-519): forest-wide auto-admin
          - Builtin Administrators (S-1-5-32-544): direct match on DCs

        Schema Admins (-518) are NOT included — they have schema-modification
        rights but aren't auto-admin on workstations.
        """
        result: set[str] = set()
        for g in groups:
            sid = g["sid"]
            # Builtin Administrators — bare or domain-prefixed
            if sid == "S-1-5-32-544" or sid.endswith("-S-1-5-32-544"):
                result.add(sid)
            for rid in ("512", "519"):
                if sid.endswith(f"-{rid}"):
                    result.add(sid)
                    break
        return result

    def _effective_members(self, groups: list[dict], group_sids: set[str], depth: int = 4) -> set[str]:
        """Recursively expand group memberships up to `depth` levels."""
        group_map: dict[str, set[str]] = {}
        for g in groups:
            members: set[str] = set()
            for dn in g["members"]:
                sid = self._dn_sid.get(dn)
                if sid:
                    members.add(sid)
            group_map[g["sid"]] = members

        effective: set[str] = set()
        queue = list(group_sids)
        seen: set[str] = set()
        for _ in range(depth):
            next_queue: list[str] = []
            for gsid in queue:
                if gsid in seen:
                    continue
                seen.add(gsid)
                for msid in group_map.get(gsid, set()):
                    effective.add(msid)
                    next_queue.append(msid)
            queue = next_queue
        return effective

    def build_graph(
        self,
        domain: dict,
        users: list[dict],
        computers: list[dict],
        groups: list[dict],
        acl_edges: list[dict] | None = None,
    ) -> dict:
        """Build a BloodHound v5-compatible JSON graph dict."""
        nodes: list[dict] = []
        edges: list[dict] = []

        nodes.append({
            "id": domain["sid"],
            "label": domain["name"].upper(),
            "type": "Domain",
            "properties": {"name": domain["name"]},
        })

        for u in users:
            nodes.append({
                "id": u["sid"],
                "label": u["name"].upper(),
                "type": "User",
                "properties": {
                    "name": u["name"],
                    "enabled": u["enabled"],
                    "admincount": u["admin_count"],
                    "unconstraineddelegation": u.get("unconstrained_delegation", False),
                    "hasspn": u.get("has_spn", False),
                    "dontreqpreauth": u.get("asrep_roastable", False),
                },
            })

        for c in computers:
            nodes.append({
                "id": c["sid"],
                "label": c["name"].upper(),
                "type": "Computer",
                "properties": {
                    "name": c["name"],
                    "operatingsystem": c.get("os"),
                    "unconstraineddelegation": c.get("unconstrained_delegation", False),
                },
            })

        for g in groups:
            nodes.append({
                "id": g["sid"],
                "label": g["name"].upper(),
                "type": "Group",
                "properties": {"name": g["name"], "admincount": g["admin_count"]},
            })

        # MemberOf from memberOf attribute (principal → parent group)
        for collection in (users, computers, groups):
            for item in collection:
                for parent_dn in item.get("member_of", []):
                    parent_sid = self._dn_sid.get(parent_dn)
                    if parent_sid:
                        edges.append({"source": item["sid"], "target": parent_sid, "label": "MemberOf"})

        # MemberOf from group.members (member → group, reverse direction)
        for g in groups:
            for member_dn in g.get("members", []):
                member_sid = self._dn_sid.get(member_dn)
                if member_sid:
                    edges.append({"source": member_sid, "target": g["sid"], "label": "MemberOf"})

        # Contains: domain → top-level groups
        for g in groups:
            edges.append({"source": domain["sid"], "target": g["sid"], "label": "Contains"})

        # ── primaryGroupID → MemberOf ───────────────────────────────────────
        # Every user/computer is implicitly a member of its primary group, but
        # AD does NOT store this in `member`/`memberOf` — the relationship is
        # inferred from the integer RID + the domain SID.
        domain_sid = domain.get("sid", "")
        if domain_sid.startswith("S-1-5-21-"):
            valid_group_sids = {g["sid"] for g in groups}
            for principal in (*users, *computers):
                rid = principal.get("primary_group_rid")
                if rid is None:
                    continue
                pg_sid = f"{domain_sid}-{rid}"
                if pg_sid in valid_group_sids:
                    edges.append({"source": principal["sid"], "target": pg_sid, "label": "MemberOf"})

        # ── AdminTo (HEURISTIC — derived from default-AD assumptions) ───────
        # WARNING: this is NOT a real local-admin enumeration. Real BloodHound
        # uses SAMR over SMB to read the local Administrators group on each
        # computer (see bloodhound-python/enumeration/computers.py
        # rpc_get_group_members(544)). LDAP cannot do that.
        # We emit AdminTo for groups that ARE auto-local-admin in default AD
        # configurations (Domain Admins, Enterprise Admins, Builtin/Admins).
        # Custom local admins, removed-from-defaults, etc. are missed.
        # Edges are flagged `derived_from: ldap_heuristic` so the UI can
        # explain the limitation to the auditor.
        priv_sids = self._privileged_group_sids(groups)
        priv_members = self._effective_members(groups, priv_sids)
        for member_sid in priv_members:
            for c in computers:
                edges.append({
                    "source": member_sid, "target": c["sid"], "label": "AdminTo",
                    "properties": {"derived_from": "ldap_heuristic"},
                })

        # ── AllowedToDelegate (constrained delegation, LDAP-derivable) ──────
        # msDS-AllowedToDelegateTo holds SPN strings. Resolve each SPN to its
        # owning principal by matching the host part against computer DNS names.
        host_to_sid = {}
        for c in computers:
            for key in ("name",):
                hn = (c.get(key) or "").lower()
                if hn:
                    host_to_sid[hn] = c["sid"]
                    # Also index just the short hostname (before first dot)
                    short = hn.split(".", 1)[0]
                    host_to_sid.setdefault(short, c["sid"])

        for principal in (*users, *computers):
            for spn in principal.get("allowed_to_delegate", []) or []:
                spn_str = str(spn)
                # SPN format: "service/host:port" or "service/host"
                try:
                    host = spn_str.split("/", 1)[1].split(":", 1)[0].split("/", 1)[0].lower()
                except (IndexError, AttributeError):
                    continue
                target_sid = host_to_sid.get(host) or host_to_sid.get(host.split(".",1)[0])
                if target_sid:
                    edges.append({
                        "source": principal["sid"], "target": target_sid,
                        "label": "AllowedToDelegate",
                    })

        # ── AllowedToAct (RBCD — LDAP-derivable from msDS-AllowedToActOn…) ─
        for c in computers:
            for principal_sid in c.get("rbcd_principals", []) or []:
                edges.append({
                    "source": principal_sid, "target": c["sid"],
                    "label": "AllowedToAct",
                })

        # ── HasSIDHistory ───────────────────────────────────────────────────
        for principal in (*users, *computers):
            for hist_sid in principal.get("sid_history", []) or []:
                edges.append({
                    "source": principal["sid"], "target": hist_sid,
                    "label": "HasSIDHistory",
                })

        # ACL-based edges (GenericAll, WriteDacl, WriteOwner, GetChangesAll, etc.)
        if acl_edges:
            edges.extend(acl_edges)

        # Synthetic Kerberoastable edges: any non-priv domain user can request a TGS
        # for any SPN-bearing account and crack the hash offline.
        kerb_targets = [u for u in users if u.get("has_spn")]
        if kerb_targets:
            nonpriv_sources = [
                u["sid"] for u in users if not u["admin_count"] and u["enabled"]
            ] + [c["sid"] for c in computers]
            for target in kerb_targets:
                for src_sid in nonpriv_sources:
                    edges.append({"source": src_sid, "target": target["sid"], "label": "Kerberoastable"})
            logger.info(
                "kerberoastable_edges_added",
                extra={"targets": len(kerb_targets), "sources": len(nonpriv_sources)},
            )

        # Synthetic ASREPRoastable edges: accounts with DONT_REQ_PREAUTH (UAC 0x400000)
        # allow any user to obtain a crackable AS-REP without prior authentication.
        asrep_targets = [u for u in users if u.get("asrep_roastable")]
        if asrep_targets:
            nonpriv_sources_asrep = [
                u["sid"] for u in users if not u["admin_count"] and u["enabled"]
            ] + [c["sid"] for c in computers]
            for target in asrep_targets:
                for src_sid in nonpriv_sources_asrep:
                    edges.append({"source": src_sid, "target": target["sid"], "label": "ASREPRoastable"})
            logger.info("asrep_edges_added", extra={"targets": len(asrep_targets)})

        # Deduplicate edges
        seen_edges: set[tuple] = set()
        unique_edges: list[dict] = []
        for e in edges:
            key = (e["source"], e["target"], e["label"])
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        return {
            "meta": {"type": "adauditai_ldap_collection", "count": len(nodes), "version": 5},
            "data": [{"nodes": nodes, "edges": unique_edges}],
        }

    # ── Main entry point ────────────────────────────────────────────────────

    def collect_all(self) -> dict:
        """Run full collection. Returns BloodHound-compatible JSON dict.

        Calls progress_callback(stage, message_fr, percent) at each phase.
        """
        self._cb("ldap_connecting", "Connexion au contrôleur de domaine…", 5)
        self.connect()

        self._cb("ldap_users", "Collecte des comptes utilisateurs…", 15)
        users = self.collect_users()

        self._cb("ldap_computers", "Collecte des ordinateurs du domaine…", 30)
        computers = self.collect_computers()

        self._cb("ldap_groups", "Collecte des groupes et membres…", 45)
        groups = self.collect_groups()

        self._cb("ldap_acls", "Lecture des ACL / droits délégués…", 65)
        acl_edges = self.collect_acls()

        self._cb("ldap_building_graph", "Construction du graphe Active Directory…", 85)
        domain = self.collect_domain_info()
        graph = self.build_graph(domain, users, computers, groups, acl_edges)

        self.disconnect()
        n = len(graph["data"][0]["nodes"])
        e = len(graph["data"][0]["edges"])
        logger.info(
            "ldap_collection_complete",
            extra={
                "nodes": n,
                "edges": e,
                "users": len(users),
                "computers": len(computers),
                "groups": len(groups),
                "acl_edges": len(acl_edges),
            },
        )
        return graph
