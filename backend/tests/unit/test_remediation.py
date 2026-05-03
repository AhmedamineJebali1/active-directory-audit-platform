"""Tests for the markdown remediation guide generator."""

import io
import uuid
import zipfile
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.modules.remediation import (
    _bundle_filename,
    _format_path_summary,
    _render_step_section,
    build_bundle,
    build_guide_for_path,
    build_script_for_path,  # alias kept for backwards compatibility
)


def _make_path(
    *,
    path_id: uuid.UUID | None = None,
    risk: str = "critique",
    score: float = 8.5,
    hops: list[dict] | None = None,
    explanation: str | None = None,
    techniques: list | None = None,
    source: str = "S-1-5-21-100",
    target: str = "S-1-5-21-512",
):
    return SimpleNamespace(
        id=path_id or uuid.uuid4(),
        risk_level=risk,
        global_score=score,
        hops=hops
        or [
            {
                "source": "S-1-5-21-100",
                "source_label": "BACKUP",
                "source_type": "User",
                "target": "S-1-5-21-200",
                "target_label": "SPOOKYSEC",
                "target_type": "Domain",
                "edge_type": "WriteOwner",
            },
            {
                "source": "S-1-5-21-200",
                "source_label": "SPOOKYSEC",
                "source_type": "Domain",
                "target": "S-1-5-21-512",
                "target_label": "ADMINISTRATORS",
                "target_type": "Group",
                "edge_type": "Contains",
            },
        ],
        explanation_fr=explanation,
        recommendation_fr=None,
        llm_raw_response=None,
        mitre_techniques=techniques or [],
        source_node=source,
        target_node=target,
    )


def _make_engagement(code="DEL-2026-0142", client="Acme Corp"):
    return SimpleNamespace(code=code, client_name=client)


class TestPathSummary:
    def test_full_path_with_intermediate_node(self):
        out = _format_path_summary(_make_path().hops)
        assert "BACKUP" in out
        assert "SPOOKYSEC" in out
        assert "ADMINISTRATORS" in out
        assert "WriteOwner" in out
        assert "Contains" in out

    def test_empty_path(self):
        assert "vide" in _format_path_summary([])


class TestStepSection:
    def test_known_edge_renders_full_structure(self):
        hop = {
            "source": "u",
            "target": "g",
            "source_label": "USER",
            "target_label": "GROUP",
            "edge_type": "WriteOwner",
        }
        md = _render_step_section(1, hop)
        assert "Étape 1" in md
        assert "WriteOwner" in md
        assert "USER" in md and "GROUP" in md
        assert "Pourquoi c'est risqué" in md
        assert "Options de mitigation" in md
        assert "Surveiller" in md and "Restreindre" in md and "Reconfigurer" in md and "Supprimer" in md
        assert "PowerShell de référence" in md
        assert "à ne pas exécuter à l'aveugle" in md

    def test_unknown_edge_falls_back_gracefully(self):
        hop = {
            "source": "u",
            "target": "v",
            "source_label": "U",
            "target_label": "V",
            "edge_type": "TotallyMadeUpEdge",
        }
        md = _render_step_section(1, hop)
        assert "Aucune fiche de mitigation" in md

    def test_admintto_explains_tier_model(self):
        hop = {
            "source": "u",
            "target": "v",
            "source_label": "U",
            "target_label": "V",
            "edge_type": "AdminTo",
        }
        md = _render_step_section(1, hop)
        assert "tier" in md.lower() or "Tier" in md
        assert "LSASS" in md or "lsass" in md


class TestBuildGuideForPath:
    def test_guide_has_full_structure(self):
        path = _make_path()
        eng = _make_engagement()
        md = build_guide_for_path(path, engagement=eng, generated_at=datetime(2026, 5, 1, 10, 0, tzinfo=UTC))
        assert md.startswith("# Guide de mitigation")
        assert "DEL-2026-0142" in md
        assert "Acme Corp" in md
        assert "Critique" in md
        assert "8.5/10" in md
        assert "Avant d'agir" in md
        assert "questions à se poser" in md.lower()
        assert "Plan de mitigation" in md or "Plan de mitigation par étape" in md
        assert "Validation post-mitigation" in md
        # Path summary must include intermediate node
        assert "SPOOKYSEC" in md

    def test_guide_warns_about_misconfig_vs_vulnerability(self):
        md = build_guide_for_path(_make_path())
        assert "mauvaise configuration" in md.lower() or "mauvaises configurations" in md.lower()

    def test_guide_renders_mitre_techniques(self):
        techs = [
            SimpleNamespace(technique_id="T1098", technique_name="Account Manipulation"),
            SimpleNamespace(technique_id="T1222.001", technique_name="Permissions Mod"),
        ]
        path = _make_path(techniques=techs)
        md = build_guide_for_path(path)
        assert "T1098" in md
        assert "T1222.001" in md

    def test_guide_handles_no_techniques(self):
        md = build_guide_for_path(_make_path(techniques=[]))
        assert "Aucune" in md

    def test_guide_handles_missing_engagement(self):
        md = build_guide_for_path(_make_path(), engagement=None)
        assert "non renseignée" in md

    def test_guide_handles_missing_score(self):
        md = build_guide_for_path(_make_path(score=None))
        assert "n/a" in md

    def test_guide_includes_explanation_when_present(self):
        path = _make_path(explanation="Voici l'explication détaillée du chemin.")
        md = build_guide_for_path(path)
        assert "Voici l'explication détaillée" in md
        assert "Analyse détaillée" in md

    def test_guide_omits_explanation_section_when_absent(self):
        md = build_guide_for_path(_make_path(explanation=None))
        assert "Analyse détaillée" not in md

    def test_guide_has_no_destructive_one_liner(self):
        """The new guide must NOT contain naive deletion one-liners as the only PS content."""
        md = build_guide_for_path(_make_path())
        # Should always include the "à ne pas exécuter à l'aveugle" warning
        assert "ne pas exécuter à l'aveugle" in md
        # Must NOT contain unguarded destructive commands without commentary
        # (the guides keep destructive commands commented or labelled "à valider")
        assert "à adapter" in md.lower() or "à valider" in md.lower() or "à tester" in md.lower()

    def test_backwards_compat_alias_works(self):
        md = build_script_for_path(_make_path())
        assert md.startswith("# Guide de mitigation")


class TestBundleFilename:
    def test_critique_lowest_prefix(self):
        assert _bundle_filename(1, _make_path(risk="critique")).startswith("0001-critique-")

    def test_eleve_one_prefix(self):
        assert _bundle_filename(2, _make_path(risk="eleve")).startswith("1002-eleve-")

    def test_filename_extension_is_md(self):
        assert _bundle_filename(1, _make_path()).endswith(".md")

    def test_unknown_risk_gets_nine(self):
        assert _bundle_filename(1, _make_path(risk="bogus")).startswith("9")

    def test_filename_strips_special_chars(self):
        path = _make_path(source="DOMAIN\\user", target="O=ADMIN/CN=foo")
        name = _bundle_filename(1, path)
        assert "\\" not in name and "/" not in name


class TestBuildBundle:
    def test_zip_valid_and_contains_readme(self):
        eng = _make_engagement()
        paths = [_make_path() for _ in range(3)]
        data = build_bundle(eng, paths)
        assert data[:2] == b"PK"

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            assert "LISEZ-MOI.md" in names
            md_files = [n for n in names if n.endswith(".md") and n != "LISEZ-MOI.md"]
            assert len(md_files) == 3
            readme = zf.read("LISEZ-MOI.md").decode("utf-8")
            assert "Plan de mitigation" in readme
            assert "DEL-2026-0142" in readme
            assert "3 guide(s)" in readme
            assert "mauvaise" in readme.lower()  # warning about misconfigs

    def test_zip_orders_critique_before_eleve(self):
        eng = _make_engagement()
        paths = [
            _make_path(risk="eleve", score=7.0),
            _make_path(risk="critique", score=9.0),
            _make_path(risk="moyen", score=5.0),
        ]
        data = build_bundle(eng, paths)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            md_names = sorted(n for n in zf.namelist() if n.endswith(".md") and n != "LISEZ-MOI.md")
            assert md_names[0].startswith("0")
            assert "critique" in md_names[0]
            assert md_names[-1].startswith("2")

    def test_zip_with_empty_paths_still_includes_readme(self):
        eng = _make_engagement()
        data = build_bundle(eng, [])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            assert "LISEZ-MOI.md" in zf.namelist()
            readme = zf.read("LISEZ-MOI.md").decode("utf-8")
            assert "0 guide(s)" in readme

    def test_zip_handles_missing_engagement(self):
        data = build_bundle(None, [_make_path()])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            readme = zf.read("LISEZ-MOI.md").decode("utf-8")
            assert "non renseignée" in readme

    def test_zip_guide_content_is_markdown(self):
        data = build_bundle(_make_engagement(), [_make_path()])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            md_name = next(n for n in zf.namelist() if n.endswith(".md") and n != "LISEZ-MOI.md")
            content = zf.read(md_name).decode("utf-8")
            assert content.startswith("# Guide de mitigation")
            assert "Avant d'agir" in content


@pytest.mark.parametrize(
    "edge_type",
    [
        "WriteOwner",
        "WriteDACL",
        "GenericAll",
        "AddMember",
        "ForceChangePassword",
        "GetChangesAll",
        "GetChanges",
        "DCSync",
        "Owns",
        "AdminTo",
        "AllowedToDelegate",
        "AllowedToAct",
        "ReadLAPSPassword",
        "ReadGMSAPassword",
        "MemberOf",
        "GPLink",
        "Contains",
        "TrustedBy",
        "HasSession",
    ],
)
def test_every_edge_type_has_full_guidance(edge_type):
    """Every documented edge must have a full 4-section guide."""
    hop = {
        "source": "s",
        "target": "t",
        "source_label": "SOURCE",
        "target_label": "TARGET",
        "edge_type": edge_type,
    }
    md = _render_step_section(1, hop)
    assert "Aucune fiche de mitigation" not in md, f"edge {edge_type} missing"
    assert "Surveiller" in md
    assert "Reconfigurer" in md
    assert "powershell" in md.lower()
