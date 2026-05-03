"""Unit tests for the PDF report generation module."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.exceptions import ReportGenerationError

_EXEC_SUMMARY = {
    "verdict_global": "Élevé",
    "resume_executif": "Synthèse exécutive de test.",
    "principaux_risques": ["Escalade de privilèges via MemberOf → Domain Admins"],
    "recommandations_prioritaires": [
        {"priorite": "1", "action": "Restreindre les délégations AdminTo", "urgence": "Immédiate"},
        {"priorite": "2", "action": "Auditer les sessions actives", "urgence": "Court terme"},
    ],
    "feuille_de_route": "Remédier sous 30 jours.",
}


def _make_path(risk: str = "critique", score: float = 9.0) -> SimpleNamespace:
    tech = SimpleNamespace(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Privilege Escalation",
        url="https://attack.mitre.org/techniques/T1078/",
    )
    return SimpleNamespace(
        id=uuid.uuid4(),
        source_node="alice@corp.local",
        target_node="DOMAIN ADMINS@CORP.LOCAL",
        hops=[
            {
                "source": "alice@corp.local",
                "source_label": "alice",
                "source_type": "User",
                "target": "DOMAIN ADMINS@CORP.LOCAL",
                "target_label": "Domain Admins",
                "target_type": "Group",
                "edge_type": "MemberOf",
            }
        ],
        length=1,
        exploitability_score=score,
        stealth_score=7.0,
        global_score=score,
        risk_level=risk,
        explanation_fr="Cette voie permet à un utilisateur standard d'accéder aux admins de domaine.",
        recommendation_fr="Restreindre les droits d'administration délégués.",
        mitre_techniques=[tech],
    )


def _make_engagement() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        client_name="Acme Corp",
        code="DEL-2026-0001",
        description="Test engagement",
    )


def _make_analysis() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        source_filename="sample_graph.json",
        total_nodes=60,
        total_edges=120,
        total_paths=5,
        llm_provider="mock",
        llm_model="mock-model",
    )


class TestGeneratePdfHappyPath:
    @pytest.mark.asyncio
    async def test_returns_bytes_starting_with_pdf_magic(self):
        paths = [_make_path("critique"), _make_path("eleve", 7.0), _make_path("moyen", 5.0)]

        with patch("app.modules.agent.generate_executive_summary", new_callable=AsyncMock) as m:
            m.return_value = _EXEC_SUMMARY
            from app.modules.report import generate_pdf
            pdf_bytes = await generate_pdf(_make_analysis(), _make_engagement(), paths)

        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes[:4] == b"%PDF", "Output does not start with %PDF magic bytes"

    @pytest.mark.asyncio
    async def test_pdf_exceeds_size_threshold(self):
        paths = [_make_path("critique")] * 5

        with patch("app.modules.agent.generate_executive_summary", new_callable=AsyncMock) as m:
            m.return_value = _EXEC_SUMMARY
            from app.modules.report import generate_pdf
            pdf_bytes = await generate_pdf(_make_analysis(), _make_engagement(), paths)

        assert len(pdf_bytes) > 10_000, f"PDF suspiciously small: {len(pdf_bytes)} bytes"

    @pytest.mark.asyncio
    async def test_empty_paths_still_generates(self):
        with patch("app.modules.agent.generate_executive_summary", new_callable=AsyncMock) as m:
            m.return_value = _EXEC_SUMMARY
            from app.modules.report import generate_pdf
            pdf_bytes = await generate_pdf(_make_analysis(), _make_engagement(), [])

        assert pdf_bytes[:4] == b"%PDF"

    @pytest.mark.asyncio
    async def test_all_risk_levels_represented(self):
        paths = [
            _make_path("critique"),
            _make_path("eleve", 7.0),
            _make_path("moyen", 5.0),
            _make_path("faible", 2.0),
        ]

        with patch("app.modules.agent.generate_executive_summary", new_callable=AsyncMock) as m:
            m.return_value = _EXEC_SUMMARY
            from app.modules.report import generate_pdf
            pdf_bytes = await generate_pdf(_make_analysis(), _make_engagement(), paths)

        assert pdf_bytes[:4] == b"%PDF"


class TestGeneratePdfErrors:
    @pytest.mark.asyncio
    async def test_raises_report_error_on_weasyprint_failure(self):
        with patch("app.modules.agent.generate_executive_summary", new_callable=AsyncMock) as m:
            m.return_value = _EXEC_SUMMARY
            with patch("weasyprint.HTML") as mock_html:
                mock_html.side_effect = RuntimeError("WeasyPrint crashed")
                from app.modules.report import generate_pdf
                with pytest.raises(ReportGenerationError):
                    await generate_pdf(_make_analysis(), _make_engagement(), [_make_path()])

    @pytest.mark.asyncio
    async def test_raises_report_error_on_template_not_found(self):
        from jinja2 import TemplateNotFound

        with patch("app.modules.agent.generate_executive_summary", new_callable=AsyncMock) as m:
            m.return_value = _EXEC_SUMMARY
            with patch("jinja2.Environment.get_template", side_effect=TemplateNotFound("report_pdf.html")):
                from app.modules.report import generate_pdf
                with pytest.raises(ReportGenerationError):
                    await generate_pdf(_make_analysis(), _make_engagement(), [_make_path()])
