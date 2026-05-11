"""Module 5 — PDF report generation via WeasyPrint + Jinja2."""

import logging
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.config import get_settings
from app.core.exceptions import ReportGenerationError

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"


async def generate_pdf(analysis, engagement, paths) -> bytes:
    """Render the Jinja2 HTML template and convert to PDF via WeasyPrint.

    Args:
        analysis: Analysis ORM object.
        engagement: Engagement ORM object.
        paths: List of AttackPath ORM objects.

    Returns:
        PDF bytes.

    Raises:
        ReportGenerationError: If generation fails.
    """
    from weasyprint import HTML

    try:
        settings = get_settings()
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )

        # Compute stats
        risk_counts: dict[str, int] = {}
        all_mitre: dict[str, dict] = {}
        for p in paths:
            rl = p.risk_level or "moyen"
            risk_counts[rl] = risk_counts.get(rl, 0) + 1
            for mt in p.mitre_techniques:
                all_mitre[mt.technique_id] = {
                    "id": mt.technique_id,
                    "name": mt.technique_name,
                    "tactic": mt.tactic,
                    "url": mt.url,
                }

        critical_paths = [p for p in paths if p.risk_level == "critique"]
        high_paths = [p for p in paths if p.risk_level == "eleve"]

        # Executive summary — skip the LLM call entirely if there are no paths.
        # (a) Saves a wasted prompt; (b) avoids template KeyErrors on empty data.
        if paths:
            from app.modules.agent import generate_executive_summary

            paths_dicts = [
                {
                    "source_node": p.source_node,
                    "target_node": p.target_node,
                    "risk_level": p.risk_level,
                    "global_score": p.global_score,
                    "explanation_fr": p.explanation_fr,
                    "mitre_techniques": [
                        {"id": mt.technique_id, "name": mt.technique_name, "tactic": mt.tactic}
                        for mt in p.mitre_techniques
                    ],
                }
                for p in paths
            ]
            exec_summary = await generate_executive_summary(
                paths=paths_dicts,
                client_name=engagement.client_name if engagement else "Client",
                engagement_code=engagement.code if engagement else "N/A",
                analysis_date=datetime.now(UTC).strftime("%d/%m/%Y"),
            )
        else:
            exec_summary = {
                "verdict_global": "Faible",
                "resume_executif": (
                    "Aucun chemin d'attaque exploitable n'a été détecté entre les "
                    "comptes non-privilégiés et les groupes à fort impact (Domain "
                    "Admins, Enterprise Admins, Administrators). Le périmètre "
                    "ingéré ne révèle pas d'escalade triviale."
                ),
                "principaux_risques": [
                    "Aucun risque majeur détecté sur le périmètre ingéré.",
                ],
                "recommandations_prioritaires": [
                    {
                        "priorite": 1,
                        "action": "Étendre la collecte aux contrôleurs de domaine et serveurs critiques pour confirmer le résultat.",
                        "urgence": "Standard",
                    },
                ],
                "feuille_de_route": (
                    "Maintenir les bonnes pratiques actuelles (Tier 0 isolé, "
                    "comptes admins distincts) et ré-auditer après tout changement "
                    "majeur d'infrastructure."
                ),
            }

        # Compliance mapping
        compliance_path = Path(__file__).parent.parent.parent / "data" / "compliance_mapping.json"
        import json

        compliance = {}
        if compliance_path.exists():
            compliance = json.loads(compliance_path.read_text(encoding="utf-8"))

        template = env.get_template("report_pdf.html")
        html_content = template.render(
            engagement=engagement,
            analysis=analysis,
            paths=paths,
            critical_paths=critical_paths,
            high_paths=high_paths,
            risk_counts=risk_counts,
            all_mitre=all_mitre,
            exec_summary=exec_summary,
            compliance=compliance,
            generated_at=datetime.now(UTC).strftime("%d/%m/%Y à %H:%M UTC"),
            brand_name=settings.report_brand_name,
            footer_text=settings.report_footer_text,
        )

        pdf_bytes = HTML(
            string=html_content,
            base_url=str(TEMPLATES_DIR),
        ).write_pdf()

        logger.info(
            "report_generated",
            extra={"analysis_id": str(analysis.id), "size_bytes": len(pdf_bytes)},
        )
        return pdf_bytes

    except Exception as exc:
        logger.exception("report_generation_failed", extra={"error": str(exc)})
        raise ReportGenerationError(f"Échec de la génération du PDF : {exc}") from exc
