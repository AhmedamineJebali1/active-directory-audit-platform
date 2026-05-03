"""Path analysis Pydantic schema (LLM response validation)."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class PathAnalysisSchema(BaseModel):
    """Expected JSON structure returned by the LLM for each attack path."""

    exploitability_score: int = Field(ge=0, le=10)
    stealth_score: int = Field(ge=0, le=10)
    global_score: int = Field(ge=0, le=10)
    risk_level: Literal["Faible", "Moyen", "Élevé", "Critique"]
    explanation: str = Field(min_length=50)
    recommendation: str = Field(min_length=30)

    @field_validator("risk_level", mode="before")
    @classmethod
    def normalize_risk_level(cls, v: str) -> str:
        mapping = {
            "faible": "Faible",
            "moyen": "Moyen",
            "élevé": "Élevé",
            "eleve": "Élevé",
            "élevé": "Élevé",
            "critique": "Critique",
        }
        return mapping.get(v.lower(), v)


class ExecutiveSummarySchema(BaseModel):
    """Expected JSON structure for the executive summary LLM call."""

    verdict_global: Literal["Faible", "Moyen", "Élevé", "Critique"]
    resume_executif: str = Field(min_length=100)
    principaux_risques: list[str] = Field(min_length=1, max_length=10)
    recommandations_prioritaires: list[dict]
    feuille_de_route: str = Field(min_length=50)
