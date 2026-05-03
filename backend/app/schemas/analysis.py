"""Analysis request/response schemas."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class AnalysisResponse(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    source_type: str
    source_filename: str | None
    status: str
    progress: int
    total_nodes: int | None
    total_edges: int | None
    total_paths: int | None
    llm_provider: str | None
    llm_model: str | None
    started_at: datetime
    completed_at: datetime | None
    error_message: str | None

    model_config = {"from_attributes": True}


class AnalysisListResponse(BaseModel):
    items: list[AnalysisResponse]
    total: int


class MitreTechniqueResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    url: str

    model_config = {"from_attributes": True}


class AttackPathResponse(BaseModel):
    id: uuid.UUID
    analysis_id: uuid.UUID
    source_node: str
    target_node: str
    hops: list
    length: int
    exploitability_score: float | None
    stealth_score: float | None
    global_score: float | None
    risk_level: str | None
    explanation_fr: str | None
    recommendation_fr: str | None
    mitre_techniques: list[MitreTechniqueResponse]
    created_at: datetime

    model_config = {"from_attributes": True}


class AttackPathListResponse(BaseModel):
    items: list[AttackPathResponse]
    total: int
    limit: int
    offset: int


class AnalysisStatsResponse(BaseModel):
    analysis_id: uuid.UUID
    total_paths: int
    by_risk_level: dict[str, int]
    avg_global_score: float
    top_techniques: list[dict]
    top_paths: list[AttackPathResponse]


class MitreCoverageResponse(BaseModel):
    analysis_id: uuid.UUID
    techniques: list[MitreTechniqueResponse]
    count_by_tactic: dict[str, int]
    top_techniques: list[dict]


class WebSocketEvent(BaseModel):
    stage: str
    progress: int
    message_fr: str
    error: str | None = None
