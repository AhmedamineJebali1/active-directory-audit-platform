"""Engagement request/response schemas."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EngagementCreate(BaseModel):
    client_name: str = Field(min_length=2, max_length=255)
    code: str = Field(min_length=3, max_length=50)

    @field_validator("code")
    @classmethod
    def normalize_code(cls, v: str) -> str:
        # Normalize to uppercase, replace spaces/underscores with hyphens, strip extras.
        normalized = v.strip().upper().replace(" ", "-").replace("_", "-")
        import re
        normalized = re.sub(r"[^A-Z0-9\-]", "", normalized)
        normalized = re.sub(r"-{2,}", "-", normalized).strip("-")
        if len(normalized) < 2:
            raise ValueError("Le code mission doit contenir au moins 2 caractères alphanumériques")
        return normalized
    description: str | None = None


class EngagementUpdate(BaseModel):
    client_name: str | None = Field(None, min_length=2, max_length=255)
    description: str | None = None
    status: Literal["draft", "in_progress", "completed", "archived"] | None = None


class EngagementNotesUpdate(BaseModel):
    notes: str


class EngagementResponse(BaseModel):
    id: uuid.UUID
    client_name: str
    code: str
    description: str | None
    notes: str | None
    notes_updated_at: datetime | None
    status: str
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    # Per-engagement role injected by require_engagement_access() — may be None
    # when the response is built without going through the access dependency
    # (e.g. list endpoint that does its own visibility filtering).
    user_role: str | None = None

    model_config = {"from_attributes": True}


class EngagementListResponse(BaseModel):
    items: list[EngagementResponse]
    total: int
    limit: int
    offset: int
