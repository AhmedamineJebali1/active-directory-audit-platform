"""Auth request/response schemas."""

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator


# Permissive email type — accepts internal domains (.local, .corp, .internal, etc.)
# EmailStr from email-validator rejects these special-use TLDs, which breaks
# enterprise deployments where AD accounts use internal domain suffixes.
def _validate_email(v: str) -> str:
    v = v.strip().lower()
    pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
    if not re.match(pattern, v):
        raise ValueError("Adresse e-mail invalide")
    return v


InternalEmail = Annotated[str, Field(min_length=3, max_length=254)]


class LoginRequest(BaseModel):
    email: InternalEmail
    password: str = Field(min_length=8)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email(v)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: Literal["admin", "manager", "auditor"]
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class RegisterRequest(BaseModel):
    email: InternalEmail
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=2, max_length=255)
    role: Literal["admin", "manager", "auditor"] = "auditor"

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email(v)


class RefreshRequest(BaseModel):
    refresh_token: str
