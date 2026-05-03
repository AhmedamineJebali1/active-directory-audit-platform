"""Analysis, AttackPath, and PathMitreTechnique models."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

# JSONB on Postgres, JSON on SQLite (used in tests). Same Python interface.
JsonType = JSONB().with_variant(JSON(), "sqlite")


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id"), nullable=False
    )
    source_type: Mapped[str] = mapped_column(
        Enum("bloodhound_json", "ldap_live", name="source_type"),
        nullable=False,
        default="bloodhound_json",
    )
    source_filename: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(
        Enum(
            "pending",
            "ingesting",
            "extracting_paths",
            "analyzing",
            "completed",
            "failed",
            name="analysis_status",
        ),
        nullable=False,
        default="pending",
    )
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_nodes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_edges: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_paths: Mapped[int | None] = mapped_column(Integer, nullable=True)
    llm_provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="analyses")
    attack_paths: Mapped[list["AttackPath"]] = relationship(back_populates="analysis")

    def __repr__(self) -> str:
        return f"<Analysis {self.id} status={self.status}>"


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analyses.id"), nullable=False
    )
    source_node: Mapped[str] = mapped_column(String(500), nullable=False)
    target_node: Mapped[str] = mapped_column(String(500), nullable=False)
    hops: Mapped[list] = mapped_column(JsonType, nullable=False, default=list)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    exploitability_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    stealth_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    global_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(
        Enum("faible", "moyen", "eleve", "critique", name="risk_level"),
        nullable=True,
    )
    explanation_fr: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation_fr: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_raw_response: Mapped[dict | None] = mapped_column(JsonType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    analysis: Mapped["Analysis"] = relationship(back_populates="attack_paths")
    mitre_techniques: Mapped[list["PathMitreTechnique"]] = relationship(
        back_populates="attack_path"
    )

    def __repr__(self) -> str:
        return f"<AttackPath {self.source_node} → {self.target_node} len={self.length}>"


class PathMitreTechnique(Base):
    __tablename__ = "path_mitre_techniques"

    path_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attack_paths.id"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)

    attack_path: Mapped["AttackPath"] = relationship(back_populates="mitre_techniques")
