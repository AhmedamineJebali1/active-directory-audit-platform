"""Initial schema — all tables

Revision ID: 0001
Revises:
Create Date: 2026-04-27 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enum types safely — idempotent even if a previous run partially applied them.
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE user_role AS ENUM ('admin', 'manager', 'auditor');
        EXCEPTION WHEN duplicate_object THEN null; END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE engagement_status AS ENUM ('draft', 'in_progress', 'completed', 'archived');
        EXCEPTION WHEN duplicate_object THEN null; END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE source_type AS ENUM ('bloodhound_json', 'ldap_live');
        EXCEPTION WHEN duplicate_object THEN null; END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE analysis_status AS ENUM ('pending', 'ingesting', 'extracting_paths', 'analyzing', 'completed', 'failed');
        EXCEPTION WHEN duplicate_object THEN null; END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE risk_level AS ENUM ('faible', 'moyen', 'eleve', 'critique');
        EXCEPTION WHEN duplicate_object THEN null; END $$;
    """)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role", sa.Enum("admin", "manager", "auditor", name="user_role", create_type=False), nullable=False, server_default="auditor"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "engagements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("client_name", sa.String(255), nullable=False),
        sa.Column("code", sa.String(50), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.Enum("draft", "in_progress", "completed", "archived", name="engagement_status", create_type=False), nullable=False, server_default="draft"),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_engagements_code", "engagements", ["code"])

    op.create_table(
        "analyses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("source_type", sa.Enum("bloodhound_json", "ldap_live", name="source_type", create_type=False), nullable=False, server_default="bloodhound_json"),
        sa.Column("source_filename", sa.String(500), nullable=True),
        sa.Column("status", sa.Enum("pending", "ingesting", "extracting_paths", "analyzing", "completed", "failed", name="analysis_status", create_type=False), nullable=False, server_default="pending"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_nodes", sa.Integer(), nullable=True),
        sa.Column("total_edges", sa.Integer(), nullable=True),
        sa.Column("total_paths", sa.Integer(), nullable=True),
        sa.Column("llm_provider", sa.String(50), nullable=True),
        sa.Column("llm_model", sa.String(100), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )

    op.create_table(
        "attack_paths",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("analysis_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("source_node", sa.String(500), nullable=False),
        sa.Column("target_node", sa.String(500), nullable=False),
        sa.Column("hops", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("exploitability_score", sa.Float(), nullable=True),
        sa.Column("stealth_score", sa.Float(), nullable=True),
        sa.Column("global_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.Enum("faible", "moyen", "eleve", "critique", name="risk_level", create_type=False), nullable=True),
        sa.Column("explanation_fr", sa.Text(), nullable=True),
        sa.Column("recommendation_fr", sa.Text(), nullable=True),
        sa.Column("llm_raw_response", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "path_mitre_techniques",
        sa.Column("path_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("attack_paths.id"), primary_key=True),
        sa.Column("technique_id", sa.String(20), primary_key=True),
        sa.Column("technique_name", sa.String(255), nullable=False),
        sa.Column("tactic", sa.String(100), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(100), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("path_mitre_techniques")
    op.drop_table("attack_paths")
    op.drop_table("analyses")
    op.drop_table("engagements")
    op.drop_table("users")
    op.execute("DROP TYPE IF EXISTS risk_level")
    op.execute("DROP TYPE IF EXISTS analysis_status")
    op.execute("DROP TYPE IF EXISTS source_type")
    op.execute("DROP TYPE IF EXISTS engagement_status")
    op.execute("DROP TYPE IF EXISTS user_role")
