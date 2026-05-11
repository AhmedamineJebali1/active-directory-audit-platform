"""Add engagement_members table for per-engagement access control.

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-11
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent: if the table already exists (e.g. created by an earlier
    # buggy create_all path), skip the CREATE and just run the backfill.
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = set(insp.get_table_names())

    if "engagement_members" not in existing_tables:
        op.create_table(
            "engagement_members",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "role_on_engagement",
                sa.Enum("lead", "contributor", "viewer", name="engagement_member_role"),
                nullable=False,
                server_default="contributor",
            ),
            sa.Column("added_by", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["added_by"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("engagement_id", "user_id", name="uq_engagement_member"),
        )
        op.create_index("ix_engagement_members_engagement_id", "engagement_members", ["engagement_id"])
        op.create_index("ix_engagement_members_user_id", "engagement_members", ["user_id"])

    # Backfill (always run): every existing engagement's creator is added as
    # lead so they don't lose access when membership filtering kicks in.
    op.execute("""
        INSERT INTO engagement_members (id, engagement_id, user_id, role_on_engagement, added_by, created_at)
        SELECT gen_random_uuid(), e.id, e.created_by, 'lead', e.created_by, CURRENT_TIMESTAMP
        FROM engagements e
        WHERE NOT EXISTS (
            SELECT 1 FROM engagement_members m
            WHERE m.engagement_id = e.id AND m.user_id = e.created_by
        )
    """)


def downgrade() -> None:
    op.drop_index("ix_engagement_members_user_id", table_name="engagement_members")
    op.drop_index("ix_engagement_members_engagement_id", table_name="engagement_members")
    op.drop_table("engagement_members")
    op.execute("DROP TYPE IF EXISTS engagement_member_role")
