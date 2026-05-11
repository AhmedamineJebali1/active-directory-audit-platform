"""Add bloodhound_zip value to source_type enum

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-05 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PostgreSQL requires ALTER TYPE to add enum values
    op.execute("ALTER TYPE source_type ADD VALUE IF NOT EXISTS 'bloodhound_zip'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values without recreating the type.
    # Safe to leave as a no-op — the value simply won't be used after rollback.
    pass
