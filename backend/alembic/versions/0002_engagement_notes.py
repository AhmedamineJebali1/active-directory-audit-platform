"""Add notes and notes_updated_at to engagements

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-29 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("engagements", sa.Column("notes", sa.Text(), nullable=True))
    op.add_column(
        "engagements",
        sa.Column("notes_updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("engagements", "notes_updated_at")
    op.drop_column("engagements", "notes")
