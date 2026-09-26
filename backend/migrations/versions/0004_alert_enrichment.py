"""alert enrichment

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "alerts", sa.Column("enrichment", postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )
    op.add_column("alerts", sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("alerts", "enriched_at")
    op.drop_column("alerts", "enrichment")
