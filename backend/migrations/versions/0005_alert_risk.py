"""alert risk score

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("risk_score", sa.SmallInteger(), nullable=True))
    op.add_column(
        "alerts", sa.Column("risk", postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )
    op.create_index("ix_alerts_risk_score", "alerts", ["risk_score"])


def downgrade() -> None:
    op.drop_index("ix_alerts_risk_score", table_name="alerts")
    op.drop_column("alerts", "risk")
    op.drop_column("alerts", "risk_score")
