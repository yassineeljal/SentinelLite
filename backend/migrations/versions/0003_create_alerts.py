"""create alerts

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("mitre", postgresql.ARRAY(sa.String(length=16)), nullable=False),
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("group_values", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("src_ip", postgresql.INET(), nullable=True),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("user_name", sa.String(length=256), nullable=True),
        sa.Column("event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("match_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("alert_id", name=op.f("pk_alerts")),
    )
    op.create_index("ix_alerts_ts", "alerts", ["ts"])
    op.create_index("ix_alerts_rule_id_ts", "alerts", ["rule_id", "ts"])
    op.create_index("ix_alerts_src_ip_ts", "alerts", ["src_ip", "ts"])


def downgrade() -> None:
    op.drop_table("alerts")
