"""create events (partitioned by day) and events_dead_letter

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("src_ip", postgresql.INET(), nullable=True),
        sa.Column("dst_ip", postgresql.INET(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("user_name", sa.String(length=256), nullable=True),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column(
            "extra",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("event_id", "ts", name=op.f("pk_events")),
        postgresql_partition_by="RANGE (ts)",
    )
    # Catch-all: agents control the timestamps in their lines, so an odd date must land
    # somewhere instead of failing the insert. Daily partitions are created by the worker.
    op.execute("CREATE TABLE events_default PARTITION OF events DEFAULT")
    op.create_index("ix_events_ts", "events", ["ts"])
    op.create_index("ix_events_src_ip_ts", "events", ["src_ip", "ts"])
    op.create_index("ix_events_action_ts", "events", ["action", "ts"])

    op.create_table(
        "events_dead_letter",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=True),
        sa.Column("origin", sa.String(length=128), nullable=True),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_events_dead_letter")),
        sa.UniqueConstraint("dedup_key", name=op.f("uq_events_dead_letter_dedup_key")),
    )


def downgrade() -> None:
    op.drop_table("events_dead_letter")
    op.drop_table("events")  # also drops every partition
