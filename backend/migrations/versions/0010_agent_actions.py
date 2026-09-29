"""Actions queued for the agents (firewall block / unblock), fetched by polling.

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_actions",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("block_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("detail", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("kind IN ('block', 'unblock')", name=op.f("ck_agent_actions_kind")),
        sa.CheckConstraint(
            "status IN ('pending', 'done', 'failed')", name=op.f("ck_agent_actions_status")
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_agent_actions_agent_id_agents")
        ),
        sa.ForeignKeyConstraint(
            ["block_id"], ["blocked_ips.id"], name=op.f("fk_agent_actions_block_id_blocked_ips")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_actions")),
        # One block and one unblock per agent and block: enqueueing twice changes nothing.
        sa.UniqueConstraint(
            "block_id", "agent_id", "kind", name=op.f("uq_agent_actions_block_id_agent_id_kind")
        ),
    )
    op.create_index("ix_agent_actions_agent_id_status", "agent_actions", ["agent_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_agent_actions_agent_id_status", table_name="agent_actions")
    op.drop_table("agent_actions")
