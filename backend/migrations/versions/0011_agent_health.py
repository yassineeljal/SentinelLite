"""Agent liveness: when each agent last reported, and since when it has been silent.

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("silent_since", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("agents", "silent_since")
    op.drop_column("agents", "last_seen_at")
