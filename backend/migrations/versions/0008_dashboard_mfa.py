"""Dashboard TOTP, recovery codes and persistent authentication attempt limits.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("totp_last_counter", sa.BigInteger(), nullable=True))
    op.add_column("users", sa.Column("totp_pending_secret", sa.Text(), nullable=True))
    op.add_column(
        "users", sa.Column("totp_pending_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("users", sa.Column("totp_pending_session_hash", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("recovery_code_hashes", postgresql.JSONB(), nullable=True))
    op.create_table(
        "auth_rate_limits",
        sa.Column("scope_hash", sa.String(64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("scope_hash", name=op.f("pk_auth_rate_limits")),
    )
    op.create_index("ix_auth_rate_limits_expires_at", "auth_rate_limits", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_auth_rate_limits_expires_at", table_name="auth_rate_limits")
    op.drop_table("auth_rate_limits")
    for column in (
        "recovery_code_hashes",
        "totp_pending_session_hash",
        "totp_pending_expires_at",
        "totp_pending_secret",
        "totp_last_counter",
        "totp_secret",
    ):
        op.drop_column("users", column)
