"""Automated response: blocked addresses, allowlist and an append-only audit log.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("alert_id", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_by", sa.String(128), nullable=True),
        sa.CheckConstraint("mode IN ('dry_run', 'enforce')", name=op.f("ck_blocked_ips_mode")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_blocked_ips")),
        sa.UniqueConstraint("alert_id", name=op.f("uq_blocked_ips_alert_id")),
    )
    op.create_index("ix_blocked_ips_ip_expires_at", "blocked_ips", ["ip", "expires_at"])
    op.create_index("ix_blocked_ips_created_at", "blocked_ips", ["created_at"])

    op.create_table(
        "allowlist",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("cidr", postgresql.CIDR(), nullable=False),
        sa.Column("note", sa.Text(), server_default="", nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_allowlist")),
        sa.UniqueConstraint("cidr", name=op.f("uq_allowlist_cidr")),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(128), nullable=False),
        sa.Column(
            "details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    # Append-only: the application role cannot rewrite the trail of automatic actions. (TRUNCATE
    # and DROP are not row operations; whoever owns the database can still do those.)
    op.execute(
        """
        CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        "CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_append_only()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER audit_log_append_only ON audit_log")
    op.execute("DROP FUNCTION audit_log_append_only()")
    op.drop_index("ix_audit_log_ts", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("allowlist")
    op.drop_index("ix_blocked_ips_created_at", table_name="blocked_ips")
    op.drop_index("ix_blocked_ips_ip_expires_at", table_name="blocked_ips")
    op.drop_table("blocked_ips")
