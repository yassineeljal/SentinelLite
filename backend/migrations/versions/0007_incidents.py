"""incidents

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("assignee_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('new', 'investigating', 'closed')", name=op.f("ck_incidents_status")
        ),
        sa.ForeignKeyConstraint(
            ["assignee_id"], ["users.id"], name=op.f("fk_incidents_assignee_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])

    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=False),
        sa.Column("body", sa.String(length=4000), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name=op.f("fk_incident_notes_incident_id_incidents")
        ),
        sa.ForeignKeyConstraint(
            ["author_id"], ["users.id"], name=op.f("fk_incident_notes_author_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_notes")),
    )
    op.create_index("ix_incident_notes_incident_id", "incident_notes", ["incident_id"])

    op.add_column("alerts", sa.Column("incident_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_alerts_incident_id_incidents"), "alerts", "incidents", ["incident_id"], ["id"]
    )

    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_alerts_incident_id", table_name="alerts")
    op.drop_constraint(op.f("fk_alerts_incident_id_incidents"), "alerts", type_="foreignkey")
    op.drop_column("alerts", "incident_id")
    op.drop_index("ix_incident_notes_incident_id", table_name="incident_notes")
    op.drop_table("incident_notes")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_table("incidents")
