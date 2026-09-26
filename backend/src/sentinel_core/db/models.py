from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Identity,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Deterministic constraint names keep Alembic migrations and autogenerate reproducible.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Agent(Base):
    """A collection agent. Only the hash of its API key is stored."""

    __tablename__ = "agents"
    __table_args__ = (CheckConstraint("os IN ('linux', 'windows')", name="os"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    os: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class EventRecord(Base):
    """A normalized event. Range-partitioned by day on `ts` (see migration 0002).

    The primary key includes `ts` because PostgreSQL requires the partition key in every unique
    constraint. Idempotent inserts use ON CONFLICT (event_id, ts).
    """

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_ts", "ts"),
        Index("ix_events_src_ip_ts", "src_ip", "ts"),
        Index("ix_events_action_ts", "action", "ts"),
        {"postgresql_partition_by": "RANGE (ts)"},
    )

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    agent_id: Mapped[UUID] = mapped_column(Uuid)
    source: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str] = mapped_column(String(16))
    severity: Mapped[int] = mapped_column(SmallInteger)
    src_ip: Mapped[str | None] = mapped_column(INET, default=None)
    dst_ip: Mapped[str | None] = mapped_column(INET, default=None)
    dst_port: Mapped[int | None] = mapped_column(Integer, default=None)
    host: Mapped[str] = mapped_column(String(255))
    user_name: Mapped[str | None] = mapped_column(String(256), default=None)
    raw: Mapped[str] = mapped_column(Text)
    extra: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))


class DeadLetter(Base):
    """A stream entry that could not be normalized, kept with the reason (never dropped)."""

    __tablename__ = "events_dead_letter"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # sha256 of the stream payload: a redelivered entry must not create a second row.
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True)
    agent_id: Mapped[UUID | None] = mapped_column(Uuid, default=None)
    source: Mapped[str | None] = mapped_column(String(32), default=None)
    origin: Mapped[str | None] = mapped_column(String(128), default=None)
    raw: Mapped[str] = mapped_column(Text)
    error: Mapped[str] = mapped_column(String(500))
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertRecord(Base):
    """A detection. `alert_id` is deterministic, so persisting the same alert twice is a no-op."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_ts", "ts"),
        Index("ix_alerts_rule_id_ts", "rule_id", "ts"),
        Index("ix_alerts_src_ip_ts", "src_ip", "ts"),
        Index("ix_alerts_risk_score", "risk_score"),
    )

    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(200))
    mitre: Mapped[list[str]] = mapped_column(ARRAY(String(16)))
    severity: Mapped[int] = mapped_column(SmallInteger)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    group_values: Mapped[dict[str, Any]] = mapped_column(JSONB)
    src_ip: Mapped[str | None] = mapped_column(INET, default=None)
    host: Mapped[str | None] = mapped_column(String(255), default=None)
    user_name: Mapped[str | None] = mapped_column(String(256), default=None)
    # Evidence: event ids, newest first. No foreign key: `events` is partitioned by time.
    event_ids: Mapped[list[str]] = mapped_column(JSONB)
    match_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Added after the alert was stored, by the enricher (see enrichment/): NULL until then, and
    # for alerts without a source address.
    enrichment: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=None)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # Computed by the enricher from the severity and the enrichment (see enrichment/risk.py):
    # the score has its own column so that it can be indexed and sorted; NULL until then.
    risk_score: Mapped[int | None] = mapped_column(SmallInteger, default=None)
    risk: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=None)
