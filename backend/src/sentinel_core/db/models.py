from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
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


class User(Base):
    """A dashboard user. Only the Argon2 hash of the password is stored; there is no
    self-registration, so this is always created through `sentinel users create` (see the CLI)."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin', 'analyst')", name="role"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    # TOTP needs a recoverable secret: Fernet ciphertext, with the key outside Postgres.
    totp_secret: Mapped[str | None] = mapped_column(Text, default=None)
    totp_last_counter: Mapped[int | None] = mapped_column(BigInteger, default=None)
    totp_pending_secret: Mapped[str | None] = mapped_column(Text, default=None)
    totp_pending_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    totp_pending_session_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    recovery_code_hashes: Mapped[list[str] | None] = mapped_column(JSONB, default=None)


class AuthRateLimit(Base):
    """Persistent fixed-window counters; identifiers are hashed, expired rows are pruned."""

    __tablename__ = "auth_rate_limits"
    __table_args__ = (Index("ix_auth_rate_limits_expires_at", "expires_at"),)

    scope_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserSession(Base):
    """A logged-in session. The primary key is the SHA-256 hash of the session token: only the
    hash is stored, like an agent's key (auth/agent_keys.py). Deleted, not just marked, on logout
    and once expired, so the table never grows with dead sessions."""

    __tablename__ = "user_sessions"
    __table_args__ = (Index("ix_user_sessions_user_id", "user_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
        Index("ix_alerts_incident_id", "incident_id"),
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
    # Triage: which incident (if any) an analyst has grouped this alert into. NULL until then.
    incident_id: Mapped[UUID | None] = mapped_column(Uuid, ForeignKey("incidents.id"), default=None)


class Incident(Base):
    """A triage case grouping related alerts. No `severity` column on purpose: it is derived from
    the linked alerts' own risk scores at query time (db/incidents.py), so it can never go stale."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("status IN ('new', 'investigating', 'closed')", name="status"),
        Index("ix_incidents_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default="new")
    assignee_id: Mapped[UUID | None] = mapped_column(Uuid, ForeignKey("users.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class IncidentNote(Base):
    """A free-text note an analyst added to an incident. Immutable once written (no edit/delete
    endpoint): an incident's timeline should read the same to everyone who looks at it later."""

    __tablename__ = "incident_notes"
    __table_args__ = (Index("ix_incident_notes_incident_id", "incident_id"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    incident_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("incidents.id"))
    author_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
