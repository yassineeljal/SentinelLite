"""Persistence and queries for alerts."""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.db.models import AlertRecord
from sentinel_core.detection.alerts import Alert
from sentinel_core.enrichment.enricher import Enrichment
from sentinel_core.enrichment.risk import RiskAssessment


class AmbiguousAlertId(Exception):
    """An id prefix matches several alerts."""


@dataclass(frozen=True)
class AlertSummary:
    alert_id: str
    rule_id: str
    title: str
    severity: int
    ts: datetime
    created_at: datetime
    src_ip: str | None
    host: str | None
    user_name: str | None
    match_count: int
    country_code: str | None  # from the enrichment, when there is one
    abuse_score: int | None  # AbuseIPDB confidence 0-100, when a reputation was fetched
    risk_score: int | None  # 0-100, once the enricher has run


@dataclass(frozen=True)
class EvidenceEvent:
    ts: datetime
    received_at: datetime
    action: str
    user_name: str | None
    src_ip: str | None
    raw: str


@dataclass(frozen=True)
class AlertDetail:
    summary: AlertSummary
    mitre: list[str]
    group: dict[str, Any]
    evidence: list[EvidenceEvent]  # oldest first
    # Time between the server receiving the triggering line and the alert being stored.
    detection_latency: timedelta | None
    enrichment: dict[str, Any] | None  # as stored; None until the enricher has run
    risk: dict[str, Any] | None  # RiskAssessment as stored: score, level, factors


async def insert_alerts(session: AsyncSession, alerts: list[Alert]) -> None:
    """Insert alerts; an alert that already exists (same deterministic id) is skipped."""
    if not alerts:
        return
    statement = pg_insert(AlertRecord).on_conflict_do_nothing(index_elements=["alert_id"])
    await session.execute(
        statement,
        [
            {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "title": alert.title,
                "mitre": alert.mitre,
                "severity": alert.severity,
                "ts": alert.ts,
                "group_values": alert.group,
                "src_ip": alert.src_ip,
                "host": alert.host,
                "user_name": alert.user_name,
                "event_ids": alert.event_ids,
                "match_count": alert.match_count,
            }
            for alert in alerts
        ],
    )


async def set_enrichment(
    session: AsyncSession, alert_id: str, enrichment: Enrichment | None, risk: RiskAssessment
) -> bool:
    """Attach (or replace) the enrichment and the risk of a stored alert.

    `enrichment` is None for an alert without a source address: it still gets its risk (from the
    severity alone). False if the alert does not exist."""
    result = await session.execute(
        text(
            "UPDATE alerts SET enrichment = CAST(:enrichment AS jsonb), enriched_at = now(), "
            "risk_score = :risk_score, risk = CAST(:risk AS jsonb) WHERE alert_id = :alert_id"
        ),
        {
            "alert_id": alert_id,
            "enrichment": json.dumps(enrichment.model_dump(mode="json")) if enrichment else None,
            "risk_score": risk.score,
            "risk": json.dumps(risk.model_dump(mode="json")),
        },
    )
    return bool(getattr(result, "rowcount", 0))


_SUMMARY_COLUMNS = (
    "alert_id, rule_id, title, severity, ts, created_at, host(src_ip) AS src_ip, host, user_name,"
    " match_count, enrichment->'geo'->>'country_code' AS country_code,"
    " CAST(enrichment->'reputation'->>'score' AS integer) AS abuse_score, risk_score"
)


def _summary(row: Any) -> AlertSummary:
    return AlertSummary(
        alert_id=row.alert_id,
        rule_id=row.rule_id,
        title=row.title,
        severity=row.severity,
        ts=row.ts,
        created_at=row.created_at,
        src_ip=row.src_ip,
        host=row.host,
        user_name=row.user_name,
        match_count=row.match_count,
        country_code=row.country_code,
        abuse_score=row.abuse_score,
        risk_score=row.risk_score,
    )


@dataclass(frozen=True)
class MitreSummaryRow:
    technique: str  # e.g. "T1110" or "T1110.003"
    count: (
        int  # alerts carrying this technique, within the window (one alert may count for several)
    )
    latest_ts: datetime


async def mitre_summary(session: AsyncSession, *, days: int = 30) -> list[MitreSummaryRow]:
    """Alert counts per MITRE technique in the last `days` days, most frequent first.

    An alert with several techniques (e.g. a rule mapped to both T1110 and T1078) counts once
    towards each: this is a coverage view ("what techniques are firing"), not a partition of
    alerts, so double-counting an alert across its own techniques is the point, not a bug.
    """
    if days <= 0:
        raise ValueError("days must be positive")
    result = await session.execute(
        text(
            # "n" not "count": a Row already has a .count() method, which would shadow the column.
            "SELECT technique, count(*) AS n, max(ts) AS latest_ts FROM "
            "(SELECT unnest(mitre) AS technique, ts FROM alerts "
            "WHERE ts >= now() - make_interval(days => :days)) per_technique "
            "GROUP BY technique ORDER BY n DESC, technique"
        ),
        {"days": days},
    )
    return [
        MitreSummaryRow(technique=row.technique, count=row.n, latest_ts=row.latest_ts)
        for row in result
    ]


async def list_alerts(
    session: AsyncSession, *, limit: int = 20, rule_id: str | None = None
) -> list[AlertSummary]:
    result = await session.execute(
        text(
            f"SELECT {_SUMMARY_COLUMNS} FROM alerts "  # noqa: S608 - constant column list
            "WHERE (CAST(:rule_id AS text) IS NULL OR rule_id = :rule_id) "
            "ORDER BY ts DESC, alert_id LIMIT :limit"
        ),
        {"rule_id": rule_id, "limit": limit},
    )
    return [_summary(row) for row in result]


async def get_alert(session: AsyncSession, alert_id_prefix: str) -> AlertDetail | None:
    """Alert by id or unambiguous id prefix (hex only), with its evidence events."""
    matches = (
        await session.execute(
            text(
                f"SELECT {_SUMMARY_COLUMNS}, mitre, group_values, event_ids, enrichment, risk "  # noqa: S608
                "FROM alerts "
                "WHERE alert_id LIKE :prefix LIMIT 2"
            ),
            {"prefix": f"{alert_id_prefix}%"},
        )
    ).all()
    if not matches:
        return None
    if len(matches) > 1:
        raise AmbiguousAlertId(alert_id_prefix)
    row = matches[0]

    events = (
        await session.execute(
            text(
                "SELECT event_id, ts, received_at, action, user_name, host(src_ip) AS src_ip, raw "
                "FROM events WHERE event_id = ANY(:ids) ORDER BY ts, event_id"
            ),
            {"ids": list(row.event_ids)},
        )
    ).all()
    evidence = [
        EvidenceEvent(
            ts=e.ts,
            received_at=e.received_at,
            action=e.action,
            user_name=e.user_name,
            src_ip=e.src_ip,
            raw=e.raw,
        )
        for e in events
    ]
    # event_ids is newest first: the first one is the event that triggered the alert.
    trigger = next((e for e in events if e.event_id == row.event_ids[0]), None)
    latency = row.created_at - trigger.received_at if trigger else None
    return AlertDetail(
        summary=_summary(row),
        mitre=list(row.mitre),
        group=dict(row.group_values),
        evidence=evidence,
        detection_latency=latency,
        enrichment=dict(row.enrichment) if row.enrichment is not None else None,
        risk=dict(row.risk) if row.risk is not None else None,
    )
