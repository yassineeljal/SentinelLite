"""Incidents: the triage cases an analyst groups related alerts into.

An incident has no `severity` column: it is always the highest `risk_score` among its linked
alerts, computed here at query time, so it can never go stale as alerts are linked or unlinked.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.db.alerts import _SUMMARY_COLUMNS, AlertSummary, _summary

VALID_STATUSES = ("new", "investigating", "closed")


class AlertLinkError(Exception):
    """An alert is missing or already belongs to another incident."""


class IncidentNotFound(Exception):
    """No incident has this id."""


@dataclass(frozen=True)
class IncidentSummary:
    id: UUID
    title: str
    status: str
    assignee_email: str | None
    created_at: datetime
    closed_at: datetime | None
    alert_count: int
    max_risk_score: int | None


@dataclass(frozen=True)
class IncidentNoteRow:
    id: UUID
    author_email: str
    body: str
    created_at: datetime


@dataclass(frozen=True)
class IncidentDetail:
    summary: IncidentSummary
    alerts: list[AlertSummary]  # newest first
    notes: list[IncidentNoteRow]  # oldest first


_SUMMARY_QUERY = """
SELECT i.id, i.title, i.status, i.created_at, i.closed_at, u.email AS assignee_email,
       count(a.alert_id) AS alert_count, max(a.risk_score) AS max_risk_score
FROM incidents i
LEFT JOIN users u ON u.id = i.assignee_id
LEFT JOIN alerts a ON a.incident_id = i.id
"""


def _to_summary(row: Any) -> IncidentSummary:
    return IncidentSummary(
        id=row.id,
        title=row.title,
        status=row.status,
        assignee_email=row.assignee_email,
        created_at=row.created_at,
        closed_at=row.closed_at,
        alert_count=row.alert_count,
        max_risk_score=row.max_risk_score,
    )


def _check_status(status: str) -> None:
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}")


async def create_incident(
    session: AsyncSession, title: str, *, alert_ids: list[str] | None = None
) -> IncidentSummary:
    incident_id = uuid4()
    await session.execute(
        text("INSERT INTO incidents (id, title, status) VALUES (:id, :title, 'new')"),
        {"id": incident_id, "title": title},
    )
    if alert_ids:
        await _link_alerts(session, incident_id, alert_ids)
    await session.commit()
    result = await session.execute(
        text(f"{_SUMMARY_QUERY} WHERE i.id = :id GROUP BY i.id, u.email"),
        {"id": incident_id},
    )
    return _to_summary(result.one())


async def list_incidents(
    session: AsyncSession, *, status: str | None = None, limit: int = 50
) -> list[IncidentSummary]:
    result = await session.execute(
        text(
            f"{_SUMMARY_QUERY}"
            " WHERE (CAST(:status AS text) IS NULL OR i.status = :status)"
            " GROUP BY i.id, u.email ORDER BY i.created_at DESC LIMIT :limit"
        ),
        {"status": status, "limit": limit},
    )
    return [_to_summary(row) for row in result]


async def get_incident(session: AsyncSession, incident_id: UUID) -> IncidentDetail | None:
    result = await session.execute(
        text(f"{_SUMMARY_QUERY} WHERE i.id = :id GROUP BY i.id, u.email"),
        {"id": incident_id},
    )
    row = result.one_or_none()
    if row is None:
        return None

    alerts = await session.execute(
        text(
            f"SELECT {_SUMMARY_COLUMNS} FROM alerts "  # noqa: S608
            "WHERE incident_id = :id ORDER BY ts DESC"
        ),
        {"id": incident_id},
    )
    notes = await session.execute(
        text(
            "SELECT n.id, n.body, n.created_at, u.email AS author_email FROM incident_notes n "
            "JOIN users u ON u.id = n.author_id WHERE n.incident_id = :id ORDER BY n.created_at"
        ),
        {"id": incident_id},
    )
    return IncidentDetail(
        summary=_to_summary(row),
        alerts=[_summary(a) for a in alerts],
        notes=[
            IncidentNoteRow(
                id=n.id, author_email=n.author_email, body=n.body, created_at=n.created_at
            )
            for n in notes
        ],
    )


async def set_status(session: AsyncSession, incident_id: UUID, status: str) -> None:
    _check_status(status)
    closed_at_clause = "COALESCE(closed_at, now())" if status == "closed" else "NULL"
    result = await session.execute(
        text(
            f"UPDATE incidents SET status = :status, closed_at = {closed_at_clause} "  # noqa: S608
            "WHERE id = :id RETURNING id"
        ),
        {"status": status, "id": incident_id},
    )
    if result.one_or_none() is None:
        raise IncidentNotFound(incident_id)
    await session.commit()


async def close_incident(session: AsyncSession, incident_id: UUID) -> None:
    await set_status(session, incident_id, "closed")


async def reopen_incident(session: AsyncSession, incident_id: UUID) -> None:
    await set_status(session, incident_id, "new")


async def claim_incident(session: AsyncSession, incident_id: UUID, user_id: UUID) -> None:
    result = await session.execute(
        text("UPDATE incidents SET assignee_id = :user_id WHERE id = :id RETURNING id"),
        {"user_id": user_id, "id": incident_id},
    )
    if result.one_or_none() is None:
        raise IncidentNotFound(incident_id)
    await session.commit()


async def unassign_incident(session: AsyncSession, incident_id: UUID) -> None:
    result = await session.execute(
        text("UPDATE incidents SET assignee_id = NULL WHERE id = :id RETURNING id"),
        {"id": incident_id},
    )
    if result.one_or_none() is None:
        raise IncidentNotFound(incident_id)
    await session.commit()


async def add_note(session: AsyncSession, incident_id: UUID, author_id: UUID, body: str) -> None:
    exists = await session.execute(
        text("SELECT 1 FROM incidents WHERE id = :id"), {"id": incident_id}
    )
    if exists.one_or_none() is None:
        raise IncidentNotFound(incident_id)
    await session.execute(
        text(
            "INSERT INTO incident_notes (id, incident_id, author_id, body) "
            "VALUES (:id, :incident_id, :author_id, :body)"
        ),
        {"id": uuid4(), "incident_id": incident_id, "author_id": author_id, "body": body},
    )
    await session.commit()


async def _require_incident(session: AsyncSession, incident_id: UUID) -> None:
    exists = await session.execute(
        text("SELECT 1 FROM incidents WHERE id = :id"), {"id": incident_id}
    )
    if exists.one_or_none() is None:
        raise IncidentNotFound(incident_id)


async def _link_alerts(session: AsyncSession, incident_id: UUID, alert_ids: list[str]) -> None:
    # Lock in a stable order: two analysts linking overlapping batches cannot steal alerts
    # from each other or deadlock. Validate the whole batch before making any changes.
    rows = list(
        await session.execute(
            text(
                "SELECT alert_id, incident_id FROM alerts WHERE alert_id = ANY(:ids) "
                "ORDER BY alert_id FOR UPDATE"
            ),
            {"ids": alert_ids},
        )
    )
    if len(rows) != len(set(alert_ids)):
        raise AlertLinkError("one or more alerts no longer exist")
    if any(row.incident_id not in (None, incident_id) for row in rows):
        raise AlertLinkError("an alert already belongs to another incident; unlink it there first")
    await session.execute(
        text("UPDATE alerts SET incident_id = :incident_id WHERE alert_id = ANY(:alert_ids)"),
        {"incident_id": incident_id, "alert_ids": alert_ids},
    )


async def link_alerts(session: AsyncSession, incident_id: UUID, alert_ids: list[str]) -> None:
    await _require_incident(session, incident_id)
    await _link_alerts(session, incident_id, alert_ids)
    await session.commit()


async def unlink_alert(session: AsyncSession, incident_id: UUID, alert_id: str) -> None:
    """Only detach from THIS incident: a stale request must not affect another incident."""
    await _require_incident(session, incident_id)
    await session.execute(
        text(
            "UPDATE alerts SET incident_id = NULL "
            "WHERE alert_id = :alert_id AND incident_id = :incident_id"
        ),
        {"alert_id": alert_id, "incident_id": incident_id},
    )
    await session.commit()
