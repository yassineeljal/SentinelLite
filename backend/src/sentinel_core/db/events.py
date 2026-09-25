"""Persistence of normalized events and dead letters (idempotent by construction)."""

from datetime import date, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.db.models import DeadLetter, EventRecord
from sentinel_core.normalizers.dead_letter import DeadLetterRecord
from sentinel_core.schema.event import Event

# Arbitrary constant: serializes partition creation between concurrent workers.
_PARTITION_LOCK_KEY = 7_265_101


def _event_row(event: Event) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "ts": event.ts,
        "received_at": event.received_at,
        "agent_id": event.agent_id,
        "source": event.source.value,
        "category": event.category.value,
        "action": event.action.value,
        "outcome": event.outcome.value,
        "severity": event.severity,
        "src_ip": str(event.src_ip) if event.src_ip else None,
        "dst_ip": str(event.dst_ip) if event.dst_ip else None,
        "dst_port": event.dst_port,
        "host": event.host,
        "user_name": event.user_name,
        "raw": event.raw,
        "extra": event.extra,
    }


async def insert_events(session: AsyncSession, events: list[Event]) -> None:
    """Insert events; rows that already exist (same event_id and ts) are skipped."""
    if not events:
        return
    statement = pg_insert(EventRecord).on_conflict_do_nothing(index_elements=["event_id", "ts"])
    await session.execute(statement, [_event_row(event) for event in events])


async def insert_dead_letters(session: AsyncSession, letters: list[DeadLetterRecord]) -> None:
    if not letters:
        return
    statement = pg_insert(DeadLetter).on_conflict_do_nothing(index_elements=["dedup_key"])
    await session.execute(
        statement,
        [
            {
                "dedup_key": letter.dedup_key,
                "agent_id": letter.agent_id,
                "source": letter.source,
                "origin": letter.origin,
                "raw": letter.raw,
                "error": letter.error,
                "received_at": letter.received_at,
            }
            for letter in letters
        ],
    )


async def ensure_event_partitions(session: AsyncSession, start: date, days: int) -> None:
    """Create the daily partitions [start, start + days) of `events` if missing (UTC days).

    Partition names and bounds are built from `date` values only, never from external input.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _PARTITION_LOCK_KEY})
    for offset in range(days):
        day = start + timedelta(days=offset)
        following = day + timedelta(days=1)
        await session.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS events_{day:%Y%m%d} PARTITION OF events "
                f"FOR VALUES FROM ('{day} 00:00:00+00') TO ('{following} 00:00:00+00')"
            )
        )
