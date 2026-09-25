"""Persistence of normalized events and dead letters (idempotent by construction)."""

import logging
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.db.models import DeadLetter, EventRecord
from sentinel_core.normalizers.dead_letter import DeadLetterRecord
from sentinel_core.schema.event import Event

logger = logging.getLogger("sentinel.partitions")

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

    One day that cannot be created (logged) does not stop the others: each runs in a savepoint.
    Partition names and bounds are built from `date` values only, never from external input.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _PARTITION_LOCK_KEY})
    for offset in range(days):
        day = start + timedelta(days=offset)
        try:
            async with session.begin_nested():
                await _create_partition(session, day)
        except DBAPIError:
            logger.exception(
                "cannot create the events partition of %s; rows stay in events_default", day
            )


async def _create_partition(session: AsyncSession, day: date) -> None:
    name = f"events_{day:%Y%m%d}"
    following = day + timedelta(days=1)
    low = datetime.combine(day, time.min, tzinfo=UTC)
    high = datetime.combine(following, time.min, tzinfo=UTC)
    bounds = f"FOR VALUES FROM ('{day} 00:00:00+00') TO ('{following} 00:00:00+00')"

    if await session.scalar(text("SELECT to_regclass(:name) IS NOT NULL"), {"name": name}):
        return
    # Agents control the timestamps in their lines: an event dated far ahead sits in the default
    # partition, and PostgreSQL refuses to create a partition whose range already holds rows of
    # the default. Those rows are moved into the new partition instead of being left blocking it.
    stray = await session.scalar(
        text("SELECT EXISTS (SELECT 1 FROM events_default WHERE ts >= :low AND ts < :high)"),
        {"low": low, "high": high},
    )
    if not stray:
        await session.execute(text(f"CREATE TABLE {name} PARTITION OF events {bounds}"))
        return
    await session.execute(
        text(f"CREATE TABLE {name} (LIKE events INCLUDING DEFAULTS INCLUDING INDEXES)")
    )
    await session.execute(
        text(
            "WITH moved AS ("  # noqa: S608 - the name is built from a date, never from input
            "DELETE FROM events_default WHERE ts >= :low AND ts < :high RETURNING *"
            f") INSERT INTO {name} SELECT * FROM moved"
        ),
        {"low": low, "high": high},
    )
    await session.execute(text(f"ALTER TABLE events ATTACH PARTITION {name} {bounds}"))
