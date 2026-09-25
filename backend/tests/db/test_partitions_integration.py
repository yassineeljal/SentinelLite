"""Daily partitions of `events` against a real Postgres."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.db.events import ensure_event_partitions, insert_events
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

TODAY = datetime.now(UTC).date()


def event(n: int, ts: datetime) -> Event:
    return Event(
        event_id=f"{n:064x}",
        ts=ts,
        received_at=datetime.now(UTC),
        agent_id=UUID(int=1),
        host="ubuntu-01",
        source=Source.LINUX_AUTH,
        category=Category.AUTHENTICATION,
        action=Action.LOGIN_FAILED,
        outcome=Outcome.FAILURE,
        severity=20,
        src_ip="203.0.113.7",
        raw="line",
    )


async def partition_of(engine: AsyncEngine, event_id: str) -> str:
    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT tableoid::regclass::text FROM events WHERE event_id = :id"),
            {"id": event_id},
        )
        return str(result.scalar_one())


async def test_a_partition_can_be_created_for_a_day_that_already_has_rows_in_the_default_partition(
    engine: AsyncEngine,
) -> None:
    """Agents control the timestamps in their lines: an event dated far ahead lands in the default
    partition, and when that day later enters the rolling window its partition must still be
    creatable (a plain CREATE ... PARTITION OF fails while the default holds rows of the range)."""
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    day = TODAY + timedelta(days=60)
    ts = datetime(day.year, day.month, day.day, 12, 0, tzinfo=UTC)
    async with sessions.begin() as session:
        await insert_events(session, [event(1, ts)])
    assert await partition_of(engine, f"{1:064x}") == "events_default"

    async with sessions.begin() as session:
        await ensure_event_partitions(session, start=day, days=1)

    assert await partition_of(engine, f"{1:064x}") == f"events_{day:%Y%m%d}"  # moved, not lost
    async with engine.connect() as conn:
        left = await conn.execute(text("SELECT count(*) FROM events_default"))
        assert left.scalar_one() == 0


async def test_new_events_of_a_moved_day_go_to_its_partition(engine: AsyncEngine) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    day = TODAY + timedelta(days=61)
    ts = datetime(day.year, day.month, day.day, 8, 0, tzinfo=UTC)
    async with sessions.begin() as session:
        await insert_events(session, [event(1, ts)])
        await ensure_event_partitions(session, start=day, days=1)
        await insert_events(session, [event(2, ts + timedelta(hours=1))])

    assert await partition_of(engine, f"{2:064x}") == f"events_{day:%Y%m%d}"


async def test_a_partition_that_cannot_be_created_does_not_stop_the_other_days(
    engine: AsyncEngine,
) -> None:
    """A range already covered by a hand-made partition makes that day's creation fail: the
    other days must still be created and nothing must raise."""
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    start = TODAY + timedelta(days=90)
    async with sessions.begin() as session:
        await session.execute(
            text(
                "CREATE TABLE IF NOT EXISTS events_manual PARTITION OF events "
                f"FOR VALUES FROM ('{start} 00:00:00+00') "
                f"TO ('{start + timedelta(days=2)} 00:00:00+00')"
            )
        )

    async with sessions.begin() as session:
        await ensure_event_partitions(session, start=start, days=4)  # days 0-1 overlap, 2-3 fine

    async with engine.connect() as conn:
        names = {
            r[0]
            for r in await conn.execute(
                text(
                    "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
                    "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'events'"
                )
            )
        }
    assert f"events_{start + timedelta(days=2):%Y%m%d}" in names
    assert f"events_{start + timedelta(days=3):%Y%m%d}" in names
    async with engine.begin() as conn:  # leave the schema as we found it
        await conn.execute(text("DROP TABLE IF EXISTS events_manual"))
