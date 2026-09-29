"""`db.alerts.mitre_summary`: alert counts per MITRE technique, against a real Postgres."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel_core.db.alerts import insert_alerts, mitre_summary
from sentinel_core.detection.alerts import Alert
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

T0 = datetime(2026, 9, 24, 15, 0, tzinfo=UTC)


def alert(
    alert_id: str, mitre: list[str], rule_id: str = "ssh-bruteforce", at: datetime = T0
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        title="test alert",
        mitre=mitre,
        severity=60,
        ts=at,
        group={},
        event_ids=["00" * 32],
        match_count=1,
    )


@pytest.fixture
def sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def test_counts_one_alert_per_technique_it_carries(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(
            session,
            [
                alert("a" * 64, ["T1110", "T1078"]),  # counts toward BOTH techniques
                alert("b" * 64, ["T1110"]),
            ],
        )

    async with sessions() as session:
        rows = await mitre_summary(session)

    counts = {r.technique: r.count for r in rows}
    assert counts["T1110"] == 2
    assert counts["T1078"] == 1


async def test_sorted_by_count_descending(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions.begin() as session:
        await insert_alerts(
            session,
            [
                alert("c" * 64, ["T1078"]),
                alert("d" * 64, ["T1110"]),
                alert("e" * 64, ["T1110"]),
                alert("f" * 64, ["T1110"]),
            ],
        )

    async with sessions() as session:
        rows = await mitre_summary(session)

    assert rows[0].technique == "T1110"
    assert all(rows[i].count >= rows[i + 1].count for i in range(len(rows) - 1))


async def test_the_most_recent_alert_time_is_reported_per_technique(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(
            session,
            [
                alert("g" * 64, ["T1110"], at=T0),
                alert("h" * 64, ["T1110"], at=T0 + timedelta(hours=1)),
            ],
        )

    async with sessions() as session:
        rows = await mitre_summary(session)

    row = next(r for r in rows if r.technique == "T1110")
    assert row.latest_ts == T0 + timedelta(hours=1)


async def test_alerts_older_than_the_window_are_excluded(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(
            session, [alert("i" * 64, ["T1548.003"], at=datetime.now(UTC) - timedelta(days=90))]
        )

    async with sessions() as session:
        rows = await mitre_summary(session, days=30)

    assert not any(r.technique == "T1548.003" for r in rows)


async def test_an_alert_within_the_window_is_included(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(
            session, [alert("j" * 64, ["T1548.003"], at=datetime.now(UTC) - timedelta(days=1))]
        )

    async with sessions() as session:
        rows = await mitre_summary(session, days=30)

    assert any(r.technique == "T1548.003" and r.count == 1 for r in rows)


async def test_no_alerts_at_all_gives_an_empty_summary(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions() as session:
        rows = await mitre_summary(session)

    assert rows == []


async def test_an_invalid_window_is_refused(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions() as session:
        with pytest.raises(ValueError, match="days"):
            await mitre_summary(session, days=0)
        with pytest.raises(ValueError, match="days"):
            await mitre_summary(session, days=-5)
