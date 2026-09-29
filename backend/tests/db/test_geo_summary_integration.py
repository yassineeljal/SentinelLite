"""`db.alerts.geo_summary`: alert counts by location (city), against a real Postgres."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel_core.db.alerts import geo_summary, insert_alerts, set_enrichment
from sentinel_core.detection.alerts import Alert
from sentinel_core.enrichment.enricher import Enrichment
from sentinel_core.enrichment.geoip import GeoInfo
from sentinel_core.enrichment.risk import assess
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

T0 = datetime(2026, 9, 24, 15, 0, tzinfo=UTC)


def alert(alert_id: str, at: datetime = T0, severity: int = 60) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="ssh-bruteforce",
        title="test alert",
        mitre=["T1110"],
        severity=severity,
        ts=at,
        group={},
        event_ids=["00" * 32],
        match_count=1,
    )


def paris_geo() -> GeoInfo:
    return GeoInfo(
        country_code="FR", country="France", city="Paris", latitude=48.85, longitude=2.35
    )


def berlin_geo() -> GeoInfo:
    return GeoInfo(
        country_code="DE", country="Germany", city="Berlin", latitude=52.52, longitude=13.4
    )


@pytest.fixture
def sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def enrich(
    sessions: async_sessionmaker[AsyncSession],
    alert_id: str,
    geo: GeoInfo | None,
    severity: int = 60,
) -> None:
    enrichment = Enrichment(ip_scope="public", geo=geo) if geo is not None else None
    risk = assess(severity, enrichment)
    async with sessions.begin() as session:
        await set_enrichment(session, alert_id, enrichment, risk)


async def test_alerts_from_the_same_city_are_grouped_together(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("a" * 64), alert("b" * 64)])
    await enrich(sessions, "a" * 64, paris_geo())
    await enrich(sessions, "b" * 64, paris_geo())

    async with sessions() as session:
        rows = await geo_summary(session)

    paris = next(r for r in rows if r.city == "Paris")
    assert paris.count == 2
    assert paris.country_code == "FR"
    assert paris.latitude == pytest.approx(48.85)
    assert paris.longitude == pytest.approx(2.35)


async def test_different_cities_are_separate_rows(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("c" * 64), alert("d" * 64)])
    await enrich(sessions, "c" * 64, paris_geo())
    await enrich(sessions, "d" * 64, berlin_geo())

    async with sessions() as session:
        rows = await geo_summary(session)

    cities = {r.city for r in rows}
    assert {"Paris", "Berlin"} <= cities


async def test_the_worst_risk_score_in_the_city_is_reported(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("e" * 64, severity=40), alert("f" * 64, severity=90)])
    await enrich(sessions, "e" * 64, paris_geo(), severity=40)
    await enrich(sessions, "f" * 64, paris_geo(), severity=90)

    async with sessions() as session:
        rows = await geo_summary(session)

    paris = next(r for r in rows if r.city == "Paris")
    assert paris.max_risk_score == 90


async def test_non_public_and_unenriched_alerts_are_excluded(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("g" * 64), alert("h" * 64)])
    await enrich(sessions, "g" * 64, None)  # non-public: no geo at all
    # "h" is never enriched at all: enrichment stays NULL

    async with sessions() as session:
        rows = await geo_summary(session)

    assert rows == []


async def test_a_public_address_unknown_to_the_geoip_database_is_excluded(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("i" * 64)])
    async with sessions.begin() as session:
        await set_enrichment(
            session, "i" * 64, Enrichment(ip_scope="public", geo=None), assess(60, None)
        )

    async with sessions() as session:
        rows = await geo_summary(session)

    assert rows == []


async def test_alerts_older_than_the_window_are_excluded(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("j" * 64, at=datetime.now(UTC) - timedelta(days=90))])
    await enrich(sessions, "j" * 64, paris_geo())

    async with sessions() as session:
        rows = await geo_summary(session, days=30)

    assert rows == []


async def test_sorted_by_count_descending(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("k" * 64), alert("l" * 64), alert("m" * 64)])
    await enrich(sessions, "k" * 64, berlin_geo())
    await enrich(sessions, "l" * 64, paris_geo())
    await enrich(sessions, "m" * 64, paris_geo())

    async with sessions() as session:
        rows = await geo_summary(session)

    assert rows[0].city == "Paris" and rows[0].count == 2
    assert all(rows[i].count >= rows[i + 1].count for i in range(len(rows) - 1))


async def test_an_invalid_window_is_refused(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions() as session:
        with pytest.raises(ValueError, match="days"):
            await geo_summary(session, days=0)
