"""Cache, budget and circuit breaker of the reputation lookups, against a real Redis."""

import logging
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from sentinel_core.enrichment.abuseipdb import (
    AuthRejected,
    BadRequest,
    CheckResult,
    QuotaExceeded,
    Reputation,
    ReputationError,
    Unavailable,
)
from sentinel_core.enrichment.reputation import ReputationService
from tests.support import REDIS_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(REDIS_URL is None, reason="SENTINEL_TEST_REDIS_URL not set"),
    pytest.mark.usefixtures("cleanup"),
]

T0 = datetime(2026, 9, 26, 15, 0, tzinfo=UTC)


def reputation(score: int = 80) -> Reputation:
    return Reputation(score=score, total_reports=10, distinct_reporters=4, checked_at=T0)


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.error: ReputationError | None = None
        self.result = CheckResult(reputation(), remaining=500, reset_at=None)

    async def check(self, ip: str) -> CheckResult:
        self.calls.append(ip)
        if self.error is not None:
            raise self.error
        return self.result


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
async def redis() -> AsyncGenerator[Redis]:
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
def prefix() -> str:
    return f"test:rep:{uuid4()}:"


@pytest.fixture
async def cleanup(redis: Redis, prefix: str) -> AsyncGenerator[None]:
    yield
    keys = [key async for key in redis.scan_iter(f"{prefix}*")]
    if keys:
        await redis.delete(*keys)


def service(
    client: FakeClient, redis: Redis, prefix: str, clock: Clock | None = None, **kwargs: int
) -> ReputationService:
    return ReputationService(client, redis, key_prefix=prefix, clock=clock or Clock(), **kwargs)


async def test_the_second_lookup_of_an_address_comes_from_the_cache(
    redis: Redis, prefix: str
) -> None:
    client = FakeClient()
    rep = service(client, redis, prefix)

    first = await rep.lookup("185.220.101.1")
    second = await rep.lookup("185.220.101.1")

    assert first == second == reputation() and client.calls == ["185.220.101.1"]


async def test_each_address_is_asked_once_and_the_cache_expires(redis: Redis, prefix: str) -> None:
    client = FakeClient()
    rep = service(client, redis, prefix, cache_ttl_seconds=100)

    await rep.lookup("185.220.101.1")
    await rep.lookup("8.8.8.8")

    assert client.calls == ["185.220.101.1", "8.8.8.8"]
    ttl = await redis.ttl(f"{prefix}abuseipdb:8.8.8.8")
    assert 0 < ttl <= 100


async def test_a_corrupt_cache_entry_is_asked_again(redis: Redis, prefix: str) -> None:
    client = FakeClient()
    await redis.set(f"{prefix}abuseipdb:8.8.8.8", "{not json")

    result = await service(client, redis, prefix).lookup("8.8.8.8")

    assert result == reputation() and client.calls == ["8.8.8.8"]


async def test_the_daily_budget_stops_the_calls_and_resets_the_next_day(
    redis: Redis, prefix: str
) -> None:
    client, clock = FakeClient(), Clock()
    rep = service(client, redis, prefix, clock, daily_limit=2)

    results = [await rep.lookup(ip) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")]

    assert [r is not None for r in results] == [True, True, False, False]
    assert client.calls == ["1.1.1.1", "2.2.2.2"]
    assert await rep.lookup("1.1.1.1") is not None  # cached answers are free
    clock.now = T0 + timedelta(days=1)  # the block ends with the day; a new budget starts
    await redis.delete(f"{prefix}blocked")
    assert await rep.lookup("5.5.5.5") is not None
    assert client.calls[-1] == "5.5.5.5"


async def test_the_budget_pause_lasts_until_the_end_of_the_day(redis: Redis, prefix: str) -> None:
    rep = service(FakeClient(), redis, prefix, daily_limit=1)
    await rep.lookup("1.1.1.1")

    await rep.lookup("2.2.2.2")

    assert 0 < await redis.ttl(f"{prefix}blocked") <= 9 * 3600  # T0 is 15:00 UTC


async def test_a_quota_answer_pauses_all_lookups_for_the_time_given(
    redis: Redis, prefix: str, caplog: pytest.LogCaptureFixture
) -> None:
    client = FakeClient()
    client.error = QuotaExceeded(600)
    rep = service(client, redis, prefix)

    with caplog.at_level(logging.WARNING, logger="sentinel.reputation"):
        assert await rep.lookup("1.1.1.1") is None
        assert await rep.lookup("2.2.2.2") is None
        assert await rep.lookup("3.3.3.3") is None

    assert client.calls == ["1.1.1.1"]  # the two others did not even try
    assert 0 < await redis.ttl(f"{prefix}blocked") <= 600
    assert len([r for r in caplog.records if "paused" in r.message]) == 1  # logged once


async def test_a_last_request_of_the_period_pauses_the_next_ones(redis: Redis, prefix: str) -> None:
    client, clock = FakeClient(), Clock()
    client.result = CheckResult(reputation(), remaining=0, reset_at=T0 + timedelta(minutes=30))
    rep = service(client, redis, prefix, clock)

    assert await rep.lookup("1.1.1.1") is not None  # this answer is good and is returned
    assert await rep.lookup("2.2.2.2") is None

    assert client.calls == ["1.1.1.1"]
    assert 0 < await redis.ttl(f"{prefix}blocked") <= 1800


async def test_a_refused_key_is_reported_loudly_once_and_paused(
    redis: Redis, prefix: str, caplog: pytest.LogCaptureFixture
) -> None:
    client = FakeClient()
    client.error = AuthRejected("the key was refused (HTTP 401)")
    rep = service(client, redis, prefix)

    with caplog.at_level(logging.WARNING, logger="sentinel.reputation"):
        await rep.lookup("1.1.1.1")
        await rep.lookup("2.2.2.2")

    assert client.calls == ["1.1.1.1"]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "refused" in errors[0].message
    assert 3000 < await redis.ttl(f"{prefix}blocked") <= 3600


async def test_an_outage_costs_one_failed_call_then_a_short_pause(
    redis: Redis, prefix: str
) -> None:
    client = FakeClient()
    client.error = Unavailable("request failed: ConnectTimeout")
    rep = service(client, redis, prefix)

    assert await rep.lookup("1.1.1.1") is None
    assert await rep.lookup("2.2.2.2") is None

    assert client.calls == ["1.1.1.1"]
    assert 0 < await redis.ttl(f"{prefix}blocked") <= 60
    assert await redis.get(f"{prefix}abuseipdb:1.1.1.1") is None  # failures are never cached


async def test_a_rejected_address_does_not_pause_anything(redis: Redis, prefix: str) -> None:
    client = FakeClient()
    client.error = BadRequest("the address was refused by the API")
    rep = service(client, redis, prefix)

    assert await rep.lookup("1.1.1.1") is None
    client.error = None
    assert await rep.lookup("2.2.2.2") is not None

    assert not await redis.exists(f"{prefix}blocked")


async def test_a_cached_answer_is_served_even_while_paused(redis: Redis, prefix: str) -> None:
    client = FakeClient()
    rep = service(client, redis, prefix)
    await rep.lookup("1.1.1.1")
    client.error = QuotaExceeded(600)
    await rep.lookup("2.2.2.2")  # starts the pause

    assert await rep.lookup("1.1.1.1") == reputation()
