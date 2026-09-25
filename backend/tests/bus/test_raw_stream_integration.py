"""Integration tests against a real Redis.

Run locally with, e.g.:
    docker run -d --rm --name sl-test-redis -p 127.0.0.1:6390:6379 redis:7-alpine
    SENTINEL_TEST_REDIS_URL=redis://127.0.0.1:6390/0 uv run pytest -m integration
In CI the URL is provided by a Redis service container.
"""

import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from sentinel_core.bus.raw_stream import BusFull, BusUnavailable, RedisRawLogPublisher
from sentinel_core.normalizers.base import RawLog
from sentinel_core.schema.event import Source

REDIS_URL = os.environ.get("SENTINEL_TEST_REDIS_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(REDIS_URL is None, reason="SENTINEL_TEST_REDIS_URL not set"),
]


@pytest.fixture
async def redis() -> AsyncGenerator[Redis]:
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
async def stream(redis: Redis) -> AsyncGenerator[str]:
    name = f"test.raw.{uuid4()}"  # unique per test: no need to flush the database
    yield name
    await redis.delete(name)


def make_logs(count: int) -> list[RawLog]:
    agent = uuid4()
    return [
        RawLog(
            agent_id=agent,
            source=Source.LINUX_AUTH,
            origin=f"1:{i}",
            line=f'line {i} with unicode é and "quotes"',
            received_at=datetime(2026, 9, 24, 15, 0, i % 60, tzinfo=UTC),
        )
        for i in range(count)
    ]


async def test_published_logs_round_trip_in_order(redis: Redis, stream: str) -> None:
    publisher = RedisRawLogPublisher(redis, stream=stream, high_watermark=1000)
    logs = make_logs(5)

    await publisher.publish(logs)

    entries = await redis.xrange(stream)
    assert entries is not None
    stored: list[RawLog] = []
    for _, fields in entries:
        assert fields is not None
        stored.append(RawLog.model_validate_json(fields["data"]))
    assert stored == logs


async def test_publishing_beyond_the_high_watermark_raises_and_writes_nothing(
    redis: Redis, stream: str
) -> None:
    publisher = RedisRawLogPublisher(redis, stream=stream, high_watermark=5)
    await publisher.publish(make_logs(3))

    with pytest.raises(BusFull):
        await publisher.publish(make_logs(3))  # 3 + 3 > 5

    assert await redis.xlen(stream) == 3  # the rejected batch left no partial write


async def test_batch_exactly_at_the_watermark_is_accepted(redis: Redis, stream: str) -> None:
    publisher = RedisRawLogPublisher(redis, stream=stream, high_watermark=4)

    await publisher.publish(make_logs(4))

    assert await redis.xlen(stream) == 4


async def test_unreachable_redis_raises_bus_unavailable() -> None:
    client = Redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)
    publisher = RedisRawLogPublisher(client, stream="x", high_watermark=10)

    with pytest.raises(BusUnavailable):
        await publisher.publish(make_logs(1))

    await client.aclose()
