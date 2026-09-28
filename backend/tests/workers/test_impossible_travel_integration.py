"""The impossible-travel rule through the real pipeline: raw lines -> normalizer -> detector ->
alert, on real Redis and Postgres, with a real (fixture) GeoIP database.

The shipped rule ships `enabled: false` (see rules/ssh-impossible-travel.yaml): most deployments
have no GeoIP database mounted for the detector. This test force-enables it to prove the wiring
(DetectionEngine + GeoIpResolver + the detector's real Redis/Postgres path) actually works.
"""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.bus.normalized_stream import RedisNormalizedPublisher
from sentinel_core.bus.raw_stream import RedisRawLogPublisher
from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.rules import load_rules
from sentinel_core.detection.store import RedisWindowStore
from sentinel_core.enrichment.geoip import GeoIpResolver
from sentinel_core.normalizers.base import RawLog
from sentinel_core.schema.event import Source
from sentinel_core.workers.detector import DetectorWorker
from sentinel_core.workers.normalizer import NormalizerWorker
from tests.enrichment.geodb import PARIS_IP, TORONTO_IP, city_db
from tests.support import DATABASE_URL, REDIS_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="SENTINEL_TEST_DATABASE_URL / SENTINEL_TEST_REDIS_URL not set",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_A = UUID("11111111-1111-1111-1111-111111111111")
AGENT_B = UUID("22222222-2222-2222-2222-222222222222")
NOW = datetime.now(UTC)


def login(at: datetime, ip: str, host: str) -> str:
    stamp = at.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return f"{stamp} {host} sshd[812]: Accepted password for alice from {ip} port 51234 ssh2"


@pytest.fixture
async def redis() -> AsyncGenerator[Redis]:
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


async def test_a_fast_trip_between_two_agents_hosts_is_detected(
    redis: Redis, engine: AsyncEngine, tmp_path: Path
) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    raw_stream, normalized_stream = f"test.raw.{uuid4()}", f"test.normalized.{uuid4()}"
    rules = [
        r.model_copy(update={"enabled": True})
        for r in load_rules(REPO_ROOT / "rules")
        if r.id == "ssh-impossible-travel"
    ]
    assert rules, "the shipped rule must still exist"
    geoip = GeoIpResolver(city_db(tmp_path / "city.mmdb"), None)
    normalizer = NormalizerWorker(
        redis,
        sessions,
        stream=raw_stream,
        consumer="n-1",
        claim_idle_ms=0,
        publisher=RedisNormalizedPublisher(redis, stream=normalized_stream),
    )
    detector = DetectorWorker(
        redis,
        sessions,
        DetectionEngine(rules, RedisWindowStore(redis, key_prefix=f"test:{uuid4()}:"), geoip=geoip),
        stream=normalized_stream,
        consumer="d-1",
        claim_idle_ms=0,
    )
    await normalizer.setup()
    await detector.setup()

    async def send(agent: UUID, origin: str, line: str) -> None:
        await RedisRawLogPublisher(redis, stream=raw_stream, high_watermark=10**6).publish(
            [
                RawLog(
                    agent_id=agent,
                    source=Source.LINUX_AUTH,
                    origin=origin,
                    line=line,
                    received_at=NOW,
                )
            ]
        )

    await send(AGENT_A, "1", login(NOW - timedelta(hours=2), PARIS_IP, "paris-host"))
    await send(AGENT_B, "2", login(NOW - timedelta(hours=1), TORONTO_IP, "toronto-host"))

    while await normalizer.run_once():
        pass
    while await detector.run_once():
        pass

    async with engine.connect() as conn:
        rows = list(
            (
                await conn.execute(
                    text("SELECT rule_id, group_values, host(src_ip) AS ip FROM alerts")
                )
            ).all()
        )
    assert len(rows) == 1
    assert rows[0].rule_id == "ssh-impossible-travel"
    assert rows[0].group_values == {"user_name": "alice"}
    assert rows[0].ip == TORONTO_IP  # the trigger event's own address
    await redis.delete(raw_stream, normalized_stream)
    geoip.close()
