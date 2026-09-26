"""Detector -> `alerts.new` -> enricher -> enrichment of the stored alert (real Redis/Postgres)."""

from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.bus.alerts_stream import RedisAlertPublisher
from sentinel_core.bus.normalized_stream import RedisNormalizedPublisher
from sentinel_core.bus.raw_stream import DATA_FIELD, RedisRawLogPublisher
from sentinel_core.db.alerts import insert_alerts
from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.rules import load_rules
from sentinel_core.detection.store import RedisWindowStore
from sentinel_core.enrichment.abuseipdb import Reputation
from sentinel_core.enrichment.enricher import Enricher
from sentinel_core.enrichment.geoip import GeoIpResolver
from sentinel_core.workers.detector import DetectorWorker
from sentinel_core.workers.enricher import GROUP, EnricherWorker
from sentinel_core.workers.normalizer import NormalizerWorker
from tests.enrichment.geodb import PARIS_IP, UNKNOWN_IP, asn_db, city_db
from tests.support import DATABASE_URL, REDIS_URL
from tests.workers.test_detector_integration import NOW, failed_line, raw

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="SENTINEL_TEST_DATABASE_URL / SENTINEL_TEST_REDIS_URL not set",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[3]
RULES = load_rules(REPO_ROOT / "rules")


class FlakyPublisher(RedisAlertPublisher):
    """Fails the first `failures` publications, like a Redis that blinked."""

    def __init__(self, *args: Any, failures: int = 0, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.failures = failures
        self.probe: Callable[[list[Alert]], Awaitable[None]] | None = None

    async def publish(self, alerts: list[Alert]) -> None:
        if self.probe is not None:
            await self.probe(
                alerts
            )  # what does the database hold at the moment of the announcement?
        if self.failures > 0:
            self.failures -= 1
            raise RedisError("blip")
        await super().publish(alerts)


class Stack:
    def __init__(
        self,
        redis: Redis,
        engine: AsyncEngine,
        streams: tuple[str, str, str],
        normalizer: NormalizerWorker,
        detector: DetectorWorker,
        enricher: EnricherWorker,
        publisher: FlakyPublisher,
    ) -> None:
        self.redis, self.engine = redis, engine
        self.raw_stream, self.alerts_stream = streams[0], streams[2]
        self.normalizer, self.detector, self.enricher = normalizer, detector, enricher
        self.publisher = publisher

    async def attack(self, ip: str, origin: str = "1") -> None:
        start = NOW - timedelta(seconds=30)
        await RedisRawLogPublisher(
            self.redis, stream=self.raw_stream, high_watermark=10**6
        ).publish(
            [
                raw(failed_line(start + timedelta(seconds=i), ip=ip), f"{origin}:{i}")
                for i in range(6)
            ]
        )

    async def pump(self) -> None:
        while await self.normalizer.run_once():
            pass
        while await self.detector.run_once():
            pass
        while await self.enricher.run_once():
            pass

    async def rows(self, sql: str) -> list[Any]:
        async with self.engine.connect() as conn:
            return list((await conn.execute(text(sql))).all())

    async def pending(self) -> int:
        info = await self.redis.xpending(self.alerts_stream, GROUP)
        assert isinstance(info, dict)
        return int(info["pending"])


@pytest.fixture
async def redis() -> AsyncGenerator[Redis]:
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
async def stack(redis: Redis, engine: AsyncEngine, tmp_path: Path) -> AsyncGenerator[Stack]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    streams = (f"test.raw.{uuid4()}", f"test.normalized.{uuid4()}", f"test.alerts.{uuid4()}")
    publisher = FlakyPublisher(redis, stream=streams[2])
    geoip = GeoIpResolver(city_db(tmp_path / "c.mmdb"), asn_db(tmp_path / "a.mmdb"))
    normalizer = NormalizerWorker(
        redis,
        sessions,
        stream=streams[0],
        consumer="n-1",
        claim_idle_ms=0,
        publisher=RedisNormalizedPublisher(redis, stream=streams[1]),
    )
    detector = DetectorWorker(
        redis,
        sessions,
        DetectionEngine(RULES, RedisWindowStore(redis, key_prefix=f"test:{uuid4()}:")),
        alert_publisher=publisher,
        stream=streams[1],
        consumer="d-1",
        claim_idle_ms=0,
    )
    enricher = EnricherWorker(
        redis, sessions, Enricher(geoip), stream=streams[2], consumer="e-1", claim_idle_ms=0
    )
    for worker in (normalizer, detector, enricher):
        await worker.setup()
    yield Stack(redis, engine, streams, normalizer, detector, enricher, publisher)
    await redis.delete(*streams)
    geoip.close()


async def test_an_attack_from_a_public_address_is_stored_then_enriched(stack: Stack) -> None:
    await stack.attack(PARIS_IP)

    await stack.pump()

    (alert,) = await stack.rows("SELECT rule_id, enrichment, enriched_at FROM alerts")
    assert alert.rule_id == "ssh-bruteforce"
    assert alert.enriched_at is not None
    assert alert.enrichment["ip_scope"] == "public"
    assert alert.enrichment["geo"]["country_code"] == "FR"
    assert alert.enrichment["geo"]["city"] == "Paris"
    assert alert.enrichment["geo"]["as_org"] == "Example Hosting SARL"
    assert await stack.redis.xlen(stack.alerts_stream) == 0 and await stack.pending() == 0


async def test_a_private_source_is_marked_non_public_without_a_location(stack: Stack) -> None:
    await stack.attack("203.0.113.7")

    await stack.pump()

    (alert,) = await stack.rows("SELECT enrichment FROM alerts")
    assert alert.enrichment == {"ip_scope": "non_public", "geo": None, "reputation": None}


async def test_a_public_address_unknown_to_the_database_is_marked_public(stack: Stack) -> None:
    await stack.attack(UNKNOWN_IP)

    await stack.pump()

    (alert,) = await stack.rows("SELECT enrichment FROM alerts")
    assert alert.enrichment == {"ip_scope": "public", "geo": None, "reputation": None}


async def test_the_alert_is_stored_before_it_is_announced(stack: Stack) -> None:
    stored_when_announced: list[int] = []

    async def probe(alerts: list[Alert]) -> None:
        for alert in alerts:
            rows = await stack.rows(f"SELECT 1 FROM alerts WHERE alert_id = '{alert.alert_id}'")  # noqa: S608
            stored_when_announced.append(len(rows))

    stack.publisher.probe = probe
    await stack.attack(PARIS_IP)
    while await stack.normalizer.run_once():
        pass
    await stack.detector.run_once()  # detector only: the enricher has not run

    assert stored_when_announced == [1]  # the row was already there when the entry was published

    entries: Any = await stack.redis.xrange(stack.alerts_stream)
    announced = [Alert.model_validate_json(fields[DATA_FIELD]).alert_id for _, fields in entries]
    stored = await stack.rows("SELECT alert_id, enrichment FROM alerts")
    assert announced == [row.alert_id for row in stored] and len(stored) == 1
    assert stored[0].enrichment is None  # stored, not yet enriched


async def test_a_blip_while_announcing_loses_neither_the_alert_nor_its_enrichment(
    stack: Stack,
) -> None:
    stack.publisher.failures = 1
    await stack.attack(PARIS_IP)
    while await stack.normalizer.run_once():
        pass

    with pytest.raises(RedisError):
        await stack.detector.run_once()
    assert len(await stack.rows("SELECT 1 FROM alerts")) == 1  # persisted before the failure
    await stack.pump()  # the batch is redelivered: same alert, announced this time

    (alert,) = await stack.rows("SELECT enrichment FROM alerts")
    assert alert.enrichment["geo"]["country_code"] == "FR"


async def test_a_redelivered_announcement_rewrites_the_same_result(stack: Stack) -> None:
    await stack.attack(PARIS_IP)
    await stack.pump()
    (entry_alert,) = await stack.rows("SELECT * FROM alerts")
    alert = Alert.model_validate(
        {
            "alert_id": entry_alert.alert_id,
            "rule_id": entry_alert.rule_id,
            "title": entry_alert.title,
            "mitre": entry_alert.mitre,
            "severity": entry_alert.severity,
            "ts": entry_alert.ts,
            "group": entry_alert.group_values,
            "src_ip": PARIS_IP,
            "event_ids": entry_alert.event_ids,
            "match_count": entry_alert.match_count,
        }
    )

    await stack.publisher.publish([alert, alert])
    await stack.pump()

    rows = await stack.rows("SELECT enrichment FROM alerts")
    assert len(rows) == 1 and rows[0].enrichment["geo"]["country_code"] == "FR"


async def test_an_alert_without_a_source_address_is_scored_from_its_severity_alone(
    stack: Stack, engine: AsyncEngine
) -> None:
    alert = Alert(
        alert_id="cd" * 32,
        rule_id="sudo-root-shell",
        title="Root shell through sudo",
        mitre=["T1548.003"],
        severity=50,
        ts=NOW,
        group={"user_name": "alice"},
        event_ids=["00" * 32],
        match_count=1,
    )
    async with async_sessionmaker(engine).begin() as session:
        await insert_alerts(session, [alert])

    await stack.publisher.publish([alert])
    await stack.pump()

    (row,) = await stack.rows("SELECT enrichment, risk_score, risk FROM alerts")
    assert row.enrichment is None  # nothing to look up
    assert row.risk_score == 50 and row.risk["level"] == "medium"
    assert [f["name"] for f in row.risk["factors"]] == ["rule severity"]
    assert await stack.pending() == 0


async def test_garbage_and_unknown_alerts_do_not_block_the_ones_behind_them(
    stack: Stack,
) -> None:
    await stack.redis.xadd(stack.alerts_stream, {DATA_FIELD: "this is not an alert"})
    await stack.redis.xadd(stack.alerts_stream, {"other": "field"})
    ghost = Alert(
        alert_id="ee" * 32,
        rule_id="ssh-bruteforce",
        title="Not in the database",
        mitre=["T1110"],
        severity=60,
        ts=NOW,
        group={"src_ip": PARIS_IP},
        src_ip=PARIS_IP,
        event_ids=["00" * 32],
        match_count=5,
    )
    await stack.publisher.publish([ghost])
    await stack.attack(PARIS_IP)

    await stack.pump()

    (alert,) = await stack.rows("SELECT enrichment FROM alerts")
    assert alert.enrichment["geo"]["country_code"] == "FR"
    assert await stack.redis.xlen(stack.alerts_stream) == 0 and await stack.pending() == 0


async def test_a_database_failure_leaves_the_announcements_pending_then_retries(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    await stack.attack(PARIS_IP)
    while await stack.normalizer.run_once():
        pass
    while await stack.detector.run_once():
        pass

    async def down(*args: object, **kwargs: object) -> bool:
        raise SQLAlchemyError("database went away")

    with monkeypatch.context() as patch:
        patch.setattr("sentinel_core.workers.enricher.set_enrichment", down)
        with pytest.raises(SQLAlchemyError):
            await stack.enricher.run_once()
    assert await stack.pending() == 1
    await stack.pump()

    (alert,) = await stack.rows("SELECT enrichment FROM alerts")
    assert alert.enrichment["geo"]["country_code"] == "FR"
    assert await stack.pending() == 0


async def test_the_announcement_stream_is_capped_instead_of_growing_forever(
    redis: Redis,
) -> None:
    stream = f"test.alerts.{uuid4()}"
    publisher = RedisAlertPublisher(redis, stream=stream, maxlen=10)
    alerts = [
        Alert(
            alert_id=f"{i:064x}",
            rule_id="ssh-bruteforce",
            title="t",
            mitre=["T1110"],
            severity=60,
            ts=datetime(2026, 9, 26, tzinfo=UTC),
            group={},
            event_ids=[],
            match_count=5,
        )
        for i in range(400)
    ]

    for alert in alerts:
        await publisher.publish([alert])

    assert await redis.xlen(stream) < 400
    await redis.delete(stream)


async def test_an_alert_that_cannot_be_enriched_does_not_block_the_others(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = stack.enricher._enricher.enrich

    async def broken_for_one(src_ip: str | None) -> Any:
        if src_ip == UNKNOWN_IP:
            raise ValueError("corrupt record")
        return await real(src_ip)

    monkeypatch.setattr(stack.enricher._enricher, "enrich", broken_for_one)
    await stack.attack(UNKNOWN_IP, "1")
    await stack.attack(PARIS_IP, "2")

    await stack.pump()

    rows = {
        r.ip: r
        for r in await stack.rows("SELECT host(src_ip) AS ip, enrichment, risk_score FROM alerts")
    }
    assert rows[UNKNOWN_IP].enrichment is None  # no context...
    assert rows[UNKNOWN_IP].risk_score == 60  # ...but still ranked, from the rule severity
    assert rows[PARIS_IP].enrichment["geo"]["country_code"] == "FR"
    assert await stack.redis.xlen(stack.alerts_stream) == 0 and await stack.pending() == 0


class FakeReputation:
    def __init__(self) -> None:
        self.asked: list[str] = []

    async def lookup(self, ip: str) -> Reputation | None:
        self.asked.append(ip)
        return Reputation(score=91, total_reports=300, distinct_reporters=40, checked_at=NOW)


async def test_the_reputation_is_stored_for_public_sources_and_never_asked_for_private_ones(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeReputation()
    monkeypatch.setattr(stack.enricher._enricher, "_reputation", fake)
    await stack.attack(PARIS_IP, "1")
    await stack.attack("192.168.139.50", "2")

    await stack.pump()

    rows = {
        r.ip: r
        for r in await stack.rows(
            "SELECT host(src_ip) AS ip, enrichment, risk_score, risk FROM alerts"
        )
    }
    assert rows[PARIS_IP].enrichment["reputation"]["score"] == 91
    assert rows[PARIS_IP].enrichment["reputation"]["source"] == "abuseipdb"
    assert rows["192.168.139.50"].enrichment["reputation"] is None
    # ssh-bruteforce is 60; a reputation of 91 adds 22: the score explains itself
    assert rows[PARIS_IP].risk_score == 82 and rows["192.168.139.50"].risk_score == 60
    assert {f["name"]: f["points"] for f in rows[PARIS_IP].risk["factors"]} == {
        "rule severity": 60,
        "reputation": 22,
    }
    assert fake.asked == [PARIS_IP]  # the private address never left


async def test_a_redis_failure_while_enriching_leaves_the_announcements_pending(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    await stack.attack(PARIS_IP)
    while await stack.normalizer.run_once():
        pass
    while await stack.detector.run_once():
        pass
    real = stack.enricher._enricher.enrich
    failures = 1

    async def redis_blips(src_ip: str | None) -> Any:
        nonlocal failures
        if failures:
            failures -= 1
            raise RedisError("cache unreachable")  # e.g. the reputation cache
        return await real(src_ip)

    monkeypatch.setattr(stack.enricher._enricher, "enrich", redis_blips)

    with pytest.raises(RedisError):
        await stack.enricher.run_once()
    assert await stack.pending() == 1  # nothing was acknowledged, nothing lost
    await stack.pump()

    (alert,) = await stack.rows("SELECT enrichment FROM alerts")
    assert alert.enrichment["geo"]["country_code"] == "FR"
