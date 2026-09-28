"""The whole pipeline on real Redis and Postgres: raw lines -> normalizer -> detector -> alerts."""

import re
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.bus.normalized_stream import RedisNormalizedPublisher
from sentinel_core.bus.raw_stream import DATA_FIELD, RedisRawLogPublisher
from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.rules import load_rules
from sentinel_core.detection.scenarios import Scenario, discover_scenarios
from sentinel_core.detection.store import RedisWindowStore
from sentinel_core.normalizers.base import RawLog
from sentinel_core.schema.event import Event, Source
from sentinel_core.workers.detector import GROUP as DETECTOR_GROUP
from sentinel_core.workers.detector import DetectorWorker
from sentinel_core.workers.normalizer import NormalizerWorker
from tests.support import DATABASE_URL, REDIS_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="SENTINEL_TEST_DATABASE_URL / SENTINEL_TEST_REDIS_URL not set",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[3]
RULES = load_rules(REPO_ROOT / "rules")
# A disabled rule needs no scenario coverage: it can never fire (see bench.py).
SCENARIOS = discover_scenarios(REPO_ROOT / "datasets", [rule.id for rule in RULES if rule.enabled])
AGENT = UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime.now(UTC)


class Pipeline:
    def __init__(
        self,
        redis: Redis,
        engine: AsyncEngine,
        raw_stream: str,
        normalized_stream: str,
        normalizer: NormalizerWorker,
        detector: DetectorWorker,
    ) -> None:
        self.redis = redis
        self.engine = engine
        self.raw_stream = raw_stream
        self.normalized_stream = normalized_stream
        self.normalizer = normalizer
        self.detector = detector

    async def send(self, *logs: RawLog) -> None:
        await RedisRawLogPublisher(
            self.redis, stream=self.raw_stream, high_watermark=100_000
        ).publish(list(logs))

    async def pump(self) -> None:
        while await self.normalizer.run_once():
            pass
        while await self.detector.run_once():
            pass

    async def rows(self, sql: str) -> list[Any]:
        async with self.engine.connect() as conn:
            return list((await conn.execute(text(sql))).all())

    async def pending(self, stream: str, group: str) -> int:
        info = await self.redis.xpending(stream, group)
        assert isinstance(info, dict)
        return int(info["pending"])


@pytest.fixture
async def redis() -> AsyncGenerator[Redis]:
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
async def pipeline(redis: Redis, engine: AsyncEngine) -> AsyncGenerator[Pipeline]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    raw_stream, normalized_stream = f"test.raw.{uuid4()}", f"test.normalized.{uuid4()}"
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
        DetectionEngine(RULES, RedisWindowStore(redis, key_prefix=f"test:{uuid4()}:")),
        stream=normalized_stream,
        consumer="d-1",
        claim_idle_ms=0,
    )
    await normalizer.setup()
    await detector.setup()
    yield Pipeline(redis, engine, raw_stream, normalized_stream, normalizer, detector)
    await redis.delete(raw_stream, normalized_stream)


def failed_line(at: datetime, ip: str = "203.0.113.7", user: str = "root") -> str:
    stamp = at.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return f"{stamp} ubuntu-01 sshd[812]: Failed password for {user} from {ip} port 51234 ssh2"


def raw(line: str, origin: str, received_at: datetime = NOW) -> RawLog:
    return RawLog(
        agent_id=AGENT,
        source=Source.LINUX_AUTH,
        origin=origin,
        line=line,
        received_at=received_at,
    )


async def test_an_attack_goes_through_the_whole_pipeline_to_one_alert(pipeline: Pipeline) -> None:
    start = NOW - timedelta(seconds=30)
    await pipeline.send(
        *[raw(failed_line(start + timedelta(seconds=i)), f"1:{i}") for i in range(6)]
    )

    await pipeline.pump()

    (alert,) = await pipeline.rows(
        "SELECT rule_id, title, mitre, severity, group_values, host(src_ip) AS ip, host,"
        " user_name, event_ids, match_count, created_at FROM alerts"
    )
    assert (alert.rule_id, alert.title, alert.mitre, alert.severity) == (
        "ssh-bruteforce",
        "SSH brute force",
        ["T1110"],
        60,
    )
    assert alert.group_values == {"src_ip": "203.0.113.7"}
    assert (alert.ip, alert.host, alert.user_name) == ("203.0.113.7", "ubuntu-01", "root")
    assert alert.match_count == 5 and len(alert.event_ids) == 5  # the 6th is in the cooldown
    assert alert.created_at is not None
    # Nothing is left behind in either stream.
    for stream, group in [
        (pipeline.raw_stream, "normalizers"),
        (pipeline.normalized_stream, DETECTOR_GROUP),
    ]:
        assert await pipeline.redis.xlen(stream) == 0
        assert await pipeline.pending(stream, group) == 0


def read_scenario(rule_id: str, scenario: str) -> tuple[int, list[str]]:
    lines = (REPO_ROOT / "datasets" / rule_id / f"{scenario}.log").read_text().splitlines()
    expected = next(int(m[1]) for x in lines if (m := re.fullmatch(r"# expect: (\d+)", x)))
    # Alerts other rules legitimately raise on the same attack (`# also: rule=n`) are stored too.
    for x in lines:
        if x.startswith("# also:"):
            expected += sum(int(n) for n in re.findall(r"=(\d+)", x))
    return expected, [x for x in lines if x and not x.startswith("#")]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: f"{s.rule_id}/{s.name}")
async def test_every_shipped_scenario_gives_the_expected_alerts_through_the_real_pipeline(
    pipeline: Pipeline, scenario: Scenario
) -> None:
    """All scenarios (attacks, benign traffic, the 2000-line normal day) through Redis, the
    normalizer, Postgres and the detector: same alerts, per rule, as the in-memory replay."""
    await pipeline.send(
        *[raw(line, f"{scenario.name}:{i}") for i, line in enumerate(scenario.lines)]
    )

    await pipeline.pump()

    rows = await pipeline.rows("SELECT rule_id, count(*) AS n FROM alerts GROUP BY rule_id")
    assert {r.rule_id: r.n for r in rows} == scenario.expected_alerts


async def test_an_agent_retrying_a_whole_batch_never_duplicates_alerts(pipeline: Pipeline) -> None:
    expected, lines = read_scenario("ssh-bruteforce", "attack")
    await pipeline.send(*[raw(line, f"attack:{i}") for i, line in enumerate(lines)])
    await pipeline.pump()
    before = (
        len(await pipeline.rows("SELECT 1 FROM alerts")),
        len(await pipeline.rows("SELECT 1 FROM events")),
    )

    later = NOW + timedelta(minutes=5)  # the API stamps a fresh received_at on every request
    await pipeline.send(*[raw(line, f"attack:{i}", later) for i, line in enumerate(lines)])
    await pipeline.pump()

    after = (
        len(await pipeline.rows("SELECT 1 FROM alerts")),
        len(await pipeline.rows("SELECT 1 FROM events")),
    )
    assert before == after
    assert before[0] == expected


async def test_a_crash_before_the_alerts_are_persisted_loses_nothing(
    pipeline: Pipeline, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The engine already recorded the alert (cooldown started) when the database fails.
    The redelivered trigger must raise it again, exactly once in the table."""
    start = NOW - timedelta(seconds=30)
    await pipeline.send(
        *[raw(failed_line(start + timedelta(seconds=i)), f"1:{i}") for i in range(5)]
    )
    while await pipeline.normalizer.run_once():
        pass

    async def crash(*args: object, **kwargs: object) -> None:
        raise SQLAlchemyError("database went away")

    with monkeypatch.context() as patch:
        patch.setattr(pipeline.detector, "_persist", crash)
        with pytest.raises(SQLAlchemyError):
            await pipeline.detector.run_once()
    assert await pipeline.rows("SELECT 1 FROM alerts") == []
    assert await pipeline.pending(pipeline.normalized_stream, DETECTOR_GROUP) == 5

    await pipeline.detector.run_once()  # redelivery

    assert len(await pipeline.rows("SELECT 1 FROM alerts")) == 1
    assert await pipeline.pending(pipeline.normalized_stream, DETECTOR_GROUP) == 0


async def test_a_bug_in_the_engine_is_contained_as_a_dead_letter(
    pipeline: Pipeline, monkeypatch: pytest.MonkeyPatch
) -> None:
    start = NOW - timedelta(seconds=30)
    await pipeline.send(
        *[raw(failed_line(start + timedelta(seconds=i)), f"1:{i}") for i in range(6)]
    )
    while await pipeline.normalizer.run_once():
        pass
    real = pipeline.detector._engine.evaluate
    calls = 0

    async def flaky(event: Event, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("bug in a rule")
        return await real(event, **kwargs)

    monkeypatch.setattr(pipeline.detector._engine, "evaluate", flaky)

    await pipeline.detector.run_once()

    letters = await pipeline.rows("SELECT source, error FROM events_dead_letter")
    assert [(r.source, r.error.startswith("detection error: RuntimeError")) for r in letters] == [
        ("events.normalized", True)
    ]
    assert await pipeline.pending(pipeline.normalized_stream, DETECTOR_GROUP) == 0  # not stuck


async def test_an_infrastructure_error_is_retried_not_dead_lettered(
    pipeline: Pipeline, monkeypatch: pytest.MonkeyPatch
) -> None:
    await pipeline.send(raw(failed_line(NOW), "1:0"))
    while await pipeline.normalizer.run_once():
        pass

    async def redis_down(event: Event, **kwargs: Any) -> Any:
        raise RedisError("connection lost")

    with monkeypatch.context() as patch:
        patch.setattr(pipeline.detector._engine, "evaluate", redis_down)
        with pytest.raises(RedisError):
            await pipeline.detector.run_once()

    assert await pipeline.rows("SELECT 1 FROM events_dead_letter") == []
    assert await pipeline.pending(pipeline.normalized_stream, DETECTOR_GROUP) == 1
    assert await pipeline.detector.run_once() == 1  # retried once Redis is back


async def test_an_undecodable_normalized_entry_goes_to_dead_letter(pipeline: Pipeline) -> None:
    await pipeline.redis.xadd(pipeline.normalized_stream, {DATA_FIELD: "not an event"})

    await pipeline.detector.run_once()

    (letter,) = await pipeline.rows("SELECT source, raw, error FROM events_dead_letter")
    assert (letter.source, letter.raw) == ("events.normalized", "not an event")
    assert letter.error.startswith("undecodable normalized event")
    assert await pipeline.redis.xlen(pipeline.normalized_stream) == 0


async def test_the_normalizer_stops_reading_while_the_detector_is_behind(
    redis: Redis, engine: AsyncEngine
) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    raw_stream, normalized_stream = f"test.raw.{uuid4()}", f"test.normalized.{uuid4()}"
    normalizer = NormalizerWorker(
        redis,
        sessions,
        stream=raw_stream,
        consumer="n-1",
        batch_size=2,
        publisher=RedisNormalizedPublisher(redis, stream=normalized_stream, high_watermark=2),
    )
    detector = DetectorWorker(
        redis,
        sessions,
        DetectionEngine(RULES, RedisWindowStore(redis, key_prefix=f"test:{uuid4()}:")),
        stream=normalized_stream,
        consumer="d-1",
    )
    await normalizer.setup()
    await detector.setup()
    logs = [raw(failed_line(NOW - timedelta(seconds=60 - i)), f"1:{i}") for i in range(5)]
    await RedisRawLogPublisher(redis, stream=raw_stream, high_watermark=100).publish(logs)

    assert await normalizer.run_once() == 2  # fills the normalized stream up to its watermark
    assert await normalizer.run_once() == 0  # detector behind: nothing more is read
    assert await redis.xlen(raw_stream) == 3  # the backlog stays upstream, bounded and visible

    await detector.run_once()  # the detector catches up...
    assert await normalizer.run_once() == 2  # ...and the normalizer resumes

    await redis.delete(raw_stream, normalized_stream)


async def test_a_crash_in_the_middle_of_a_long_batch_loses_none_of_the_earlier_alerts(
    pipeline: Pipeline, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The brute-force attack scenario holds three alerts 10 minutes apart. When one batch spans
    more than window + tolerance, later events advance the detection state: an alert that was
    not persisted yet could no longer be raised again after redelivery. Alerts must therefore be
    persisted as soon as their event is evaluated, not at the end of the batch."""
    expected, lines = read_scenario("ssh-bruteforce", "attack")
    await pipeline.send(*[raw(line, f"attack:{i}") for i, line in enumerate(lines)])
    while await pipeline.normalizer.run_once():
        pass
    real_persist = pipeline.detector._persist
    calls = 0

    async def crash_on_the_third_alert(alerts: Any, letters: Any) -> None:
        nonlocal calls
        if alerts:
            calls += 1
            if calls == 3:
                raise SQLAlchemyError("database went away mid-batch")
        await real_persist(alerts, letters)

    with monkeypatch.context() as patch:
        patch.setattr(pipeline.detector, "_persist", crash_on_the_third_alert)
        with pytest.raises(SQLAlchemyError):
            await pipeline.detector.run_once()

    await pipeline.detector.run_once()  # redelivery of the whole batch

    ids = [r.alert_id for r in await pipeline.rows("SELECT alert_id FROM alerts")]
    assert len(ids) == expected and len(set(ids)) == expected
