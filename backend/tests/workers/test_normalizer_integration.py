"""Integration tests: real Redis (stream + consumer group) and real Postgres (events)."""

import asyncio
import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import DataError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel_core.bus.raw_stream import RedisRawLogPublisher
from sentinel_core.normalizers.base import RawLog
from sentinel_core.schema.event import Event, Source
from sentinel_core.workers.normalizer import GROUP, NormalizerWorker
from tests.support import DATABASE_URL, REDIS_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="SENTINEL_TEST_DATABASE_URL / SENTINEL_TEST_REDIS_URL not set",
    ),
]

AGENT = UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime.now(UTC)


def failed(ip: str = "203.0.113.7", user: str = "root", ts: str | None = None) -> str:
    stamp = ts or NOW.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return f"{stamp} ubuntu-01 sshd[812]: Failed password for {user} from {ip} port 51234 ssh2"


def raw(line: str, origin: str, source: Source = Source.LINUX_AUTH) -> RawLog:
    return RawLog(agent_id=AGENT, source=source, origin=origin, line=line, received_at=NOW)


@pytest.fixture
async def redis() -> AsyncGenerator[Redis]:
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
async def stream(redis: Redis) -> AsyncGenerator[str]:
    name = f"test.raw.{uuid4()}"
    yield name
    await redis.delete(name)


@pytest.fixture
def sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
async def worker(
    redis: Redis, sessions: async_sessionmaker[AsyncSession], stream: str
) -> NormalizerWorker:
    w = NormalizerWorker(redis, sessions, stream=stream, consumer="test-1", claim_idle_ms=60_000)
    await w.setup()
    return w


async def publish(redis: Redis, stream: str, *logs: RawLog) -> None:
    await RedisRawLogPublisher(redis, stream=stream, high_watermark=10_000).publish(list(logs))


async def rows(engine: AsyncEngine, sql: str) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql))).all())


async def pending(redis: Redis, stream: str) -> int:
    info = await redis.xpending(stream, GROUP)
    assert isinstance(info, dict)
    return int(info["pending"])


async def test_valid_lines_become_events_and_entries_are_removed(
    redis: Redis, stream: str, worker: NormalizerWorker, engine: AsyncEngine
) -> None:
    await publish(
        redis,
        stream,
        raw(failed(user="root"), "1:0"),
        raw(failed(user="admin", ip="198.51.100.9"), "1:1"),
        raw(
            NOW.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            + " ubuntu-01 sshd[9]: Accepted publickey for alice from 10.0.0.5 port 22"
            " ssh2: RSA SHA256:x",
            "1:2",
        ),
    )

    handled = await worker.run_once()

    assert handled == 3
    result = await rows(engine, "SELECT action, user_name FROM events ORDER BY user_name")
    assert [tuple(r) for r in result] == [
        ("login_failed", "admin"),
        ("login_success", "alice"),
        ("login_failed", "root"),
    ]
    assert await redis.xlen(stream) == 0  # acknowledged entries are deleted
    assert await pending(redis, stream) == 0


async def test_event_fields_are_stored_faithfully(
    redis: Redis, stream: str, worker: NormalizerWorker, engine: AsyncEngine
) -> None:
    line = failed()
    await publish(redis, stream, raw(line, "1:0"))

    await worker.run_once()

    (row,) = await rows(
        engine,
        "SELECT host, source, category, action, outcome, severity, host(src_ip) AS src_ip,"
        " dst_port, user_name, raw, extra, agent_id, length(event_id) FROM events",
    )
    assert row.host == "ubuntu-01"
    assert (row.source, row.category, row.action, row.outcome) == (
        "linux.auth",
        "authentication",
        "login_failed",
        "failure",
    )
    assert (row.severity, row.src_ip, row.dst_port, row.user_name) == (
        20,
        "203.0.113.7",
        22,
        "root",
    )
    assert row.raw == line
    assert row.extra == {"method": "password", "src_port": 51234, "invalid_user": False}
    assert row.agent_id == AGENT
    assert row.length == 64


async def test_ignored_and_undecodable_lines_are_never_silently_lost(
    redis: Redis, stream: str, worker: NormalizerWorker, engine: AsyncEngine
) -> None:
    cron = f"{NOW:%Y-%m-%dT%H:%M:%S+00:00} h CRON[2]: pam_unix(cron:session): session opened"
    await publish(
        redis,
        stream,
        raw(cron, "1:0"),  # well-formed, nothing to model: acknowledged, no row anywhere
        raw("this is not a syslog line", "1:1"),  # malformed: dead letter
        raw("GET / HTTP/1.1", "1:2", source=Source.NGINX_ACCESS),  # no normalizer yet
    )

    await worker.run_once()

    assert await rows(engine, "SELECT 1 FROM events") == []
    dead = await rows(
        engine, "SELECT source, origin, raw, error FROM events_dead_letter ORDER BY origin"
    )
    assert [(r.source, r.origin, r.raw) for r in dead] == [
        ("linux.auth", "1:1", "this is not a syslog line"),
        ("nginx.access", "1:2", "GET / HTTP/1.1"),
    ]
    assert "syslog" in dead[0].error and "no normalizer" in dead[1].error
    assert await redis.xlen(stream) == 0 and await pending(redis, stream) == 0


async def test_replayed_entries_do_not_create_duplicates(
    redis: Redis, stream: str, worker: NormalizerWorker, engine: AsyncEngine
) -> None:
    good, bad = raw(failed(), "1:0"), raw("garbage", "1:1")
    later = NOW + timedelta(minutes=5)  # the API stamps a fresh received_at on every request
    retry = [
        good.model_copy(update={"received_at": later}),
        bad.model_copy(update={"received_at": later}),
    ]
    await publish(redis, stream, good, bad, *retry)  # an agent retrying a batch

    await worker.run_once()

    assert len(await rows(engine, "SELECT 1 FROM events")) == 1
    assert len(await rows(engine, "SELECT 1 FROM events_dead_letter")) == 1
    assert await redis.xlen(stream) == 0


async def test_entries_stay_pending_when_the_database_fails_and_are_retried(
    redis: Redis,
    sessions: async_sessionmaker[AsyncSession],
    stream: str,
    engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = NormalizerWorker(redis, sessions, stream=stream, consumer="test-1", claim_idle_ms=0)
    await worker.setup()
    await publish(redis, stream, raw(failed(), "1:0"), raw(failed(user="x"), "1:1"))

    async def broken(*args: object, **kwargs: object) -> None:
        raise SQLAlchemyError("database is down")

    with monkeypatch.context() as patch:
        patch.setattr(worker, "_persist", broken)
        with pytest.raises(SQLAlchemyError):
            await worker.run_once()
    assert await rows(engine, "SELECT 1 FROM events") == []
    assert await pending(redis, stream) == 2  # nothing acknowledged: nothing lost

    handled = await worker.run_once()  # database is back: the pending entries are re-delivered

    assert handled == 2
    assert len(await rows(engine, "SELECT 1 FROM events")) == 2
    assert await pending(redis, stream) == 0 and await redis.xlen(stream) == 0


async def test_entries_of_a_crashed_consumer_are_taken_over(
    redis: Redis, sessions: async_sessionmaker[AsyncSession], stream: str, engine: AsyncEngine
) -> None:
    crashed = NormalizerWorker(redis, sessions, stream=stream, consumer="crashed", claim_idle_ms=0)
    await crashed.setup()
    await publish(redis, stream, raw(failed(), "1:0"), raw(failed(user="x"), "1:1"))
    # The doomed consumer reads the entries and dies before acknowledging them.
    await redis.xreadgroup(GROUP, "crashed", {stream: ">"}, count=10)
    assert await pending(redis, stream) == 2

    survivor = NormalizerWorker(
        redis, sessions, stream=stream, consumer="survivor", claim_idle_ms=0
    )
    handled = await survivor.run_once()

    assert handled == 2
    assert len(await rows(engine, "SELECT 1 FROM events")) == 2
    assert await pending(redis, stream) == 0


async def test_events_go_to_daily_partitions_and_odd_dates_to_the_default_partition(
    redis: Redis, stream: str, worker: NormalizerWorker, engine: AsyncEngine
) -> None:
    await publish(
        redis,
        stream,
        raw(failed(), "1:0"),
        # An authenticated agent controls the timestamps in its lines: this must not fail.
        raw(failed(ts="1999-01-01T00:00:00+00:00"), "1:1"),
        raw(failed(ts="2999-01-01T00:00:00+00:00"), "1:2"),
    )

    await worker.run_once()

    placed = await rows(
        engine, "SELECT tableoid::regclass::text AS part, ts FROM events ORDER BY ts"
    )
    assert [r.part for r in placed] == ["events_default", f"events_{NOW:%Y%m%d}", "events_default"]


async def test_partition_setup_is_idempotent(worker: NormalizerWorker, engine: AsyncEngine) -> None:
    await worker.setup()
    await worker.setup()

    parts = await rows(
        engine,
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
        " JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'events' ORDER BY 1",
    )
    names = [r.relname for r in parts]
    assert "events_default" in names
    assert f"events_{NOW:%Y%m%d}" in names
    assert len(names) == len(set(names))


async def test_run_loop_processes_new_entries_and_stops_on_request(
    redis: Redis, stream: str, worker: NormalizerWorker, engine: AsyncEngine
) -> None:
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop, block_ms=50))

    await publish(redis, stream, raw(failed(), "1:0"))
    for _ in range(100):
        if await rows(engine, "SELECT 1 FROM events"):
            break
        await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=5)

    assert len(await rows(engine, "SELECT 1 FROM events")) == 1


async def test_an_entry_the_database_rejects_is_quarantined_and_does_not_block_the_batch(
    redis: Redis,
    sessions: async_sessionmaker[AsyncSession],
    stream: str,
    engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deterministic storage error (e.g. data PostgreSQL refuses) would fail on every retry of
    the batch and hold back every other line behind it: the offender must be isolated."""
    worker = NormalizerWorker(redis, sessions, stream=stream, consumer="t", claim_idle_ms=0)
    await worker.setup()
    real_persist = worker._persist

    async def picky(events: list[Event], letters: list[Any]) -> None:
        if any(e.user_name == "poison" for e in events):
            raise DataError("INSERT ...", {}, Exception("the database rejects this value"))
        await real_persist(events, letters)

    monkeypatch.setattr(worker, "_persist", picky)
    await publish(
        redis,
        stream,
        raw(failed(user="alice"), "1:0"),
        raw(failed(user="poison"), "1:1"),
        raw(failed(user="bob"), "1:2"),
    )

    handled = await worker.run_once()

    assert handled == 3
    users = await rows(engine, "SELECT user_name FROM events ORDER BY user_name")
    assert [r.user_name for r in users] == ["alice", "bob"]  # the innocent lines went through
    (letter,) = await rows(engine, "SELECT origin, error FROM events_dead_letter")
    assert letter.origin == "1:1" and letter.error.startswith("unstorable entry")
    assert await redis.xlen(stream) == 0 and await pending(redis, stream) == 0


async def test_claimed_entries_are_not_held_back_by_a_blocking_read(
    redis: Redis, sessions: async_sessionmaker[AsyncSession], stream: str, engine: AsyncEngine
) -> None:
    crashed = NormalizerWorker(redis, sessions, stream=stream, consumer="crashed", claim_idle_ms=0)
    await crashed.setup()
    await publish(redis, stream, raw(failed(), "1:0"))
    await redis.xreadgroup(GROUP, "crashed", {stream: ">"}, count=10)  # read, never acknowledged
    survivor = NormalizerWorker(
        redis, sessions, stream=stream, consumer="survivor", claim_idle_ms=0
    )

    started = time.monotonic()
    handled = await survivor.run_once(block_ms=3000)  # the stream is idle: nothing new to wait for

    assert handled == 1
    assert time.monotonic() - started < 1.5  # not the 3 s block of the read for new entries
    assert len(await rows(engine, "SELECT 1 FROM events")) == 1


async def test_stale_entries_are_drained_over_several_batches(
    redis: Redis, sessions: async_sessionmaker[AsyncSession], stream: str, engine: AsyncEngine
) -> None:
    crashed = NormalizerWorker(redis, sessions, stream=stream, consumer="crashed", claim_idle_ms=0)
    await crashed.setup()
    await publish(redis, stream, *[raw(failed(user=f"u{i}"), f"1:{i}") for i in range(5)])
    await redis.xreadgroup(GROUP, "crashed", {stream: ">"}, count=10)
    survivor = NormalizerWorker(
        redis, sessions, stream=stream, consumer="survivor", claim_idle_ms=0, batch_size=2
    )

    handled = [await survivor.run_once() for _ in range(3)]

    assert handled == [2, 2, 1]
    assert len(await rows(engine, "SELECT 1 FROM events")) == 5
    assert await pending(redis, stream) == 0


async def test_a_failing_partition_refresh_neither_crashes_the_worker_nor_is_retried_in_a_loop(
    redis: Redis,
    sessions: async_sessionmaker[AsyncSession],
    stream: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = NormalizerWorker(redis, sessions, stream=stream, consumer="t")
    await worker.setup()
    calls = 0

    async def broken() -> None:
        nonlocal calls
        calls += 1
        raise SQLAlchemyError("partition maintenance failed")

    monkeypatch.setattr(worker, "ensure_partitions", broken)
    worker._last_partition_check = time.monotonic() - 10_000  # the hourly refresh is due

    with pytest.raises(SQLAlchemyError):
        await worker.on_tick()
    await worker.on_tick()  # not due again: the failed attempt counted, no hot retry loop

    assert calls == 1
