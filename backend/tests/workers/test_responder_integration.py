"""Alerts -> `alerts.respond` -> responder -> block decisions (real Redis and Postgres)."""

import argparse
import hashlib
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core import cli
from sentinel_core.bus.alerts_stream import RedisAlertPublisher
from sentinel_core.bus.normalized_stream import RedisNormalizedPublisher
from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.store import RedisWindowStore
from sentinel_core.response.policy import ResponsePolicy
from sentinel_core.workers.detector import DetectorWorker
from sentinel_core.workers.normalizer import NormalizerWorker
from sentinel_core.workers.responder import ResponderWorker
from tests.support import DATABASE_URL, REDIS_URL
from tests.workers.test_detector_integration import NOW, RULES, failed_line, raw

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="SENTINEL_TEST_DATABASE_URL / SENTINEL_TEST_REDIS_URL not set",
    ),
]

ATTACKER = "45.83.64.10"  # global: documentation ranges (203.0.113.0/24...) are never blocked


def make_alert(
    *,
    src_ip: str | None = ATTACKER,
    rule_id: str = "ssh-bruteforce",
    severity: int = 60,
    tag: str | None = None,
) -> Alert:
    tag = tag or str(uuid4())
    return Alert(
        alert_id=hashlib.sha256(tag.encode()).hexdigest(),
        rule_id=rule_id,
        title="SSH brute force",
        mitre=["T1110"],
        severity=severity,
        ts=datetime.now(UTC),
        group={"src_ip": src_ip or ""},
        src_ip=src_ip,
        event_ids=[],
        match_count=5,
    )


class Responder:
    def __init__(self, redis: Redis, engine: AsyncEngine, stream: str, policy: ResponsePolicy):
        self.redis, self.engine, self.stream = redis, engine, stream
        self.publisher = RedisAlertPublisher(redis, stream=stream)
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)
        self.worker = ResponderWorker(
            redis, self.sessions, policy, consumer="r-1", stream=stream, claim_idle_ms=0
        )

    async def alerts(self, *alerts: Alert) -> None:
        await self.publisher.publish(list(alerts))
        while await self.worker.run_once():
            pass

    async def rows(self, sql: str) -> list[Any]:
        async with self.engine.connect() as conn:
            return list((await conn.execute(text(sql))).all())


@pytest.fixture
async def redis() -> AsyncGenerator[Redis]:
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
async def responder(redis: Redis, engine: AsyncEngine) -> AsyncGenerator[Responder]:
    stream = f"test.respond.{uuid4()}"
    r = Responder(redis, engine, stream, ResponsePolicy())
    await r.worker.setup()
    yield r
    await redis.delete(stream)


async def test_a_scan_is_recorded_as_a_dry_run_block_with_an_audit_line(
    responder: Responder,
) -> None:
    await responder.alerts(make_alert())

    (block,) = await responder.rows(
        "SELECT host(ip), mode, rule_id, expires_at - created_at, released_at FROM blocked_ips"
    )
    assert block[0] == ATTACKER
    assert block[1] == "dry_run"
    assert block[2] == "ssh-bruteforce"
    assert block[3] == timedelta(hours=1)  # the TTL is mandatory
    assert block[4] is None
    (audit,) = await responder.rows("SELECT actor, action, target, details FROM audit_log")
    assert audit[:3] == ("responder", "block.dry_run", ATTACKER)
    assert audit[3]["rule_id"] == "ssh-bruteforce"


async def test_a_redelivered_alert_changes_nothing(responder: Responder) -> None:
    alert = make_alert(tag="same-alert")
    await responder.alerts(alert)
    await responder.alerts(alert)  # the stream is at-least-once

    assert len(await responder.rows("SELECT 1 FROM blocked_ips")) == 1
    assert len(await responder.rows("SELECT 1 FROM audit_log")) == 1


async def test_a_second_alert_for_a_blocked_address_does_not_block_it_again(
    responder: Responder,
) -> None:
    await responder.alerts(make_alert(tag="one"), make_alert(tag="two"))

    assert len(await responder.rows("SELECT 1 FROM blocked_ips")) == 1


@pytest.mark.parametrize("address", ["10.0.1.5", "203.0.113.7", "127.0.0.1", "224.0.0.1"])
async def test_non_public_addresses_are_never_blocked(responder: Responder, address: str) -> None:
    await responder.alerts(make_alert(src_ip=address))

    assert await responder.rows("SELECT 1 FROM blocked_ips") == []


async def test_alerts_about_successful_logins_never_block(responder: Responder) -> None:
    await responder.alerts(make_alert(rule_id="ssh-success-after-failures", severity=85))

    assert await responder.rows("SELECT 1 FROM blocked_ips") == []


async def test_the_database_allowlist_protects_an_address_and_is_audited(
    responder: Responder,
) -> None:
    async with responder.sessions.begin() as session:
        from sentinel_core.db.responses import add_allowlist

        await add_allowlist(session, "45.83.64.0/24", "the operator", "test")

    await responder.alerts(make_alert())

    assert await responder.rows("SELECT 1 FROM blocked_ips") == []
    actions = [r[0] for r in await responder.rows("SELECT action FROM audit_log ORDER BY id")]
    assert actions == ["allowlist.add", "skip.allowlisted"]


async def test_the_configured_allowlist_protects_an_address(
    redis: Redis, engine: AsyncEngine
) -> None:
    from sentinel_core.response.policy import parse_networks

    stream = f"test.respond.{uuid4()}"
    r = Responder(redis, engine, stream, ResponsePolicy(allowlist=parse_networks([ATTACKER])))
    await r.worker.setup()
    await r.alerts(make_alert())

    assert await r.rows("SELECT 1 FROM blocked_ips") == []
    await redis.delete(stream)


async def test_the_rate_cap_stops_a_runaway_rule(redis: Redis, engine: AsyncEngine) -> None:
    stream = f"test.respond.{uuid4()}"
    r = Responder(redis, engine, stream, ResponsePolicy(max_blocks_per_minute=2))
    await r.worker.setup()

    await r.alerts(
        *[make_alert(src_ip=f"45.83.64.{n}") for n in (10, 11, 12)],
    )

    assert len(await r.rows("SELECT 1 FROM blocked_ips")) == 2
    skips = await r.rows("SELECT action FROM audit_log WHERE action LIKE 'skip.%'")
    assert skips == [("skip.rate_limited",)]
    await redis.delete(stream)


async def test_a_malformed_address_is_audited_and_does_not_break_the_batch(
    responder: Responder,
) -> None:
    hostile = "1.2.3.4; rm -rf / \x1b[31m"
    await responder.alerts(make_alert(src_ip=hostile), make_alert(tag="fine"))

    assert len(await responder.rows("SELECT 1 FROM blocked_ips")) == 1  # the good one went through
    (skip,) = await responder.rows(
        "SELECT action, target FROM audit_log WHERE action LIKE 'skip.%'"
    )
    assert skip[0] == "skip.invalid_address"
    assert "\x1b" not in skip[1]  # untrusted text is sanitised before it is stored


async def test_the_audit_log_cannot_be_rewritten(responder: Responder) -> None:
    await responder.alerts(make_alert())

    for statement in ("UPDATE audit_log SET actor = 'someone'", "DELETE FROM audit_log"):
        with pytest.raises(DBAPIError, match="append-only"):
            async with responder.engine.begin() as conn:
                await conn.execute(text(statement))
    assert len(await responder.rows("SELECT 1 FROM audit_log")) == 1


async def test_the_whole_chain_from_raw_logs_to_a_dry_run_block(
    redis: Redis, engine: AsyncEngine
) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    raw_stream, normalized, respond = (f"test.{n}.{uuid4()}" for n in ("raw", "norm", "respond"))
    normalizer = NormalizerWorker(
        redis,
        sessions,
        stream=raw_stream,
        consumer="n-1",
        claim_idle_ms=0,
        publisher=RedisNormalizedPublisher(redis, stream=normalized),
    )
    detector = DetectorWorker(
        redis,
        sessions,
        DetectionEngine(RULES, RedisWindowStore(redis, key_prefix=f"test:{uuid4()}:")),
        stream=normalized,
        consumer="d-1",
        claim_idle_ms=0,
        response_publisher=RedisAlertPublisher(redis, stream=respond),
    )
    responder = ResponderWorker(
        redis, sessions, ResponsePolicy(), consumer="r-1", stream=respond, claim_idle_ms=0
    )
    for worker in (normalizer, detector, responder):
        await worker.setup()

    from sentinel_core.bus.raw_stream import RedisRawLogPublisher

    start = NOW - timedelta(seconds=30)
    await RedisRawLogPublisher(redis, stream=raw_stream, high_watermark=10**6).publish(
        [raw(failed_line(start + timedelta(seconds=i), ip=ATTACKER), f"1:{i}") for i in range(6)]
    )
    for worker in (normalizer, detector, responder):
        while await worker.run_once():
            pass

    async with engine.connect() as conn:
        blocks = (await conn.execute(text("SELECT host(ip), mode FROM blocked_ips"))).all()
    assert blocks == [(ATTACKER, "dry_run")]
    await redis.delete(raw_stream, normalized, respond)


async def test_the_cli_manages_the_allowlist_and_lists_blocks(
    responder: Responder, capsys: pytest.CaptureFixture[str]
) -> None:
    parser = cli.build_parser()

    async def run(*argv: str) -> int:
        return await cli._response(parser.parse_args(argv), responder.sessions)

    assert await run("allowlist", "add", "198.51.100.0/24", "--note", "office") == 0
    assert await run("allowlist", "add", "198.51.100.0/24") == 1  # already there
    assert await run("allowlist", "add", "not-a-network") == 1
    assert await run("allowlist", "list") == 0
    assert "198.51.100.0/24" in capsys.readouterr().out
    assert await run("allowlist", "remove", "198.51.100.0/24") == 0
    assert await run("allowlist", "remove", "198.51.100.0/24") == 1  # gone

    await responder.alerts(make_alert())
    assert await run("blocks") == 0
    out = capsys.readouterr().out
    assert ATTACKER in out and "dry_run" in out


def test_argparse_namespace_has_no_surprise() -> None:
    args = cli.build_parser().parse_args(["blocks", "--limit", "5"])
    assert isinstance(args, argparse.Namespace) and args.limit == 5
