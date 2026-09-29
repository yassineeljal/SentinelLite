"""Enforce mode: a block becomes an action the agent polls for, applies, acknowledges and, when
its time is up, is told to lift (real Redis and Postgres)."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core import cli
from sentinel_core.api.main import create_app
from sentinel_core.auth.registry import PostgresAgentRepository
from sentinel_core.bus.alerts_stream import RedisAlertPublisher
from sentinel_core.config import Settings
from sentinel_core.db.events import ensure_event_partitions
from sentinel_core.detection.alerts import Alert
from sentinel_core.response.policy import ResponsePolicy
from sentinel_core.workers.responder import ResponderWorker
from tests.support import DATABASE_URL, REDIS_URL, InMemoryPublisher
from tests.workers.test_responder_integration import ATTACKER, make_alert

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DATABASE_URL is None or REDIS_URL is None,
        reason="SENTINEL_TEST_DATABASE_URL / SENTINEL_TEST_REDIS_URL not set",
    ),
]


class Platform:
    def __init__(self, redis: Redis, engine: AsyncEngine, client: AsyncClient) -> None:
        self.engine, self.client = engine, client
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)
        self.registry = PostgresAgentRepository(self.sessions)
        self.stream = f"test.respond.{uuid4()}"
        self.publisher = RedisAlertPublisher(redis, stream=self.stream)
        self.worker = ResponderWorker(
            redis,
            self.sessions,
            ResponsePolicy(),
            mode="enforce",
            consumer="r-1",
            stream=self.stream,
            claim_idle_ms=0,
            release_interval=0.0,
        )

    async def agent(self, os: str = "linux") -> tuple[UUID, dict[str, str]]:
        created = await self.registry.create_agent(name=f"agent-{uuid4()}", os=os)
        return created.agent.id, {"Authorization": f"Bearer {created.token}"}

    async def event(self, agent_id: UUID) -> str:
        event_id = uuid4().hex.ljust(64, "0")
        now = datetime.now(UTC)
        async with self.sessions.begin() as session:
            await ensure_event_partitions(session, now.date(), 1)
            await session.execute(
                text(
                    "INSERT INTO events (event_id, ts, received_at, agent_id, source, category, "
                    "action, outcome, severity, src_ip, host, raw) VALUES (:id, :ts, :ts, :agent, "
                    "'linux.auth', 'authentication', 'login_failed', 'failure', 10, "
                    "CAST(:ip AS inet), 'h', 'raw')"
                ),
                {"id": event_id, "ts": now, "agent": agent_id, "ip": ATTACKER},
            )
        return event_id

    async def alert(self, *event_ids: str) -> Alert:
        alert = make_alert().model_copy(update={"event_ids": list(event_ids)})
        await self.publisher.publish([alert])
        while await self.worker.run_once():
            pass
        return alert

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
async def platform(redis: Redis, engine: AsyncEngine) -> AsyncGenerator[Platform]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    app = create_app(
        settings=Settings(database_url=str(engine.url), session_cookie_secure=False),
        agent_repo=PostgresAgentRepository(sessions),
        publisher=InMemoryPublisher(),
        db_sessions=sessions,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        p = Platform(redis, engine, client)
        await p.worker.setup()
        yield p
    await redis.delete(p.stream)


async def test_a_block_is_queued_only_for_the_agent_that_saw_the_attacker(
    platform: Platform,
) -> None:
    seen, seen_auth = await platform.agent()
    _other, other_auth = await platform.agent()
    await platform.alert(await platform.event(seen))

    fetched = (await platform.client.get("/v1/agents/me/actions", headers=seen_auth)).json()
    (action,) = fetched["actions"]
    assert (action["kind"], action["ip"]) == ("block", ATTACKER)
    other = (await platform.client.get("/v1/agents/me/actions", headers=other_auth)).json()
    assert other["actions"] == []


async def test_dry_run_queues_nothing(redis: Redis, engine: AsyncEngine) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    stream = f"test.respond.{uuid4()}"
    worker = ResponderWorker(
        redis, sessions, ResponsePolicy(), mode="dry_run", consumer="r", stream=stream
    )
    await worker.setup()
    agent = (await PostgresAgentRepository(sessions).create_agent("a-dry", "linux")).agent.id
    p = Platform(redis, engine, AsyncClient())
    event_id = await p.event(agent)
    await RedisAlertPublisher(redis, stream=stream).publish(
        [make_alert().model_copy(update={"event_ids": [event_id]})]
    )
    while await worker.run_once():
        pass

    assert await p.rows("SELECT 1 FROM agent_actions") == []
    await redis.delete(stream)


async def test_an_alert_no_agent_saw_blocks_on_the_record_but_queues_nothing(
    platform: Platform,
) -> None:
    await platform.alert()  # no evidence events

    assert len(await platform.rows("SELECT 1 FROM blocked_ips WHERE mode = 'enforce'")) == 1
    assert await platform.rows("SELECT 1 FROM agent_actions") == []


async def test_a_revoked_agent_gets_nothing(platform: Platform) -> None:
    agent, auth = await platform.agent()
    event_id = await platform.event(agent)
    await platform.registry.revoke_agent(agent)
    await platform.alert(event_id)

    assert await platform.rows("SELECT 1 FROM agent_actions") == []
    assert (await platform.client.get("/v1/agents/me/actions", headers=auth)).status_code == 401


async def test_the_actions_endpoints_reject_missing_or_wrong_credentials(
    platform: Platform,
) -> None:
    assert (await platform.client.get("/v1/agents/me/actions")).status_code == 401
    bad = {"Authorization": f"Bearer {uuid4()}.{'x' * 43}"}
    assert (await platform.client.get("/v1/agents/me/actions", headers=bad)).status_code == 401
    assert (
        await platform.client.post("/v1/agents/me/actions/1/ack", json={"status": "done"})
    ).status_code == 401


async def test_ack_records_the_outcome_once_and_only_for_the_owner(platform: Platform) -> None:
    owner, owner_auth = await platform.agent()
    _, intruder_auth = await platform.agent()
    await platform.alert(await platform.event(owner))
    (action,) = (await platform.client.get("/v1/agents/me/actions", headers=owner_auth)).json()[
        "actions"
    ]
    url = f"/v1/agents/me/actions/{action['id']}/ack"

    stolen = await platform.client.post(url, json={"status": "done"}, headers=intruder_auth)
    assert stolen.status_code == 404
    ok = await platform.client.post(
        url, json={"status": "failed", "detail": "ufw: not found"}, headers=owner_auth
    )
    assert ok.status_code == 204
    again = await platform.client.post(url, json={"status": "done"}, headers=owner_auth)
    assert again.status_code == 404  # already answered

    ((status, detail),) = await platform.rows("SELECT status, detail FROM agent_actions")
    assert (status, detail) == ("failed", "ufw: not found")
    listed = (await platform.client.get("/v1/agents/me/actions", headers=owner_auth)).json()
    assert listed["actions"] == []  # an answered action is not handed out again


async def test_a_malformed_ack_is_refused(platform: Platform) -> None:
    _, auth = await platform.agent()
    for body in ({"status": "maybe"}, {"status": "done", "extra": 1}, {}):
        r = await platform.client.post("/v1/agents/me/actions/1/ack", json=body, headers=auth)
        assert r.status_code == 422
    r = await platform.client.post(
        "/v1/agents/me/actions/99999999999999999999/ack", json={"status": "done"}, headers=auth
    )
    assert r.status_code in (404, 422)


async def test_an_expired_block_is_released_and_the_agent_is_told_to_lift_it(
    platform: Platform,
) -> None:
    agent, auth = await platform.agent()
    await platform.alert(await platform.event(agent))
    async with platform.engine.begin() as conn:  # the hour has passed
        await conn.execute(text("UPDATE blocked_ips SET expires_at = now() - interval '1 second'"))
        await conn.execute(text("UPDATE agent_actions SET status = 'done'"))

    await platform.worker.on_tick()
    await platform.worker.on_tick()  # a second sweep changes nothing

    (block,) = await platform.rows("SELECT released_at, released_by FROM blocked_ips")
    assert block[0] is not None and block[1] == "responder"
    fetched = (await platform.client.get("/v1/agents/me/actions", headers=auth)).json()
    (action,) = fetched["actions"]
    assert (action["kind"], action["ip"]) == ("unblock", ATTACKER)
    audited = [r[0] for r in await platform.rows("SELECT action FROM audit_log ORDER BY id")]
    assert audited.count("unblock") == 1


async def test_a_block_that_expired_before_it_was_fetched_is_not_handed_out(
    platform: Platform,
) -> None:
    agent, auth = await platform.agent()
    await platform.alert(await platform.event(agent))
    async with platform.engine.begin() as conn:
        await conn.execute(
            text("UPDATE agent_actions SET expires_at = :past"),
            {"past": datetime.now(UTC) - timedelta(seconds=5)},
        )

    fetched = (await platform.client.get("/v1/agents/me/actions", headers=auth)).json()
    assert fetched["actions"] == []


async def unblock(platform: Platform, address: str) -> int:
    args = cli.build_parser().parse_args(["unblock", address])
    return await cli._response(args, platform.sessions)


async def test_unblock_releases_the_block_queues_an_unblock_and_audits_it(
    platform: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    agent, auth = await platform.agent()
    await platform.alert(await platform.event(agent))

    assert await unblock(platform, ATTACKER) == 0

    assert "allowlist add" in capsys.readouterr().out  # tells how to keep it out for good
    ((released_at, released_by),) = await platform.rows(
        "SELECT released_at, released_by FROM blocked_ips"
    )
    assert released_at is not None and released_by == "cli"
    fetched = (await platform.client.get("/v1/agents/me/actions", headers=auth)).json()
    kinds = [a["kind"] for a in fetched["actions"]]
    assert kinds == ["block", "unblock"]  # the agent applies them in this order: net effect none
    actions = [r[0] for r in await platform.rows("SELECT action FROM audit_log ORDER BY id")]
    assert actions == ["block.enforce", "unblock.manual"]


async def test_unblock_works_with_the_mapped_ipv6_form_and_is_not_repeated(
    platform: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    agent, _ = await platform.agent()
    await platform.alert(await platform.event(agent))

    assert await unblock(platform, f"::ffff:{ATTACKER}") == 1  # a different address, no match
    assert await unblock(platform, ATTACKER) == 0
    assert await unblock(platform, ATTACKER) == 1  # nothing left to lift
    assert "no active block" in capsys.readouterr().err
    assert len(await platform.rows("SELECT 1 FROM agent_actions WHERE kind = 'unblock'")) == 1


@pytest.mark.parametrize(
    "value", ["not-an-ip", "1.2.3.4; DROP TABLE blocked_ips", "1.2.3.0/24", ""]
)
async def test_unblock_refuses_what_is_not_an_address(
    platform: Platform, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await unblock(platform, value) == 1
    assert "not an IP address" in capsys.readouterr().err


async def test_unblocking_a_dry_run_block_queues_nothing(
    platform: Platform,
) -> None:
    agent, _ = await platform.agent()
    await platform.alert(await platform.event(agent))
    async with platform.engine.begin() as conn:
        await conn.execute(text("UPDATE blocked_ips SET mode = 'dry_run'"))
        await conn.execute(text("DELETE FROM agent_actions"))

    assert await unblock(platform, ATTACKER) == 0
    assert await platform.rows("SELECT 1 FROM agent_actions") == []
