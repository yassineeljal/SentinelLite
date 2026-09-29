"""Heartbeats in, silence and recovery announced once (real Postgres)."""

import json
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core import cli
from sentinel_core.api.main import create_app
from sentinel_core.auth.registry import PostgresAgentRepository
from sentinel_core.config import Settings
from sentinel_core.notify.discord import DiscordNotifier
from sentinel_core.workers.watchdog import Watchdog
from tests.support import DATABASE_URL, InMemoryPublisher

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
SILENCE = timedelta(minutes=5)


class Rig:
    def __init__(self, engine: AsyncEngine, client: AsyncClient) -> None:
        self.engine, self.client = engine, client
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)
        self.registry = PostgresAgentRepository(self.sessions)
        self.posts: list[str] = []
        self.discord = DiscordNotifier(
            "https://discord.com/api/webhooks/1/token",
            httpx.AsyncClient(transport=httpx.MockTransport(self._discord)),
        )
        self.watchdog = Watchdog(self.sessions, SILENCE, self.discord)

    def _discord(self, request: httpx.Request) -> httpx.Response:
        self.posts.append(json.loads(request.content)["content"])
        return httpx.Response(204)

    async def agent(self, name: str = "vps-1") -> tuple[object, dict[str, str]]:
        created = await self.registry.create_agent(name=name, os="linux")
        return created.agent.id, {"Authorization": f"Bearer {created.token}"}

    async def seen(self, agent_id: object, when: datetime) -> None:
        async with self.engine.begin() as conn:
            await conn.execute(
                text("UPDATE agents SET last_seen_at = :t WHERE id = :i"),
                {"t": when, "i": agent_id},
            )

    async def state(self, agent_id: object) -> tuple[datetime | None, datetime | None]:
        async with self.engine.connect() as conn:
            row = (
                await conn.execute(
                    text("SELECT last_seen_at, silent_since FROM agents WHERE id = :i"),
                    {"i": agent_id},
                )
            ).one()
        return row[0], row[1]


@pytest.fixture
async def rig(engine: AsyncEngine) -> AsyncGenerator[Rig]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    app = create_app(
        settings=Settings(database_url=str(engine.url), session_cookie_secure=False),
        agent_repo=PostgresAgentRepository(sessions),
        publisher=InMemoryPublisher(),
        db_sessions=sessions,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield Rig(engine, client)


async def test_a_heartbeat_records_that_the_agent_is_alive(rig: Rig) -> None:
    agent, auth = await rig.agent()
    assert (await rig.state(agent))[0] is None

    result = await rig.client.post("/v1/agents/me/heartbeat", headers=auth)

    assert result.status_code == 204
    seen, silent = await rig.state(agent)
    assert seen is not None and silent is None
    assert abs((datetime.now(UTC) - seen).total_seconds()) < 30


async def test_a_heartbeat_needs_a_valid_key_and_only_touches_its_own_agent(rig: Rig) -> None:
    mine, auth = await rig.agent("mine")
    other, _ = await rig.agent("other")

    assert (await rig.client.post("/v1/agents/me/heartbeat")).status_code == 401
    bad = {"Authorization": f"Bearer {mine}.{'x' * 43}"}
    assert (await rig.client.post("/v1/agents/me/heartbeat", headers=bad)).status_code == 401
    await rig.client.post("/v1/agents/me/heartbeat", headers=auth)

    assert (await rig.state(other))[0] is None


async def test_a_revoked_agent_cannot_heartbeat(rig: Rig) -> None:
    agent, auth = await rig.agent()
    await rig.registry.revoke_agent(agent)  # type: ignore[arg-type]

    assert (await rig.client.post("/v1/agents/me/heartbeat", headers=auth)).status_code == 401


async def test_a_silent_agent_is_announced_once(rig: Rig) -> None:
    agent, _ = await rig.agent("vps-1")
    await rig.seen(agent, NOW - timedelta(minutes=12))

    first = await rig.watchdog.check(NOW)
    second = await rig.watchdog.check(NOW + timedelta(minutes=1))

    assert len(first) == 1 and "SILENT" in first[0] and "vps-1" in first[0]
    assert "12 min" in first[0]
    assert second == []  # already announced
    assert rig.posts == first
    assert (await rig.state(agent))[1] == NOW


async def test_an_agent_within_the_limit_is_not_silent(rig: Rig) -> None:
    agent, _ = await rig.agent()
    await rig.seen(agent, NOW - timedelta(minutes=4))

    assert await rig.watchdog.check(NOW) == []


async def test_an_agent_that_never_reported_is_not_silent(rig: Rig) -> None:
    await rig.agent("not-deployed-yet")

    assert await rig.watchdog.check(NOW) == []


async def test_a_revoked_agent_is_never_announced(rig: Rig) -> None:
    agent, _ = await rig.agent()
    await rig.seen(agent, NOW - timedelta(hours=3))
    await rig.registry.revoke_agent(agent)  # type: ignore[arg-type]

    assert await rig.watchdog.check(NOW) == []


async def test_a_recovered_agent_is_announced_once_and_can_go_silent_again(rig: Rig) -> None:
    agent, auth = await rig.agent("vps-1")
    await rig.seen(agent, NOW - timedelta(minutes=10))
    await rig.watchdog.check(NOW)

    await rig.client.post("/v1/agents/me/heartbeat", headers=auth)  # it is back (real clock)
    back = await rig.watchdog.check(datetime.now(UTC))
    again = await rig.watchdog.check(datetime.now(UTC))

    assert len(back) == 1 and "reporting again" in back[0]
    assert again == []
    assert (await rig.state(agent))[1] is None

    await rig.seen(agent, NOW - timedelta(minutes=30))
    silent_again = await rig.watchdog.check(datetime.now(UTC))
    assert len(silent_again) == 1 and "SILENT" in silent_again[0]


async def test_two_agents_two_messages_and_discord_down_changes_nothing(rig: Rig) -> None:
    a, _ = await rig.agent("a")
    b, _ = await rig.agent("b")
    await rig.seen(a, NOW - timedelta(minutes=9))
    await rig.seen(b, NOW - timedelta(minutes=20))
    rig.watchdog._notifier = DiscordNotifier(
        "https://discord.com/api/webhooks/1/token",
        httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
    )

    notes = await rig.watchdog.check(NOW)

    assert len(notes) == 2
    assert (await rig.state(a))[1] is not None and (await rig.state(b))[1] is not None


async def test_agents_list_shows_when_each_agent_was_last_seen(
    rig: Rig, capsys: pytest.CaptureFixture[str]
) -> None:
    seen, _ = await rig.agent("seen")
    await rig.agent("never")
    await rig.seen(seen, datetime(2026, 9, 29, 12, 34, 56, tzinfo=UTC))

    args = cli.build_parser().parse_args(["agents", "list"])
    assert await cli._agents(args, rig.registry) == 0

    out = capsys.readouterr().out
    assert "last seen 2026-09-29 12:34:56Z" in out
    assert "last seen never" in out
