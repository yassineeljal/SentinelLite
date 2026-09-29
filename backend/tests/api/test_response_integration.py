"""The dashboard's view of the response: everyone signed in can look, only admins can change."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.api.main import create_app
from sentinel_core.auth.agent_keys import DenyAllAgentRepository
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import Settings
from sentinel_core.db.responses import record_block
from tests.support import DATABASE_URL, InMemoryPublisher

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]
PASSWORD = "correct horse battery staple"  # noqa: S105
ATTACKER = "45.83.64.10"


class Rig:
    def __init__(self, engine: AsyncEngine, client: AsyncClient) -> None:
        self.engine, self.client = engine, client
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def block(
        self, ip: str = ATTACKER, tag: str = "a", mode: str = "enforce", ttl_hours: float = 1
    ) -> None:
        async with self.sessions.begin() as session:
            await record_block(
                session,
                ip=ip,
                alert_id=tag * 64,
                rule_id="ssh-bruteforce",
                reason="ssh-bruteforce: SSH brute force (9 event(s), severity 60)",
                mode=mode,
                now=datetime.now(UTC),
                ttl=timedelta(hours=ttl_hours),
            )

    async def rows(self, sql: str) -> list[tuple[object, ...]]:
        async with self.engine.connect() as conn:
            return [tuple(r) for r in (await conn.execute(text(sql))).all()]

    async def login(self, role: str) -> None:
        result = await self.client.post(
            "/v1/auth/login", json={"email": f"{role}@example.com", "password": PASSWORD}
        )
        assert result.status_code == 200


@pytest.fixture
async def rig(engine: AsyncEngine) -> AsyncGenerator[Rig]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    users = PostgresUserRepository(sessions)
    await users.create_user("analyst@example.com", PASSWORD, "analyst")
    await users.create_user("admin@example.com", PASSWORD, "admin")
    app = create_app(
        settings=Settings(database_url=str(engine.url), session_cookie_secure=False),
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=sessions,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield Rig(engine, client)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/v1/response/blocks", None),
        ("POST", "/v1/response/blocks/unblock", {"address": ATTACKER}),
        ("GET", "/v1/response/allowlist", None),
        ("POST", "/v1/response/allowlist", {"cidr": "198.51.100.0/24"}),
        ("DELETE", "/v1/response/allowlist?cidr=198.51.100.0/24", None),
    ],
)
async def test_every_route_requires_a_session(
    rig: Rig, method: str, path: str, body: dict[str, str] | None
) -> None:
    assert (await rig.client.request(method, path, json=body)).status_code == 401


async def test_an_analyst_can_look_but_not_change(rig: Rig) -> None:
    await rig.block()
    await rig.login("analyst")

    listed = (await rig.client.get("/v1/response/blocks")).json()
    assert [(b["ip"], b["state"], b["mode"]) for b in listed] == [(ATTACKER, "active", "enforce")]
    assert (await rig.client.get("/v1/response/allowlist")).json() == []

    unblock = await rig.client.post("/v1/response/blocks/unblock", json={"address": ATTACKER})
    add = await rig.client.post("/v1/response/allowlist", json={"cidr": "198.51.100.0/24"})
    remove = await rig.client.delete("/v1/response/allowlist?cidr=198.51.100.0/24")
    assert (unblock.status_code, add.status_code, remove.status_code) == (403, 403, 403)
    assert (await rig.rows("SELECT released_at FROM blocked_ips")) == [(None,)]
    assert await rig.rows("SELECT 1 FROM audit_log") == []


async def test_an_admin_unblocks_and_it_is_audited_under_their_name(rig: Rig) -> None:
    await rig.block()
    await rig.login("admin")

    done = await rig.client.post("/v1/response/blocks/unblock", json={"address": ATTACKER})

    assert done.status_code == 204
    ((by,),) = await rig.rows("SELECT released_by FROM blocked_ips")
    assert by == "user:admin@example.com"
    ((who, action, target),) = await rig.rows("SELECT actor, action, target FROM audit_log")
    assert (who, action, target) == ("user:admin@example.com", "unblock.manual", ATTACKER)
    (listed,) = (await rig.client.get("/v1/response/blocks")).json()
    assert listed["state"] == "released" and listed["released_by"] == "user:admin@example.com"
    again = await rig.client.post("/v1/response/blocks/unblock", json={"address": ATTACKER})
    assert again.status_code == 404  # nothing left to lift


@pytest.mark.parametrize("value", ["not-an-ip", "1.2.3.0/24", "1.2.3.4; DROP TABLE x", "", " "])
async def test_unblock_refuses_what_is_not_an_address(rig: Rig, value: str) -> None:
    await rig.login("admin")

    result = await rig.client.post("/v1/response/blocks/unblock", json={"address": value})

    assert result.status_code == 422


async def test_the_states_of_a_block(rig: Rig) -> None:
    await rig.block(ip="45.83.64.1", tag="a")
    await rig.block(ip="45.83.64.2", tag="b")
    await rig.block(ip="45.83.64.3", tag="c", mode="dry_run")
    async with rig.engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE blocked_ips SET expires_at = now() - interval '1 minute' "
                "WHERE alert_id = :a"
            ),
            {"a": "b" * 64},
        )
    await rig.login("analyst")

    states = {
        b["ip"]: (b["state"], b["mode"])
        for b in (await rig.client.get("/v1/response/blocks")).json()
    }

    assert states == {
        "45.83.64.1": ("active", "enforce"),
        "45.83.64.2": ("expired", "enforce"),
        "45.83.64.3": ("active", "dry_run"),
    }


async def test_the_limit_is_bounded(rig: Rig) -> None:
    await rig.login("analyst")
    assert (await rig.client.get("/v1/response/blocks?limit=0")).status_code == 422
    assert (await rig.client.get("/v1/response/blocks?limit=201")).status_code == 422


async def test_an_admin_manages_the_allowlist_with_an_audit_trail(rig: Rig) -> None:
    await rig.login("admin")

    added = await rig.client.post(
        "/v1/response/allowlist", json={"cidr": "198.51.100.0/24", "note": "  the office  "}
    )
    assert added.status_code == 201
    assert added.json()["note"] == "the office"
    assert added.json()["created_by"] == "user:admin@example.com"
    dup = await rig.client.post("/v1/response/allowlist", json={"cidr": "198.51.100.0/24"})
    assert dup.status_code == 409
    bad = await rig.client.post("/v1/response/allowlist", json={"cidr": "oops"})
    assert bad.status_code == 422
    listed = (await rig.client.get("/v1/response/allowlist")).json()
    assert [e["cidr"] for e in listed] == ["198.51.100.0/24"]

    assert (
        await rig.client.delete("/v1/response/allowlist?cidr=198.51.100.0/24")
    ).status_code == 204
    assert (
        await rig.client.delete("/v1/response/allowlist?cidr=198.51.100.0/24")
    ).status_code == 404
    assert (await rig.client.delete("/v1/response/allowlist?cidr=oops")).status_code == 422
    audited = await rig.rows("SELECT actor, action FROM audit_log ORDER BY id")
    assert audited == [
        ("user:admin@example.com", "allowlist.add"),
        ("user:admin@example.com", "allowlist.remove"),
    ]


async def test_unknown_fields_are_refused(rig: Rig) -> None:
    await rig.login("admin")
    result = await rig.client.post(
        "/v1/response/blocks/unblock", json={"address": ATTACKER, "actor": "someone else"}
    )
    assert result.status_code == 422
