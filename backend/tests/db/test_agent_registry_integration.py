"""Integration tests against a real Postgres.

Run locally with, e.g.:
    docker run -d --rm --name sl-test-pg -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test \
        -e POSTGRES_DB=test -p 127.0.0.1:5440:5432 postgres:16-alpine
    SENTINEL_TEST_DATABASE_URL=postgresql+asyncpg://test:test@127.0.0.1:5440/test \
        uv run pytest -m integration
In CI the URL is provided by a Postgres service container.
"""

from uuid import UUID

import pytest
from alembic import command
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core import cli
from sentinel_core.api.main import create_app
from sentinel_core.auth.agent_keys import hash_secret, parse_bearer_token
from sentinel_core.auth.registry import AgentNameTaken, PostgresAgentRepository
from sentinel_core.config import get_settings
from tests.support import DATABASE_URL, InMemoryPublisher, alembic_config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

LINE = "2026-09-24T15:04:05+00:00 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"


@pytest.fixture
def registry(engine: AsyncEngine) -> PostgresAgentRepository:
    return PostgresAgentRepository(async_sessionmaker(engine, expire_on_commit=False))


async def test_created_agent_gets_a_key_that_verifies_against_the_stored_hash(
    registry: PostgresAgentRepository,
) -> None:
    created = await registry.create_agent(name="ubuntu-01", os="linux")

    credentials = parse_bearer_token(f"Bearer {created.token}")
    assert credentials is not None
    assert credentials.agent_id == created.agent.id
    assert await registry.get_key_hash(created.agent.id) == hash_secret(credentials.secret)


async def test_only_the_hash_is_stored_never_the_key(
    registry: PostgresAgentRepository, engine: AsyncEngine
) -> None:
    created = await registry.create_agent(name="ubuntu-01", os="linux")
    secret = created.token.split(".", 1)[1]

    async with engine.connect() as conn:
        rows = (await conn.execute(text("SELECT * FROM agents"))).all()

    dump = " ".join(str(value) for row in rows for value in row)
    assert secret not in dump
    assert created.token not in dump


async def test_unknown_agent_has_no_key_hash(registry: PostgresAgentRepository) -> None:
    assert await registry.get_key_hash(UUID(int=42)) is None


async def test_revoked_agent_is_treated_as_unknown(registry: PostgresAgentRepository) -> None:
    created = await registry.create_agent(name="ubuntu-01", os="linux")

    assert await registry.revoke_agent(created.agent.id) is True

    assert await registry.get_key_hash(created.agent.id) is None


async def test_revoking_twice_or_an_unknown_agent_reports_false(
    registry: PostgresAgentRepository,
) -> None:
    created = await registry.create_agent(name="ubuntu-01", os="linux")
    await registry.revoke_agent(created.agent.id)

    assert await registry.revoke_agent(created.agent.id) is False
    assert await registry.revoke_agent(UUID(int=42)) is False


async def test_agent_names_are_unique(registry: PostgresAgentRepository) -> None:
    await registry.create_agent(name="ubuntu-01", os="linux")

    with pytest.raises(AgentNameTaken):
        await registry.create_agent(name="ubuntu-01", os="windows")


async def test_list_agents_exposes_status_but_no_key_material(
    registry: PostgresAgentRepository,
) -> None:
    active = await registry.create_agent(name="a-active", os="linux")
    revoked = await registry.create_agent(name="b-revoked", os="windows")
    await registry.revoke_agent(revoked.agent.id)

    agents = await registry.list_agents()

    assert [(a.name, a.os, a.revoked_at is not None) for a in agents] == [
        ("a-active", "linux", False),
        ("b-revoked", "windows", True),
    ]
    assert agents[0].id == active.agent.id
    assert not any(hasattr(a, "key_hash") or hasattr(a, "token") for a in agents)


async def test_database_rejects_an_unknown_os(engine: AsyncEngine) -> None:
    registry = PostgresAgentRepository(async_sessionmaker(engine, expire_on_commit=False))

    with pytest.raises(ValueError, match="os"):
        await registry.create_agent(name="x", os="plan9")


async def test_end_to_end_create_ingest_revoke_reject(
    registry: PostgresAgentRepository,
) -> None:
    created = await registry.create_agent(name="ubuntu-01", os="linux")
    publisher = InMemoryPublisher()
    app = create_app(agent_repo=registry, publisher=publisher)
    body = {"source": "linux.auth", "lines": [{"origin": "1:0", "line": LINE}]}
    headers = {"Authorization": f"Bearer {created.token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        accepted = await client.post("/v1/ingest", json=body, headers=headers)
        await registry.revoke_agent(created.agent.id)
        rejected = await client.post("/v1/ingest", json=body, headers=headers)

    assert accepted.status_code == 202
    assert [log.agent_id for log in publisher.logs] == [created.agent.id]
    assert rejected.status_code == 401
    assert len(publisher.logs) == 1  # nothing published after revocation


def test_cli_creates_lists_and_revokes_agents(
    engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert DATABASE_URL is not None
    monkeypatch.setenv("SENTINEL_DATABASE_URL", DATABASE_URL)
    get_settings.cache_clear()
    try:
        assert cli.main(["agents", "create", "--name", "cli-agent", "--os", "linux"]) == 0
        created = capsys.readouterr()
        token = next(
            line.removeprefix("key: ").strip()
            for line in created.out.splitlines()
            if line.startswith("key: ")
        )
        credentials = parse_bearer_token(f"Bearer {token}")
        assert credentials is not None
        agent_id = credentials.agent_id

        assert cli.main(["agents", "list"]) == 0
        listing = capsys.readouterr().out
        assert "cli-agent" in listing and str(agent_id) in listing
        assert credentials.secret not in listing  # the key is only ever shown at creation

        assert cli.main(["agents", "revoke", str(agent_id)]) == 0
        capsys.readouterr()
        assert cli.main(["agents", "revoke", str(agent_id)]) == 1  # already revoked
    finally:
        get_settings.cache_clear()


def test_models_match_the_migrations(engine: AsyncEngine) -> None:
    config = alembic_config()

    command.check(config)  # fails if the models drifted from the migrations
