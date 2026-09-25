from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel_core.api.main import create_app
from sentinel_core.auth.agent_keys import InMemoryAgentRepository, generate_agent_key
from sentinel_core.bus.raw_stream import BusFull, BusUnavailable
from sentinel_core.config import Settings
from sentinel_core.schema.event import Source
from tests.support import InMemoryPublisher

AGENT_ID = UUID("11111111-1111-1111-1111-111111111111")
LINE = "2026-09-24T15:04:05+00:00 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"


class Env:
    def __init__(self, client: AsyncClient, publisher: InMemoryPublisher, token: str) -> None:
        self.client = client
        self.publisher = publisher
        self.token = token

    def auth(self, token: str | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {token or self.token}"}

    async def post(self, body: Any, headers: dict[str, str] | None = None) -> Any:
        return await self.client.post(
            "/v1/ingest", json=body, headers=self.auth() if headers is None else headers
        )


@pytest.fixture
async def env() -> AsyncGenerator[Env]:
    key = generate_agent_key(AGENT_ID)
    repo = InMemoryAgentRepository()
    repo.add(AGENT_ID, key.secret_hash)
    publisher = InMemoryPublisher()
    app = create_app(agent_repo=repo, publisher=publisher)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield Env(client, publisher, key.token)


def batch(*origins: str, source: str = "linux.auth") -> dict[str, Any]:
    return {"source": source, "lines": [{"origin": o, "line": LINE} for o in origins]}


async def test_valid_batch_is_accepted_and_published(env: Env) -> None:
    before = datetime.now(UTC)

    response = await env.post(batch("1:0", "1:100"))

    assert response.status_code == 202
    assert response.json() == {"accepted": 2}
    logs = env.publisher.logs
    assert [log.origin for log in logs] == ["1:0", "1:100"]
    assert all(log.agent_id == AGENT_ID for log in logs)
    assert all(log.source is Source.LINUX_AUTH and log.line == LINE for log in logs)
    assert all(before <= log.received_at <= before + timedelta(seconds=30) for log in logs)


async def test_agent_identity_comes_from_the_key_never_from_the_body(env: Env) -> None:
    body = batch("1:0") | {"agent_id": str(uuid4())}

    response = await env.post(body)

    assert response.status_code == 422
    assert env.publisher.logs == []


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer garbage"}, {"Authorization": "Basic abc"}],
)
async def test_missing_or_malformed_credentials_are_rejected(
    env: Env, headers: dict[str, str]
) -> None:
    response = await env.post(batch("1:0"), headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert env.publisher.logs == []


async def test_unknown_agent_and_wrong_secret_are_indistinguishable(env: Env) -> None:
    unknown_agent = generate_agent_key(uuid4()).token
    wrong_secret = generate_agent_key(AGENT_ID).token  # right agent id, other secret

    unknown = await env.post(batch("1:0"), headers=env.auth(unknown_agent))
    wrong = await env.post(batch("1:0"), headers=env.auth(wrong_secret))

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    assert env.publisher.logs == []


async def test_default_app_fails_closed_without_an_agent_registry() -> None:
    publisher = InMemoryPublisher()
    app = create_app(publisher=publisher)  # no repository configured
    token = generate_agent_key(AGENT_ID).token

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/ingest", json=batch("1:0"), headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 401
    assert publisher.logs == []


@pytest.mark.parametrize(
    "body",
    [
        {"source": "linux.auth", "lines": []},
        {"source": "not.a.source", "lines": [{"origin": "1:0", "line": LINE}]},
        {"source": "linux.auth"},
        {"source": "linux.auth", "lines": [{"origin": "", "line": LINE}]},
        {"source": "linux.auth", "lines": [{"origin": "x" * 129, "line": LINE}]},
        {"source": "linux.auth", "lines": [{"origin": "1:0", "line": "x" * 8193}]},
        {"source": "linux.auth", "lines": [{"origin": "1:0", "line": LINE, "extra": 1}]},
    ],
)
async def test_invalid_payloads_are_rejected(env: Env, body: dict[str, Any]) -> None:
    response = await env.post(body)

    assert response.status_code == 422
    assert env.publisher.logs == []


async def test_batch_size_is_capped_at_500_lines(env: Env) -> None:
    assert (await env.post(batch(*[f"1:{i}" for i in range(500)]))).status_code == 202
    assert (await env.post(batch(*[f"2:{i}" for i in range(501)]))).status_code == 422


async def test_full_bus_answers_429_with_retry_after(env: Env) -> None:
    env.publisher.error = BusFull()

    response = await env.post(batch("1:0"))

    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 0


async def test_unavailable_bus_answers_503(env: Env) -> None:
    env.publisher.error = BusUnavailable()

    response = await env.post(batch("1:0"))

    assert response.status_code == 503


async def test_oversized_body_is_rejected_by_content_length() -> None:
    key = generate_agent_key(AGENT_ID)
    repo = InMemoryAgentRepository()
    repo.add(AGENT_ID, key.secret_hash)
    publisher = InMemoryPublisher()
    app = create_app(
        settings=Settings(ingest_max_body_bytes=1024), agent_repo=repo, publisher=publisher
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/ingest",
            content=b"x" * 2048,
            headers={"Authorization": f"Bearer {key.token}", "Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert publisher.logs == []


async def test_oversized_chunked_body_is_rejected_without_content_length() -> None:
    key = generate_agent_key(AGENT_ID)
    repo = InMemoryAgentRepository()
    repo.add(AGENT_ID, key.secret_hash)
    publisher = InMemoryPublisher()
    app = create_app(
        settings=Settings(ingest_max_body_bytes=1024), agent_repo=repo, publisher=publisher
    )

    async def chunks() -> AsyncGenerator[bytes]:
        for _ in range(10):
            yield b"x" * 512

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/ingest",
            content=chunks(),  # streamed: httpx sends Transfer-Encoding: chunked
            headers={"Authorization": f"Bearer {key.token}", "Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert publisher.logs == []
