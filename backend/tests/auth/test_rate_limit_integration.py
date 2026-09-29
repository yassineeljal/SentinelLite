"""Real shared counters: concurrency, independent scopes, expiry and fail-closed HTTP routes."""

import asyncio
from collections.abc import AsyncGenerator
from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.api import security
from sentinel_core.api.main import create_app
from sentinel_core.auth.agent_keys import DenyAllAgentRepository
from sentinel_core.auth.rate_limit import TooManyAttempts, check_attempts
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import Settings
from tests.support import DATABASE_URL, InMemoryPublisher

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]
PASSWORD = "correct horse battery staple"  # noqa: S105


@pytest.fixture
async def client(engine: AsyncEngine) -> AsyncGenerator[AsyncClient]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    users = PostgresUserRepository(sessions)
    await users.create_user("known@example.test", PASSWORD, "analyst")
    app = create_app(
        settings=Settings(
            database_url=str(engine.url),
            session_cookie_secure=False,
            auth_account_attempts=3,
            auth_ip_attempts=8,
        ),
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=sessions,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def test_shared_budget_is_atomic_under_concurrency(engine: AsyncEngine) -> None:
    async def attempt() -> bool:
        # Independent factories stand in for separate API processes.
        try:
            await check_attempts(async_sessionmaker(engine), {"account:x": 5, "peer:x": 100}, 300)
        except TooManyAttempts:
            return False
        return True

    result = await asyncio.gather(*(attempt() for _ in range(20)))
    assert sum(result) == 5
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM auth_rate_limits"))).scalar_one() == 2


async def test_expiry_allows_retry_and_prunes_old_identifiers(engine: AsyncEngine) -> None:
    sessions = async_sessionmaker(engine)
    await check_attempts(sessions, {"account:x": 1}, 300)
    with pytest.raises(TooManyAttempts) as caught:
        await check_attempts(sessions, {"account:x": 1}, 300)
    assert 1 <= caught.value.retry_after <= 300
    async with engine.begin() as conn:
        before: datetime = (
            await conn.execute(text("SELECT expires_at FROM auth_rate_limits"))
        ).scalar_one()
    with pytest.raises(TooManyAttempts):
        await check_attempts(sessions, {"account:x": 1}, 300)
    async with engine.begin() as conn:
        assert (
            await conn.execute(text("SELECT expires_at FROM auth_rate_limits"))
        ).scalar_one() == before
        await conn.execute(
            text("UPDATE auth_rate_limits SET expires_at = now() - interval '1 second'")
        )
    await check_attempts(sessions, {"account:y": 1}, 300)
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM auth_rate_limits"))).scalar_one() == 1


async def test_email_case_and_whitespace_do_not_bypass_limits(client: AsyncClient) -> None:
    for email in ("known@example.test", "KNOWN@example.test", " known@example.test "):
        result = await client.post("/v1/auth/login", json={"email": email, "password": "wrong"})
        assert result.status_code == 401
    response = await client.post(
        "/v1/auth/login", json={"email": "known@example.test", "password": PASSWORD}
    )
    assert response.status_code == 429
    assert 1 <= int(response.headers["retry-after"]) <= 300
    assert "set-cookie" not in response.headers


async def test_unknown_accounts_get_the_same_limit(client: AsyncClient) -> None:
    for _ in range(3):
        response = await client.post(
            "/v1/auth/login", json={"email": "missing@example.test", "password": PASSWORD}
        )
        assert response.status_code == 401
    response = await client.post(
        "/v1/auth/login", json={"email": "missing@example.test", "password": PASSWORD}
    )
    assert response.status_code == 429


async def test_source_budget_limits_password_spraying_and_ignores_forwarded_header(
    client: AsyncClient,
) -> None:
    for index in range(8):
        response = await client.post(
            "/v1/auth/login",
            json={"email": f"u{index}@example.test", "password": PASSWORD},
            headers={"X-Forwarded-For": f"203.0.113.{index}"},
        )
        assert response.status_code == 401
    response = await client.post(
        "/v1/auth/login", json={"email": "known@example.test", "password": PASSWORD}
    )
    assert response.status_code == 429


async def test_success_does_not_reset_the_budget(client: AsyncClient) -> None:
    for _ in range(3):
        assert (
            await client.post(
                "/v1/auth/login", json={"email": "known@example.test", "password": PASSWORD}
            )
        ).status_code == 200
    assert (
        await client.post(
            "/v1/auth/login", json={"email": "known@example.test", "password": PASSWORD}
        )
    ).status_code == 429


async def test_mfa_management_attempts_are_limited_even_for_valid_sessions(
    client: AsyncClient,
) -> None:
    assert (
        await client.post(
            "/v1/auth/login", json={"email": "known@example.test", "password": PASSWORD}
        )
    ).status_code == 200
    for _ in range(3):
        assert (
            await client.post("/v1/auth/2fa/setup", json={"password": "wrong"})
        ).status_code == 401
    assert (await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})).status_code == 429


async def test_unavailable_limiter_fails_closed(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable(*args: object) -> None:
        raise OperationalError("test outage", {}, Exception("offline"))

    monkeypatch.setattr(security, "check_attempts", unavailable)
    response = await client.post(
        "/v1/auth/login", json={"email": "known@example.test", "password": PASSWORD}
    )
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
