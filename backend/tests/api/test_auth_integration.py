"""`/v1/auth/*` and `/v1/alerts` against a real Postgres. See
tests/db/test_agent_registry_integration.py for how to run these locally."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.api.auth import COOKIE_NAME
from sentinel_core.api.main import create_app
from sentinel_core.auth.agent_keys import DenyAllAgentRepository
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import Settings
from sentinel_core.db.alerts import insert_alerts
from sentinel_core.detection.alerts import Alert
from tests.support import DATABASE_URL, InMemoryPublisher

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

PASSWORD = "correct horse battery staple"  # noqa: S105
T0 = datetime(2026, 9, 24, 15, 0, tzinfo=UTC)


def alert(alert_id: str, rule_id: str = "ssh-bruteforce") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        title="SSH brute force",
        mitre=["T1110"],
        severity=60,
        ts=T0,
        group={"src_ip": "203.0.113.7"},
        src_ip="203.0.113.7",
        event_ids=["00" * 32],
        match_count=5,
    )


@pytest.fixture
def users(engine: AsyncEngine) -> PostgresUserRepository:
    return PostgresUserRepository(async_sessionmaker(engine, expire_on_commit=False))


@pytest.fixture
async def client(engine: AsyncEngine, users: PostgresUserRepository) -> AsyncGenerator[AsyncClient]:
    app = create_app(
        settings=Settings(
            database_url=str(engine.url), session_cookie_secure=False
        ),  # httpx enforces Secure like a real browser: http://test needs it off
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=async_sessionmaker(engine, expire_on_commit=False),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def test_login_sets_a_cookie_and_returns_the_user(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("alice@example.com", PASSWORD, "analyst")

    response = await client.post(
        "/v1/auth/login", json={"email": "alice@example.com", "password": PASSWORD}
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": response.json()["id"],
        "email": "alice@example.com",
        "role": "analyst",
    }
    assert UUID(response.json()["id"])
    cookie = response.cookies.get(COOKIE_NAME)
    assert cookie is not None
    assert response.headers["set-cookie"].lower().count("httponly") == 1
    assert "samesite=strict" in response.headers["set-cookie"].lower()


async def test_the_cookie_authenticates_subsequent_requests(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("bob@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "bob@example.com", "password": PASSWORD})

    me = await client.get("/v1/auth/me")

    assert me.status_code == 200 and me.json()["email"] == "bob@example.com"


async def test_a_wrong_password_is_rejected_with_a_generic_message(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("carol@example.com", PASSWORD, "analyst")

    wrong_password = await client.post(
        "/v1/auth/login", json={"email": "carol@example.com", "password": "the wrong one"}
    )
    unknown_email = await client.post(
        "/v1/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json()["detail"] == unknown_email.json()["detail"]
    assert COOKIE_NAME not in wrong_password.cookies


async def test_me_without_a_session_is_rejected(client: AsyncClient) -> None:
    response = await client.get("/v1/auth/me")

    assert response.status_code == 401


async def test_a_malformed_cookie_is_rejected_not_trusted(client: AsyncClient) -> None:
    client.cookies.set(COOKIE_NAME, "not-a-real-session-token")

    response = await client.get("/v1/auth/me")

    assert response.status_code == 401


async def test_logout_ends_the_session(client: AsyncClient, users: PostgresUserRepository) -> None:
    await users.create_user("dave@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "dave@example.com", "password": PASSWORD})

    logout = await client.post("/v1/auth/logout")
    after = await client.get("/v1/auth/me")

    assert logout.status_code == 204
    assert after.status_code == 401


async def test_alerts_requires_authentication(client: AsyncClient) -> None:
    response = await client.get("/v1/alerts")

    assert response.status_code == 401


async def test_alerts_lists_the_stored_alerts_once_logged_in(
    client: AsyncClient, users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    async with async_sessionmaker(engine, expire_on_commit=False).begin() as session:
        await insert_alerts(session, [alert("ab" * 32), alert("cd" * 32, "ssh-root-login")])
    await users.create_user("erin@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "erin@example.com", "password": PASSWORD})

    listed = await client.get("/v1/alerts")
    filtered = await client.get("/v1/alerts", params={"rule": "ssh-root-login"})

    assert listed.status_code == 200 and len(listed.json()) == 2
    assert [a["rule_id"] for a in filtered.json()] == ["ssh-root-login"]
    assert listed.json()[0]["src_ip"] == "203.0.113.7"


async def test_a_revoked_users_session_stops_working(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    created = await users.create_user("frank@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "frank@example.com", "password": PASSWORD})

    await users.revoke_user(created.id)
    response = await client.get("/v1/auth/me")

    assert response.status_code == 401


async def test_an_unknown_field_in_the_login_body_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/login",
        json={"email": "x@example.com", "password": PASSWORD, "remember_me": True},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "body", [{"email": "not-an-email", "password": PASSWORD}, {"email": "x@example.com"}]
)
async def test_a_malformed_login_body_is_rejected(
    client: AsyncClient, body: dict[str, str]
) -> None:
    response = await client.post("/v1/auth/login", json=body)

    assert response.status_code == 422


async def test_the_secure_flag_is_set_by_default(
    engine: AsyncEngine, users: PostgresUserRepository
) -> None:
    """`session_cookie_secure` defaults to True: the cookie must carry `Secure` unless the
    operator explicitly turns it off (for a plain-HTTP lab; see docs/OPERATIONS.md)."""
    app = create_app(
        settings=Settings(database_url=str(engine.url)),  # default: session_cookie_secure=True
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=async_sessionmaker(engine, expire_on_commit=False),
    )
    await users.create_user("grace@example.com", PASSWORD, "analyst")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/login", json={"email": "grace@example.com", "password": PASSWORD}
        )

    assert "secure" in response.headers["set-cookie"].lower()


async def test_a_local_lab_domain_is_accepted_not_just_real_ones(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    """This is a login identifier, not a deliverable address: a self-hosted lab may use
    reserved/internal TLDs (.local, .internal, .test...) that a real email validator would
    refuse as "special-use"."""
    await users.create_user("admin@sentinellite.local", PASSWORD, "admin")

    response = await client.post(
        "/v1/auth/login", json={"email": "admin@sentinellite.local", "password": PASSWORD}
    )

    assert response.status_code == 200 and response.json()["email"] == "admin@sentinellite.local"
