"""Real database + HTTP coverage of authentication boundaries and factor lifecycle."""

import asyncio
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pyotp
import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.api.auth import COOKIE_NAME
from sentinel_core.api.main import create_app
from sentinel_core.auth import mfa, user_registry
from sentinel_core.auth.agent_keys import DenyAllAgentRepository
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import Settings
from tests.support import DATABASE_URL, InMemoryPublisher

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]
PASSWORD = "correct horse battery staple"  # noqa: S105
EMAIL = "mfa@example.test"
NOW = datetime(2099, 1, 1, tzinfo=UTC)
KEY = Fernet.generate_key().decode()


class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz: object = None) -> datetime:  # type: ignore[override]
        return NOW


@pytest.fixture
async def client(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> AsyncGenerator[AsyncClient]:
    monkeypatch.setattr(mfa, "datetime", FixedDateTime)
    monkeypatch.setattr(user_registry, "datetime", FixedDateTime)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    users = PostgresUserRepository(sessions)
    await users.create_user(EMAIL, PASSWORD, "analyst")
    app = create_app(
        settings=Settings(
            database_url=str(engine.url),
            session_cookie_secure=False,
            mfa_encryption_key=SecretStr(KEY),
            auth_account_attempts=100,
            auth_ip_attempts=1000,
        ),
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=sessions,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def login(client: AsyncClient, code: str = "", password: str = PASSWORD) -> int:
    response = await client.post(
        "/v1/auth/login",
        json={
            "email": EMAIL,
            "password": password,
            "code": code,
        },
    )
    return response.status_code


async def enable(client: AsyncClient) -> tuple[str, list[str]]:
    assert await login(client) == 200
    setup = await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert pyotp.parse_uri(setup.json()["provisioning_uri"]).secret == secret
    # Confirm with the previous accepted time step so the current code can log in next.
    result = await client.post(
        "/v1/auth/2fa/confirm",
        json={
            "password": PASSWORD,
            "code": pyotp.TOTP(secret).at(int(NOW.timestamp()) - 30),
        },
    )
    assert result.status_code == 200
    assert result.headers["cache-control"] == "no-store"
    return secret, result.json()["recovery_codes"]


async def test_complete_lifecycle_and_no_password_only_bypass(client: AsyncClient) -> None:
    secret, codes = await enable(client)
    status = (await client.get("/v1/auth/2fa")).json()
    assert status == {"enabled": True, "setup_available": True, "recovery_codes_remaining": 10}
    assert len(codes) == len(set(codes)) == 10
    await client.post("/v1/auth/logout")
    assert await login(client) == 401
    assert (await client.get("/v1/alerts")).status_code == 401
    assert await login(client, "000000") == 401
    code = pyotp.TOTP(secret).at(NOW)
    assert await login(client, code) == 200
    await client.post("/v1/auth/logout")
    assert await login(client, code) == 401  # replay
    assert await login(client, codes[0], password="wrong password") == 401  # noqa: S106
    assert await login(client, codes[0]) == 200  # wrong password didn't consume it
    assert (await client.get("/v1/auth/2fa")).json()["recovery_codes_remaining"] == 9
    await client.post("/v1/auth/logout")
    assert await login(client, codes[0]) == 401
    assert await login(client, codes[1].upper().replace("-", "")) == 200
    disabled = await client.post(
        "/v1/auth/2fa/disable", json={"password": PASSWORD, "code": codes[2]}
    )
    assert disabled.status_code == 204
    assert (await client.get("/v1/auth/2fa")).json()["enabled"] is False
    await client.post("/v1/auth/logout")
    assert await login(client) == 200


async def test_secrets_are_encrypted_codes_hashed_and_public_responses_contain_neither(
    client: AsyncClient,
    engine: AsyncEngine,
) -> None:
    secret, codes = await enable(client)
    async with engine.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM users WHERE email = :e"), {"e": EMAIL})).one()
    assert secret not in row.totp_secret
    assert all(code not in str(row.recovery_code_hashes) for code in codes)
    assert row.totp_pending_secret is None
    for path in ("/v1/auth/me", "/v1/auth/2fa"):
        response = await client.get(path)
        assert secret not in response.text and not any(code in response.text for code in codes)
        assert response.headers["cache-control"] == "no-store"


async def test_setup_requires_password_and_activation_requires_code(client: AsyncClient) -> None:
    assert await login(client) == 200
    assert (await client.post("/v1/auth/2fa/setup", json={"password": "wrong"})).status_code == 401
    setup = await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})
    assert setup.status_code == 200
    assert (await client.get("/v1/auth/2fa")).json()["enabled"] is False
    assert (
        await client.post("/v1/auth/2fa/confirm", json={"password": PASSWORD, "code": "wrong"})
    ).status_code == 401
    assert (await client.get("/v1/auth/2fa")).json()["enabled"] is False
    await client.post("/v1/auth/logout")
    assert await login(client) == 200  # pending enrollment never locks out the account


async def test_enrollment_is_session_bound_and_expires(
    client: AsyncClient, engine: AsyncEngine
) -> None:
    await login(client)
    setup = (await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})).json()
    original = client.cookies.get(COOKIE_NAME)
    await login(client)  # different valid session, same user
    payload = {"password": PASSWORD, "code": pyotp.TOTP(setup["secret"]).at(NOW)}
    assert (await client.post("/v1/auth/2fa/confirm", json=payload)).status_code == 401
    client.cookies.clear()
    assert original is not None
    client.cookies.set(COOKIE_NAME, original, domain="test.local")
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET totp_pending_expires_at = now() - interval '1 hour'")
        )
    assert (await client.post("/v1/auth/2fa/confirm", json=payload)).status_code == 401


async def test_restarting_setup_invalidates_the_previous_secret(client: AsyncClient) -> None:
    await login(client)
    first = (await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})).json()
    second = (await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})).json()
    assert first["secret"] != second["secret"]
    response = await client.post(
        "/v1/auth/2fa/confirm",
        json={
            "password": PASSWORD,
            "code": pyotp.TOTP(first["secret"]).at(NOW),
        },
    )
    assert response.status_code == 401


async def test_activation_and_regeneration_revoke_old_sessions_and_codes(
    client: AsyncClient,
) -> None:
    await login(client)
    old_cookie = client.cookies.get(COOKIE_NAME)
    _, codes = await enable(client)
    active_cookie = client.cookies.get(COOKIE_NAME)
    assert active_cookie != old_cookie
    client.cookies.clear()
    assert old_cookie is not None
    client.cookies.set(COOKIE_NAME, old_cookie, domain="test.local")
    assert (await client.get("/v1/auth/me")).status_code == 401
    assert active_cookie is not None
    client.cookies.clear()
    client.cookies.set(COOKIE_NAME, active_cookie, domain="test.local")
    result = await client.post(
        "/v1/auth/2fa/recovery-codes", json={"password": PASSWORD, "code": codes[0]}
    )
    assert result.status_code == 200
    replacement = result.json()["recovery_codes"]
    assert not set(replacement) & set(codes)
    rotated = client.cookies.get(COOKIE_NAME)
    assert rotated != active_cookie
    client.cookies.clear()
    client.cookies.set(COOKIE_NAME, active_cookie, domain="test.local")
    assert (await client.get("/v1/auth/me")).status_code == 401
    assert await login(client, codes[1]) == 401
    assert await login(client, replacement[0]) == 200


@pytest.mark.parametrize("endpoint", ["disable", "recovery-codes"])
async def test_management_needs_both_password_and_unused_factor(
    client: AsyncClient, endpoint: str
) -> None:
    _, codes = await enable(client)
    path = f"/v1/auth/2fa/{endpoint}"
    for password, code in (("wrong", codes[0]), (PASSWORD, ""), (PASSWORD, "invalid")):
        result = await client.post(path, json={"password": password, "code": code})
        assert result.status_code in (401, 422)
    assert (await client.get("/v1/auth/2fa")).json()["recovery_codes_remaining"] == 10
    assert (await client.post(path, json={"password": PASSWORD, "code": codes[0]})).status_code in (
        200,
        204,
    )


@pytest.mark.parametrize("use_recovery", [True, False])
async def test_concurrent_use_of_one_code_creates_only_one_session(
    client: AsyncClient, use_recovery: bool, engine: AsyncEngine
) -> None:
    secret, codes = await enable(client)
    await client.post("/v1/auth/logout")
    code = codes[0] if use_recovery else pyotp.TOTP(secret).at(NOW)
    results = await asyncio.gather(login(client, code), login(client, code))
    assert sorted(results) == [200, 401]
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM user_sessions"))).scalar_one() == 1


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "", None),
        ("POST", "/setup", {"password": PASSWORD}),
        ("POST", "/confirm", {"password": PASSWORD, "code": "123456"}),
        ("POST", "/disable", {"password": PASSWORD, "code": "123456"}),
        ("POST", "/recovery-codes", {"password": PASSWORD, "code": "123456"}),
    ],
)
async def test_every_mfa_route_requires_a_full_session(
    client: AsyncClient,
    method: str,
    path: str,
    body: dict[str, str] | None,
) -> None:
    result = await client.request(method, "/v1/auth/2fa" + path, json=body)
    assert result.status_code == 401


async def test_missing_key_never_bypasses_enabled_mfa_and_recovery_still_works(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret, codes = await enable(client)
    # Replace only the box used by HTTP requests; stored ciphertext remains untouched.
    from sentinel_core.api import auth as auth_api
    from sentinel_core.auth.totp import SecretBox

    monkeypatch.setattr(auth_api, "SecretBox", lambda _: SecretBox(None))
    await client.post("/v1/auth/logout")
    assert await login(client, pyotp.TOTP(secret).at(NOW)) == 503
    assert (await client.get("/v1/auth/me")).status_code == 401
    assert await login(client, codes[0]) == 200


async def test_no_setup_key_means_unavailable_not_unencrypted_enrollment(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinel_core.api import mfa as mfa_api
    from sentinel_core.auth.totp import SecretBox

    monkeypatch.setattr(mfa_api, "SecretBox", lambda _: SecretBox(None))
    assert await login(client) == 200
    assert (await client.get("/v1/auth/2fa")).json()["setup_available"] is False
    result = await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})
    assert result.status_code == 503
    assert "secret" not in result.json()
    assert (await client.get("/v1/auth/2fa")).json()["enabled"] is False


async def test_revocation_racing_with_login_cannot_leave_a_live_session(
    client: AsyncClient,
    engine: AsyncEngine,
) -> None:
    users = PostgresUserRepository(async_sessionmaker(engine, expire_on_commit=False))
    user = (await users.list_users())[0]
    _, result = await asyncio.gather(users.revoke_user(user.id), login(client))
    assert result in (200, 401)
    assert (await client.get("/v1/auth/me")).status_code == 401


async def test_enabling_mfa_racing_with_password_login_leaves_only_confirmed_session(
    client: AsyncClient,
    engine: AsyncEngine,
) -> None:
    await login(client)
    setup = (await client.post("/v1/auth/2fa/setup", json={"password": PASSWORD})).json()
    users = PostgresUserRepository(async_sessionmaker(engine, expire_on_commit=False))
    from datetime import timedelta

    from sentinel_core.auth.totp import SecretBox

    confirmed, password_login = await asyncio.gather(
        client.post(
            "/v1/auth/2fa/confirm",
            json={
                "password": PASSWORD,
                "code": pyotp.TOTP(setup["secret"]).at(NOW),
            },
        ),
        users.login(EMAIL, PASSWORD, "", timedelta(hours=1), SecretBox(SecretStr(KEY))),
    )
    assert confirmed.status_code == 200
    if password_login is not None:
        assert await users.resolve_session(password_login[1]) is None
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM user_sessions"))).scalar_one() == 1
