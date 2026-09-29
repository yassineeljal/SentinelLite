"""Users and sessions against a real Postgres. See tests/db/test_agent_registry_integration.py
for how to run these locally."""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.auth.passwords import WeakPassword
from sentinel_core.auth.sessions import hash_session_token
from sentinel_core.auth.user_registry import EmailTaken, PostgresUserRepository
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

PASSWORD = "correct horse battery staple"  # noqa: S105


@pytest.fixture
def users(engine: AsyncEngine) -> PostgresUserRepository:
    return PostgresUserRepository(async_sessionmaker(engine, expire_on_commit=False))


async def test_a_created_user_can_authenticate(users: PostgresUserRepository) -> None:
    created = await users.create_user("Alice@Example.com", PASSWORD, "analyst")

    found = await users.authenticate("alice@example.com", PASSWORD)  # normalized: case-insensitive

    assert found == created
    assert created.email == "alice@example.com"  # stored lowercased


async def test_the_wrong_password_does_not_authenticate(users: PostgresUserRepository) -> None:
    await users.create_user("bob@example.com", PASSWORD, "analyst")

    assert await users.authenticate("bob@example.com", "the wrong password entirely") is None


async def test_an_unknown_email_does_not_authenticate(users: PostgresUserRepository) -> None:
    assert await users.authenticate("nobody@example.com", PASSWORD) is None


async def test_a_revoked_user_can_no_longer_authenticate(users: PostgresUserRepository) -> None:
    created = await users.create_user("carol@example.com", PASSWORD, "analyst")

    assert await users.revoke_user(created.id) is True

    assert await users.authenticate("carol@example.com", PASSWORD) is None
    assert await users.revoke_user(created.id) is False  # already revoked


async def test_revoking_a_user_also_revokes_every_one_of_their_sessions(
    users: PostgresUserRepository,
) -> None:
    created = await users.create_user("dave@example.com", PASSWORD, "analyst")
    token = await users.create_session(created.id, timedelta(hours=1))
    assert await users.resolve_session(token) == created

    await users.revoke_user(created.id)

    assert await users.resolve_session(token) is None


async def test_revoking_an_unknown_user_is_reported_as_such(users: PostgresUserRepository) -> None:
    assert await users.revoke_user(uuid4()) is False


async def test_the_same_email_cannot_be_used_twice(users: PostgresUserRepository) -> None:
    await users.create_user("erin@example.com", PASSWORD, "analyst")

    with pytest.raises(EmailTaken):
        await users.create_user("ERIN@example.com", PASSWORD, "analyst")  # normalized, still taken


async def test_an_invalid_role_is_refused(users: PostgresUserRepository) -> None:
    with pytest.raises(ValueError, match="role"):
        await users.create_user("frank@example.com", PASSWORD, "superadmin")


async def test_an_invalid_email_is_refused(users: PostgresUserRepository) -> None:
    with pytest.raises(ValueError, match="email"):
        await users.create_user("not-an-email", PASSWORD, "analyst")


async def test_a_weak_password_is_refused_before_anything_is_stored(
    users: PostgresUserRepository,
) -> None:
    with pytest.raises(WeakPassword):
        await users.create_user("grace@example.com", "short", "analyst")

    assert await users.authenticate("grace@example.com", "short") is None
    assert not any(u.email == "grace@example.com" for u in await users.list_users())


async def test_list_users_never_carries_password_material(users: PostgresUserRepository) -> None:
    await users.create_user("heidi@example.com", PASSWORD, "admin")

    listed = await users.list_users()

    assert all(not hasattr(u, "password_hash") for u in listed)
    assert any(u.email == "heidi@example.com" and u.role == "admin" for u in listed)


async def test_a_session_can_be_logged_out(users: PostgresUserRepository) -> None:
    created = await users.create_user("ivan@example.com", PASSWORD, "analyst")
    token = await users.create_session(created.id, timedelta(hours=1))

    await users.revoke_session(token)

    assert await users.resolve_session(token) is None


async def test_an_expired_session_no_longer_resolves(users: PostgresUserRepository) -> None:
    created = await users.create_user("judy@example.com", PASSWORD, "analyst")
    token = await users.create_session(created.id, timedelta(seconds=-1))  # already in the past

    assert await users.resolve_session(token) is None


async def test_an_unknown_session_token_does_not_resolve(users: PostgresUserRepository) -> None:
    assert await users.resolve_session("not-a-real-token") is None


async def test_revoking_an_unknown_session_does_not_raise(users: PostgresUserRepository) -> None:
    await users.revoke_session("not-a-real-token")  # must not raise


async def test_only_the_hash_of_the_session_token_is_stored(
    users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    created = await users.create_user("kevin@example.com", PASSWORD, "analyst")
    token = await users.create_session(created.id, timedelta(hours=1))

    async with engine.connect() as conn:
        rows = list((await conn.execute(text("SELECT id FROM user_sessions"))).all())

    assert len(rows) == 1
    assert rows[0].id != token
    assert rows[0].id == hash_session_token(token)


async def test_only_the_hash_of_the_password_is_stored(
    users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    await users.create_user("laura@example.com", PASSWORD, "analyst")

    async with engine.connect() as conn:
        rows = list((await conn.execute(text("SELECT password_hash FROM users"))).all())

    assert len(rows) == 1
    assert PASSWORD not in rows[0].password_hash


async def test_resolve_session_itself_rejects_a_revoked_user_even_if_the_session_survives(
    users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    """`revoke_user` deletes every session too, but `resolve_session` must not rely on that alone:
    if a session row somehow outlives its user's revocation, it must still be refused."""
    created = await users.create_user("mallory@example.com", PASSWORD, "analyst")
    token = await users.create_session(created.id, timedelta(hours=1))

    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET revoked_at = now() WHERE id = :id"), {"id": created.id}
        )

    assert await users.resolve_session(token) is None
