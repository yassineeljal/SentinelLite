"""`sentinel users create|list|revoke` against a real Postgres."""

import asyncio
import re
from collections.abc import Iterator
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core import cli
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import get_settings
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

PASSWORD = "correct horse battery staple"  # noqa: S105


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    assert DATABASE_URL is not None
    monkeypatch.setenv("SENTINEL_DATABASE_URL", DATABASE_URL)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _typed(monkeypatch: pytest.MonkeyPatch, *answers: str) -> None:
    remaining = list(answers)
    monkeypatch.setattr("sentinel_core.cli.getpass.getpass", lambda prompt="": remaining.pop(0))


def test_cli_creates_lists_and_revokes_users(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _typed(monkeypatch, PASSWORD, PASSWORD)
    assert cli.main(["users", "create", "--email", "CLI@Example.com", "--role", "admin"]) == 0
    created = capsys.readouterr().out
    assert "cli@example.com" in created and "admin" in created  # stored lowercased
    match = re.search(r"[0-9a-f-]{36}", created)
    assert match
    user_id = match.group()

    assert cli.main(["users", "list"]) == 0
    listing = capsys.readouterr().out
    assert "cli@example.com" in listing and "admin" in listing and "active" in listing
    assert PASSWORD not in listing

    assert cli.main(["users", "revoke", user_id]) == 0
    capsys.readouterr()
    assert cli.main(["users", "revoke", user_id]) == 1  # already revoked


def test_create_refuses_when_the_two_passwords_differ(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _typed(monkeypatch, PASSWORD, "a different password entirely")

    assert (
        cli.main(["users", "create", "--email", "mismatch@example.com", "--role", "analyst"]) == 1
    )

    assert "did not match" in capsys.readouterr().err


def test_create_refuses_a_weak_password(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _typed(monkeypatch, "short", "short")

    assert cli.main(["users", "create", "--email", "weak@example.com", "--role", "analyst"]) == 1

    assert "error" in capsys.readouterr().err


def test_create_refuses_a_duplicate_email(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _typed(monkeypatch, PASSWORD, PASSWORD)
    assert cli.main(["users", "create", "--email", "dupe@example.com", "--role", "analyst"]) == 0
    capsys.readouterr()

    _typed(monkeypatch, PASSWORD, PASSWORD)
    assert cli.main(["users", "create", "--email", "dupe@example.com", "--role", "analyst"]) == 1

    assert "error" in capsys.readouterr().err


def test_revoke_of_an_unknown_user_is_reported(
    engine: AsyncEngine, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["users", "revoke", str(uuid4())]) == 1

    assert "unknown" in capsys.readouterr().err


async def test_the_created_password_actually_verifies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], engine: AsyncEngine
) -> None:
    _typed(monkeypatch, PASSWORD, PASSWORD)
    assert (
        await asyncio.to_thread(
            cli.main, ["users", "create", "--email", "verify@example.com", "--role", "analyst"]
        )
    ) == 0
    capsys.readouterr()

    registry = PostgresUserRepository(async_sessionmaker(engine, expire_on_commit=False))
    found = await registry.authenticate("verify@example.com", PASSWORD)

    assert found is not None
