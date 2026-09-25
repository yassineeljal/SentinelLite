from collections.abc import AsyncGenerator

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from tests.support import DATABASE_URL, alembic_config


@pytest.fixture(autouse=True)
def _required_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings has no credential defaults; provide harmless test values."""
    monkeypatch.setenv("SENTINEL_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")


@pytest.fixture(scope="session")
def migrated_database() -> None:
    """Applies migrations once, proving upgrade -> downgrade -> upgrade works."""
    config = alembic_config()
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    command.upgrade(config, "head")


@pytest.fixture
async def engine(migrated_database: None) -> AsyncGenerator[AsyncEngine]:
    """Engine on the test database with empty tables. Requires SENTINEL_TEST_DATABASE_URL."""
    assert DATABASE_URL is not None
    engine = create_async_engine(DATABASE_URL)
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE agents, events, events_dead_letter, alerts"))
    yield engine
    await engine.dispose()
