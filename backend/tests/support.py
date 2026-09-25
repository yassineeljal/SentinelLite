"""Test doubles and helpers shared across test modules."""

import os
from pathlib import Path

from alembic.config import Config

from sentinel_core.bus.raw_stream import BusFull, BusUnavailable
from sentinel_core.normalizers.base import RawLog


class InMemoryPublisher:
    """Records published batches; can simulate a full or a broken bus."""

    def __init__(self) -> None:
        self.batches: list[list[RawLog]] = []
        self.error: BusFull | BusUnavailable | None = None

    async def publish(self, logs: list[RawLog]) -> None:
        if self.error is not None:
            raise self.error
        self.batches.append(list(logs))

    @property
    def logs(self) -> list[RawLog]:
        return [log for batch in self.batches for log in batch]


# --- Integration helpers (real Redis / Postgres) -------------------------------------------

DATABASE_URL = os.environ.get("SENTINEL_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("SENTINEL_TEST_REDIS_URL")

BACKEND_DIR = Path(__file__).resolve().parents[1]


def alembic_config() -> Config:
    assert DATABASE_URL is not None
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
    return config
