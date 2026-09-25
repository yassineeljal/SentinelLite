import pytest


@pytest.fixture(autouse=True)
def _required_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings has no credential defaults; provide harmless test values."""
    monkeypatch.setenv("SENTINEL_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
