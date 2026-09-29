"""The responder refuses to start in any configuration that could mislead."""

from collections.abc import Iterator

import pytest

from sentinel_core.config import get_settings
from sentinel_core.workers import responder


@pytest.fixture(autouse=True)
def _fresh_settings() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def test_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_RESPONDER_ENABLED", raising=False)
    assert await responder.amain() == 1


async def test_a_malformed_allowlist_entry_stops_the_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_RESPONDER_ENABLED", "true")
    monkeypatch.setenv("SENTINEL_RESPONDER_ALLOWLIST", "10.0.0.0/8,not-a-cidr")

    assert await responder.amain() == 1


def test_the_ttl_setting_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_RESPONDER_TTL_SECONDS", str(30 * 24 * 3600))
    with pytest.raises(ValueError):
        get_settings()


async def test_an_invalid_discord_webhook_stops_the_worker_without_printing_it(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SENTINEL_RESPONDER_ENABLED", "true")
    monkeypatch.setenv("SENTINEL_DISCORD_WEBHOOK_URL", "https://evil.example/hook/TOPSECRET")

    assert await responder.amain() == 1
    assert "invalid SENTINEL_DISCORD_WEBHOOK_URL" in caplog.text
    assert "TOPSECRET" not in caplog.text


def test_an_empty_discord_webhook_means_notifications_are_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_DISCORD_WEBHOOK_URL", "  ")
    assert get_settings().discord_webhook_url is None
