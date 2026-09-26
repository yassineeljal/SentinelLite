import pytest

from sentinel_core.config import Settings

DB = "postgresql+asyncpg://u:p@localhost/db"


def settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    monkeypatch.setenv("SENTINEL_DATABASE_URL", DB)
    monkeypatch.delenv("SENTINEL_ABUSEIPDB_API_KEY", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(f"SENTINEL_{name}", value)
    return Settings(_env_file=None)


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_abuseipdb_key_means_reputation_is_off(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """docker compose passes an unset `${VAR:-}` as an empty string."""
    assert settings(monkeypatch, ABUSEIPDB_API_KEY=value).abuseipdb_api_key is None


def test_the_key_is_kept_secret_in_reprs(monkeypatch: pytest.MonkeyPatch) -> None:
    key = "s3cret-key-value-" + "x" * 40

    loaded = settings(monkeypatch, ABUSEIPDB_API_KEY=key)

    assert loaded.abuseipdb_api_key is not None
    assert loaded.abuseipdb_api_key.get_secret_value() == key
    assert key not in repr(loaded) and key not in str(loaded)


def test_reputation_is_off_by_default_and_the_budget_stays_under_the_free_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = settings(monkeypatch)

    assert loaded.abuseipdb_api_key is None
    assert loaded.abuseipdb_daily_limit < 1000  # the free plan's daily limit
