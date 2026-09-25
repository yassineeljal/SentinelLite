from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel_core import __version__
from sentinel_core.api.main import create_app
from sentinel_core.config import Settings


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient]:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_healthz_returns_ok(client: AsyncClient) -> None:
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_responder_mode_defaults_to_dry_run() -> None:
    assert Settings().responder_mode == "dry_run"


def test_responder_mode_rejects_unknown_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_RESPONDER_MODE", "yolo")

    with pytest.raises(ValueError):
        Settings()


def test_database_url_has_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_DATABASE_URL")

    with pytest.raises(ValueError):
        Settings(_env_file=None)


def test_the_api_redis_client_has_socket_timeouts() -> None:
    """Without them a stalled Redis would hang every ingest request instead of answering 503."""
    from sentinel_core.bus.client import API_SOCKET_TIMEOUT_SECONDS, build_redis

    kwargs = build_redis(
        "redis://localhost:6379/0", API_SOCKET_TIMEOUT_SECONDS
    ).connection_pool.connection_kwargs

    assert 0 < kwargs["socket_timeout"] <= 10
    assert 0 < kwargs["socket_connect_timeout"] <= 10
