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
