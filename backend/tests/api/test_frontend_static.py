"""`create_app`'s serving of the built dashboard (see `_mount_frontend` in api/main.py)."""

from pathlib import Path

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_core.api.main import _resolve_static_path, create_app
from sentinel_core.auth.agent_keys import DenyAllAgentRepository
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import Settings
from tests.support import InMemoryPublisher

# httpx's ASGITransport never runs the app's lifespan (no startup/shutdown), so app.state.users
# would otherwise never be set. These routes never query the database without a session cookie
# (authenticate_user short-circuits first), so a sessionmaker that is never actually connected to
# is enough here.
_DUMMY_SESSIONS = async_sessionmaker(create_async_engine("postgresql+asyncpg://u:p@localhost/db"))


def app_with_frontend(static_dir: Path) -> AsyncClient:
    settings = Settings(database_url="postgresql+asyncpg://u:p@localhost/db", static_dir=static_dir)
    app = create_app(
        settings=settings,
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=PostgresUserRepository(_DUMMY_SESSIONS),
        db_sessions=_DUMMY_SESSIONS,
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def built(tmp_path: Path) -> Path:
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "index-abc123.js").write_text("console.log('hi')")
    (tmp_path / "index.html").write_text("<html><body>SentinelLite</body></html>")
    (tmp_path / "favicon.svg").write_text("<svg></svg>")
    return tmp_path


async def test_without_static_dir_unknown_paths_are_a_plain_404() -> None:
    settings = Settings(database_url="postgresql+asyncpg://u:p@localhost/db")
    app = create_app(
        settings=settings, agent_repo=DenyAllAgentRepository(), publisher=InMemoryPublisher()
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/alerts")  # a React Router path, not an API one

    assert response.status_code == 404


async def test_the_api_still_works_when_the_frontend_is_mounted(built: Path) -> None:
    async with app_with_frontend(built) as client:
        health = await client.get("/healthz")
        auth = await client.get("/v1/auth/me")  # a real API route: never swallowed by the catch-all

    assert health.status_code == 200
    assert auth.status_code == 401  # not 200 with index.html, and not the SPA fallback either


async def test_the_index_page_is_served_at_the_root(built: Path) -> None:
    async with app_with_frontend(built) as client:
        response = await client.get("/")

    assert response.status_code == 200 and "SentinelLite" in response.text


async def test_a_client_routed_path_falls_back_to_index_html(built: Path) -> None:
    """`/alerts` is not a real file: React Router owns it client-side, so a hard refresh (or
    someone pasting the link) must still get the app, not a 404."""
    async with app_with_frontend(built) as client:
        response = await client.get("/alerts")

    assert response.status_code == 200 and "SentinelLite" in response.text


async def test_a_real_asset_file_is_served_as_is(built: Path) -> None:
    async with app_with_frontend(built) as client:
        response = await client.get("/favicon.svg")

    assert response.status_code == 200 and response.text == "<svg></svg>"


async def test_bundled_assets_are_served_under_assets(built: Path) -> None:
    async with app_with_frontend(built) as client:
        response = await client.get("/assets/index-abc123.js")

    assert response.status_code == 200 and "console.log" in response.text


@pytest.mark.parametrize(
    "path", ["/../pyproject.toml", "/..%2f..%2fpyproject.toml", "/%2e%2e/etc/passwd"]
)
async def test_path_traversal_out_of_the_static_directory_is_refused(
    built: Path, path: str
) -> None:
    async with app_with_frontend(built) as client:
        response = await client.get(path)

    # Either blocked by the ASGI server's own path normalisation (a 404 before reaching the app)
    # or by resolve_target's containment check (falls back to index.html): never the escaped file.
    assert "sentinel-core" not in response.text  # a distinctive string from pyproject.toml


async def test_a_missing_index_html_is_a_clear_404_not_a_crash(tmp_path: Path) -> None:
    async with app_with_frontend(tmp_path) as client:  # built dir exists but is empty
        response = await client.get("/")

    assert response.status_code == 404


# --- _resolve_static_path: the containment check in isolation, independent of whatever the ASGI
# server or Starlette's own routing does to a raw HTTP path before this ever runs -------------


def test_a_real_asset_resolves_to_itself(built: Path) -> None:
    assert _resolve_static_path(built, "favicon.svg") == built / "favicon.svg"


def test_an_unknown_path_falls_back_to_index_html(built: Path) -> None:
    assert _resolve_static_path(built, "alerts") == built / "index.html"


@pytest.mark.parametrize(
    "escape",
    [
        "../pyproject.toml",
        "../../pyproject.toml",
        "assets/../../pyproject.toml",
        "....//....//pyproject.toml",
    ],
)
def test_a_literal_escape_never_resolves_outside_static_dir(built: Path, escape: str) -> None:
    """The real attack this defends against: `full_path` containing actual '..' components,
    however they got there (this is what the mutation-tested containment check exists for)."""
    target = _resolve_static_path(built, escape)

    assert target.is_relative_to(built.resolve())
    assert target == built / "index.html"  # never the file outside static_dir, even if it exists


def test_an_absolute_path_component_does_not_escape_either(
    built: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    # A genuinely separate directory, not a sibling under the same tmp_path as `built`: the point
    # is to prove containment against a REAL file that actually exists outside static_dir.
    outside = tmp_path_factory.mktemp("elsewhere") / "outside.txt"
    outside.write_text("secret")
    assert not outside.is_relative_to(built)

    target = _resolve_static_path(built, str(outside))

    assert target.is_relative_to(built.resolve())
    assert target != outside.resolve()


def test_a_missing_static_dir_falls_back_cleanly(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    with pytest.raises(HTTPException):
        _resolve_static_path(missing, "anything")
