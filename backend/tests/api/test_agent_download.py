"""The platform serves the agent installer: public, read-only, never a path chosen by the caller."""

from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel_core.api.main import create_app
from sentinel_core.config import Settings
from tests.support import InMemoryPublisher

WHEEL = "sentinel_agent-0.1.0-py3-none-any.whl"
SCRIPT = "#!/usr/bin/env bash\necho installing\n"


def client_for(dist: Path | None) -> AsyncClient:
    app = create_app(
        settings=Settings(database_url="postgresql+asyncpg://t:t@localhost/t", agent_dist_dir=dist),
        publisher=InMemoryPublisher(),
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    (tmp_path / "install.sh").write_text(SCRIPT)
    (tmp_path / WHEEL).write_bytes(b"PK-not-really-a-wheel")
    (tmp_path / "secret.txt").write_text("not for download")
    return tmp_path


@pytest.fixture
async def client(dist: Path) -> AsyncGenerator[AsyncClient]:
    async with client_for(dist) as running:
        yield running


async def test_the_installer_script_is_served_as_a_shell_script(client: AsyncClient) -> None:
    result = await client.get("/agent/install.sh")

    assert result.status_code == 200
    assert result.text == SCRIPT
    assert result.headers["content-type"].startswith("text/x-shellscript")
    assert result.headers["cache-control"] == "no-cache"


async def test_the_wheel_is_announced_by_name_then_downloaded_under_that_name(
    client: AsyncClient,
) -> None:
    name = (await client.get("/agent/wheel-name")).text.strip()
    assert name == WHEEL

    result = await client.get(f"/agent/wheel/{name}")

    assert result.status_code == 200
    assert result.content == b"PK-not-really-a-wheel"
    assert WHEEL in result.headers["content-disposition"]


async def test_no_credentials_are_needed(client: AsyncClient) -> None:
    for path in ("/agent/install.sh", "/agent/wheel-name", f"/agent/wheel/{WHEEL}"):
        assert (await client.get(path)).status_code == 200


@pytest.mark.parametrize(
    "name",
    [
        "other-1.0-py3-none-any.whl",
        "secret.txt",
        "install.sh",
        "..%2fsecret.txt",
        "..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2fsecret.txt",
        "sentinel_agent-0.1.0-py3-none-any.whl%00.txt",
    ],
)
async def test_a_name_cannot_select_anything_but_the_one_wheel(
    client: AsyncClient, name: str
) -> None:
    result = await client.get(f"/agent/wheel/{name}")

    assert result.status_code == 404
    assert "not for download" not in result.text


async def test_only_the_files_of_the_installer_are_offered(client: AsyncClient) -> None:
    assert (await client.get("/agent/secret.txt")).status_code in (404, 405)
    assert (await client.get("/agent/")).status_code in (404, 405)
    assert (await client.post("/agent/install.sh")).status_code == 405


async def test_the_newest_wheel_is_the_one_offered(dist: Path) -> None:
    (dist / "sentinel_agent-0.2.0-py3-none-any.whl").write_bytes(b"newer")

    async with client_for(dist) as running:
        assert (
            (await running.get("/agent/wheel-name")).text.strip().startswith("sentinel_agent-0.2.0")
        )


@pytest.mark.parametrize("configured", ["unset", "missing directory", "empty directory"])
async def test_a_platform_without_the_agent_says_so(configured: str, tmp_path: Path) -> None:
    directory: Path | None = {
        "unset": None,
        "missing directory": tmp_path / "nope",
        "empty directory": tmp_path,
    }[configured]

    async with client_for(directory) as running:
        assert (await running.get("/agent/install.sh")).status_code == 404
        assert (await running.get("/agent/wheel-name")).status_code == 404
        assert (await running.get(f"/agent/wheel/{WHEEL}")).status_code == 404
