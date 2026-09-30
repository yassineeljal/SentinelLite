"""The agent installer, served by the platform itself.

`curl https://SIEM/agent/install.sh | sudo bash -s -- --server https://SIEM --key KEY` installs the
agent that matches this platform, with nothing fetched from anywhere else. These are the same files
as in the open-source repository: nothing here is secret, so no authentication. They are read from
one directory that the image fills at build time (`SENTINEL_AGENT_DIST_DIR`), and a request never
chooses a path: the wheel is looked up by comparing the requested name with the one file there is.
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse

router = APIRouter(prefix="/agent", tags=["agent-download"])

NO_CACHE = {"Cache-Control": "no-cache"}


def _dist(request: Request) -> Path:
    directory: Path | None = request.app.state.settings.agent_dist_dir
    if directory is None or not directory.is_dir():
        raise HTTPException(status_code=404, detail="The agent is not available on this platform")
    return directory


def _wheel(directory: Path) -> Path:
    wheels = sorted(directory.glob("*.whl"))
    if not wheels:
        raise HTTPException(status_code=404, detail="No agent wheel on this platform")
    return wheels[-1]


@router.get("/install.sh")
async def install_script(request: Request) -> FileResponse:
    script = _dist(request) / "install.sh"
    if not script.is_file():
        raise HTTPException(status_code=404, detail="The installer is not available")
    return FileResponse(script, media_type="text/x-shellscript; charset=utf-8", headers=NO_CACHE)


@router.get("/wheel-name")
async def wheel_name(request: Request) -> PlainTextResponse:
    return PlainTextResponse(_wheel(_dist(request)).name + "\n", headers=NO_CACHE)


@router.get("/wheel/{name}")
async def wheel(name: str, request: Request) -> FileResponse:
    path = _wheel(_dist(request))
    if name != path.name:  # the name selects nothing: it can only confirm the one file there is
        raise HTTPException(status_code=404, detail="No such agent wheel")
    return FileResponse(
        path, media_type="application/octet-stream", filename=path.name, headers=NO_CACHE
    )
