from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio.to_thread
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel_core import __version__
from sentinel_core.api import (
    agent_actions,
    agent_health,
    alerts,
    auth,
    incidents,
    ingest,
    mfa,
    response,
    stats,
)
from sentinel_core.api.body_limit import BodySizeLimitMiddleware
from sentinel_core.auth.agent_keys import AgentRepository, DenyAllAgentRepository
from sentinel_core.auth.registry import PostgresAgentRepository
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.bus.client import API_SOCKET_TIMEOUT_SECONDS, build_redis
from sentinel_core.bus.raw_stream import RawLogPublisher, RedisRawLogPublisher
from sentinel_core.config import Settings, get_settings
from sentinel_core.db.session import create_engine, create_sessionmaker


def create_app(
    settings: Settings | None = None,
    agent_repo: AgentRepository | None = None,
    publisher: RawLogPublisher | None = None,
    user_repo: PostgresUserRepository | None = None,
    db_sessions: async_sessionmaker[AsyncSession] | None = None,
) -> FastAPI:
    """Build the API. Dependencies are injectable for tests.

    Without an agent repository, a Postgres-backed one is created at startup; until then (and
    in any app that never starts) the app fails closed: every ingestion request is rejected.
    Without a publisher, a Redis-backed one is created at startup. Without a user repository or a
    session maker (for `/v1/alerts`), Postgres-backed ones are created at startup, sharing one
    engine with the agent repository.
    """
    settings = settings or get_settings()
    needs_engine = agent_repo is None or user_repo is None or db_sessions is None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        client: Redis | None = None
        engine: AsyncEngine | None = None
        if needs_engine:
            engine = create_engine(settings)
            sessions = create_sessionmaker(engine)
            if agent_repo is None:
                app.state.agents = PostgresAgentRepository(sessions)
            if user_repo is None:
                app.state.users = PostgresUserRepository(sessions)
            if db_sessions is None:
                app.state.db_sessions = sessions
        if publisher is None:
            client = build_redis(settings.redis_url, API_SOCKET_TIMEOUT_SECONDS)
            app.state.publisher = RedisRawLogPublisher(
                client, high_watermark=settings.raw_stream_high_watermark
            )
        try:
            yield
        finally:
            if client is not None:
                await client.aclose()
            if engine is not None:
                await engine.dispose()

    app = FastAPI(title="SentinelLite API", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.agents = agent_repo or DenyAllAgentRepository()
    if publisher is not None:
        app.state.publisher = publisher
    if user_repo is not None:
        app.state.users = user_repo
    if db_sessions is not None:
        app.state.db_sessions = db_sessions
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.ingest_max_body_bytes)
    app.include_router(ingest.router)
    app.include_router(agent_actions.router)
    app.include_router(agent_health.router)
    app.include_router(auth.router)
    app.include_router(mfa.router)
    app.include_router(alerts.router)
    app.include_router(stats.router)
    app.include_router(incidents.router)
    app.include_router(response.router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    if settings.static_dir is not None:
        _mount_frontend(app, settings.static_dir)

    return app


def _resolve_static_path(static_dir: Path, full_path: str) -> Path:
    """The file `full_path` names inside `static_dir`, or `index.html` (the SPA fallback).

    Module-level and pure (a `Path` in, a `Path` out) specifically so the path-escape defence can
    be tested directly, independent of whatever normalisation the ASGI server or Starlette's own
    routing already does to the raw HTTP request path before this ever runs: relying on that
    upstream behaviour alone, untested, is how this exact class of bug hides.
    """
    resolved_root = static_dir.resolve()
    # A path that escapes static_dir (e.g. "../..") must never be served or even stat'd.
    candidate = (static_dir / full_path).resolve()
    if candidate.is_relative_to(resolved_root) and candidate.is_file():
        return candidate
    index = static_dir / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail="Not Found")
    return index


def _mount_frontend(app: FastAPI, static_dir: Path) -> None:
    """Serve the built dashboard (frontend/dist) from the same origin as the API.

    Same-origin on purpose: the session cookie is SameSite=Strict (docs/DASHBOARD.md), which a
    separate frontend origin would break without loosening that setting. Registered LAST, after
    every API router, so `/v1/*` and `/healthz` are always matched first; this catch-all only
    ever sees requests nothing else claimed, and answers them with the client-routed app's
    `index.html` so React Router's own routes (e.g. `/alerts`) work on a hard refresh too.
    """
    assets_dir = static_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str) -> FileResponse:
        target = await anyio.to_thread.run_sync(_resolve_static_path, static_dir, full_path)
        return FileResponse(target)
