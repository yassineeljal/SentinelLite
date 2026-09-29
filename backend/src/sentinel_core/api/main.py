from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel_core import __version__
from sentinel_core.api import alerts, auth, ingest
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
    app.include_router(auth.router)
    app.include_router(alerts.router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
