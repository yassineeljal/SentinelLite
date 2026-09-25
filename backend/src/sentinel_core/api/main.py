from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel_core import __version__
from sentinel_core.api import ingest
from sentinel_core.api.body_limit import BodySizeLimitMiddleware
from sentinel_core.auth.agent_keys import AgentRepository, DenyAllAgentRepository
from sentinel_core.auth.registry import PostgresAgentRepository
from sentinel_core.bus.client import API_SOCKET_TIMEOUT_SECONDS, build_redis
from sentinel_core.bus.raw_stream import RawLogPublisher, RedisRawLogPublisher
from sentinel_core.config import Settings, get_settings
from sentinel_core.db.session import create_engine, create_sessionmaker


def create_app(
    settings: Settings | None = None,
    agent_repo: AgentRepository | None = None,
    publisher: RawLogPublisher | None = None,
) -> FastAPI:
    """Build the API. Dependencies are injectable for tests.

    Without an agent repository, a Postgres-backed one is created at startup; until then (and
    in any app that never starts) the app fails closed: every ingestion request is rejected.
    Without a publisher, a Redis-backed one is created at startup.
    """
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        client: Redis | None = None
        engine: AsyncEngine | None = None
        if agent_repo is None:
            engine = create_engine(settings)
            app.state.agents = PostgresAgentRepository(create_sessionmaker(engine))
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
    app.state.agents = agent_repo or DenyAllAgentRepository()
    if publisher is not None:
        app.state.publisher = publisher
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.ingest_max_body_bytes)
    app.include_router(ingest.router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
