from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from sentinel_core import __version__
from sentinel_core.api import ingest
from sentinel_core.api.body_limit import BodySizeLimitMiddleware
from sentinel_core.auth.agent_keys import AgentRepository, DenyAllAgentRepository
from sentinel_core.bus.raw_stream import RawLogPublisher, RedisRawLogPublisher
from sentinel_core.config import Settings, get_settings


def create_app(
    settings: Settings | None = None,
    agent_repo: AgentRepository | None = None,
    publisher: RawLogPublisher | None = None,
) -> FastAPI:
    """Build the API. Dependencies are injectable for tests.

    Without an agent repository the app fails closed (every ingestion request is rejected).
    Without a publisher, a Redis-backed one is created at startup.
    """
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        client: Redis | None = None
        if publisher is None:
            client = Redis.from_url(settings.redis_url, decode_responses=True)
            app.state.publisher = RedisRawLogPublisher(
                client, high_watermark=settings.raw_stream_high_watermark
            )
        try:
            yield
        finally:
            if client is not None:
                await client.aclose()

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
