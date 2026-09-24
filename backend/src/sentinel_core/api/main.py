from fastapi import FastAPI

from sentinel_core import __version__


def create_app() -> FastAPI:
    app = FastAPI(title="SentinelLite API", version=__version__)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
