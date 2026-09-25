# syntax=docker/dockerfile:1
# Build context is the repository root (see docker-compose.yml).

FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app

# Install dependencies first to maximise layer caching.
COPY backend/pyproject.toml backend/uv.lock backend/README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY backend/src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home sentinel
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY backend/alembic.ini ./alembic.ini
COPY backend/migrations ./migrations
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER sentinel
EXPOSE 8000
CMD ["uvicorn", "sentinel_core.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
