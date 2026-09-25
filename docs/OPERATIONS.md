# Operations guide

How to run, administer and test SentinelLite on the development Mac (OrbStack). Keep this in sync
with the stack: every new service or command added to the project gets documented here.

## Prerequisites

- OrbStack (or Docker) — the CLI lives in `~/.orbstack/bin`; add it to `PATH` if `docker` is not found.
- [`uv`](https://docs.astral.sh/uv/) for the backend (it pins Python 3.12 from `backend/.python-version`).

## Run the stack

```bash
cd deploy
cp .env.example .env          # then set a strong POSTGRES_PASSWORD (never commit .env)
docker compose up -d --build
curl localhost:8000/healthz   # {"status":"ok","version":"..."}
```

Startup order: `postgres` and `redis` become healthy → `migrate` applies the Alembic migrations and
exits → `api` starts. Only the API is published, on `127.0.0.1:8000` by default. Once the lab
network exists, set `SENTINEL_BIND_ADDR` to the host-only interface IP (never `0.0.0.0`).

## Administer agents

```bash
docker compose exec api sentinel agents create --name ubuntu-01 --os linux   # key shown once
docker compose exec api sentinel agents list
docker compose exec api sentinel agents revoke <agent_id>
```

See [`INGESTION_API.md`](INGESTION_API.md) for the agent-facing contract.

## Database migrations

```bash
cd backend
SENTINEL_DATABASE_URL=postgresql+asyncpg://user:pass@127.0.0.1:5432/db uv run alembic upgrade head
uv run alembic revision --autogenerate -m "describe the change"   # then review the generated file
uv run alembic check                                              # models vs migrations drift
```

Inside the stack, migrations are applied automatically by the `migrate` service.

## Tests

Unit tests need nothing:

```bash
cd backend
uv run pytest -q                       # integration tests are skipped
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
```

Integration tests need real Redis and Postgres. Start throw-away containers bound to localhost:

```bash
docker run -d --rm --name sl-test-pg -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=test -p 127.0.0.1:5440:5432 postgres:16-alpine
docker run -d --rm --name sl-test-redis -p 127.0.0.1:6390:6379 redis:7-alpine

SENTINEL_TEST_DATABASE_URL=postgresql+asyncpg://test:test@127.0.0.1:5440/test \
SENTINEL_TEST_REDIS_URL=redis://127.0.0.1:6390/0 \
  uv run pytest -q

docker stop sl-test-pg sl-test-redis
```

The Postgres tests truncate the `agents` table of the test database: never point
`SENTINEL_TEST_DATABASE_URL` at a database that holds real data. CI runs the same tests with
service containers.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `no space left on device` while pulling images | The Mac disk is full. Free space (Xcode caches, `docker system prune`) |
| `docker: command not found` | `export PATH="$HOME/.orbstack/bin:$PATH"` |
| API container restarts with `ModuleNotFoundError` | Image built with an editable install; the Dockerfile must use `uv sync --no-editable` |
| `POSTGRES_PASSWORD` error on `docker compose` | `deploy/.env` is missing: copy it from `.env.example` |
| Ingestion answers `401` for a valid key | The agent was revoked, or the key was created against another database |
| Ingestion answers `429` | `events.raw` is above its high watermark: nothing consumes it yet (the normalizer worker is the next step), or consumers do not delete acknowledged entries |
