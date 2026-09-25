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
exits → `api` and `normalizer` start. Only the API is published, on `127.0.0.1:8000` by default. Once the lab
network exists, set `SENTINEL_BIND_ADDR` to the host-only interface IP (never `0.0.0.0`).

## Administer agents

```bash
docker compose exec api sentinel agents create --name ubuntu-01 --os linux   # key shown once
docker compose exec api sentinel agents list
docker compose exec api sentinel agents revoke <agent_id>
```

See [`INGESTION_API.md`](INGESTION_API.md) for the agent-facing contract.

## Normalizer worker

The `normalizer` service consumes `events.raw`, normalizes each line and writes `events` (daily
partitions) and `events_dead_letter`. Entries are deleted from the stream once persisted.

```bash
docker compose logs -f normalizer                       # one INFO line per batch
docker compose up -d --scale normalizer=3               # consumer group: each entry goes to one worker
docker compose exec postgres psql -U <user> -d sentinel \
  -c "select ts, action, user_name, host(src_ip) from events order by ts desc limit 20"
docker compose exec postgres psql -U <user> -d sentinel \
  -c "select created_at, source, origin, error from events_dead_letter order by id desc limit 20"
docker compose exec redis redis-cli xlen events.raw     # backlog (should stay near 0)
docker compose exec redis redis-cli xpending events.raw normalizers   # delivered, not yet acknowledged
```

Behaviour worth knowing:
- **Dead letters** hold lines that could not be normalized, with the reason: a malformed line, or a
  source without a normalizer yet (e.g. `nginx.access`). Well-formed lines that carry nothing to
  model (cron, unrelated sshd messages) are acknowledged and not stored anywhere.
- **Crash or database outage**: entries stay pending and are redelivered (after
  `SENTINEL_NORMALIZER_CLAIM_IDLE_MS`, 60 s by default, for entries owned by a dead worker). Inserts are
  idempotent, so redelivery never duplicates rows.
- **Partitions**: created at startup and refreshed hourly for yesterday..today+7. An event with a
  date outside that range (agents control the timestamps in their lines) lands in `events_default`.
  Retention (dropping old partitions) is not automated yet.

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

The Postgres tests truncate `agents`, `events` and `events_dead_letter` in the test database: never point
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
| Ingestion answers `429` | `events.raw` is above its high watermark: the `normalizer` service is down or stuck (check `docker compose ps` / `logs normalizer`, and `redis-cli xpending events.raw normalizers`) |
| Events missing but the stream is empty | Look in `events_dead_letter` (malformed line or source without a normalizer), or the line was well-formed with nothing to model |
| `events_default` keeps growing | Events are dated outside yesterday..today+7: wrong agent clock, or replayed old logs |
