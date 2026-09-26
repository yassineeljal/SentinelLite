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
exits → `api`, `normalizer` and `detector` start. Only the API is published, on `127.0.0.1:8000` by default. Once the lab
network exists, set `SENTINEL_BIND_ADDR` to the host-only interface IP (never `0.0.0.0`).

## Administer agents

```bash
docker compose exec api sentinel agents create --name ubuntu-01 --os linux   # key shown once
docker compose exec api sentinel agents list
docker compose exec api sentinel agents revoke <agent_id>
```

See [`INGESTION_API.md`](INGESTION_API.md) for the agent-facing contract.

## Linux agent

For a realistic setup (target machine, attacker, real `sshd` and `hydra`) see [`lab/README.md`](../lab/README.md).

The agent (`agents/linux/`, see [`AGENT.md`](AGENT.md)) runs on the monitored hosts. To try it against
the local stack without a VM:

```bash
docker compose exec api sentinel agents create --name demo --os linux    # prints the key once
mkdir -p /tmp/demo && printf '%s' '<key>' > /tmp/demo/key && chmod 600 /tmp/demo/key
cat > /tmp/demo/agent.toml <<'EOT'
[server]
url = "http://127.0.0.1:8000"
key_file = "/tmp/demo/key"
[agent]
state_file = "/tmp/demo/state.json"
[[sources]]
path = "/tmp/demo/auth.log"
source = "linux.auth"
EOT
: > /tmp/demo/auth.log
cd agents/linux && uv run sentinel-agent --config /tmp/demo/agent.toml &
# append six failed logins (ISO timestamps, like rsyslog on Ubuntu 24.04) and read the alert
docker compose exec api sentinel alerts list
```

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
- **Entries the database rejects** (deterministic storage errors): the batch is retried entry by
  entry and the offender is recorded in `events_dead_letter` (`unstorable entry`, payload
  ASCII-escaped) instead of blocking the entries around it. NUL bytes and lone surrogates are
  already neutralised at the API, so this is a safety net.
- **Partitions**: created at startup and refreshed hourly for yesterday..today+7. An event with a
  date outside that range (agents control the timestamps in their lines) lands in `events_default`.
  When that day later enters the window, its partition is created and the rows of the default
  partition that belong to it are moved in (PostgreSQL refuses to create a partition over a range
  that the default already holds rows of). A day that cannot be created is logged and skipped; the
  others still are, and the worker keeps running. A failed refresh is retried at the next interval,
  not on every loop. Retention (dropping old partitions) is not automated yet.

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

## Detector worker and alerts

The `detector` service consumes `events.normalized`, applies the rules in `rules/` and writes the
`alerts` table. Rules are read once at startup (mounted read-only): after editing them,
`docker compose restart detector`. An invalid or empty rule set makes it exit with the reason.

```bash
docker compose logs -f detector                                  # "ALERT <rule> ..." per detection
docker compose exec api sentinel alerts list [--rule ssh-bruteforce] [--limit 50]
docker compose exec api sentinel alerts show <id-prefix>         # evidence + detection latency
docker compose exec redis redis-cli xlen events.normalized       # backlog for the detector
docker compose exec redis redis-cli --scan --pattern 'sl:det:*'  # window / cooldown state
```

Try it without the lab: send failed SSH logins through the API (see `INGESTION_API.md`), e.g. six
`Failed password for root from 203.0.113.7` lines dated now, within a few seconds, then run
`sentinel alerts list`. Replaying the shipped scenarios (`datasets/`) through the API works too,
but read "Replaying old logs" in [`DETECTION.md`](DETECTION.md) first.

## Detection rules and scenarios

```bash
cd backend
uv run pytest tests/detection -q      # rule validation, engine, store contract, scenarios
uv run sentinel bench                  # detection rate / false alerts of every scenario
uv run sentinel bench --output ../docs/BENCHMARK.md   # regenerate the committed report
uv run sentinel bench --throughput     # in-memory engine speed (not part of the report)
```

Rules live in `rules/`, scenarios in `datasets/<rule-id>/{attack,benign}*.log` (and `datasets/_shared/`). The Redis variant
of the store contract tests runs when `SENTINEL_TEST_REDIS_URL` is set. See
[`DETECTION.md`](DETECTION.md) for the rule format and how to add a rule.

## Enrichment (GeoIP)

Optional: adds country, city and network to alerts (see [`ENRICHMENT.md`](ENRICHMENT.md)). Run
`deploy/fetch-geoip.sh`, set `SENTINEL_ENRICHMENT_ENABLED=true` and `COMPOSE_PROFILES=enrichment`
in `deploy/.env`, then `docker compose up -d --build`. The `enricher` service exits at startup with
the reason if a database is missing. Data by DB-IP.com (CC BY 4.0).

```bash
docker compose logs -f enricher                              # "batch: n enriched, ..."
docker compose exec redis redis-cli xlen alerts.new          # announcements waiting (normally 0)
docker compose exec api sentinel alerts show <id-prefix>     # the `from` line
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `no space left on device` while pulling images | The Mac disk is full. Free space (Xcode caches, `docker system prune`) |
| `docker: command not found` | `export PATH="$HOME/.orbstack/bin:$PATH"` |
| API container restarts with `ModuleNotFoundError` | Image built with an editable install; the Dockerfile must use `uv sync --no-editable` |
| `POSTGRES_PASSWORD` error on `docker compose` | `deploy/.env` is missing: copy it from `.env.example` |
| Ingestion answers `401` for a valid key | The agent was revoked, or the key was created against another database. The Linux agent then exits with code 2 and keeps the refused lines unacknowledged |
| Ingestion answers `429` | `events.raw` is above its high watermark: the `normalizer` service is down or stuck (check `docker compose ps` / `logs normalizer`, and `redis-cli xpending events.raw normalizers`) |
| Attack sent but no alert | `docker compose logs detector` (did it start? rules loaded?); is the group's state ahead in time (old-dated replay, see DETECTION.md)? did the line normalize (`events_dead_letter`)? |
| `detector` exits at startup | Invalid or empty rule set: the log lists every faulty file. Fix `rules/` and restart |
| `events.normalized` keeps growing | The detector is down or slower than the normalizer; the normalizer pauses at the watermark |
| Events missing but the stream is empty | Look in `events_dead_letter` (malformed line or source without a normalizer), or the line was well-formed with nothing to model |
| `enricher` exits at startup | Enrichment disabled (`SENTINEL_ENRICHMENT_ENABLED`), or a GeoIP database is missing / not a database / of the wrong kind: the log names the file. Run `deploy/fetch-geoip.sh` |
| Alerts show `not enriched` | The enricher is not running (`--profile enrichment`), was enabled after the alert, or the alert has no source address (sudo, account rules) |
| `events_default` keeps growing | Events are dated outside yesterday..today+7: wrong agent clock, or replayed old logs |
