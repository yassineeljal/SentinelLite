# SentinelLite — Development log

Chronological journal of what was built, why, how it was verified, and what went wrong.
**Rule: every change adds an entry here in the same PR** (newest first). Design decisions also go to
[`ARCHITECTURE.md`](ARCHITECTURE.md) (ADR table, section 13).

Entry template:

```
## YYYY-MM-DD — <milestone> — <title> (PR #n)
**What** · **Why** · **How verified** · **Problems & lessons** · **Next**
```

---

## 2026-09-25 — M1 (step 4) — Normalizer worker, events and dead letters (PR #5)

**What**
- `workers/normalizer.py`: consumer-group worker (`events.raw` → Postgres). `process_entry()` is a pure function (entry → `Event` | `DeadLetterRecord` | ignored); `NormalizerWorker` handles Redis and the database. Runs as the `normalizer` compose service (`python -m sentinel_core.workers.normalizer`), scalable with `--scale`.
- Migration `0002`: `events` table range-partitioned by day on `ts` with a default partition and three indexes, and `events_dead_letter`. Models `EventRecord` / `DeadLetter`.
- `db/events.py`: idempotent inserts (`ON CONFLICT DO NOTHING`) and `ensure_event_partitions` (daily partitions, guarded by an advisory lock so several workers cannot race).
- `normalizers/registry.py` (source → normalizer map), `normalizers/dead_letter.py`.
- `alembic check` now ignores the runtime-created partitions (`include_object`).
- Test fixtures for real Redis/Postgres moved to `tests/conftest.py` / `tests/support.py`.
- Docs: ADR 18, ARCHITECTURE §5 step 3, `OPERATIONS.md` (worker section + troubleshooting), `INGESTION_API.md`.

**Why**
Until now accepted lines just piled up in the stream. This step closes the first half of the vertical slice (agent → API → queue → **events in Postgres**) with the guarantees the detector will rely on: nothing lost, nothing duplicated, nothing dropped silently.

**Design notes**
- Order of operations: read → write to Postgres (one transaction) → ack + delete from the stream. A crash in between redelivers the batch; idempotent inserts absorb the repeat. Entries abandoned by a crashed consumer are taken over with `XAUTOCLAIM` after `SENTINEL_NORMALIZER_CLAIM_IDLE_MS`.
- Three outcomes per entry: event; dead letter (malformed line, undecodable entry, source without a normalizer, or a bug in a parser — contained, message truncated to 500 chars, raw truncated to 16 KiB); ignored (well-formed, nothing to model).
- Agents control the timestamps in their lines, so a default partition guarantees an odd date cannot fail an insert; the worker keeps yesterday..today+7 partitions ready.
- `ts` is part of the `events` primary key (PostgreSQL requires the partition key in unique constraints). Known edge: an event whose `ts` depends on the receipt year (traditional syslog format without a year) and that is replayed across New Year could be stored twice.
- `events.normalized` is **not** published yet: nothing would consume it. It is added with the detector, together with its own ack semantics.

**How verified**
- 90 tests with real Redis and Postgres (66 unit, 24 integration). New: pure classification of every kind of entry; lines become events and entries are deleted; stored fields (`inet`, `jsonb`) round-trip; dead letters keep their context; replays create no duplicates; **database failure leaves entries pending and they are retried**; **a crashed consumer's entries are taken over**; daily and default partitions; partition setup idempotent; the run loop processes entries and stops on request.
- `ruff`, `mypy --strict` clean.
- Real stack, end to end (agent key → `POST /v1/ingest` → Redis → worker → Postgres): 7 lines gave 5 events, 1 dead letter, 1 ignored (cron); the username-spoofing line stored the real source IP; the stream was empty afterwards; replaying the batch created no new event and no new dead letter.

**Problems & lessons (both found only by running the real stack)**
- **Redis read timeout**: the worker blocks 5 s on `XREADGROUP`, and the client's default read timeout is of the same order, so an idle worker dropped its connection and logged a `TimeoutError` every few seconds. The tests blocked 50 ms and could not see it. Fix: explicit `socket_timeout` (15 s) above the blocking time, with a unit test tying the two values together.
- **Dead letters duplicated on agent retry**: the dedup key was a hash of the whole stream payload, which contains `received_at`; a retried batch is stamped with a new `received_at`, so it produced a new row. The events were fine (their id ignores `received_at`), the dead letters were not. Fix: the key now uses the same identity as `event_id` (agent, source, origin). The first integration test replayed identical objects and missed it; it now retries with a different `received_at`.
- `inet::text` in Postgres renders `203.0.113.7/32`; tests use `host(src_ip)`.
- Two long `docker compose up --build` runs appeared to stall for ~10+ minutes and completed normally afterwards; log timestamps show a 16-minute gap inside a script that only sleeps a few seconds, which points at the Mac being suspended rather than at the build. Not investigated further.

**Not done yet / limits**
- No retention job (dropping old partitions) and no metrics endpoint for the worker.
- No poison-message handling beyond containment: an entry that always fails to persist would be retried forever.
- Only `linux.auth` has a normalizer; `nginx.access`, `windows.*` lines are dead-lettered until their normalizers exist.
- `linux.auth` handles sshd only (no `sudo`/`useradd` yet).

**Next**: the detection engine — first rule types (`match`, `threshold`) and the SSH brute-force rule reading events, emitting alerts (and only then publishing `events.normalized`).

---

## 2026-09-25 — M1 (step 3) — Postgres agent registry, migrations and admin CLI (PR #4)

**What**
- `db/models.py`, `db/session.py`: SQLAlchemy 2 (async, asyncpg), `Agent` model with named constraints (`pk_agents`, `uq_agents_name`, `ck_agents_os`).
- Alembic (`backend/alembic.ini`, `backend/migrations/`): async `env.py` reading `SENTINEL_DATABASE_URL`, migration `0001_create_agents`.
- `auth/registry.py`: `PostgresAgentRepository` — `get_key_hash` (active agents only), `create_agent` (key returned once), `revoke_agent`, `list_agents` (public `AgentInfo` carries no key material).
- `cli.py` (`sentinel agents create|list|revoke`, installed as a console script).
- `create_app()` builds the Postgres registry at startup when none is injected; before startup (and in apps that never start) it stays fail-closed.
- Compose: one-shot `migrate` service (`alembic upgrade head`) that the API waits for (`service_completed_successfully`); the image now ships `alembic.ini` and `migrations/`.
- CI: Postgres service container next to Redis, so the database tests run there too.
- Docs: new [`OPERATIONS.md`](OPERATIONS.md) (run, administer, migrate, test, troubleshoot), `INGESTION_API.md` gained "Managing agents", ADR 17.

**Why**
Until now `/v1/ingest` failed closed for everyone. A persistent, revocable registry is what turns the authenticated API into something the lab agents can actually use, and it introduces the database layer (SQLAlchemy + Alembic) that events, alerts and incidents will reuse.

**Design notes**
- Revocation is a timestamp (`revoked_at`), not a delete: the agent stays listed for audit, and `get_key_hash` filters revoked rows, so a revoked key gets the same `401` as an unknown one.
- The plaintext key exists only in the return value of `create_agent` and the CLI's stdout (`key: …`); the warning goes to stderr so scripts can capture the key cleanly.
- Migrations run in a separate one-shot service instead of the API entrypoint (ADR 17): explicit, reversible, and safe with several API replicas.

**How verified**
- 67 tests (52 unit + 15 integration against real Postgres and Redis). New DB tests cover: key verifies against the stored hash; only the hash is stored (the secret and token appear nowhere in a full `SELECT *`); unknown/revoked agents; double revoke; unique names; the `os` check; listing exposes no key material; **end to end** create → ingest (202) → revoke → ingest (401, nothing published); CLI create/list/revoke; migrations upgrade → downgrade → upgrade; `alembic check` (models match migrations).
- `ruff`, `mypy --strict` clean.
- Real compose stack: `migrate` ran `0001`, `sentinel agents create` inside the container, `POST /v1/ingest` with the real key → `202` and the line is in `events.raw`; wrong secret → `401`; after `agents revoke` → `401`; the database holds a 64-char hash only.

**Security review of PR #3 (ingestion API)**: no finding at or above the reporting threshold. Low-severity notes kept for later:
- `/docs`, `/openapi.json` and the version in `/healthz` are unauthenticated → disable outside development.
- An authenticated agent controls the timestamps in its lines → the detection engine should also compare event `ts` with the server-side `received_at` and flag large skews.
- `ghcr.io/astral-sh/uv:latest` and `actions/checkout@v4` are not pinned by digest → pin before any production use.
- Local users can forge `sshd` lines with `logger -t sshd` (inherent to syslog) → mitigated later by multi-source correlation.

**Problems & lessons**
- `create_agent` is used both from the API process and the CLI, so the name-uniqueness error is a domain exception (`AgentNameTaken`) rather than a leaked `IntegrityError`.
- pytest-asyncio + Alembic: `env.py` uses `asyncio.run`, which cannot run inside a running event loop, so the migration fixture and the `alembic check` test are synchronous.
- The integration tests truncate `agents`: documented in `OPERATIONS.md` that `SENTINEL_TEST_DATABASE_URL` must never point at real data.

**Not done yet / limits**
- Nothing consumes `events.raw` yet; the compose stack accumulates lines until the watermark (`429`). The normalizer worker is the next step.
- No `last_seen_at`, no key rotation (revoke + create), no per-agent rate limiting.

**Next**: normalizer worker — consumer group on `events.raw`, `linux.auth` normalizer, `events` table (daily partitions) and `events_dead_letter`, deleting entries after acknowledgement.

---

## 2026-09-24 — M1 (step 2) — Ingestion API and raw log stream (PR #3)

**What**
- `POST /v1/ingest` (`api/ingest.py`): authenticated batches of raw lines → `RawLog` → Redis Stream `events.raw`. Contract documented in [`INGESTION_API.md`](INGESTION_API.md).
- Agent keys (`auth/agent_keys.py`): `Bearer <uuid>.<256-bit secret>`, only the SHA-256 is stored, constant-time comparison, one generic `401` for every failure, `AgentRepository` protocol with a fail-closed `DenyAllAgentRepository` default.
- Bus (`bus/raw_stream.py`): `RedisRawLogPublisher` (one entry per line, batch in `MULTI/EXEC`, high watermark → `BusFull` → `429`, Redis errors → `BusUnavailable` → `503`).
- `BodySizeLimitMiddleware`: 413 on declared `Content-Length` and on chunked bodies, enforced before FastAPI buffers the body.
- `create_app()` is now a factory with injectable dependencies; the container starts it with `uvicorn --factory`.
- CI runs a Redis service container so the integration tests run there too.
- ARCHITECTURE: §5 backpressure text corrected, ADRs 14–16 added.

**Why**
Ingestion is the trust boundary of the whole product: everything after it assumes events come from an authenticated agent and were bounded in size. Getting auth, limits and idempotency right here is cheaper than retrofitting them.

**Design notes**
- Agent identity comes only from the key. A body carrying `agent_id` is a `422`.
- Backpressure is explicit (`429`) rather than `MAXLEN` trimming, which would silently lose unprocessed events (ADR 14). Consequence for the next step: the normalizer must delete entries after acknowledging them, or the watermark will eventually block ingestion.
- `received_at` uses the server clock; agent clocks are never trusted.

**How verified**
- 56 tests: 52 unit (auth parsing, every rejection path, no agent-id enumeration, batch/line limits, 429/503 mapping, both body-size paths, fail-closed default) + 4 integration against a real Redis (round trip, watermark writes nothing, exact watermark accepted, unreachable Redis → `BusUnavailable`). Integration run locally with a throw-away `redis:7-alpine` container (see the docstring in `tests/bus/test_raw_stream_integration.py`).
- `ruff`, `mypy --strict` clean.
- Smoke test on the rebuilt compose stack: `/healthz` 200; ingest without key → 401; ingest with a well-formed but unregistered key → 401; 9 MB body → 413; nothing written to `events.raw`.

**Problems & lessons**
- A module-level `app = create_app()` failed at import because settings need `SENTINEL_DATABASE_URL`. Replaced by an app factory (`--factory`): no side effects at import time.
- FastAPI turns any non-HTTP exception raised while reading the body into a generic `400`, so the streaming size guard raises `HTTPException(413)` (which FastAPI re-raises untouched) instead of a custom exception.
- redis-py return types are `Optional` for mypy; tests assert non-None rather than silencing the type checker.

**Not done yet / limits**
- No persistent agent registry: in the compose stack every ingest request is `401` by design until the next step adds it.
- No per-agent rate limiting; no `GET /v1/agents/me/actions` yet.
- The normalizer worker that consumes `events.raw` does not exist yet, so accepted lines just accumulate in the stream (not a problem for a dev stack; the watermark bounds it).

**Next**: Postgres agent registry (`agents` table, Alembic migration, CLI to create/revoke agents), then the normalizer worker.

---

## 2026-09-24 — M1 (step 1) — Common event schema and Linux auth.log normalizer (PR #2)

**What**
- `sentinel_core/schema/event.py`: flat, immutable pydantic `Event` with `Source`, `Category`, `Action`, `Outcome` enums.
- `sentinel_core/normalizers/base.py`: `RawLog` (what an agent ships), `ParseError`, the `Normalizer` protocol and `make_event_id`.
- `sentinel_core/normalizers/linux_auth.py`: sshd `Failed` / `Accepted` / `Invalid user`, IPv6, ISO and traditional syslog timestamps.
- `ARCHITECTURE.md` §6 and §9 aligned with the implemented flat schema (`user_name`, `extra` JSONB, `received_at` column).

**Why**
The whole pipeline (detection, enrichment, response) depends on one stable event shape, so it is fixed first, test-first, before ingestion.

**Design notes**
- Contract: a well-formed line with nothing to model (cron noise, unrelated sshd lines) returns `None`; a line that is not even syslog-framed raises `ParseError` and will land in `events_dead_letter`. Nothing is dropped silently.
- `event_id = sha256(agent_id | source | origin)` where `origin` is the line's stable position in its file (e.g. `<inode>:<offset>`). Replaying a batch produces the same ids → idempotent inserts with a `UNIQUE` constraint.
- Traditional syslog timestamps have no year: the year of receipt is assumed, stepping back one year if the result would be in the future (log written just before New Year). Offset-less timestamps use a configurable timezone (default UTC).

**Security notes (untrusted input)**
- The SSH username is attacker-controlled. A username such as `x from 10.0.0.99 port 22 ssh2` would make a naive regex report the wrong source IP. Patterns match the user greedily and are anchored on the **last** `from <ip> port <n>`; covered by `test_username_cannot_spoof_source_ip`.
- Usernames are truncated to 256 chars; a source that does not parse as an IP is stored in `extra.src_host` and never trusted as `src_ip`.

**How verified**
- 17 tests (`backend/tests/normalizers/test_linux_auth.py`): all sshd shapes, IPv6, both timestamp formats, year rollover, spoofing, truncation, ignored lines, parse errors, `event_id` determinism.
- `ruff`, `mypy --strict` clean; CI green (backend, docker-build, GitGuardian).

**Not done yet / limits**
- Only sshd events; `sudo`, `useradd`, PAM lines come later (needed for the privilege-escalation and new-admin rules).
- `dst_port` is assumed to be 22 for sshd events (sshd may listen elsewhere; not derivable from the line).

**Next**: ingestion API (`POST /v1/ingest`, agent key auth, write to Redis Streams) with the first integration test against a real Redis.

---

## 2026-09-24 — M0 — Foundations (PR #1)

**What**
- Architecture v0.2 in `docs/ARCHITECTURE.md` (components, data flow, event schema, detection engine, response safety, data model, security, roadmap by vertical slices, 13 ADRs).
- Backend skeleton `backend/` (`uv`, Python 3.12, FastAPI): `/healthz`, environment-based `Settings` (prefix `SENTINEL_`), `responder_mode` restricted to `dry_run|enforce` and defaulting to `dry_run`.
- `deploy/`: multi-stage non-root Dockerfile and `docker-compose.yml` (Postgres 16, Redis 7, API). Only the API is published, on `127.0.0.1` by default (`SENTINEL_BIND_ADDR`).
- CI (`.github/workflows/ci.yml`): ruff, mypy strict, pytest, image build, compose validation.

**Decisions taken with the user**
- Platform runs in Docker (OrbStack) on the Mac; the lab VMs (targets + attacker) run in UTM, all arm64 (Apple Silicon). First planned as a dedicated `platform` VM, revised (ADR 10).
- Discord is the first notification channel; everything in the repo is in English; the GitHub repo is private.

**How verified**
- Local: `ruff`, `mypy --strict`, `pytest`.
- `docker compose up --build` on OrbStack: 3 healthy containers, `GET /healthz` → 200, API process runs as non-root user `sentinel`, Postgres and Redis not published on the host.
- CI on the PR: backend, docker-build and GitGuardian all green.

**Problems & lessons**
- The first real container run crashed with `ModuleNotFoundError: sentinel_core`: `uv sync` installs the project in editable mode, pointing at `/app/src`, which the final image stage does not contain. Fix: `uv sync --no-editable`. Lesson: never trust a Dockerfile that has not been run.
- The API was first published on `0.0.0.0`, which would expose the SIEM on the Wi-Fi. Now `127.0.0.1` by default; to be set to the lab host-only IP once the lab exists, never `0.0.0.0`.
- GitGuardian flagged `${POSTGRES_PASSWORD:?message}` in the compose file (false positive: a variable reference, not a secret). While investigating, a real weakness was found and fixed: `config.py` had a hard-coded default DB credential. `database_url` now has no default (a test enforces it) and the compose uses `${VAR:?}`.
- The Mac's disk was full (531 MB free), which blocked the OrbStack download. After explicit approval, regenerable caches were removed (Xcode iOS DeviceSupport, XCTestDevices, DerivedData, Homebrew/npm caches, one app model cache), freeing ~109 GB.
- OrbStack's `docker` binary lives in `~/.orbstack/bin`; add it to `PATH` if `docker` is not found in a new shell.
- The PR branch was amended and force-pushed once (own branch, no other contributors) so that the flagged commit no longer appears in the PR history.

**Next**: event schema + first normalizer (done above), then ingestion API.
