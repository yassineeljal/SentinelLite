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
