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

## Secret scanning in CI

The `secrets` CI job runs [ggshield](https://github.com/GitGuardian/ggshield-action) against the
PR diff, using the repo secret `GITGUARDIAN_API_KEY` (set once with
`gh secret set GITGUARDIAN_API_KEY`, never committed). Known non-secrets (e.g. RFC test vectors
used in tests) are listed, with a reason, in `.gitguardian.yaml` at the repo root — this file is
read by `ggshield` itself, not by GitGuardian's separate hosted GitHub App check, which ignores it
and must instead be resolved per-incident on the GitGuardian dashboard.

## Dashboard accounts

See [`DASHBOARD.md`](DASHBOARD.md) for the design. There is no self-registration: create the first
account after the stack is up.

```bash
docker compose exec api sentinel users create --email you@example.com --role admin
docker compose exec api sentinel users list                              # never shows password hashes
docker compose exec api sentinel users revoke <user-id>                  # also ends every session
```

Then open `http://127.0.0.1:8000/` (or wherever `SENTINEL_BIND_ADDR` points): the API serves the
built dashboard on the same origin. `npm run dev` under `frontend/` is for frontend development
only (hot reload, proxied to a backend on `:8000`); the compose stack always serves the built app.

`SENTINEL_SESSION_COOKIE_SECURE` defaults to `true` (the cookie is only ever sent over HTTPS). This
lab's compose stack talks plain HTTP: `deploy/.env` sets it to `false` for that reason. **Set it
back to `true` (or remove the line) for any deployment reachable over a real network** — a
`Secure` cookie leaking on the wire is far cheaper to prevent than to explain afterward.

### Two-factor setup and login limits

Apply migration `0008` before the updated API starts (the compose `migrate` service handles this).
Generate a **stable** Fernet key once, using the backend environment:

```bash
cd backend
uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Put it in the ignored `deploy/.env` as `SENTINEL_MFA_ENCRYPTION_KEY=<generated key>`, keep a secure
backup separate from Postgres, and recreate the API service. Never commit or regenerate this key
on each restart. Losing/changing it makes existing authenticator secrets unreadable; recovery codes
continue to work and can disable 2FA before re-enrolling with a new key. There is no automatic key
rotation in this version. An empty value leaves existing password-only accounts usable but makes new
2FA enrollment unavailable. Invalid key syntax fails settings validation. The UI explains how to
scan the local QR, confirm enrollment and save recovery codes once the key is configured.

Optional attempt limits (defaults shown):

```dotenv
SENTINEL_AUTH_WINDOW_SECONDS=300
SENTINEL_AUTH_ACCOUNT_ATTEMPTS=10
SENTINEL_AUTH_IP_ATTEMPTS=50
```

All attempts count, including successful ones. Login is limited by normalized identifier and peer
address; 2FA management is separately limited by user and shares the address budget. 429 includes
`Retry-After`; blocked attempts do not extend the window. Limits live in Postgres, and expired rows
are pruned on the next attempt. During a database outage authentication fails closed with 503.

The Docker command explicitly uses `--no-proxy-headers`: an arbitrary `X-Forwarded-For` header
cannot change the source budget. When running uvicorn directly, use that flag too. If a reverse proxy
is introduced, configure uvicorn to trust only its known peer addresses and ensure the proxy replaces
forwarded headers; otherwise all clients behind it share one source budget. Do not trust `*`.
Use HTTPS and synchronized clocks for TOTP deployments. A code is accepted only once (including
setup confirmation); if a freshly used code is refused, wait for the next 30-second step.

## Detector worker and alerts

The `detector` service consumes `events.normalized`, applies the rules in `rules/` and writes the
`alerts` table. Rules are read once at startup (mounted read-only): after editing them,
`docker compose restart detector`. An invalid or empty rule set makes it exit with the reason, and
so does an *enabled* `type: stateful` rule (e.g. `ssh-impossible-travel`, shipped disabled) without
a GeoIP database: run `deploy/fetch-geoip.sh` first (see [`ENRICHMENT.md`](ENRICHMENT.md) and
[`DETECTION.md`](DETECTION.md)); the detector reads the same `SENTINEL_GEOIP_CITY_DB`/`ASN_DB` files
as the enricher, independently of whether enrichment itself is on.

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

Optional AbuseIPDB reputation: set `SENTINEL_ABUSEIPDB_API_KEY` in `deploy/.env` (free key). **This
sends the public source address of alerts to abuseipdb.com**; leave it empty to keep every address
local. Cache, daily budget and pauses are described in [`ENRICHMENT.md`](ENRICHMENT.md).

```bash
docker compose logs -f enricher                              # "batch: n enriched, ..."
docker compose exec redis redis-cli xlen alerts.new          # announcements waiting (normally 0)
docker compose exec redis redis-cli get sl:rep:quota:$(date -u +%Y%m%d)   # AbuseIPDB requests made today
docker compose exec redis redis-cli get sl:rep:blocked       # set = lookups paused (the value says why)
docker compose exec api sentinel alerts show <id-prefix>     # `from`, `abuse` and `risk` lines
```

## Deploy on a VPS behind Coolify's proxy

A public, HTTPS deployment on a single VPS that already runs [Coolify](https://coolify.io) (its
Traefik proxy owns ports 80/443). `deploy/docker-compose.vps.yml` is an overlay: no host port is
published, the API joins Coolify's `coolify` network and Traefik routes a hostname to it (Let's
Encrypt certificate included).

```bash
cd deploy
cp .env.example .env                       # strong POSTGRES_PASSWORD; keep SENTINEL_RESPONDER_MODE=dry_run
# In docker-compose.vps.yml, replace the hostname in the Traefik labels with yours
# (DNS: an A record for it pointing at the VPS).
docker compose -f docker-compose.yml -f docker-compose.vps.yml up -d --build
curl https://<your-hostname>/healthz
# Interactive (needs a real terminal: `ssh -t`): the password is asked, never passed as an argument.
docker compose -f docker-compose.yml -f docker-compose.vps.yml exec api sentinel users create --email you@example.com --role admin
```

Monitor the VPS itself by installing the Linux agent on it (see "Linux agent"), pointing
`server.url` at the public HTTPS hostname.

**Name collision with Coolify.** Coolify's own database and Redis containers answer to `postgres`
and `redis` on the `coolify` network. The API is on both networks, so those names resolved to
Coolify's services (`password authentication failed for user "sentinel"`, and nothing reached our
Postgres). The overlay gives our services the unique aliases `sentinel-postgres` /
`sentinel-redis` and points only the API at them; the workers are on the private network alone and
are unaffected. Check with `docker compose exec api getent hosts sentinel-postgres`.

## Automated response (dry run, then enforce)

The responder decides which source addresses to block. In `dry_run` (the default) it only records
the decision and an audit line and touches nothing. In `enforce` it also queues a block action for
the agent(s) that saw the attacker; their enforcer applies it to the firewall (docs/AGENT.md) and the
block is lifted, and audited, when its TTL ends. Measure the dry-run first (`sentinel blocks`).

```bash
# deploy/.env
SENTINEL_RESPONDER_ENABLED=true
SENTINEL_RESPONDER_ALLOWLIST=<your public address>,<the platform's address>
COMPOSE_PROFILES=response
docker compose up -d --build                  # the detector now announces alerts on alerts.respond
docker compose exec api sentinel blocks       # what would be blocked, until when, and why
docker compose exec api sentinel unblock 203.0.113.7      # lift a block now (false positive)
docker compose exec api sentinel allowlist add 203.0.113.7 --note "my office"
docker compose exec api sentinel allowlist list
docker compose exec api sentinel allowlist remove 203.0.113.7
```

**Guardrails** (all in `sentinel_core/response/policy.py`, each refusal has a named reason):

| Guardrail | Behaviour |
|---|---|
| Eligible rules | Only `ssh-bruteforce`, `ssh-user-enumeration`, `ssh-invalid-user-flood` (`SENTINEL_RESPONDER_BLOCK_RULES`). Alerts about a **successful** login or a new account never block: the source may be a legitimate user |
| Severity floor | `SENTINEL_RESPONDER_MIN_SEVERITY` (default 40) |
| Non-public addresses | Private, loopback, link-local, multicast, reserved and documentation ranges are never blocked, including when wrapped as `::ffff:a.b.c.d` |
| Allowlist | `SENTINEL_RESPONDER_ALLOWLIST` plus the database allowlist (`sentinel allowlist`). It wins over everything; an IPv4-mapped IPv6 form of an allowed address is allowed too |
| Mandatory TTL | `SENTINEL_RESPONDER_TTL_SECONDS` (default 1 h, at most 7 days). There is no permanent automatic block |
| Rate cap | At most `SENTINEL_RESPONDER_MAX_BLOCKS_PER_MINUTE` (default 10) new blocks a minute: a rule bug must not block half the Internet |
| Idempotent | One decision per alert (the stream is at-least-once); an already-blocked address is not blocked again |
| Audit | Every block and every guardrail refusal (`allowlisted`, `rate_limited`, `invalid_address`) is written to `audit_log`, which a trigger makes append-only |

Put your own address on the allowlist **before** anything can enforce: `who` on the VPS shows the
address of your SSH session.

**Discord notifications.** With `SENTINEL_DISCORD_WEBHOOK_URL` set (a Discord webhook: server
settings > Integrations > Webhooks), the responder posts one message per batch: `BLOCKED` (or
`would block` in dry run) with the address, TTL, rule and severity, and `RELEASED` when a block
expires. It is best effort: a Discord outage never delays or cancels a block, messages are sent after
the decision is committed, a redelivered alert is not announced twice, a burst is cut at 10 lines,
and mentions are disabled. The URL is validated at startup (only `https://discord.com/api/webhooks/…`),
never logged, and the `httpx` request log (which would print it) is silenced.

**A false positive.** `sentinel unblock <address>` releases every active block of that address, queues
an `unblock` for the agents that applied it (they drop the rule at their next poll, a few seconds
later) and writes `unblock.manual` to the audit log. It does not stop the address from being blocked
again by a later alert: for that, `sentinel allowlist add <address>`. If the platform is down, on the
host: `sudo iptables -D SENTINEL -s <address> -j DROP` (the agent also lifts it by itself at the end of
its TTL).

**Going from dry run to enforce**

1. Watch `sentinel blocks` for a few days: is every "would block" a real attacker?
2. On each monitored host, add a `[response]` section to `agent.toml` (`never_block` = the addresses
   you SSH from), start with `backend = "log"`, and enable the `sentinel-agent-enforcer` service.
3. Set `SENTINEL_RESPONDER_MODE=enforce` and restart the responder. Provoke a block from an address
   you control (not allowlisted), check `iptables -L SENTINEL -n` on the agent, and that it
   disappears when the TTL ends. Only then switch the agent to `backend = "iptables"`.
4. To undo everything at once: `SENTINEL_RESPONDER_MODE=dry_run`, and on the hosts stop the enforcer
   and run `iptables -F SENTINEL` (blocks that were queued are then never re-applied).

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
| Dashboard login works but `/v1/auth/me` (or the frontend) always answers 401 | `SENTINEL_SESSION_COOKIE_SECURE` is `true` (the default) while the browser talks plain HTTP: the cookie is never sent back, by design. Set it to `false` in `deploy/.env` for a plain-HTTP lab only |
| `enricher` exits at startup | Enrichment disabled (`SENTINEL_ENRICHMENT_ENABLED`), or a GeoIP database is missing / not a database / of the wrong kind: the log names the file. Run `deploy/fetch-geoip.sh` |
| Alerts have a country but no `abuse` line | No key set, address not public, or lookups paused: `redis-cli get sl:rep:blocked` gives the reason, and `docker compose logs enricher` the moment it started ("reputation lookups paused") |
| `reputation lookups paused: the key was refused` | The AbuseIPDB key is wrong, revoked or not activated; fix `SENTINEL_ABUSEIPDB_API_KEY` and `docker compose up -d enricher` |
| Alerts show `not enriched` | The enricher is not running (`--profile enrichment`), was enabled after the alert, or the alert has no source address (sudo, account rules) |
| `events_default` keeps growing | Events are dated outside yesterday..today+7: wrong agent clock, or replayed old logs |
