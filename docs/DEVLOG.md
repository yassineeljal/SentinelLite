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

## 2026-09-25 — Lab guide, deployment scripts and the first real attack (PR #12)

**What**
- `lab/README.md`: the lab (topology, two ways to build it, safety rules, troubleshooting, measured result).
- `lab/scripts/`: `deploy-agent.sh` (from the platform host: builds the agent wheel, registers the agent, sends the key over SSH to a private file, installs and starts the service), `remote-install.sh` (runs on the monitored host, idempotent: packages, rsyslog, service user in `adm`, virtualenv, config, key, systemd unit), `attack-ssh-bruteforce.sh` (hydra; refuses any non-private target), `detection-delay.sh` (attack → alert timings from the database), `wordlists/small.txt`.
- Docs updated: `AGENT.md` (unit now validated), ARCHITECTURE §3 note, M1 criterion result, ADR 24, `OPERATIONS.md`, `.env.example` (host address varies).

**Why**
The M1 criterion is "a real attack from Kali raises an alert in under 10 s", and the agent and its systemd unit had never run on a real Linux host. Waiting for UTM VMs (an interactive installer per VM) would have delayed that proof; OrbStack, already installed, creates real systemd Linux machines (including a Kali one) with one command.

**Result — measured, real chain** (Ubuntu 24.04.5 arm64 target and Kali arm64 attacker as OrbStack machines, hydra 9.7 with 4 tasks and 20 passwords against `root`): hydra → sshd → rsyslog → `/var/log/auth.log` → `sentinel-agent` under systemd → API → Redis → normalizer → Postgres → detector → alert. First failed login logged at +3.8 s, threshold (5th failure) at +6.9 s, **alert stored at +7.4 s**; the pipeline itself (5th failure logged → alert stored) took 473 ms including the agent's polling interval, the rest is how fast the attacker fails five times. **The M1 criterion (< 10 s) is met.** One run: a demonstration, not a benchmark.
Also validated on a real host: the systemd unit starts as designed (dedicated user, group `adm` for `auth.log`, `0700` state directory, unreadable key), `systemd-analyze security` exposure **4.2 (OK)**, and real rsyslog lines (ISO timestamps with microseconds) are parsed.

**Design notes**
- OrbStack machines reach the Mac through `host.orb.internal`, which lands on the Mac's `localhost`: the API stays bound to `127.0.0.1`. UTM VMs cannot, so `SENTINEL_BIND_ADDR` must be the Mac's address on the VM network, and that interface only exists while a VM runs (start VMs, then `docker compose up`).
- The attack script only accepts RFC 1918 / loopback targets. The key never appears on a command line or in output: it is written to a `0600` temporary file, copied over SSH and installed `0600` owned by the service user.
- UTM guidance is taken from UTM's and Kali's documentation and marked "not executed": Apple Virtualization offers only Shared and Bridged networking, Host Only requires the QEMU backend, and Kali's UTM guide currently needs a temporary serial device during install (a fallback — a second Ubuntu VM with `hydra` — is documented).

**Problems & lessons**
- **A wrong assumption caught early**: I had assumed the Mac is `192.168.64.1` on UTM's network. On this Mac the bridge is `192.168.139.x` with the host at `.3`. The guide now tells the reader to discover it, and says why.
- The bridge address (`192.168.139.3:8000`) was refused from the OrbStack machine while `host.orb.internal:8000` answered: the first is bound-address dependent, the second is not.
- OrbStack's Ubuntu image has no `openssh-server` (script `--with-sshd`) and Kali has no Python (the attack script's timestamps use GNU `date +%s%3N`, not Python).
- My first `deploy-agent.sh` run failed because this branch had been created from `main`, which does not contain the agent yet (PR #11 is unmerged). The lab branch is therefore stacked on `feat/linux-agent`: **merge #11 first**, then this PR.
- The user already has two UTM VMs ("Linux" x86_64, "Linux 2" aarch64); they were only inspected read-only and are not touched. New VMs get distinct names.
- One documentation URL I guessed for UTM's network page returned 404; the facts were re-checked from pages that exist before writing them down.

**Not done yet**
- **Path B (UTM VMs) was not executed**: its steps follow the documentation and are labelled as such. The scripts it relies on are the ones validated in path A.
- The OrbStack machines (`sl-target`, `sl-attacker`, agent `lab-target-1` registered on the platform) were kept but stopped; remove with `orb delete` and `sentinel agents revoke` when no longer wanted.
- Windows target and Sysmon (M6), response/blocking (M5), detection-rate and false-positive measurements (M2).

**Next**: M2 — more rules (new admin account, sudo, encoded PowerShell…), the `sequence`/`stateful` types, a bounded-time regex engine, and the benchmark that turns the scenarios into detection-rate / false-positive figures.

---

## 2026-09-25 — Linux agent (PR #11)

**Housekeeping first** — PRs #1–#10 (M0 and the whole M1 backend slice) were merged into `main` on 2026-09-25 with merge commits, in order, each retargeted to `main` beforehand; `main` is identical to the last stacked branch and its CI is green (246 tests). The merged branches were kept on GitHub. From now on each piece of work is a branch from `main` and a PR straight into `main`.

**What**
- `agents/linux/` (`sentinel-agent`, standard library only, Python ≥ 3.11): `config.py` (strict TOML, key from a private file or the environment), `state.py` (atomic position store), `tailer.py` (rotation-aware line reader), `client.py` (HTTP client mapping every status of the API contract to a value), `shipper.py` (delivery loop), `cli.py` (`--once`, exit codes).
- `deploy/sentinel-agent.service` (hardened systemd unit) and `agent.toml.example`; a CI job for the agent (ruff, mypy strict, pytest).
- Docs: new [`AGENT.md`](AGENT.md) (guarantees, log handling table, install, exit codes, security, limits), ADR 23, `OPERATIONS.md` recipe to try it against the local stack, cross-link from `INGESTION_API.md`.

**Design notes**
- **The log file is the buffer.** A position is committed only after a `202`; a crash or outage re-sends, never skips, and the server's idempotency key (agent + source + `<inode>:<offset>` + content) absorbs the repeats. No separate disk queue: it would only add failure modes.
- **Rotation like `tail -F`**: the old file stays open until drained (even if deleted: link count 0 is detected, which also covers a recycled inode number), then the new one is followed from its start; after a restart the rotated file is found by its saved inode; a fingerprint of the first 256 bytes, stored once the position is past them, distinguishes files that reuse an inode number.
- **Never stuck, never silently discarding**: a refused batch (`422`/`413`) is bisected until the offending line is alone and only that line is dropped; ten refused lines in a row stop the agent (exit 3) instead of eating the log. `401` stops it (exit 2) with the refused lines left unacknowledged. `503`/network errors are retried forever with capped exponential backoff and jitter; `429` waits `Retry-After`.
- **Hostile bytes never reach the API as a poison pill** (mirror of the server-side fix): NUL escaped, invalid UTF-8 replaced, lines above 8192 characters truncated after escaping, so the API never has reason to refuse a whole batch.
- **Key hygiene**: never read from the configuration file, refused if its file is group/other-readable, hidden from `repr()` and logs, never sent through a redirect (redirects are refused), TLS verification cannot be disabled. A plaintext `http://` server on a non-loopback address is accepted (isolated lab) with a warning.

**How verified**
- 95 tests, ruff and mypy strict clean: config (24 cases incl. key handling and typos), state (atomic write, corruption), tailer (rotation by rename/delete, copytruncate, resume across a rotation, recycled inode, partial lines, hostile bytes, long lines, batching), client against a **real local HTTP server** (every status, timeouts, refused connection, redirect refusal, key never logged), shipper (commit only after the ack, 429/backoff, bisection, circuit breaker, crash before commit, stop during backoff, two sources), CLI exit codes.
- **Mutation checks**: committing the position before the server answers fails four shipper tests; removing the circuit breaker fails the systematic-rejection test.
- **Real end-to-end** (agent on the Mac tailing a temp `auth.log`, against the real Docker stack): six failed SSH logins written over 5 s → one `ssh-bruteforce` alert; **106 ms** from the fifth line being written to the alert being stored (poll interval 0.2 s). API stopped during an attack → the agent backed off and retried (`TimeoutError`, `Connection refused`), and after the API came back the five events and the single alert arrived once each. `mv auth.log auth.log.1` + a new file → all four lines (two before, two after the rotation) arrived, positions moved to the new inode. Agent stopped with SIGTERM, 30 lines written meanwhile, restart → exactly 30 events, all distinct. Key revoked → the agent exited with a clear message and left the refused line unacknowledged (115 bytes).

**Problems & lessons**
- A first version of the client test bounded only the server's error text, not the `HTTP 422:` prefix, so the "bounded detail" assertion failed: the bound now applies to the whole string.
- My "stop during a backoff" test set the stop flag *before* running, which cannot exercise a wait interrupted by SIGTERM; rewritten so the wait itself requests the stop.
- Two of my end-to-end shell checks were wrong (`docker compose` run from the wrong directory reported "0 events"; a path with a double `/` raised a `KeyError`), and I first read them as agent failures. Both were re-run correctly and the data was right each time. Lesson: verify the measuring script before doubting the system.
- `pytest` teardown of the fake HTTP server took 0.5 s per test (default `serve_forever` poll interval); set to 20 ms.

**Not done yet / limits** (also in `AGENT.md`)
- **Not run on a real Linux host**: the systemd unit and its hardening are unvalidated until the lab exists; the agent itself ran on macOS against the local stack.
- Polling instead of inotify; compressed rotated files not followed; `copytruncate` can lose a few lines; `nginx.access` lines are accepted by the API but dead-lettered (no normalizer yet); no response channel (actions by pull come with M5); no client certificates or proxy support.

**Next**: `lab/README.md` (UTM VMs, host-only network, sshd on `target-linux`, installing the agent there) and the real attack from Kali, measuring the "attack → alert < 10 s" criterion with a real attacker.

---

## 2026-09-25 — Robustness fixes from the full M1 code review (PR #10)

**Context** — `/code-review high backend/src/sentinel_core` was the first review that actually read the whole M1 code (the two earlier runs had been scoped to the README and to one commit). It reported ten findings; eight were real and are fixed here, one is declined, one is deferred.

**Fixed**
1. **Poison line (high).** A NUL byte (or a lone UTF-16 surrogate) in a log line made the Postgres insert fail on every retry: the batch was never acknowledged and one authenticated agent could stop every other agent's lines from being normalized. Now: neutralised at the API and in `RawLog` (`text.storable`, before the length check), dead letters are built through `make_dead_letter` so that recording a failure cannot itself fail, and the consumer base class has a safety net — a `DataError` makes the batch be retried entry by entry and the offender is quarantined as a dead letter instead of blocking the others.
2. **Partition creation (high).** An event dated far ahead sits in `events_default`; when its day entered the rolling window, `CREATE TABLE … PARTITION OF` failed ("default partition would be violated"), crashing the normalizer at every startup. Now the rows of that day are moved from the default into the new partition (create, move, attach), each day runs in a savepoint so one failure does not stop the others, and a failed hourly refresh is retried at the next interval instead of on every loop.
3. **Lost alerts in a long batch (found while triaging finding 4).** With alerts persisted at the end of the batch, a crash redelivered it, later events had advanced the windows past the first alert and it could no longer be raised again. The detector now persists the alerts of an event before evaluating the next one; the "trigger re-raises" mechanism then only has to cover the event in flight.
4. **One failing rule discarded the other rules' alerts.** `DetectionEngine.evaluate` now isolates each rule (error handler, Redis errors still propagate), so alerts already produced for the event survive.
5. **Rule keys.** `populate_by_name` allowed `window_seconds` / `cooldown_seconds`, which silently skipped the default cooldown. Only the documented keys exist now.
6. **Event identity.** `event_id` now includes a hash of the line content: after log rotation an inode can be reused and offsets repeat, so one origin could designate different lines that collapsed into one event (and one dead letter).
7. **Consumer.** Entries taken over from a crashed worker no longer wait for the 5 s blocking read of new entries, and the `XAUTOCLAIM` cursor is now honoured.
8. **API Redis client** had no socket timeouts (a stalled Redis would hang ingest requests instead of answering 503); the duplicated dead-letter/stop-signal code of the two workers is shared.

**Declined** — clamping timestamps in the normalizer instead of the engine: the primary key of `events` contains `ts`, so rewriting it with the (per-retry) receipt time would break idempotency for retried lines. The partition problem is fixed at its source instead (item 2).
**Deferred** — the request body is read and parsed before the agent is authenticated (up to 8 MiB per unauthenticated request): resource exhaustion only, tracked for the hardening pass.

**How verified** — every fix has a test that failed first. Mutation checks (each reverted afterwards): persisting at the end of the batch fails the mid-batch crash test; removing the `DataError` isolation fails the quarantine test; blocking reads even with claimed entries fails the latency test; creating partitions without moving the default rows fails both partition tests. 246 tests with real Redis and Postgres (183 pass without them); `ruff`, `mypy --strict` clean. Real stack: a batch with a NUL byte and a lone surrogate among normal lines was accepted (202), all four events were stored (`ro\x00ot`, `bob\ud800`), both streams were empty, no worker errors.

**Problems & lessons**
- Triage of finding 4 revealed a larger flaw than the one reported (any batch spanning more than window + tolerance), which a simpler change (persist per event) fixes better than the reviewer's suggested cooldown history.
- Two older tests replaced `engine.evaluate` with a one-argument fake; changing the signature broke them. Test doubles that mirror a signature need to follow it.
- Poison-data handling is a class of bug, not a single bug: every place where attacker text reaches the database (raw line, event fields, dead letters, error messages) had to be considered, and the last line of defence is the quarantine.

**Not done** — TLS agent↔API, `/docs` exposure, pinning of images and actions, authentication before body parsing.

---

## 2026-09-25 — Follow-ups of the code review of the hardening commit (PR #9)

**What** — `/code-review high` on the hardening commit reported seven findings; three were real defects in my change and are fixed, one is an accepted trade-off, two are documented, one is declined with a reason.
- **Fixed — duplicate alert on retry** (`engine.py`): a host whose clock runs more than 5 s ahead gets its lines dated by the server receipt time, which is new on every retry of the same batch. Threshold alert ids were built from that time, so each retry stored one more alert for the same attack. The id now uses the *triggering event* (stable across retries).
- **Fixed — group digest collisions** (`engine.py`): group values were joined with `\x1f` without lengths, so `("a\x1fb", "c")` and `("a", "b\x1fc")` hashed to the same key. Encoding is now length-prefixed (matters under `scope: global`, where it reached across agents).
- **Fixed — empty strings** (`terminal.py`): `sanitize("")` printed nothing where the old code printed `-`; columns looked shifted. Empty and `None` both show `-`.
- **Added — invariant test**: `MAX_FUTURE_SKEW < LATE_TOLERANCE_MS`, the coupling behind the clamp that was only implicit.
- **Documented — global-scope cooldown**: a forged event can start a `global` rule's cooldown, but it has to reach the threshold first, which raises a visible alert. The reviewer's "swallowed" wording overstated it.
- **Documented — cross-host spraying**: with `scope: agent` the shipped `ssh-bruteforce` does not catch one source spreading failures thinly over several hosts. Accepted trade-off; a `scope: global` rule with multi-agent scenarios is planned for M2.
- **Declined — evict relative to the receipt clock** instead of the newest entry: it would drop late-arriving events after an agent outage and break replays, which is the point of event-time windows. The small skew plus per-agent scope already closes the attack that was reproduced; the invariant is now tested.

**How verified**: three new tests failed first (retry duplicate, digest collision, empty string) and pass after the fixes; 222 tests with real Redis and Postgres (167 pass without them); `ruff`, `mypy --strict` clean.

**Problems & lessons**
- Both `/code-review` runs had a narrower scope than intended: the first (default target = current diff) reviewed only the uncommitted `README.md`, the second only the last commit plus the README, because the branches are stacked and the tool diffs against the upstream. The M1 code as a whole has therefore **not** yet had a full quality review; a path-targeted run is the next step.
- The retry-duplicate bug existed only because the clamp was added in the previous step: a fix that changes which value flows into an identifier needs a check of every identifier derived from it. The earlier retry test only covered past-dated lines.
- The README findings (pasted chat text, French, describes features that do not exist) concern the author's own uncommitted file and were left alone pending their decision.

---

## 2026-09-25 — M1 security fixes from the review (PR #8)

**What**
- **Cross-agent blinding fixed** (medium, found by the M1 security review). New rule option `scope: agent | global` (default `agent`): detection windows, cooldowns and alert ids are now per agent unless a rule opts into `global`. `MAX_FUTURE_SKEW` lowered from 5 minutes to **5 seconds** (later dates are replaced by the server-side receipt time).
- **Terminal escape injection fixed** (below the review's reporting threshold, fixed anyway): `sentinel_core/terminal.py::sanitize` escapes control, format (bidi) and unassigned characters; every attacker-controlled field printed by `sentinel alerts list|show` goes through it.
- Docs: `DETECTION.md` (scope, "Agents are not fully trusted"), ARCHITECTURE §10 + ADR 21.

**The vulnerability, in one paragraph**
The age of a window is measured from its newest entry, whose date comes from the agent, and 5 minutes of "future" were tolerated — more than `window + tolerance` (90 s). A compromised agent (its key lives on a monitored host) could send one line for the attacker's IP dated +299 s; real failed logins of that IP reported by another agent were then older than the horizon and discarded as "too late", so no alert. The same shared state let an agent add fake failures to a victim IP (framing) or take over an alert id.

**How verified**
- Regression tests: the exploit from the review (`test_the_review_exploit_cannot_blind_detection_across_agents`, for both scopes); per-agent isolation (framing, counting, alert-id collision); `global` still correlates across agents; future dates kept within 5 s and clamped beyond; `scope` validation; `sanitize` (ANSI cursor/erase, OSC 52, CR/LF/TAB, 8-bit CSI, DEL, bidi override, zero-width, every Unicode code point); a CLI test with escape sequences in user name, host, group and evidence.
- **Mutation checks**: restoring the 5-minute skew makes the exploit succeed again (`attack went undetected with scope=global`) and fails the two skew tests; making state shared across agents fails the three isolation tests. Both restored afterwards.
- 218 tests with real Redis and Postgres (163 pass without them); `ruff`, `mypy --strict` clean.

**Trade-offs**
- Correlating one source across several hosts now needs `scope: global` (none of the shipped rules does; both are per-host).
- Hosts with clocks more than 5 s ahead get their lines dated by the server: detection still works, ordering inside a batch is lost.
- `scope: global` rules still share state; they rely on the clamp only. Documented in `DETECTION.md`.

**Problems & lessons**
- My first attempt to write these docs failed on a quoting error in a helper script, yet the commit command that followed still ran and produced a commit *without* the documentation. Caught immediately from the commit's file list and amended before pushing. Lesson: chain such steps so that a failed step stops the rest.

**Not done**: the `code-review` pass over M1 (next), TLS between agents and the API (lab only for now), `/docs` exposure, pinning of images and actions.

---

## 2026-09-25 — M1 (step 6) — Detector worker, alerts and the end-to-end slice (PR #7)

**What**
- `workers/consumer.py`: `StreamConsumer` base (consumer group, stale-entry takeover, ack + delete, retry loop, downstream backpressure hook). The normalizer was refactored onto it.
- `workers/detector.py` + `detector` compose service: reads `events.normalized`, applies the engine with `RedisWindowStore`, persists alerts, contains rule bugs as dead letters, refuses to start on a broken or empty rule set.
- `bus/normalized_stream.py`: the normalizer now publishes `events.normalized` (after persisting, before acking) and stops reading `events.raw` while the detector is behind.
- Migration `0003` + `AlertRecord`, `db/alerts.py` (idempotent insert, list, show with evidence and detection latency).
- CLI: `sentinel alerts list|show`. No HTTP endpoint on purpose (alerts are sensitive; user authentication arrives with the dashboard).
- Store change: the event that raised an alert may raise it again during the cooldown (in memory and in the Lua scripts).
- Image ships `rules/`; compose mounts them read-only. Docs: ADR 20, `DETECTION.md` (worker, replay caveat), `OPERATIONS.md`.

**Why**
This closes the M1 vertical slice: a line sent by an agent now becomes an alert with its evidence, measured and inspectable, through every real component.

**Design notes**
- **The at-least-once trap.** The engine records "alert raised" (cooldown) while evaluating. If the worker crashed before persisting the alert, the redelivered event would find the cooldown set and the alert would be lost. Now the trigger event re-raises the alert (same deterministic id, so the insert is a no-op if it was stored), every other event of the cooldown stays suppressed.
- Persist first, publish downstream second, ack last: a crash in between only causes idempotent repeats (events are published even if the insert found them already stored, otherwise a crash could hide an event from the detector).
- Rule bug vs infrastructure error: a `RedisError` propagates (batch retried); any other exception from one rule dead-letters that event and lets the batch proceed, so a single bad rule cannot wedge the stream.

**How verified**
- 198 tests with real Redis and Postgres (144 pass and 54 skip without them). New: pipeline tests raw → normalizer → detector → `alerts` (an attack raises one alert with the right fields, streams end empty); every shipped scenario through the real pipeline; an agent retrying a whole batch adds no alert and no event; **a crash before the alerts are persisted loses nothing and duplicates nothing**; a rule bug is dead-lettered without blocking; a Redis error is retried, not dead-lettered; an undecodable entry is dead-lettered; the normalizer pauses while the detector is behind and resumes after; CLI list/show/ambiguous/malformed ids.
- **Mutation check**: removing the trigger re-raise from the Lua script makes exactly the two crash/redelivery tests fail (and restoring it fixes them), so they do guard the property.
- **Real stack, real HTTP**: six failed SSH logins sent to `POST /v1/ingest` raised one `ssh-bruteforce` alert; `sentinel alerts show` lists its five evidence lines and a **detection latency of 39 ms** (line received by the API → alert stored, single batch on a warm dev stack, not a benchmark). The shipped scenarios replayed through the API gave `ssh-bruteforce` 3 alerts and `ssh-root-login` 2 (per run), the benign files none; both streams empty; no errors in the worker logs.

**Problems & lessons**
- The first replay of the scenarios gave 1 `ssh-bruteforce` alert instead of 3. Not a bug: my earlier live test had moved the state of `203.0.113.7` to the 25th, so the datasets (24th) were "too late" — exactly the documented semantics. It is now documented as "Replaying old logs" (with how to clear the state), and the clean rerun gave the expected 3.
- `ssh-root-login` showed 4 alerts after two replays: each replay used different origins, hence different events, hence different alerts (2 per run). Same event identity ⇒ same alert; different identity ⇒ another alert.
- zsh: `LINES` is a special variable, my shell test failed on it. Unrelated to the project, noted so I stop using that name.
- Two of my own CLI tests were wrong (column index, a 2-character id prefix the CLI rightly refuses). Fixed in the tests, not in the code.
- The DB-side alert `created_at` is the transaction start time, which is what the latency figure uses.

**Not done yet / limits**
- The M1 review (`security-review`, `code-review`) and the lab guide for the real Kali attack are the next two tasks; the "Hydra ⇒ alert in < 10 s" criterion is not yet measured with a real attacker.
- No hot reload of rules, no per-rule metrics, alerts have no status/enrichment yet, no `alerts.new` stream (added with enrichment/response).
- Only `linux.auth` normalization; two rules.

**Next**: security and code review of the whole M1 slice, then `lab/README.md` (UTM VMs, network, agent) — after which the actual Linux agent that tails `auth.log` and ships it to the API.

---

## 2026-09-25 — M1 (step 5) — Detection engine core and first two rules (PR #6)

**What**
- `detection/rules.py`: strict YAML rule format (`match` and `threshold`), durations, field/enum validation, `load_rules()` that reports every faulty file and duplicate id.
- `detection/store.py`: sliding-window state with two implementations of one contract — `InMemoryWindowStore` (reference) and `RedisWindowStore` (sorted sets + atomic Lua scripts).
- `detection/engine.py`: `DetectionEngine.evaluate(event) -> list[Alert]`; `detection/alerts.py`: `Alert` with deterministic ids.
- Rules `rules/ssh-bruteforce.yaml` (T1110) and `rules/ssh-root-login.yaml` (T1078), each with `datasets/<id>/attack.log` and `benign.log`.
- Docs: new [`DETECTION.md`](DETECTION.md) (format, semantics, how to add a rule), ADR 19, `OPERATIONS.md` section.

**Why**
Detection is the product. Building it as a pure library first — no queue, no database — makes the semantics (time, windows, cooldown, hostile input) testable in isolation before the worker wires it to the stream.

**Design notes**
- **Fail loudly at load time.** A misspelled field would mean an attack that is silently never detected, so unknown fields, unknown enum values (`login_failedd`), bad durations, unknown keys and inconsistent rule types all refuse to load, naming the file. Files are read with `yaml.safe_load`.
- **Event time, not wall clock**, with a 30 s out-of-order tolerance and inclusive window bounds; cooldown is in event time too. Full semantics in `DETECTION.md`.
- **Atomicity**: one Lua call per event (add, evict, count, cooldown check), so several detector workers can share a window without races. TTLs are wall-clock but only free memory.
- **Hostile input**: group values (user names, IPs) are attacker-controlled → hashed for Redis keys, truncated in alerts; events lacking a group field are skipped rather than mis-grouped; a far-future timestamp forged by an agent is clamped to the server receipt time (otherwise one crafted line could push the window away from real events and hide an attack).
- **Deterministic alert ids** so that replaying events cannot duplicate alerts once they are persisted.
- **Scenario convention enforced by a test**: every rule must ship an attack and a benign scenario with a `# expect: N` header; a rule without them fails the build. This is also the seed of the detection-rate / false-positive measurements.

**How verified**
- 178 tests with real Redis and Postgres (141 pass and 37 Redis/Postgres tests are skipped without the services). New: 41 rule-validation cases; 13 store contract tests run against **both** stores, i.e. 26 cases (the Lua script behaves exactly like the in-memory reference); 14 engine tests (match, any-of, `extra.*`, per-group cooldown, groups independent, slow failures, missing group field, hostile group value, deterministic ids, disabled rules, several rules on one event, forged future timestamp); 7 scenario tests (2 rules × attack/benign, plus the presence and header conventions).
- **The scenario harness has teeth**: temporarily weakening `ssh-bruteforce` from 5 to 3 attempts made the *benign* scenario fail (three typos by a legitimate user), and restoring it made everything pass again.
- `ruff`, `mypy --strict` clean.

**Problems & lessons**
- Re-reading my own store tests before implementing showed two wrong expectations (an eviction case that contradicted the semantics I wanted, and a confusing comment). Fixing the tests first kept the implementation from bending to bad tests; the implementation then passed all of them on the first run.
- `Event.user_name` is already capped at 256 characters, so my "hostile" test string had to respect that limit; the truncation itself lives in the normalizer.
- Pydantic wraps validator errors in `ValidationError`, so `Rule.model_validate` is overridden to raise `RuleLoadError` with a readable message.
- A `cooldown` of `0s` must stay valid (it is the way to disable the anti-repeat), unlike a `window` of `0s`.

**Not done yet / limits**
- **Not connected to anything**: no detector worker, no `alerts` table, `events.normalized` is still not published, and nothing of this step runs in the compose stack yet (verified with tests and real Redis only).
- Only `match` and `threshold`; no regular expressions or substring conditions (they need a bounded-time engine because they run on attacker-controlled text).
- Logs replayed more than 30 s out of order across a window boundary can be missed (documented).
- Two rules on one source. The M1 security/code review is planned once the slice is complete (detector worker + alerts API).

**Next**: the detector worker — normalizer publishes `events.normalized`, the detector consumes it (consumer group, ack after persisting), evaluates the engine with `RedisWindowStore`, persists alerts (`alerts` table, idempotent on `alert_id`), and an alerts endpoint. That completes the M1 vertical slice.

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
