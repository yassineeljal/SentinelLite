# Detection engine

How rules are written, how they are evaluated, and how to add one. Code in
`backend/src/sentinel_core/detection/`; rules in `rules/`; scenarios in `datasets/`.

## Rule format

One YAML file per rule in `rules/`.

```yaml
id: ssh-bruteforce            # unique, [a-z0-9-], 2-64 chars
title: SSH brute force
description: >                # free text, shown to analysts
  Five or more failed SSH logins from the same source IP within 60 seconds.
mitre: [T1110]                # at least one technique, e.g. T1110 or T1059.001
severity: 60                  # 0-100
type: threshold               # match | threshold | sequence
match:                        # ALL conditions must hold (AND)
  source: linux.auth
  action: login_failed        # a list means any-of: action: [login_failed, invalid_user]
group_by: [src_ip]            # threshold: count per group. match: cooldown per group (optional)
threshold: {count: 5, window: 60s}   # threshold rules only; 2 <= count <= 5000. Add `distinct: <field>` to count distinct values
cooldown: 300s                # optional. Default: the window (threshold) / none (match). 0s disables
scope: agent                  # optional. agent (default): state per agent | global: events of all agents together
enabled: true                 # optional
```

- **`exclude`** (optional, same syntax as `match`): an event that satisfies **all** the exclusion's
  conditions is left out even if `match` holds, e.g. `exclude: {extra.shell: [/usr/sbin/nologin]}`.
  Use it to remove a known-benign shape, and write the blind spot it creates in the rule's
  description (an exclusion is also what an attacker can hide behind).
- **Fields** usable in `match`, `exclude` and `group_by`: `source`, `category`, `action`, `outcome`, `severity`,
  `src_ip`, `dst_ip`, `dst_port`, `user_name`, `host`, `agent_id`, and `extra.<path>` for
  source-specific data (e.g. `extra.method`). `raw` is deliberately not matchable.
- **Durations**: `45s`, `5m`, `2h`, `1d` (integers only). A window must be > 0; a cooldown may be `0s`.
- **Comparison** is on the string form of the value (enums by value, IPs in canonical form).
- **Validation is strict and happens at load time**: an unknown field or enum value, a bad
  duration, an unknown key, a threshold rule without `threshold`/`group_by`, a duplicate id — all
  refuse to load and name the file. A typo can therefore never turn into an attack that is silently
  never detected. Rule files are parsed with `yaml.safe_load` (no Python object construction).

### Rule types

| Type | Status | Fires when |
|---|---|---|
| `match` | implemented | one event satisfies the conditions (and the group's cooldown allows it) |
| `threshold` | implemented | `count` matching events of the same group fall within `window` |
| `sequence` | implemented | a `then` event arrives within `window` after `first` (at least `first.count` events) for the same group |
| `stateful` | planned (M2/M3) | needs history/enrichment: impossible travel, off-hours |

**`threshold` with `distinct`.** `threshold: {count: 6, window: 60s, distinct: user_name}` counts the
different values of a field instead of the events: ten attempts on one name count once. Used for user
enumeration and password spraying, where the interesting signal is the number of *names*, not of
failures. A matching event that lacks the field is skipped. The count is per (rule, group); values are
hashed before they reach Redis. The cooldown identity is the *event*, not the value, so a second event
carrying an already-counted name cannot re-raise the alert.

**`sequence`.** Two steps that share a group (`group_by` is required):

```yaml
type: sequence
group_by: [src_ip]
sequence:
  window: 10m
  first:                                  # at least `count` of these (default 1, max 5000)
    match: {source: linux.auth, action: login_failed}
    count: 5
  then:                                   # the event that completes the sequence (no count)
    match: {source: linux.auth, action: login_success}
```

Each step has its own `match` (required) and optional `exclude`; a sequence rule has no top-level
`match`/`exclude`/`threshold`. Semantics: the `then` event is checked against the `first` events
already in the window **before** it is itself recorded, so one event never completes a sequence with
itself (a step may match both shapes). The alert's evidence is the `then` event followed by the
`first` events; the cooldown (default: the window) is per group. Order matters: successes before the
failures do not count, and neither do failures older than `window`. Both steps use the same
group values, so `group_by: [user_name, host]` ties an account creation and its group change together.

Fields and values available per source: see [`EVENTS.md`](EVENTS.md).

Not supported yet: regular expressions and substring conditions (needed by the web/SQLi rules).
Regexes are evaluated against attacker-controlled text, so they will come with a bounded-time
engine rather than plain `re`.

## Evaluation semantics

- **Event time.** Windows use the event's own timestamp, in milliseconds, not the wall clock: an
  agent catching up after an outage, or a replayed dataset, behaves like live traffic.
- **Sliding, inclusive window.** An event is counted against `[ts - window, ts]`, bounds included.
- **Idempotent.** Re-adding the same event id changes nothing (replays do not double count), and
  alert ids are deterministic (`sha256(rule | group | triggering event)`), so a replay
  cannot duplicate an alert downstream.
- **Cooldown** is also in event time: after an alert at time `t`, further hits with
  `ts < t + cooldown` for the same group are suppressed (late events with `ts < t` included).
- **Out-of-order tolerance (30 s).** Entries older than `newest - window - 30 s` are evicted. A late
  event inside the tolerance still counts against its own window. An event older than that is
  dropped on arrival: it counts for nothing and never alerts. Consequence: logs replayed more than
  30 s out of order across a window boundary can be missed.
- **Group keys** (per agent unless `scope: global`) are hashed (SHA-256, length-prefixed so that no two different tuples encode alike) before use in a Redis key: group values such as user names are
  attacker-controlled and unbounded. The alert keeps a copy of each group value (≤ 256 chars).
- **Events that lack a group field** (e.g. a login whose source IP could not be parsed) are skipped
  by rules grouping on that field: they cannot be attributed.
- **Agents are not fully trusted.** An agent's key lives on a monitored host, so a compromised host
  can send any line: any source IP, any timestamp. Two rules of the engine bound the damage:
  - **Forged timestamps.** The age of a window is measured from its *newest* entry, so a date far
    in the future would push the window away from real events and get them discarded as "too
    late" (blinding detection). A timestamp more than **5 seconds** ahead of the server-side receipt
    time is therefore replaced by the receipt time. The skew must stay well below
    `window + 30 s`; at 5 s a forged date can only shorten the out-of-order tolerance slightly.
    A host whose clock runs more than 5 s ahead is simply dated by the server. (The first version
    tolerated 5 minutes, which allowed exactly that attack; see the security review in the DEVLOG.)
  - **Agent isolation (`scope`).** By default (`scope: agent`) every agent has its own windows and
    cooldowns: a compromised agent cannot add fake failures to an IP that other agents report
    (framing), cannot disturb their windows, and cannot occupy their alert ids. Use
    `scope: global` only for rules that must correlate hosts, e.g. one source spraying many
    machines; such rules share state across agents and rely on the timestamp clamp above.
    Even so, a forged event can start a `global` rule's cooldown (it must first reach the threshold,
    which raises an alert, so the activity is visible but its evidence is forged): use `global`
    sparingly. No shipped rule uses it yet; a cross-host spraying rule with multi-agent scenarios is
    planned for M2. Until then, one source spreading failures thinly over several hosts is not
    caught by `ssh-bruteforce`, which counts per agent.
  - **Invariant**: `MAX_FUTURE_SKEW` (5 s) must stay below the store's late tolerance (30 s), so
    that a date accepted within the skew can never evict an event still inside any window's
    tolerance. A test enforces it.
- **Capacity.** A window keeps at most 10 000 entries (oldest dropped first): a flood cannot grow the
  state without bound, and it is why `count` is capped at 5000 at load time (a larger count could never
  be reached, so it is refused instead of silently never firing).
- **Evidence** is the list of event ids in the window, newest first, capped at 50 (`match_count`
  still reports the true count).
- **State store.** `RedisWindowStore` keeps one sorted set per (rule, group) and evaluates each
  event in a single Lua script (atomic: several detector workers can share a window).
  `InMemoryWindowStore` is the reference implementation used by tests and dataset replays; the
  same contract tests run against both (`tests/detection/test_store_contract.py`).
  Redis TTLs are wall-clock and only free memory; they never drive detection.

## Shipped rules

| Rule | Technique | Type | Logic |
|---|---|---|---|
| `ssh-bruteforce` | T1110 | threshold | ≥ 5 failed logins per source IP **as seen by one agent** in 60 s, one alert per 5 min |
| `ssh-root-login` | T1078 | match | successful login as `root`, one alert per source IP per minute |
| `linux-new-account` | T1136.001 | match | a local account **with a login shell** was created (`useradd`/`adduser`). Excludes nologin/false shells (package service accounts): **blind spot**, a backdoor account with a nologin shell is not reported by this rule |
| `linux-uid-zero-account` | T1136.001 | match | an account created with UID 0 (a second root), whatever its shell: covers the nologin blind spot above |
| `linux-privileged-group-member` | T1098.007 | match | a member added to `sudo`, `admin`, `wheel`, `root`, `shadow`, `disk`, `docker` or `lxd` (usermod and gpasswd count once) |
| `sudo-root-shell` | T1548.003 | match | an interactive root shell through sudo (`sudo -i`, `-s`, `su`, `su -`, `bash`…): the logged command is exactly a shell with no arguments. One alert per user and host per minute. Administrators do this routinely: moderate severity, the value is the trail |
| `sudo-auth-failures` | T1110.001, T1548.003 | threshold | ≥ 3 failed sudo **invocations** (wrong password or not in sudoers) per user and host in 10 min. Counts invocations, not guesses: sudo asks up to three times per invocation and logs one summary line |
| `ssh-success-after-failures` | T1110, T1078 | sequence | a successful login from a source that failed ≥ 5 times in the previous 10 min: the guessing worked. Per source address (also covers spraying), severity 85, one alert per source per 10 min |
| `ssh-user-enumeration` | T1110.003, T1087.001 | threshold (distinct) | ≥ 6 **distinct** user names tried from one source in 60 s (`Invalid user` and `Failed password for invalid user` of one attempt count once). One name tried many times is `ssh-bruteforce`, not this |
| `linux-new-admin-account` | T1136.001, T1098.007 | sequence | an account is created and, within 15 min, added to `sudo`/`admin`/`wheel`/`root` on the same host: a backdoor administrator. The two single-step rules also fire; this one is the correlation. Other privileged groups (`docker`, `shadow`…) are not part of it: **blind spot** |

## Adding a rule

1. Write `rules/<id>.yaml`.
2. Add scenarios under `datasets/<id>/`: raw log lines of the rule's source, time-ordered, in files
   named `attack*.log`, `benign*.log` and, optionally, `negative*.log` (at least one attack and one
   benign; several variants are better: boundary cases, IPv6, noise, slow attacks, look-alikes).
   A **negative** scenario is a near miss: it starts with `# expect: 0` (the owner rule must stay
   silent) and may declare `# also: other-rule=n` for the related rules that do fire, e.g. a sequence
   whose second step arrives one minute too late. Each file starts with header comments:

   ```
   # expect: 2                      required. Attack: alerts the rule must raise (>= 1).
                                    Benign: 0, and NO rule of the whole set may alert.
   # also: other-rule=1             optional: alerts other rules legitimately raise on an attack
   # description: one line          optional, shown in the benchmark report
   # source: linux.auth             optional (default): which normalizer reads the lines
   ```

   Any other comment is free text; a header-looking line with an unknown key (`# expet: 2`) is an
   error, so a typo cannot silently disable a check. Benign scenarios should be the traffic most
   likely to cause false positives (typos, sub-threshold probes, distributed noise, slow guessing).
   `datasets/_shared/` holds benign traffic that **every** rule must ignore (e.g. a normal day).
3. Run `uv run pytest tests/detection -q`, then regenerate the report:
   `uv run sentinel bench --output ../docs/BENCHMARK.md`. The build fails if a rule lacks a scenario,
   a header is inconsistent, a scenario does not produce exactly the expected alerts, or
   `docs/BENCHMARK.md` is out of date.
4. Note the rule in the table above.

## Benchmark

`sentinel bench` replays every scenario like production does (normalizer, then the engine with **all**
rules loaded) and reports the detection rate and the false alerts: [`BENCHMARK.md`](BENCHMARK.md)
(generated, checked by CI). `--throughput` measures the in-memory engine speed (one core; not
end-to-end, and machine-dependent, so not part of the committed file).

What it shows and does not show: the scenarios are curated by the rule author, so the numbers are a
**regression measure of the rules**, not an estimate of detection on real traffic. They do show that the
shipped rules are neither too sensitive nor too lax on the cases we thought of: weakening
`ssh-bruteforce` (threshold 5 → 3, 5 → 8, window 60 s → 30 s, no cooldown) makes the report fail in
each case, with a different symptom (false alerts, missed attacks, wrong alert counts).

## In the stack: the detector worker

`docker compose` runs a `detector` service (`sentinel_core/workers/detector.py`):

1. the normalizer publishes every persisted event to the stream `events.normalized`;
2. the detector reads it through the consumer group `detectors`, evaluates the engine
   (`RedisWindowStore`), writes the alerts to the `alerts` table (and evaluation failures to
   `events_dead_letter`), and only then acknowledges and deletes the entries.

- **Rules are read once at startup** from `SENTINEL_RULES_DIR` (`rules/`, mounted read-only in
  compose). An invalid rule set, or an empty one, makes the worker refuse to start and print every
  problem. After editing rules: `docker compose restart detector`. Hot reload is not implemented.
- **At-least-once, without lost or duplicate alerts.** If the worker crashes after evaluating but
  before persisting, the entries are redelivered. Window state is idempotent per event, alert ids
  are deterministic (rule + group + triggering event), inserts ignore
  duplicates, and the event that raised an alert is allowed to raise it again during the cooldown.
  Every other event of the cooldown stays suppressed. Tested with a real crash simulation.
- **Alerts are persisted as soon as their event is evaluated**, not at the end of the batch. Later
  events of the same batch advance the windows; if the batch were persisted only at its end, a
  crash would redeliver it, an earlier alert could no longer be raised again (its window has moved
  on) and would be lost. Persisting per event leaves at most the event in flight unpersisted, and
  that one re-raises. Tested with a batch holding three alerts ten minutes apart and a crash
  after the second.
- **One failing rule does not affect the others.** If a rule raises on an event, the failure is
  recorded (dead letter `detection error in rule <id>`) and the other rules still run, so alerts
  already produced for that event are kept. Infrastructure (Redis) errors always propagate: the
  batch is retried.
- **Failure handling.** A Redis/Postgres error leaves the batch pending and it is retried. A bug in
  one rule (exception while evaluating an event) is contained: that event is recorded in
  `events_dead_letter` with `source = events.normalized`, the rest of the batch proceeds.
- **Backpressure.** While `events.normalized` holds `SENTINEL_NORMALIZED_STREAM_HIGH_WATERMARK`
  entries (default 100 000) the normalizer stops reading `events.raw`; the backlog then builds up
  where it is bounded, and the API answers `429` to agents.
- **Reading alerts.** `sentinel alerts list [--rule ID] [--limit N]` and `sentinel alerts show <id
  prefix>` (evidence events and the detection latency: line received by the API -> alert stored).
  There is deliberately no HTTP endpoint yet: it would need user authentication (dashboard, M4).

### Replaying old logs

Detection state is per (rule, group) and in event time. After live traffic has moved a group's
window to time `T`, replaying logs of that group older than `T - window - 30 s` finds them
"too late" and they are ignored (and their cooldown was in the future). To test with historical
data on a running stack, either use groups (e.g. IPs) not seen live, or clear the detector state:
`redis-cli --scan --pattern 'sl:det:*' | xargs redis-cli del`.

## Limits

- Ten rules, one source (`linux.auth`); no `stateful` rules (time of day, impossible travel), no regex conditions.
- `sequence` has two steps only (no chains of three), and its `first` step counts events, not distinct values.
- `ssh-success-after-failures` counts failures per source address: an attacker who stays under five failures per ten minutes, or who rotates addresses, is not caught by it.
- No hot reload of rules; no per-rule metrics yet.
- Alerts have no status, assignee or enrichment yet (incidents and enrichment are M3/M4).
- No poison-event handling beyond containment of rule exceptions.
