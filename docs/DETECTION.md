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
type: threshold               # match | threshold
match:                        # ALL conditions must hold (AND)
  source: linux.auth
  action: login_failed        # a list means any-of: action: [login_failed, invalid_user]
group_by: [src_ip]            # threshold: count per group. match: cooldown per group (optional)
threshold: {count: 5, window: 60s}   # threshold rules only; count >= 2
cooldown: 300s                # optional. Default: the window (threshold) / none (match). 0s disables
scope: agent                  # optional. agent (default): state per agent | global: events of all agents together
enabled: true                 # optional
```

- **Fields** usable in `match` and `group_by`: `source`, `category`, `action`, `outcome`, `severity`,
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
| `sequence` | planned (M2) | ordered events per key, e.g. success after N failures |
| `stateful` | planned (M2/M3) | needs history/enrichment: impossible travel, off-hours |

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

## Adding a rule

1. Write `rules/<id>.yaml`.
2. Add `datasets/<id>/attack.log` and `datasets/<id>/benign.log`: raw log lines of the rule's
   source, time-ordered, starting with a `# expect: N` header (the number of alerts this rule must
   raise on that file). The attack file must expect ≥ 1, the benign file must expect `0`. Benign
   scenarios should be the traffic most likely to cause false positives (typos, sub-threshold
   probes, distributed noise, slow guessing).
3. Run `uv run pytest tests/detection -q`. The build fails if a rule lacks a scenario, if the
   headers are inconsistent, or if a scenario does not produce exactly the expected alerts.
4. Note the rule in the table above.

Scenarios are also the seed of the detection benchmark (detection rate / false positives) planned
for the final report.

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

- Two rules, one source (`linux.auth`); no `sequence` / `stateful` rules, no regex conditions.
- No hot reload of rules; no per-rule metrics yet.
- Alerts have no status, assignee or enrichment yet (incidents and enrichment are M3/M4).
- No poison-event handling beyond containment of rule exceptions.
