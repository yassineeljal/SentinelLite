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
  alert ids are deterministic (`sha256(rule | group | ts)` or `sha256(rule | event)`), so a replay
  cannot duplicate an alert downstream.
- **Cooldown** is also in event time: after an alert at time `t`, further hits with
  `ts < t + cooldown` for the same group are suppressed (late events with `ts < t` included).
- **Out-of-order tolerance (30 s).** Entries older than `newest - window - 30 s` are evicted. A late
  event inside the tolerance still counts against its own window. An event older than that is
  dropped on arrival: it counts for nothing and never alerts. Consequence: logs replayed more than
  30 s out of order across a window boundary can be missed.
- **Group keys** are hashed (SHA-256) before use in a Redis key: group values such as user names are
  attacker-controlled and unbounded. The alert keeps a copy of each group value (≤ 256 chars).
- **Events that lack a group field** (e.g. a login whose source IP could not be parsed) are skipped
  by rules grouping on that field: they cannot be attributed.
- **Forged timestamps.** Agents control the timestamps in their lines. A timestamp more than
  5 minutes after the server-side receipt time is replaced by the receipt time, so a far-future
  date can neither drag a window away from real events nor hide an attack.
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
| `ssh-bruteforce` | T1110 | threshold | ≥ 5 failed logins per source IP in 60 s, one alert per 5 min |
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

## Limits of this step

- Nothing reads events yet: the detector worker (consume `events.normalized`, persist alerts) is the
  next step. The engine only exists as a library plus tests.
- Two rules, one source (`linux.auth`).
