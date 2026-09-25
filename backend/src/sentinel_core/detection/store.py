"""Sliding-window state for the detection engine.

Windows are evaluated on the EVENT time (milliseconds since the epoch), not on the wall clock,
so an agent catching up after an outage, or a replayed dataset, behaves like live traffic.

Semantics shared by every implementation (checked by tests/detection/test_store_contract.py):
  * a window holds (member -> event time); adding the same member again is a no-op (idempotent);
  * entries older than (newest - window - LATE_TOLERANCE_MS) are evicted; an event that is
    itself that old is dropped on arrival: it counts for nothing and never alerts;
  * an event is counted against its own window [ts - window, ts] (bounds inclusive), so a late
    event within the tolerance can still complete a threshold that existed at its own time;
  * the cooldown is also in event time: after an alert at time t, hits with ts < t + cooldown
    are suppressed (this includes late events with ts < t).
"""

from dataclasses import dataclass
from typing import Any, Protocol

from redis.asyncio import Redis

LATE_TOLERANCE_MS = 30_000
MAX_EVIDENCE = 50
_TTL_SLACK_SECONDS = 3600  # wall-clock memory cleanup only; never used for detection logic


@dataclass(frozen=True)
class ThresholdResult:
    hit: bool  # the threshold was reached AND the cooldown allows an alert
    count: int  # events inside the window of this event (may exceed len(evidence))
    evidence: list[str]  # newest first, at most MAX_EVIDENCE


class WindowStore(Protocol):
    async def record_and_check(
        self,
        key: str,
        member: str,
        ts_ms: int,
        *,
        window_ms: int,
        count: int,
        cooldown_ms: int,
    ) -> ThresholdResult: ...

    async def acquire_cooldown(self, key: str, ts_ms: int, cooldown_ms: int) -> bool:
        """True (and starts the cooldown) if no alert was raised within `cooldown_ms` of ts."""
        ...


class InMemoryWindowStore:
    """Reference implementation: tests, dataset replays, single-process use."""

    def __init__(self) -> None:
        self._windows: dict[str, dict[str, int]] = {}
        self._cooldowns: dict[str, int] = {}

    async def record_and_check(
        self,
        key: str,
        member: str,
        ts_ms: int,
        *,
        window_ms: int,
        count: int,
        cooldown_ms: int,
    ) -> ThresholdResult:
        window = self._windows.setdefault(key, {})
        window[member] = ts_ms
        horizon = max(window.values()) - window_ms - LATE_TOLERANCE_MS
        for stale in [m for m, score in window.items() if score < horizon]:
            del window[stale]

        inside = sorted(
            ((score, m) for m, score in window.items() if ts_ms - window_ms <= score <= ts_ms),
            reverse=True,
        )
        hit = len(inside) >= count
        if hit and cooldown_ms > 0:
            hit = await self.acquire_cooldown(f"cd:{key}", ts_ms, cooldown_ms)
        return ThresholdResult(
            hit=hit, count=len(inside), evidence=[m for _, m in inside[:MAX_EVIDENCE]]
        )

    async def acquire_cooldown(self, key: str, ts_ms: int, cooldown_ms: int) -> bool:
        if cooldown_ms <= 0:
            return True
        last = self._cooldowns.get(key)
        if last is not None and ts_ms < last + cooldown_ms:
            return False
        self._cooldowns[key] = ts_ms
        return True


# KEYS: window zset, cooldown key.  ARGV: member, ts, window, count, cooldown, tolerance,
# max evidence, ttl seconds.  Returns {hit, count, evidence...}.  Atomic: several detector
# workers can share one window without races.
_THRESHOLD_SCRIPT = """
local window_key, cooldown_key = KEYS[1], KEYS[2]
local member = ARGV[1]
local ts = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local count = tonumber(ARGV[4])
local cooldown = tonumber(ARGV[5])
local tolerance = tonumber(ARGV[6])
local max_evidence = tonumber(ARGV[7])
local ttl = tonumber(ARGV[8])

redis.call('ZADD', window_key, ts, member)
local newest = tonumber(redis.call('ZREVRANGE', window_key, 0, 0, 'WITHSCORES')[2])
local horizon = string.format('%d', newest - window - tolerance)
redis.call('ZREMRANGEBYSCORE', window_key, '-inf', '(' .. horizon)

local low = string.format('%d', ts - window)
local high = string.format('%d', ts)
local n = redis.call('ZCOUNT', window_key, low, high)
local evidence = redis.call('ZREVRANGEBYSCORE', window_key, high, low, 'LIMIT', 0, max_evidence)

local hit = 0
if n >= count then
  hit = 1
  if cooldown > 0 then
    local last = redis.call('GET', cooldown_key)
    if last and ts < tonumber(last) + cooldown then
      hit = 0
    else
      redis.call('SET', cooldown_key, string.format('%d', ts), 'EX', ttl)
    end
  end
end
redis.call('EXPIRE', window_key, ttl)

local result = {hit, n}
for _, id in ipairs(evidence) do table.insert(result, id) end
return result
"""

# KEYS: cooldown key.  ARGV: ts, cooldown, ttl seconds.  Returns 1 if allowed.
_COOLDOWN_SCRIPT = """
local ts = tonumber(ARGV[1])
local cooldown = tonumber(ARGV[2])
local last = redis.call('GET', KEYS[1])
if last and ts < tonumber(last) + cooldown then
  return 0
end
redis.call('SET', KEYS[1], string.format('%d', ts), 'EX', tonumber(ARGV[3]))
return 1
"""


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


class RedisWindowStore:
    """Redis implementation: sorted sets for windows, Lua scripts for atomic evaluation."""

    def __init__(self, client: Redis, key_prefix: str = "sl:det:") -> None:
        self._prefix = key_prefix
        self._threshold = client.register_script(_THRESHOLD_SCRIPT)
        self._cooldown = client.register_script(_COOLDOWN_SCRIPT)

    @staticmethod
    def _ttl(*durations_ms: int) -> int:
        return max(durations_ms) * 2 // 1000 + _TTL_SLACK_SECONDS

    async def record_and_check(
        self,
        key: str,
        member: str,
        ts_ms: int,
        *,
        window_ms: int,
        count: int,
        cooldown_ms: int,
    ) -> ThresholdResult:
        raw = await self._threshold(
            keys=[f"{self._prefix}win:{key}", f"{self._prefix}cd:{key}"],
            args=[
                member,
                ts_ms,
                window_ms,
                count,
                cooldown_ms,
                LATE_TOLERANCE_MS,
                MAX_EVIDENCE,
                self._ttl(window_ms, cooldown_ms),
            ],
        )
        return ThresholdResult(
            hit=int(raw[0]) == 1, count=int(raw[1]), evidence=[_text(item) for item in raw[2:]]
        )

    async def acquire_cooldown(self, key: str, ts_ms: int, cooldown_ms: int) -> bool:
        if cooldown_ms <= 0:
            return True
        allowed = await self._cooldown(
            keys=[f"{self._prefix}cd:{key}"],
            args=[ts_ms, cooldown_ms, self._ttl(cooldown_ms)],
        )
        return int(allowed) == 1
