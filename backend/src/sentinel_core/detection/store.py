"""Sliding-window state for the detection engine.

Windows are evaluated on the EVENT time (milliseconds since the epoch), not on the wall clock,
so an agent catching up after an outage, or a replayed dataset, behaves like live traffic.

Semantics shared by every implementation (checked by tests/detection/test_store_contract.py):
  * a window holds (member -> event time); adding the same member again is a no-op (idempotent);
  * entries older than (newest - window - LATE_TOLERANCE_MS) are evicted; an event that is
    itself that old is dropped on arrival: it counts for nothing and never alerts;
  * an event is counted against its own window [ts - window, ts] (bounds inclusive), so a late
    event within the tolerance can still complete a threshold that existed at its own time;
  * a window holds at most `max_entries` members: beyond that the OLDEST are dropped, so a flood
    (a compromised agent, a scanner) cannot make the state grow without bound;
  * DISTINCT counting: when `evidence` is given, `member` is the distinct value (its time is
    the last time it was seen) and `evidence` is the event that last showed it; the count is the
    number of distinct values in the window. (For a late event this can undercount values seen
    LATER than it: the safe direction, fewer alerts.)
  * `peek` reads a window like `record_and_check` would, without writing to it (sequence rules
    read the window of their first step when the second step arrives);
  * the cooldown is also in event time: after an alert at time t, hits with ts < t + cooldown
    are suppressed (this includes late events with ts < t) ... except for the very event that
    raised that alert: delivery is at-least-once, so if a worker crashes after evaluating but
    before persisting, the redelivered trigger must raise the alert again rather than find it
    "already raised". Alert ids are deterministic, so raising it twice is harmless.
"""

from dataclasses import dataclass
from typing import Any, Protocol

from redis.asyncio import Redis

LATE_TOLERANCE_MS = 30_000
MAX_EVIDENCE = 50
MAX_WINDOW_ENTRIES = 10_000
_TTL_SLACK_SECONDS = 3600  # wall-clock memory cleanup only; never used for detection logic


@dataclass(frozen=True)
class ThresholdResult:
    hit: bool  # the threshold was reached AND the cooldown allows an alert
    count: int  # members inside the window of this event (may exceed len(evidence))
    evidence: list[str]  # event ids, newest first, at most MAX_EVIDENCE


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
        evidence: str | None = None,
    ) -> ThresholdResult: ...

    async def peek(self, key: str, ts_ms: int, *, window_ms: int) -> ThresholdResult:
        """The window of `ts_ms` as `record_and_check` would see it, without recording anything.
        `hit` is always False."""
        ...

    async def acquire_cooldown(self, key: str, ts_ms: int, cooldown_ms: int, member: str) -> bool:
        """True (and starts the cooldown) if no alert was raised within `cooldown_ms` of ts,
        or if `member` is the very event that raised the current one (redelivery)."""
        ...


class InMemoryWindowStore:
    """Reference implementation: tests, dataset replays, single-process use."""

    def __init__(self, max_entries: int = MAX_WINDOW_ENTRIES) -> None:
        self._max_entries = max_entries
        self._windows: dict[str, dict[str, int]] = {}
        self._evidence: dict[str, dict[str, str]] = {}  # distinct windows: value -> event id
        self._cooldowns: dict[str, tuple[int, str]] = {}  # key -> (ts, triggering member)

    def _drop(self, key: str, members: list[str]) -> None:
        window, evidence = self._windows[key], self._evidence.get(key, {})
        for member in members:
            del window[member]
            evidence.pop(member, None)

    def _inside(self, key: str, ts_ms: int, window_ms: int) -> ThresholdResult:
        window = self._windows.get(key, {})
        inside = sorted(
            ((score, m) for m, score in window.items() if ts_ms - window_ms <= score <= ts_ms),
            reverse=True,
        )
        evidence = self._evidence.get(key, {})
        return ThresholdResult(
            hit=False,
            count=len(inside),
            evidence=[evidence.get(m, m) for _, m in inside[:MAX_EVIDENCE]],
        )

    async def record_and_check(
        self,
        key: str,
        member: str,
        ts_ms: int,
        *,
        window_ms: int,
        count: int,
        cooldown_ms: int,
        evidence: str | None = None,
    ) -> ThresholdResult:
        window = self._windows.setdefault(key, {})
        window[member] = ts_ms
        if evidence is not None:
            self._evidence.setdefault(key, {})[member] = evidence
        horizon = max(window.values()) - window_ms - LATE_TOLERANCE_MS
        self._drop(key, [m for m, score in window.items() if score < horizon])
        if len(window) > self._max_entries:
            oldest = sorted(window.items(), key=lambda item: (item[1], item[0]))
            self._drop(key, [m for m, _ in oldest[: len(window) - self._max_entries]])

        result = self._inside(key, ts_ms, window_ms)
        hit = result.count >= count
        if hit and cooldown_ms > 0:
            # The trigger is an EVENT: for a distinct window the member is only the counted value.
            hit = await self.acquire_cooldown(f"cd:{key}", ts_ms, cooldown_ms, evidence or member)
        return ThresholdResult(hit=hit, count=result.count, evidence=result.evidence)

    async def peek(self, key: str, ts_ms: int, *, window_ms: int) -> ThresholdResult:
        return self._inside(key, ts_ms, window_ms)

    async def acquire_cooldown(self, key: str, ts_ms: int, cooldown_ms: int, member: str) -> bool:
        if cooldown_ms <= 0:
            return True
        last = self._cooldowns.get(key)
        if last is not None and ts_ms < last[0] + cooldown_ms:
            return member == last[1]  # only the trigger itself may re-raise
        self._cooldowns[key] = (ts_ms, member)
        return True


# KEYS: window zset, cooldown key, evidence hash.  ARGV: member, ts, window, count, cooldown,
# tolerance, max evidence, ttl seconds, evidence ('' = plain counting), max entries.
# Returns {hit, count, evidence...}.  Atomic: several detector workers can share one window
# without races.
_THRESHOLD_SCRIPT = """
local window_key, cooldown_key, evidence_key = KEYS[1], KEYS[2], KEYS[3]
local member = ARGV[1]
local ts = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local count = tonumber(ARGV[4])
local cooldown = tonumber(ARGV[5])
local tolerance = tonumber(ARGV[6])
local max_evidence = tonumber(ARGV[7])
local ttl = tonumber(ARGV[8])
local evidence = ARGV[9]
local max_entries = tonumber(ARGV[10])
local track = evidence ~= ''
local trigger = member
if track then trigger = evidence end  -- the trigger is an event, not the counted value

local function forget(members)
  for i = 1, #members, 500 do
    redis.call('HDEL', evidence_key, unpack(members, i, math.min(i + 499, #members)))
  end
end

redis.call('ZADD', window_key, ts, member)
if track then redis.call('HSET', evidence_key, member, evidence) end

local newest = tonumber(redis.call('ZREVRANGE', window_key, 0, 0, 'WITHSCORES')[2])
local horizon = '(' .. string.format('%d', newest - window - tolerance)
if track then forget(redis.call('ZRANGEBYSCORE', window_key, '-inf', horizon)) end
redis.call('ZREMRANGEBYSCORE', window_key, '-inf', horizon)

local size = redis.call('ZCARD', window_key)
if size > max_entries then
  local over = size - max_entries
  if track then forget(redis.call('ZRANGE', window_key, 0, over - 1)) end
  redis.call('ZREMRANGEBYRANK', window_key, 0, over - 1)
end

local low = string.format('%d', ts - window)
local high = string.format('%d', ts)
local n = redis.call('ZCOUNT', window_key, low, high)
local ids = redis.call('ZREVRANGEBYSCORE', window_key, high, low, 'LIMIT', 0, max_evidence)
if track and #ids > 0 then
  local mapped, found = redis.call('HMGET', evidence_key, unpack(ids)), {}
  for _, id in ipairs(mapped) do if id then table.insert(found, id) end end
  ids = found
end

local hit = 0
if n >= count then
  hit = 1
  if cooldown > 0 then
    local last = redis.call('GET', cooldown_key)
    local starts_new_period = true
    if last then
      local sep = string.find(last, '|', 1, true)
      local last_ts = tonumber(string.sub(last, 1, sep - 1))
      if ts < last_ts + cooldown then
        starts_new_period = false
        -- inside the cooldown only the event that raised the alert may raise it again
        if string.sub(last, sep + 1) ~= trigger then hit = 0 end
      end
    end
    if starts_new_period then
      redis.call('SET', cooldown_key, string.format('%d', ts) .. '|' .. trigger, 'EX', ttl)
    end
  end
end
redis.call('EXPIRE', window_key, ttl)
if track then redis.call('EXPIRE', evidence_key, ttl) end

local result = {hit, n}
for _, id in ipairs(ids) do table.insert(result, id) end
return result
"""

# KEYS: window zset.  ARGV: ts, window, max evidence.  Returns {0, count, evidence...}; no write.
_PEEK_SCRIPT = """
local ts = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local low = string.format('%d', ts - window)
local high = string.format('%d', ts)
local n = redis.call('ZCOUNT', KEYS[1], low, high)
local ids = redis.call('ZREVRANGEBYSCORE', KEYS[1], high, low, 'LIMIT', 0, tonumber(ARGV[3]))
local result = {0, n}
for _, id in ipairs(ids) do table.insert(result, id) end
return result
"""

# KEYS: cooldown key.  ARGV: ts, cooldown, ttl seconds, member.  Returns 1 if allowed.
_COOLDOWN_SCRIPT = """
local ts = tonumber(ARGV[1])
local cooldown = tonumber(ARGV[2])
local member = ARGV[4]
local last = redis.call('GET', KEYS[1])
if last then
  local sep = string.find(last, '|', 1, true)
  if ts < tonumber(string.sub(last, 1, sep - 1)) + cooldown then
    if string.sub(last, sep + 1) == member then return 1 end
    return 0
  end
end
redis.call('SET', KEYS[1], string.format('%d', ts) .. '|' .. member, 'EX', tonumber(ARGV[3]))
return 1
"""


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


class RedisWindowStore:
    """Redis implementation: sorted sets for windows, Lua scripts for atomic evaluation."""

    def __init__(
        self,
        client: Redis,
        key_prefix: str = "sl:det:",
        max_entries: int = MAX_WINDOW_ENTRIES,
    ) -> None:
        self._prefix = key_prefix
        self._max_entries = max_entries
        self._threshold = client.register_script(_THRESHOLD_SCRIPT)
        self._peek = client.register_script(_PEEK_SCRIPT)
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
        evidence: str | None = None,
    ) -> ThresholdResult:
        raw = await self._threshold(
            keys=[
                f"{self._prefix}win:{key}",
                f"{self._prefix}cd:{key}",
                f"{self._prefix}ev:{key}",
            ],
            args=[
                member,
                ts_ms,
                window_ms,
                count,
                cooldown_ms,
                LATE_TOLERANCE_MS,
                MAX_EVIDENCE,
                self._ttl(window_ms, cooldown_ms),
                evidence or "",
                self._max_entries,
            ],
        )
        return ThresholdResult(
            hit=int(raw[0]) == 1, count=int(raw[1]), evidence=[_text(item) for item in raw[2:]]
        )

    async def peek(self, key: str, ts_ms: int, *, window_ms: int) -> ThresholdResult:
        raw = await self._peek(
            keys=[f"{self._prefix}win:{key}"], args=[ts_ms, window_ms, MAX_EVIDENCE]
        )
        return ThresholdResult(
            hit=False, count=int(raw[1]), evidence=[_text(item) for item in raw[2:]]
        )

    async def acquire_cooldown(self, key: str, ts_ms: int, cooldown_ms: int, member: str) -> bool:
        if cooldown_ms <= 0:
            return True
        allowed = await self._cooldown(
            keys=[f"{self._prefix}cd:{key}"],
            args=[ts_ms, cooldown_ms, self._ttl(cooldown_ms), member],
        )
        return int(allowed) == 1
