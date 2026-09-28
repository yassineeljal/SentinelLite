"""Detection engine: applies rules to normalized events and yields alerts."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from math import asin, cos, radians, sin, sqrt
from typing import Any

from redis.exceptions import RedisError

from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.rules import Rule, SequenceStep, StatefulSpec
from sentinel_core.detection.schedule import Schedule
from sentinel_core.detection.store import WindowStore
from sentinel_core.enrichment.geoip import GeoIpResolver
from sentinel_core.schema.event import Event

# An agent controls the timestamps in its lines. The age of a window is measured from its NEWEST
# entry, so a date far ahead would push the window away from real events and get them discarded
# as "too late". Dates ahead of the server-side receipt time by more than this small skew are
# replaced by the receipt time. It must stay well below window + tolerance, otherwise a forged
# date could still hide real events (see DETECTION.md, "Forged timestamps"). A host whose clock
# runs ahead by more than this is simply dated by the server.
MAX_FUTURE_SKEW = timedelta(seconds=5)
MAX_GROUP_VALUE_LENGTH = 256

# Called with (rule, event, exception) when ONE rule fails on an event.
RuleErrorHandler = Callable[[Rule, Event, Exception], None]
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MS = timedelta(milliseconds=1)


def _normalize(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def field_value(event: Event, name: str) -> str | None:
    """Value of a rule field on an event as a string, or None if absent."""
    if name.startswith("extra."):
        current: Any = event.extra
        for part in name.removeprefix("extra.").split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return _normalize(current)
    return _normalize(getattr(event, name))


@dataclass(frozen=True)
class _Step:
    conditions: list[tuple[str, frozenset[str]]]
    exclusions: list[tuple[str, frozenset[str]]]
    when: Schedule | None


class _CompiledRule:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.conditions = self._compile(rule.match)
        self.exclusions = self._compile(rule.exclude)
        self.first: _Step | None = None
        self.then: _Step | None = None
        if rule.sequence is not None:
            self.first = self._step(rule.sequence.first)
            self.then = self._step(rule.sequence.then)

    def _step(self, spec: SequenceStep) -> "_Step":
        return _Step(self._compile(spec.match), self._compile(spec.exclude), spec.when)

    @staticmethod
    def _compile(mapping: dict[str, Any]) -> list[tuple[str, frozenset[str]]]:
        compiled: list[tuple[str, frozenset[str]]] = []
        for name, condition in mapping.items():
            values = condition if isinstance(condition, list) else [condition]
            compiled.append((name, frozenset(str(_normalize(v)) for v in values)))
        return compiled

    @staticmethod
    def _holds(event: Event, conditions: list[tuple[str, frozenset[str]]]) -> bool:
        return all(field_value(event, name) in allowed for name, allowed in conditions)

    def step_holds(self, event: Event, step: "_Step", ts: datetime) -> bool:
        if step.when is not None and not step.when.contains(ts):
            return False
        if not self._holds(event, step.conditions):
            return False
        return not (step.exclusions and self._holds(event, step.exclusions))

    def matches(self, event: Event, ts: datetime) -> bool:
        """Is this event relevant to the rule (for a sequence: to either of its steps)?"""
        if self.first is not None and self.then is not None:
            return self.step_holds(event, self.first, ts) or self.step_holds(event, self.then, ts)
        if self.rule.when is not None and not self.rule.when.contains(ts):
            return False
        if not self._holds(event, self.conditions):
            return False
        return not (self.exclusions and self._holds(event, self.exclusions))

    def group_values(self, event: Event) -> list[str] | None:
        """Values of the group_by fields, or None if the event lacks one (cannot be attributed)."""
        values = [field_value(event, name) for name in self.rule.group_by]
        return None if any(v is None for v in values) else [str(v) for v in values]


def _digest(*parts: str) -> str:
    # Length-prefixed, so that no two different tuples of parts can encode to the same bytes:
    # the parts are attacker-controlled and may contain any separator character.
    return sha256("".join(f"{len(part)}:{part}" for part in parts).encode()).hexdigest()


def _group_digest(rule: Rule, event: Event, group: list[str]) -> str:
    """Identity of the state a group's events are counted in (hashed: values are untrusted)."""
    if rule.scope == "agent":
        return _digest(str(event.agent_id), *group)
    return _digest(*group)


_EARTH_RADIUS_KM = 6371.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km. Ignores altitude and the shape of real travel routes: a lower
    bound on how far the traveller actually went, never an overestimate."""
    p1, p2 = radians(lat1), radians(lat2)
    d_phi, d_lambda = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(d_phi / 2) ** 2 + cos(p1) * cos(p2) * sin(d_lambda / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * asin(min(1.0, sqrt(a)))


def _encode_location(event_id: str, ts_ms: int, lat: float, lon: float) -> str:
    # event_id is hex-only and ts/lat/lon never contain '|': safe as a plain separator.
    return f"{event_id}|{ts_ms}|{lat!r}|{lon!r}"


@dataclass(frozen=True)
class _Location:
    event_id: str
    ts_ms: int
    lat: float
    lon: float


def _decode_location(encoded: str) -> "_Location | None":
    parts = encoded.split("|")
    if len(parts) != 4:
        return None  # defensive: this store only ever holds what _encode_location wrote
    event_id, ts_ms, lat, lon = parts
    try:
        return _Location(event_id, int(ts_ms), float(lat), float(lon))
    except ValueError:
        return None


def _previous_location(evidence: list[str], own_event_id: str) -> "_Location | None":
    """The most recent entry that is not `own_event_id` (a redelivered event may already be its
    own newest entry: peek() runs before this event records itself, but on redelivery after a
    crash the earlier attempt's write may already be there)."""
    for encoded in evidence:
        location = _decode_location(encoded)
        if location is not None and location.event_id != own_event_id:
            return location
    return None


class MissingGeoIp(ValueError):
    """A loaded, enabled rule needs GeoIP lookups but none were configured."""


class DetectionEngine:
    def __init__(
        self,
        rules: Sequence[Rule],
        store: WindowStore,
        on_rule_error: RuleErrorHandler | None = None,
        geoip: GeoIpResolver | None = None,
    ) -> None:
        self._rules = [_CompiledRule(rule) for rule in rules if rule.enabled]
        self._store = store
        self._on_rule_error = on_rule_error
        self._geoip = geoip
        needing = [c.rule.id for c in self._rules if c.rule.type == "stateful"]
        if needing and geoip is None:
            raise MissingGeoIp(
                f"rule(s) {', '.join(needing)} need GeoIP lookups (type: stateful) but no "
                "GeoIP database was configured; see docs/DETECTION.md"
            )

    async def evaluate(
        self, event: Event, on_rule_error: RuleErrorHandler | None = None
    ) -> list[Alert]:
        """Alerts raised by `event`.

        A rule that fails does not affect the others: when an error handler is given (here or at
        construction) the failure is reported to it and the remaining rules still run, so the
        alerts already produced for this event are not lost. Without a handler the exception
        propagates. Infrastructure errors (Redis) always propagate: the caller must retry.
        """
        handler = on_rule_error or self._on_rule_error
        ts = self._effective_ts(event)
        alerts: list[Alert] = []
        for compiled in self._rules:
            if not compiled.matches(event, ts):
                continue
            try:
                if compiled.rule.type == "threshold":
                    alert = await self._threshold(compiled, event, ts)
                elif compiled.rule.type == "sequence":
                    alert = await self._sequence(compiled, event, ts)
                elif compiled.rule.type == "stateful":
                    alert = await self._stateful(compiled, event, ts)
                else:
                    alert = await self._match(compiled, event, ts)
            except RedisError:
                raise
            except Exception as exc:
                if handler is None:
                    raise
                handler(compiled.rule, event, exc)
                continue
            if alert is not None:
                alerts.append(alert)
        return alerts

    @staticmethod
    def _effective_ts(event: Event) -> datetime:
        if event.ts > event.received_at + MAX_FUTURE_SKEW:
            return event.received_at
        return event.ts

    async def _match(self, compiled: _CompiledRule, event: Event, ts: datetime) -> Alert | None:
        rule = compiled.rule
        group = compiled.group_values(event)
        if group is None:
            return None
        if rule.cooldown_seconds > 0:
            allowed = await self._store.acquire_cooldown(
                f"mat:{rule.id}:{_group_digest(rule, event, group)}",
                _to_ms(ts),
                rule.cooldown_seconds * 1000,
                event.event_id,
            )
            if not allowed:
                return None
        return self._alert(
            compiled, event, ts, group, _digest(rule.id, event.event_id), [event.event_id], 1
        )

    async def _threshold(self, compiled: _CompiledRule, event: Event, ts: datetime) -> Alert | None:
        rule = compiled.rule
        spec = rule.threshold
        if spec is None:  # cannot happen: Rule validation requires it for threshold rules
            raise RuntimeError(f"threshold rule {rule.id!r} has no threshold spec")
        group = compiled.group_values(event)
        if group is None:
            return None
        digest = _group_digest(rule, event, group)
        ts_ms = _to_ms(ts)
        member, evidence = event.event_id, None
        if spec.distinct is not None:  # count distinct values of a field, not events
            value = field_value(event, spec.distinct)
            if value is None:
                return None  # nothing to count for this event
            member, evidence = _digest(value), event.event_id
        result = await self._store.record_and_check(
            f"thr:{rule.id}:{digest}",
            member,
            ts_ms,
            window_ms=spec.window_seconds * 1000,
            count=spec.count,
            cooldown_ms=rule.cooldown_seconds * 1000,
            evidence=evidence,
        )
        if not result.hit:
            return None
        return self._alert(
            compiled,
            event,
            ts,
            group,
            # The trigger event, not its time: the effective time can be the server receipt time
            # (clamped), which is new on every retry of the same batch by the agent.
            _digest(rule.id, digest, event.event_id),
            result.evidence,
            result.count,
        )

    async def _sequence(self, compiled: _CompiledRule, event: Event, ts: datetime) -> Alert | None:
        """`first` (>= count events) then `then`, per group, within the window.

        The completing event reads the window of the first step BEFORE it is itself recorded as a
        first-step event, so that one event can never complete a sequence with itself.
        """
        rule = compiled.rule
        spec = rule.sequence
        if spec is None or compiled.first is None or compiled.then is None:
            raise RuntimeError(f"sequence rule {rule.id!r} has no sequence spec")
        group = compiled.group_values(event)
        if group is None:
            return None
        digest = _group_digest(rule, event, group)
        key = f"seq:{rule.id}:{digest}"
        ts_ms = _to_ms(ts)
        window_ms = spec.window_seconds * 1000

        alert: Alert | None = None
        if compiled.step_holds(event, compiled.then, ts):
            prior = await self._store.peek(key, ts_ms, window_ms=window_ms)
            if prior.count >= spec.first.count and await self._store.acquire_cooldown(
                key, ts_ms, rule.cooldown_seconds * 1000, event.event_id
            ):
                alert = self._alert(
                    compiled,
                    event,
                    ts,
                    group,
                    _digest(rule.id, digest, event.event_id),
                    [event.event_id, *prior.evidence],
                    prior.count + 1,
                )
        if compiled.step_holds(event, compiled.first, ts):
            await self._store.record_and_check(
                key, event.event_id, ts_ms, window_ms=window_ms, count=1, cooldown_ms=0
            )
        return alert

    async def _stateful(self, compiled: _CompiledRule, event: Event, ts: datetime) -> Alert | None:
        rule = compiled.rule
        spec = rule.stateful
        if spec is None:  # cannot happen: Rule validation requires it for stateful rules
            raise RuntimeError(f"stateful rule {rule.id!r} has no stateful spec")
        if spec.kind == "impossible_travel":
            return await self._impossible_travel(compiled, spec, event, ts)
        raise RuntimeError(f"unknown stateful kind {spec.kind!r}")  # unreachable: validated at load

    async def _impossible_travel(
        self, compiled: _CompiledRule, spec: StatefulSpec, event: Event, ts: datetime
    ) -> Alert | None:
        """Alerts when this login could not physically follow the group's previous one.

        The location this event is remembered under is written AFTER the comparison (`peek` then
        `record_and_check`, like a sequence's `first` step): an event never travels from itself.
        `_previous_location` also skips any entry matching this event's own id, in case a crash
        between that write and the alert being persisted caused the entry to already be there on
        redelivery -- the same trigger must always compare against the same true previous point.
        """
        rule = compiled.rule
        group = compiled.group_values(event)
        if group is None or event.src_ip is None or self._geoip is None:
            return None
        geo = self._geoip.lookup(str(event.src_ip))
        if geo is None or geo.latitude is None or geo.longitude is None:
            return None  # non-public, or the database has no coordinates for it
        digest = _group_digest(rule, event, group)
        key = f"trv:{rule.id}:{digest}"
        ts_ms = _to_ms(ts)
        window_ms = spec.window_seconds * 1000

        prior = await self._store.peek(key, ts_ms, window_ms=window_ms)
        previous = _previous_location(prior.evidence, event.event_id)
        alert: Alert | None = None
        if previous is not None:
            distance_km = _haversine_km(previous.lat, previous.lon, geo.latitude, geo.longitude)
            if distance_km >= spec.min_distance_km:
                hours = max((ts_ms - previous.ts_ms) / 3_600_000, 1 / 3600)  # floor: 1 second
                if distance_km / hours > spec.max_speed_kmh and await self._store.acquire_cooldown(
                    key, ts_ms, rule.cooldown_seconds * 1000, event.event_id
                ):
                    alert = self._alert(
                        compiled,
                        event,
                        ts,
                        group,
                        _digest(rule.id, digest, event.event_id),
                        [event.event_id, previous.event_id],
                        2,
                    )
        await self._store.record_and_check(
            key,
            event.event_id,
            ts_ms,
            window_ms=window_ms,
            count=1,
            cooldown_ms=0,
            evidence=_encode_location(event.event_id, ts_ms, geo.latitude, geo.longitude),
        )
        return alert

    @staticmethod
    def _alert(
        compiled: _CompiledRule,
        event: Event,
        ts: datetime,
        group: list[str],
        alert_id: str,
        evidence: list[str],
        count: int,
    ) -> Alert:
        rule = compiled.rule
        return Alert(
            alert_id=alert_id,
            rule_id=rule.id,
            title=rule.title,
            mitre=list(rule.mitre),
            severity=rule.severity,
            ts=ts,
            group={
                name: value[:MAX_GROUP_VALUE_LENGTH]
                for name, value in zip(rule.group_by, group, strict=True)
            },
            src_ip=str(event.src_ip) if event.src_ip else None,
            host=event.host,
            user_name=event.user_name,
            event_ids=evidence,
            match_count=count,
        )


def _to_ms(ts: datetime) -> int:
    return (ts - _EPOCH) // _MS
