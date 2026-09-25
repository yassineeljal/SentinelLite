"""Detection engine: applies rules to normalized events and yields alerts."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from typing import Any

from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.rules import Rule
from sentinel_core.detection.store import WindowStore
from sentinel_core.schema.event import Event

# An agent controls the timestamps in its lines. A timestamp further in the future than this
# (relative to the server-side receipt time) is replaced by the receipt time, so a forged
# far-future date can neither drag a window away from real events nor hide an attack.
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_GROUP_VALUE_LENGTH = 256
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


class _CompiledRule:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.conditions: list[tuple[str, frozenset[str]]] = []
        for name, condition in rule.match.items():
            values = condition if isinstance(condition, list) else [condition]
            self.conditions.append((name, frozenset(str(_normalize(v)) for v in values)))

    def matches(self, event: Event) -> bool:
        return all(field_value(event, name) in allowed for name, allowed in self.conditions)

    def group_values(self, event: Event) -> list[str] | None:
        """Values of the group_by fields, or None if the event lacks one (cannot be attributed)."""
        values = [field_value(event, name) for name in self.rule.group_by]
        return None if any(v is None for v in values) else [str(v) for v in values]


def _digest(*parts: str) -> str:
    return sha256("\x1f".join(parts).encode()).hexdigest()


class DetectionEngine:
    def __init__(self, rules: Sequence[Rule], store: WindowStore) -> None:
        self._rules = [_CompiledRule(rule) for rule in rules if rule.enabled]
        self._store = store

    async def evaluate(self, event: Event) -> list[Alert]:
        ts = self._effective_ts(event)
        alerts: list[Alert] = []
        for compiled in self._rules:
            if not compiled.matches(event):
                continue
            alert = (
                await self._threshold(compiled, event, ts)
                if compiled.rule.type == "threshold"
                else await self._match(compiled, event, ts)
            )
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
                f"mat:{rule.id}:{_digest(*group)}",
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
        digest = _digest(*group)  # group values are attacker-controlled: hash them for the key
        ts_ms = _to_ms(ts)
        result = await self._store.record_and_check(
            f"thr:{rule.id}:{digest}",
            event.event_id,
            ts_ms,
            window_ms=spec.window_seconds * 1000,
            count=spec.count,
            cooldown_ms=rule.cooldown_seconds * 1000,
        )
        if not result.hit:
            return None
        return self._alert(
            compiled,
            event,
            ts,
            group,
            _digest(rule.id, digest, str(ts_ms)),
            result.evidence,
            result.count,
        )

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
