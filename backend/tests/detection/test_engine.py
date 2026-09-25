from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.rules import Rule
from sentinel_core.detection.store import InMemoryWindowStore
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source

AGENT = UUID("11111111-1111-1111-1111-111111111111")
T0 = datetime(2026, 9, 24, 15, 0, 0, tzinfo=UTC)


def make_event(
    n: int,
    *,
    action: Action = Action.LOGIN_FAILED,
    at: float = 0,
    src_ip: str | None = "203.0.113.7",
    user: str | None = "root",
    received_at: datetime | None = None,
    extra: dict[str, Any] | None = None,
) -> Event:
    ts = T0 + timedelta(seconds=at)
    return Event(
        event_id=f"{n:064x}",
        ts=ts,
        received_at=received_at or ts + timedelta(seconds=1),
        agent_id=AGENT,
        host="ubuntu-01",
        source=Source.LINUX_AUTH,
        category=Category.AUTHENTICATION,
        action=action,
        outcome=Outcome.FAILURE if action is not Action.LOGIN_SUCCESS else Outcome.SUCCESS,
        severity=20,
        src_ip=src_ip,
        user_name=user,
        raw="raw line",
        extra=extra or {},
    )


def brute_force_rule(**changes: Any) -> Rule:
    data: dict[str, Any] = {
        "id": "ssh-bruteforce",
        "title": "SSH brute force",
        "mitre": ["T1110"],
        "severity": 60,
        "type": "threshold",
        "match": {"source": "linux.auth", "action": "login_failed"},
        "group_by": ["src_ip"],
        "threshold": {"count": 5, "window": "60s"},
        "cooldown": "300s",
    }
    return Rule.model_validate(data | changes)


def root_login_rule(**changes: Any) -> Rule:
    data: dict[str, Any] = {
        "id": "ssh-root-login",
        "title": "Root login over SSH",
        "mitre": ["T1078"],
        "severity": 70,
        "type": "match",
        "match": {"action": "login_success", "user_name": "root"},
    }
    return Rule.model_validate(data | changes)


def engine(*rules: Rule) -> DetectionEngine:
    return DetectionEngine(list(rules), InMemoryWindowStore())


async def test_match_rule_alerts_on_a_single_matching_event() -> None:
    eng = engine(root_login_rule())

    alerts = await eng.evaluate(make_event(1, action=Action.LOGIN_SUCCESS))

    assert len(alerts) == 1
    alert = alerts[0]
    assert (alert.rule_id, alert.title, alert.mitre, alert.severity) == (
        "ssh-root-login",
        "Root login over SSH",
        ["T1078"],
        70,
    )
    assert alert.event_ids == [f"{1:064x}"]
    assert (alert.src_ip, alert.host, alert.user_name) == ("203.0.113.7", "ubuntu-01", "root")
    assert alert.ts == T0


async def test_non_matching_events_do_not_alert() -> None:
    eng = engine(root_login_rule())

    assert await eng.evaluate(make_event(1, action=Action.LOGIN_FAILED)) == []
    assert await eng.evaluate(make_event(2, action=Action.LOGIN_SUCCESS, user="alice")) == []


async def test_list_values_match_any_of() -> None:
    rule = root_login_rule(match={"action": ["login_success", "invalid_user"]})
    eng = engine(rule)

    assert len(await eng.evaluate(make_event(1, action=Action.INVALID_USER))) == 1
    assert len(await eng.evaluate(make_event(2, action=Action.LOGIN_SUCCESS))) == 1
    assert await eng.evaluate(make_event(3, action=Action.LOGIN_FAILED)) == []


async def test_extra_fields_can_be_matched() -> None:
    eng = engine(root_login_rule(match={"extra.method": "password"}))

    assert await eng.evaluate(make_event(1, extra={"method": "publickey"})) == []
    assert len(await eng.evaluate(make_event(2, extra={"method": "password"}))) == 1


async def test_match_rule_cooldown_is_per_group() -> None:
    rule = root_login_rule(group_by=["src_ip"], cooldown="60s")
    eng = engine(rule)
    ok = Action.LOGIN_SUCCESS

    first = await eng.evaluate(make_event(1, action=ok, at=0))
    repeat = await eng.evaluate(make_event(2, action=ok, at=10))
    other_ip = await eng.evaluate(make_event(3, action=ok, at=11, src_ip="198.51.100.9"))
    later = await eng.evaluate(make_event(4, action=ok, at=70))

    assert (len(first), len(repeat), len(other_ip), len(later)) == (1, 0, 1, 1)


async def test_threshold_rule_alerts_when_the_count_is_reached_then_stays_quiet() -> None:
    eng = engine(brute_force_rule())

    alerts = [await eng.evaluate(make_event(i, at=i * 2)) for i in range(8)]

    assert [len(a) for a in alerts] == [0, 0, 0, 0, 1, 0, 0, 0]  # cooldown absorbs the rest
    alert = alerts[4][0]
    assert alert.rule_id == "ssh-bruteforce"
    assert alert.group == {"src_ip": "203.0.113.7"}
    assert alert.match_count == 5
    assert alert.event_ids == [f"{i:064x}" for i in (4, 3, 2, 1, 0)]
    assert alert.ts == T0 + timedelta(seconds=8)


async def test_threshold_groups_are_independent() -> None:
    eng = engine(brute_force_rule())
    ips = ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"]

    # Five failures in total within seconds, but from five different sources.
    alerts = [await eng.evaluate(make_event(i, at=i, src_ip=ip)) for i, ip in enumerate(ips)]

    assert all(a == [] for a in alerts)


async def test_slow_failures_never_reach_the_threshold() -> None:
    eng = engine(brute_force_rule())

    alerts = [await eng.evaluate(make_event(i, at=i * 20)) for i in range(30)]

    assert all(a == [] for a in alerts)


async def test_an_event_without_the_group_field_is_skipped_not_crashed() -> None:
    eng = engine(brute_force_rule())

    alerts = [await eng.evaluate(make_event(i, at=i, src_ip=None)) for i in range(10)]

    assert all(a == [] for a in alerts)


async def test_group_values_are_attacker_controlled_and_handled_safely() -> None:
    rule = brute_force_rule(group_by=["user_name"])
    eng = engine(rule)
    hostile = "x\x00\n| ‮'; DROP TABLE alerts;--" + "A" * 200

    alerts = [await eng.evaluate(make_event(i, at=i, user=hostile)) for i in range(5)]

    assert len(alerts[4]) == 1  # grouped like any other value
    assert alerts[4][0].group["user_name"] == hostile


async def test_alert_ids_are_deterministic_so_replays_do_not_duplicate_alerts() -> None:
    ids = []
    for _ in range(2):  # two independent runs over the same events, e.g. a replay
        eng = engine(brute_force_rule())
        alerts: list[Alert] = []
        for i in range(5):
            alerts += await eng.evaluate(make_event(i, at=i))
        ids.append(alerts[0].alert_id)

    assert ids[0] == ids[1]
    assert len(ids[0]) == 64


async def test_disabled_rules_are_ignored() -> None:
    eng = engine(root_login_rule(enabled=False))

    assert await eng.evaluate(make_event(1, action=Action.LOGIN_SUCCESS)) == []


async def test_several_rules_can_fire_on_the_same_event() -> None:
    both_match = root_login_rule(id="another-root-rule")
    eng = engine(root_login_rule(), both_match)

    alerts = await eng.evaluate(make_event(1, action=Action.LOGIN_SUCCESS))

    assert sorted(a.rule_id for a in alerts) == ["another-root-rule", "ssh-root-login"]


async def test_a_forged_future_timestamp_cannot_evict_evidence_or_hide_an_attack() -> None:
    """An agent controls the timestamps of its lines. A far-future `ts` is clamped to the
    server-side receipt time instead of dragging the window away from real events."""
    eng = engine(brute_force_rule())
    now = T0 + timedelta(seconds=5)
    for i in range(4):
        await eng.evaluate(make_event(i, at=i, received_at=T0 + timedelta(seconds=i)))

    forged = make_event(99, at=0, received_at=now).model_copy(
        update={"ts": datetime(2999, 1, 1, tzinfo=UTC)}
    )
    alerts = await eng.evaluate(forged)

    assert len(alerts) == 1  # the fifth failure still counts
    assert alerts[0].ts == now  # and it is dated with the clamped time


async def test_redelivered_trigger_re_raises_the_same_alert_and_nothing_else() -> None:
    """A detector that crashed before persisting sees the same events again."""
    eng = engine(brute_force_rule())
    events = [make_event(i, at=i) for i in range(7)]
    first_pass = [a for e in events for a in await eng.evaluate(e)]

    second_pass = [a for e in events for a in await eng.evaluate(e)]

    assert len(first_pass) == 1
    assert [a.alert_id for a in second_pass] == [
        first_pass[0].alert_id
    ]  # same id: no duplicate row
