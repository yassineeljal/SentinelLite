from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from redis.exceptions import RedisError

from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.engine import MAX_FUTURE_SKEW, DetectionEngine
from sentinel_core.detection.rules import Rule
from sentinel_core.detection.store import LATE_TOLERANCE_MS, InMemoryWindowStore
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source

AGENT = UUID("11111111-1111-1111-1111-111111111111")
AGENT_B = UUID("22222222-2222-2222-2222-222222222222")
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
    agent: UUID = AGENT,
) -> Event:
    ts = T0 + timedelta(seconds=at)
    return Event(
        event_id=f"{n:064x}",
        ts=ts,
        received_at=received_at or ts + timedelta(seconds=1),
        agent_id=agent,
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


# --- Isolation between agents and forged timestamps (security review of M1) -----------------
#
# An agent controls the lines it sends: the source IP and the timestamp inside them. Its key
# sits on a monitored host, so a compromised host must not be able to blind or frame the rest.


async def test_by_default_a_rule_counts_each_agent_separately() -> None:
    eng = engine(brute_force_rule())  # scope defaults to "agent"

    # Four failures reported by agent A and one by agent B for the same source IP: nobody saw five.
    for i in range(4):
        assert await eng.evaluate(make_event(i, at=i, agent=AGENT)) == []
    assert await eng.evaluate(make_event(100, at=5, agent=AGENT_B)) == []


async def test_a_compromised_agent_cannot_frame_an_ip_seen_by_another_agent() -> None:
    eng = engine(brute_force_rule())
    for i in range(4):  # forged failures "from" a victim IP, claimed by agent A
        await eng.evaluate(make_event(i, at=i, agent=AGENT, src_ip="192.0.2.10"))

    # Agent B honestly saw a single failed login from that IP: still no alert.
    assert await eng.evaluate(make_event(100, at=5, agent=AGENT_B, src_ip="192.0.2.10")) == []


async def test_global_scope_correlates_across_agents() -> None:
    eng = engine(brute_force_rule(id="spraying", scope="global"))
    alerts = []
    for i in range(5):  # a password-spraying source hitting five different hosts once each
        alerts += await eng.evaluate(make_event(i, at=i, agent=UUID(int=i + 10)))

    assert len(alerts) == 1
    assert alerts[0].match_count == 5


async def test_alert_ids_of_different_agents_never_collide() -> None:
    a, b = engine(brute_force_rule()), engine(brute_force_rule())
    ids = []
    for eng, agent, base in [(a, AGENT, 0), (b, AGENT_B, 100)]:
        for i in range(5):
            found = await eng.evaluate(make_event(base + i, at=i, agent=agent))
            ids += [alert.alert_id for alert in found]

    assert len(ids) == 2 and ids[0] != ids[1]  # same rule, group and time, different agents


async def test_the_review_exploit_cannot_blind_detection_across_agents() -> None:
    """Reproduces the attack from the security review: agent A (compromised) sends a line dated
    ~5 minutes ahead for the attacker's IP, hoping to push the window away so that the real
    failures reported by agent B are discarded as 'too late'."""
    for scope in ("agent", "global"):
        eng = engine(brute_force_rule(scope=scope))
        received = T0 + timedelta(seconds=10)
        forged = make_event(900, at=299, agent=AGENT, received_at=received)
        await eng.evaluate(forged)

        alerts = []
        for i in range(5):  # the real attack, seen by agent B
            alerts += await eng.evaluate(make_event(i, at=i, agent=AGENT_B))

        assert len(alerts) == 1, f"attack went undetected with scope={scope}"


async def test_future_dates_are_kept_within_the_small_skew_and_clamped_beyond() -> None:
    eng = engine(root_login_rule(group_by=[], cooldown="0s"))
    received = T0 + timedelta(seconds=10)
    ok = Action.LOGIN_SUCCESS

    within = await eng.evaluate(make_event(1, action=ok, at=15, received_at=received))  # +5 s
    beyond = await eng.evaluate(make_event(2, action=ok, at=16, received_at=received))  # +6 s

    assert within[0].ts == T0 + timedelta(seconds=15)
    assert beyond[0].ts == received  # replaced by the server-side receipt time


# --- Follow-ups of the code review of the hardening commit -----------------------------------


async def test_a_retried_batch_from_a_fast_clock_host_does_not_duplicate_the_alert() -> None:
    """The clamp replaces a future date by the receipt time, which is new on every retry. The
    alert id must not depend on it, or each retry would store one more alert for one attack."""
    for retry_delay in (10, 400):  # inside the cooldown, and after it
        eng = engine(brute_force_rule())
        ids = []
        for received in (T0 + timedelta(seconds=10), T0 + timedelta(seconds=10 + retry_delay)):
            for i in range(5):  # a host whose clock runs a minute ahead
                events = make_event(i, at=60 + i, received_at=received)
                ids += [a.alert_id for a in await eng.evaluate(events)]

        assert len(set(ids)) == 1, f"retry after {retry_delay}s produced {set(ids)}"


async def test_group_values_containing_the_separator_cannot_collide() -> None:
    rule = brute_force_rule(group_by=["user_name", "host"], scope="global")
    eng = engine(rule)
    base = make_event(0, user="a\x1fb")
    other = make_event(1, user="a")

    # ("a\x1fb", "c") and ("a", "b\x1fc") are different groups: five events split across the
    # two must not add up to a threshold.
    for i in range(3):
        await eng.evaluate(base.model_copy(update={"event_id": f"{i:064x}", "host": "c"}))
    for i in range(3, 6):
        alerts = await eng.evaluate(
            other.model_copy(update={"event_id": f"{i:064x}", "host": "b\x1fc"})
        )
        assert alerts == []


def test_the_future_skew_stays_below_the_late_tolerance() -> None:
    """Invariant behind the timestamp clamp: a forged date within the skew must not be able to
    evict events that are still within the out-of-order tolerance of any window."""
    assert MAX_FUTURE_SKEW.total_seconds() * 1000 < LATE_TOLERANCE_MS


# --- One failing rule must not affect the others (code review) -------------------------------


class _Boom(Exception):
    pass


def two_match_rules() -> tuple[Rule, Rule]:
    return root_login_rule(id="rule-a"), root_login_rule(id="rule-b")


def make_rule_b_raise(eng: DetectionEngine) -> None:
    real = eng._match

    async def failing(compiled: Any, event: Event, ts: datetime) -> Any:
        if compiled.rule.id == "rule-b":
            raise _Boom("bug in rule b")
        return await real(compiled, event, ts)

    eng._match = failing  # type: ignore[method-assign]


async def test_a_failing_rule_does_not_discard_the_alerts_of_the_other_rules() -> None:
    errors: list[tuple[str, str]] = []
    eng = DetectionEngine(
        list(two_match_rules()),
        InMemoryWindowStore(),
        on_rule_error=lambda rule, event, exc: errors.append((rule.id, type(exc).__name__)),
    )
    make_rule_b_raise(eng)

    alerts = await eng.evaluate(make_event(1, action=Action.LOGIN_SUCCESS))

    assert [a.rule_id for a in alerts] == ["rule-a"]  # rule A's alert survives rule B's bug
    assert errors == [("rule-b", "_Boom")]


async def test_without_an_error_handler_a_rule_failure_still_propagates() -> None:
    eng = DetectionEngine(list(two_match_rules()), InMemoryWindowStore())
    make_rule_b_raise(eng)

    with pytest.raises(_Boom):
        await eng.evaluate(make_event(1, action=Action.LOGIN_SUCCESS))


async def test_infrastructure_errors_are_never_swallowed_by_the_error_handler() -> None:
    """A Redis outage must make the whole batch be retried, not become a per-rule 'bug'."""
    seen: list[str] = []
    eng = DetectionEngine(
        list(two_match_rules()),
        InMemoryWindowStore(),
        on_rule_error=lambda rule, event, exc: seen.append(rule.id),
    )

    async def redis_down(*args: Any, **kwargs: Any) -> Any:
        raise RedisError("connection lost")

    eng._match = redis_down  # type: ignore[method-assign]

    with pytest.raises(RedisError):
        await eng.evaluate(make_event(1, action=Action.LOGIN_SUCCESS))
    assert seen == []


# --- exclude ---------------------------------------------------------------------------------


def account_event(n: int, *, login_shell: str, uid: int = 1001) -> Event:
    return make_event(n, action=Action.ACCOUNT_CREATED, src_ip=None, user=f"acct{n}").model_copy(
        update={"extra": {"shell": login_shell, "uid": uid}, "category": Category.IAM}
    )


def new_account_rule(**changes: Any) -> Rule:
    data: dict[str, Any] = {
        "id": "new-account",
        "title": "New login account",
        "mitre": ["T1136.001"],
        "severity": 50,
        "type": "match",
        "match": {"action": "account_created"},
        "exclude": {"extra.shell": ["/usr/sbin/nologin", "/bin/false"]},
    }
    return Rule.model_validate(data | changes)


async def test_an_event_matching_the_exclusion_is_not_alerted() -> None:
    eng = engine(new_account_rule())

    assert len(await eng.evaluate(account_event(1, login_shell="/bin/bash"))) == 1
    assert await eng.evaluate(account_event(2, login_shell="/usr/sbin/nologin")) == []
    assert await eng.evaluate(account_event(3, login_shell="/bin/false")) == []


async def test_the_exclusion_needs_all_its_conditions_to_hold() -> None:
    rule = new_account_rule(exclude={"extra.shell": "/usr/sbin/nologin", "extra.uid": 104})
    eng = engine(rule)

    excluded = await eng.evaluate(account_event(1, login_shell="/usr/sbin/nologin", uid=104))
    other_uid = await eng.evaluate(account_event(2, login_shell="/usr/sbin/nologin", uid=0))

    assert excluded == []
    assert len(other_uid) == 1  # a nologin account with UID 0 is not excluded


# --- distinct aggregation ----------------------------------------------------------------------


def enumeration_rule(**changes: Any) -> Rule:
    data: dict[str, Any] = {
        "id": "ssh-enum",
        "title": "User enumeration",
        "mitre": ["T1110.003"],
        "severity": 55,
        "type": "threshold",
        "match": {"source": "linux.auth", "action": ["login_failed", "invalid_user"]},
        "group_by": ["src_ip"],
        "threshold": {"count": 6, "window": "60s", "distinct": "user_name"},
        "cooldown": "300s",
    }
    return Rule.model_validate(data | changes)


async def test_distinct_users_from_one_source_raise_the_alert_with_one_event_per_user() -> None:
    eng = engine(enumeration_rule())
    names = ["root", "admin", "test", "oracle", "git", "pi"]

    alerts = [await eng.evaluate(make_event(i, at=i, user=n)) for i, n in enumerate(names)]

    assert [len(a) for a in alerts] == [0, 0, 0, 0, 0, 1]
    alert = alerts[5][0]
    assert alert.match_count == 6
    assert alert.event_ids == [f"{i:064x}" for i in range(5, -1, -1)]  # newest first


async def test_one_user_tried_many_times_is_a_brute_force_not_an_enumeration() -> None:
    eng = engine(enumeration_rule())

    alerts = [await eng.evaluate(make_event(i, at=i, user="root")) for i in range(30)]

    assert all(a == [] for a in alerts)  # ssh-bruteforce is the rule for that


async def test_failed_password_and_invalid_user_lines_of_one_name_count_once() -> None:
    """sshd writes both `Invalid user X` and `Failed password for invalid user X`."""
    eng = engine(enumeration_rule())
    alerts = []
    for i, name in enumerate(["a", "b", "c", "d", "e"]):
        alerts += await eng.evaluate(make_event(2 * i, at=2 * i, user=name))
        alerts += await eng.evaluate(
            make_event(2 * i + 1, action=Action.INVALID_USER, at=2 * i + 1, user=name)
        )

    assert alerts == []  # ten events but five distinct names


async def test_distinct_groups_and_missing_fields() -> None:
    eng = engine(enumeration_rule())
    names = ["a", "b", "c", "d", "e", "f"]

    split = [
        await eng.evaluate(make_event(i, at=i, user=n, src_ip=f"203.0.113.{i % 2}"))
        for i, n in enumerate(names)
    ]
    nameless = [await eng.evaluate(make_event(50 + i, at=10 + i, user=None)) for i in range(10)]

    assert all(a == [] for a in split)  # three names per source
    assert all(a == [] for a in nameless)  # no user name: nothing to count


async def test_the_enumeration_cooldown_absorbs_the_rest_of_the_scan() -> None:
    eng = engine(enumeration_rule())

    alerts = [await eng.evaluate(make_event(i, at=i, user=f"user{i}")) for i in range(20)]

    assert sum(len(a) for a in alerts) == 1


# --- sequence rules ------------------------------------------------------------------------------


def success_after_failures(**changes: Any) -> Rule:
    data: dict[str, Any] = {
        "id": "success-after-failures",
        "title": "Login success after failures",
        "mitre": ["T1110", "T1078"],
        "severity": 80,
        "type": "sequence",
        "group_by": ["src_ip"],
        "sequence": {
            "window": "10m",
            "first": {"match": {"action": "login_failed"}, "count": 5},
            "then": {"match": {"action": "login_success"}},
        },
    }
    return Rule.model_validate(data | changes)


async def run_events(eng: DetectionEngine, events: list[Event]) -> list[Alert]:
    found: list[Alert] = []
    for event in events:
        found += await eng.evaluate(event)
    return found


def failures(count: int, start: float = 0, ip: str = "203.0.113.7", base: int = 0) -> list[Event]:
    return [make_event(base + i, at=start + i * 2, src_ip=ip) for i in range(count)]


def success(n: int, at: float, ip: str = "203.0.113.7", agent: UUID = AGENT) -> Event:
    return make_event(n, action=Action.LOGIN_SUCCESS, at=at, src_ip=ip, agent=agent)


async def test_a_success_after_enough_failures_raises_the_alert() -> None:
    eng = engine(success_after_failures())

    alerts = await run_events(eng, [*failures(5), success(100, at=20)])

    assert len(alerts) == 1
    alert = alerts[0]
    assert (alert.rule_id, alert.severity, alert.mitre) == (
        "success-after-failures",
        80,
        ["T1110", "T1078"],
    )
    assert alert.event_ids[0] == f"{100:064x}"  # the completing event first, then the failures
    assert alert.event_ids[1:] == [f"{i:064x}" for i in range(4, -1, -1)]
    assert alert.match_count == 6 and alert.group == {"src_ip": "203.0.113.7"}


async def test_too_few_failures_or_a_success_first_do_not_raise_it() -> None:
    eng = engine(success_after_failures())

    few = await run_events(eng, [*failures(4, ip="203.0.113.1"), success(100, 20, "203.0.113.1")])
    early = await run_events(
        eng, [success(200, 0, "203.0.113.2"), *failures(6, 10, "203.0.113.2", base=300)]
    )

    assert few == [] and early == []  # order matters: failures BEFORE the success


async def test_the_success_must_come_inside_the_window() -> None:
    eng = engine(success_after_failures())

    late = await run_events(eng, [*failures(5), success(100, at=11 * 60)])  # 11 min, window 10 min
    inside = await run_events(
        eng, [*failures(5, ip="203.0.113.9", base=500), success(600, at=9 * 60, ip="203.0.113.9")]
    )

    assert late == [] and len(inside) == 1


async def test_a_success_from_another_source_is_unrelated() -> None:
    eng = engine(success_after_failures())

    alerts = await run_events(eng, [*failures(6), success(100, at=20, ip="198.51.100.5")])

    assert alerts == []


async def test_the_sequence_cooldown_and_redelivery() -> None:
    eng = engine(success_after_failures())
    first = await run_events(eng, [*failures(5), success(100, at=20)])
    again = await eng.evaluate(success(101, at=25))  # a second login moments later: same attack

    redelivered = await eng.evaluate(success(100, at=20))  # the trigger comes back after a crash

    assert len(first) == 1 and again == []
    assert [a.alert_id for a in redelivered] == [first[0].alert_id]


async def test_an_event_never_completes_a_sequence_with_itself() -> None:
    same = success_after_failures(
        sequence={
            "window": "10m",
            "first": {"match": {"action": "login_failed"}, "count": 1},
            "then": {"match": {"action": "login_failed"}},
        }
    )
    eng = engine(same)

    one = await eng.evaluate(make_event(1, at=0))
    two = await eng.evaluate(make_event(2, at=1))

    assert one == [] and len(two) == 1  # the second failure follows the first


async def test_sequences_are_isolated_by_agent_unless_global() -> None:
    other = UUID("22222222-2222-2222-2222-222222222222")
    events = [*failures(5), success(100, at=20, agent=other)]

    per_agent = await run_events(engine(success_after_failures()), events)
    shared = await run_events(engine(success_after_failures(scope="global")), events)

    assert per_agent == []  # failures seen by one agent, the success by another
    assert len(shared) == 1


async def test_a_step_exclusion_is_honoured() -> None:
    rule = success_after_failures(
        sequence={
            "window": "10m",
            "first": {"match": {"action": "login_failed"}, "count": 5},
            "then": {"match": {"action": "login_success"}, "exclude": {"user_name": "backup"}},
        }
    )
    eng = engine(rule)

    alerts = await run_events(
        eng, [*failures(5), success(100, 20).model_copy(update={"user_name": "backup"})]
    )

    assert alerts == []
