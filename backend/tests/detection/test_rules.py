from pathlib import Path
from typing import Any

import pytest

from sentinel_core.detection.rules import Rule, RuleLoadError, load_rules, parse_rule_yaml

REPO_ROOT = Path(__file__).resolve().parents[3]

THRESHOLD_RULE = """
id: ssh-bruteforce
title: SSH brute force
mitre: [T1110]
severity: 60
type: threshold
match:
  source: linux.auth
  action: login_failed
group_by: [src_ip]
threshold: {count: 5, window: 60s}
cooldown: 300s
"""

MATCH_RULE = """
id: ssh-root-login
title: Root login over SSH
mitre: [T1078]
severity: 70
type: match
match:
  source: linux.auth
  action: login_success
  user_name: root
"""


def rule_dict(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "test-rule",
        "title": "Test rule",
        "mitre": ["T1110"],
        "severity": 50,
        "type": "match",
        "match": {"action": "login_failed"},
    }
    return base | changes


def test_threshold_rule_is_parsed_with_durations_in_seconds() -> None:
    rule = parse_rule_yaml(THRESHOLD_RULE)

    assert rule.id == "ssh-bruteforce"
    assert rule.mitre == ["T1110"]
    assert rule.threshold is not None
    assert (rule.threshold.count, rule.threshold.window_seconds) == (5, 60)
    assert rule.cooldown_seconds == 300
    assert rule.group_by == ["src_ip"]


def test_match_rule_is_parsed() -> None:
    rule = parse_rule_yaml(MATCH_RULE)

    assert rule.type == "match"
    assert rule.threshold is None
    assert rule.cooldown_seconds == 0


def test_threshold_cooldown_defaults_to_the_window_to_avoid_alert_floods() -> None:
    text = THRESHOLD_RULE.replace("cooldown: 300s\n", "")

    assert parse_rule_yaml(text).cooldown_seconds == 60


@pytest.mark.parametrize(
    ("text", "seconds"), [("45s", 45), ("5m", 300), ("2h", 7200), ("1d", 86400)]
)
def test_duration_units(text: str, seconds: int) -> None:
    rule = parse_rule_yaml(THRESHOLD_RULE.replace("cooldown: 300s", f"cooldown: {text}"))

    assert rule.cooldown_seconds == seconds


@pytest.mark.parametrize("bad", ["-5s", "5 minutes", "60", "1w", "s", "1.5m", ""])
def test_invalid_durations_are_rejected(bad: str) -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(THRESHOLD_RULE.replace("cooldown: 300s", f"cooldown: '{bad}'"))


def test_a_zero_cooldown_is_allowed_but_a_zero_window_is_not() -> None:
    no_cooldown = parse_rule_yaml(THRESHOLD_RULE.replace("cooldown: 300s", "cooldown: 0s"))

    assert no_cooldown.cooldown_seconds == 0
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(THRESHOLD_RULE.replace("window: 60s", "window: 0s"))


def test_unknown_match_field_is_rejected_so_typos_cannot_silently_never_match() -> None:
    with pytest.raises(RuleLoadError, match="src_ipp"):
        Rule.model_validate(rule_dict(match={"src_ipp": "1.2.3.4"}))


def test_unknown_enum_value_is_rejected() -> None:
    with pytest.raises(RuleLoadError, match="login_failedd"):
        Rule.model_validate(rule_dict(match={"action": "login_failedd"}))


def test_unknown_group_by_field_is_rejected() -> None:
    with pytest.raises(RuleLoadError, match="nope"):
        Rule.model_validate(
            rule_dict(
                type="threshold",
                group_by=["nope"],
                threshold={"count": 3, "window": "60s"},
            )
        )


def test_extra_fields_are_addressable_with_a_dotted_path() -> None:
    rule = Rule.model_validate(rule_dict(match={"extra.method": "password"}))

    assert rule.match == {"extra.method": "password"}
    with pytest.raises(RuleLoadError):
        Rule.model_validate(rule_dict(match={"extra.": "x"}))


def test_list_values_mean_any_of() -> None:
    rule = Rule.model_validate(rule_dict(match={"action": ["login_failed", "invalid_user"]}))

    assert rule.match["action"] == ["login_failed", "invalid_user"]


@pytest.mark.parametrize(
    "changes",
    [
        {"type": "threshold", "group_by": ["src_ip"]},  # threshold type without threshold spec
        {"type": "threshold", "threshold": {"count": 3, "window": "60s"}},  # no group_by
        {"type": "match", "threshold": {"count": 3, "window": "60s"}},  # match with threshold
        {"type": "threshold", "group_by": ["src_ip"], "threshold": {"count": 1, "window": "60s"}},
        {"id": "Bad Id"},
        {"id": ""},
        {"mitre": []},
        {"mitre": ["1110"]},
        {"mitre": ["T11"]},
        {"severity": 101},
        {"severity": -1},
        {"type": "sequence"},
        {"match": {}},
        {"unexpected": "field"},
    ],
)
def test_invalid_rules_are_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(RuleLoadError):
        Rule.model_validate(rule_dict(**changes))


def test_subtechniques_are_accepted() -> None:
    assert Rule.model_validate(rule_dict(mitre=["T1059.001", "T1110"])).mitre == [
        "T1059.001",
        "T1110",
    ]


def test_yaml_that_is_not_a_mapping_is_rejected() -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml("- just\n- a list\n")


def test_yaml_cannot_instantiate_python_objects() -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml("id: !!python/object/apply:os.system ['echo pwned']\n")


def test_load_rules_reads_every_file_in_a_stable_order(tmp_path: Path) -> None:
    (tmp_path / "b.yaml").write_text(MATCH_RULE)
    (tmp_path / "a.yaml").write_text(THRESHOLD_RULE)
    (tmp_path / "notes.txt").write_text("ignored")

    rules = load_rules(tmp_path)

    assert [rule.id for rule in rules] == ["ssh-bruteforce", "ssh-root-login"]


def test_load_rules_names_the_faulty_file(tmp_path: Path) -> None:
    (tmp_path / "good.yaml").write_text(MATCH_RULE)
    (tmp_path / "broken.yaml").write_text(MATCH_RULE.replace("login_success", "nope"))

    with pytest.raises(RuleLoadError, match=r"broken\.yaml"):
        load_rules(tmp_path)


def test_load_rules_rejects_duplicate_ids(tmp_path: Path) -> None:
    (tmp_path / "one.yaml").write_text(MATCH_RULE)
    (tmp_path / "two.yaml").write_text(MATCH_RULE)

    with pytest.raises(RuleLoadError, match="duplicate"):
        load_rules(tmp_path)


def test_the_rules_shipped_with_the_project_are_valid() -> None:
    rules = load_rules(REPO_ROOT / "rules")

    assert {rule.id for rule in rules} >= {"ssh-bruteforce", "ssh-root-login"}


def test_scope_defaults_to_agent_and_accepts_global() -> None:
    assert parse_rule_yaml(THRESHOLD_RULE).scope == "agent"
    assert parse_rule_yaml(THRESHOLD_RULE + "scope: global\n").scope == "global"


def test_scope_rejects_unknown_values() -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(THRESHOLD_RULE + "scope: everyone\n")


@pytest.mark.parametrize(
    "text",
    [
        THRESHOLD_RULE.replace("window: 60s", "window_seconds: 60s"),
        THRESHOLD_RULE.replace("cooldown: 300s", "cooldown_seconds: 300s"),
    ],
)
def test_internal_field_names_are_not_accepted_as_keys(text: str) -> None:
    """Only the documented keys exist: an alias-only rule would silently skip the default
    cooldown and raise one alert per extra event."""
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(text)


def test_exclude_uses_the_same_fields_and_is_optional() -> None:
    rule = Rule.model_validate(
        rule_dict(
            exclude={"extra.shell": ["/usr/sbin/nologin", "/bin/false"], "outcome": "success"}
        )
    )

    assert rule.exclude["extra.shell"] == ["/usr/sbin/nologin", "/bin/false"]
    assert Rule.model_validate(rule_dict()).exclude == {}


@pytest.mark.parametrize(
    "exclude",
    [{"src_ipp": "1.2.3.4"}, {"action": "nope"}, {"extra.": "x"}, {"action": []}],
)
def test_exclude_is_validated_like_match(exclude: dict[str, Any]) -> None:
    with pytest.raises(RuleLoadError):
        Rule.model_validate(rule_dict(exclude=exclude))


# --- distinct aggregation and sequence rules ---------------------------------------------------

ENUMERATION = """
id: ssh-enum
title: User enumeration
mitre: [T1110.003]
severity: 55
type: threshold
match: {source: linux.auth, action: [login_failed, invalid_user]}
group_by: [src_ip]
threshold: {count: 6, window: 60s, distinct: user_name}
"""

SEQUENCE = """
id: success-after-failures
title: Login success after failures
mitre: [T1110, T1078]
severity: 80
type: sequence
group_by: [src_ip]
sequence:
  window: 10m
  first: {match: {source: linux.auth, action: login_failed}, count: 5}
  then: {match: {source: linux.auth, action: login_success}}
"""


def test_a_threshold_can_count_distinct_values_of_a_field() -> None:
    rule = parse_rule_yaml(ENUMERATION)

    assert rule.threshold is not None and rule.threshold.distinct == "user_name"
    assert (rule.threshold.count, rule.threshold.window_seconds) == (6, 60)


def test_distinct_must_name_a_known_field() -> None:
    with pytest.raises(RuleLoadError, match="usr_name"):
        parse_rule_yaml(ENUMERATION.replace("distinct: user_name", "distinct: usr_name"))


def test_the_threshold_count_is_bounded_by_the_window_capacity() -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(ENUMERATION.replace("count: 6", "count: 9999"))


def test_a_sequence_rule_is_parsed_with_its_two_steps() -> None:
    rule = parse_rule_yaml(SEQUENCE)

    assert rule.type == "sequence" and rule.match == {} and rule.threshold is None
    assert rule.sequence is not None
    assert rule.sequence.window_seconds == 600
    assert rule.sequence.first.count == 5 and rule.sequence.then.count == 1
    assert rule.sequence.first.match["action"] == "login_failed"
    assert rule.cooldown_seconds == 600  # defaults to the window, like a threshold rule


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("sequence:\n  window: 10m\n", "sequence:\n"),  # no window
        lambda t: t.replace("group_by: [src_ip]\n", ""),  # no group_by
        lambda t: t.replace("  then: {match: {source: linux.auth, action: login_success}}\n", ""),
        lambda t: t.replace("action: login_failed", "action: login_failedd"),  # typo in a step
        lambda t: t.replace("count: 5", "count: 0"),
        lambda t: t + "match: {action: login_failed}\n",  # top-level match forbidden
        lambda t: t + "threshold: {count: 3, window: 60s}\n",
    ],
)
def test_invalid_sequence_rules_are_refused(mutate: Any) -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(mutate(SEQUENCE))


def test_a_sequence_step_supports_exclude_and_is_validated_like_match() -> None:
    text = SEQUENCE.replace(
        "then: {match: {source: linux.auth, action: login_success}}",
        "then: {match: {source: linux.auth, action: login_success}, exclude: {user_name: backup}}",
    )

    assert parse_rule_yaml(text).sequence.then.exclude == {"user_name": "backup"}  # type: ignore[union-attr]
    with pytest.raises(RuleLoadError, match="src_ipp"):
        parse_rule_yaml(text.replace("user_name: backup", "src_ipp: x"))


def test_a_sequence_section_is_not_allowed_on_other_types() -> None:
    with pytest.raises(RuleLoadError):
        Rule.model_validate(
            rule_dict(
                sequence={
                    "window": "5m",
                    "first": {"match": {"action": "login_failed"}},
                    "then": {"match": {"action": "login_success"}},
                }
            )
        )


def test_only_the_first_step_of_a_sequence_can_have_a_count() -> None:
    """`then` is the event that completes the sequence: a count there would be silently ignored."""
    with pytest.raises(RuleLoadError, match="then"):
        parse_rule_yaml(
            SEQUENCE.replace(
                "then: {match: {source: linux.auth, action: login_success}}",
                "then: {match: {source: linux.auth, action: login_success}, count: 3}",
            )
        )


# --- time-of-day conditions --------------------------------------------------------------------

OFF_HOURS = """
id: off-hours-login
title: Login outside working hours
mitre: [T1078]
severity: 40
type: match
match: {source: linux.auth, action: login_success}
when:
  timezone: America/Toronto
  any_of:
    - hours: "22:00-06:00"
    - days: [sat, sun]
"""


def test_a_match_rule_can_carry_a_schedule() -> None:
    rule = parse_rule_yaml(OFF_HOURS)

    assert rule.when is not None and rule.when.timezone == "America/Toronto"
    assert [(e.hours, e.days) for e in rule.when.any_of] == [
        ("22:00-06:00", None),
        (None, ["sat", "sun"]),
    ]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("timezone: America/Toronto\n", ""),  # no default timezone
        lambda t: t.replace("America/Toronto", "Mars/Olympus"),
        lambda t: t.replace("22:00-06:00", "22h-6h"),
        lambda t: t.replace("[sat, sun]", "[saturday]"),
        lambda t: t.replace("any_of", "any"),  # unknown key
        lambda t: t.replace("    - days: [sat, sun]\n", "    - {}\n"),
    ],
)
def test_invalid_schedules_are_refused(mutate: Any) -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(mutate(OFF_HOURS))


def test_a_sequence_rule_puts_its_schedule_on_a_step() -> None:
    night = 'when: {timezone: UTC, any_of: [{hours: "22:00-06:00"}]}'
    on_a_step = SEQUENCE.replace(
        "then: {match: {source: linux.auth, action: login_success}}",
        f"then: {{match: {{source: linux.auth, action: login_success}}, {night}}}",
    )
    at_the_top = SEQUENCE + OFF_HOURS[OFF_HOURS.index("when:") :]

    assert parse_rule_yaml(on_a_step).sequence.then.when is not None  # type: ignore[union-attr]
    with pytest.raises(RuleLoadError, match="steps"):
        parse_rule_yaml(at_the_top)


# --- stateful rules (impossible travel) ---------------------------------------------------------

IMPOSSIBLE_TRAVEL = """
id: ssh-impossible-travel
title: Impossible travel between two SSH logins
mitre: [T1078]
severity: 70
type: stateful
match: {source: linux.auth, action: login_success}
group_by: [user_name]
scope: global
stateful:
  kind: impossible_travel
  window: 30d
  max_speed_kmh: 900
  min_distance_km: 300
"""


def test_a_stateful_rule_is_parsed_with_its_spec() -> None:
    rule = parse_rule_yaml(IMPOSSIBLE_TRAVEL)

    assert rule.type == "stateful" and rule.threshold is None and rule.sequence is None
    assert rule.stateful is not None
    assert rule.stateful.kind == "impossible_travel"
    assert rule.stateful.window_seconds == 30 * 86400
    assert (rule.stateful.max_speed_kmh, rule.stateful.min_distance_km) == (900, 300)
    assert rule.cooldown_seconds == 30 * 86400  # defaults to the window, like threshold/sequence


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("stateful:\n  kind: impossible_travel\n", "stateful:\n"),  # no kind
        lambda t: t.replace("impossible_travel", "teleportation"),  # unknown kind
        lambda t: t.replace("  window: 30d\n", ""),  # no window
        lambda t: t.replace("max_speed_kmh: 900", "max_speed_kmh: 0"),
        lambda t: t.replace("min_distance_km: 300", "min_distance_km: -1"),
        lambda t: t.replace("match: {source: linux.auth, action: login_success}\n", ""),  # no match
        lambda t: t.replace("group_by: [user_name]\n", ""),  # no group_by
        lambda t: t + "threshold: {count: 3, window: 60s}\n",  # threshold forbidden
        lambda t: t + "sequence: {window: 10m, first: {match: {a: b}}, then: {match: {a: b}}}\n",
    ],
)
def test_invalid_stateful_rules_are_refused(mutate: Any) -> None:
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(mutate(IMPOSSIBLE_TRAVEL))


def test_a_non_stateful_rule_cannot_have_a_stateful_spec() -> None:
    spec = "{kind: impossible_travel, window: 1d, max_speed_kmh: 900, min_distance_km: 300}"
    text = MATCH_RULE + f"stateful: {spec}\n"

    with pytest.raises(RuleLoadError, match="stateful"):
        parse_rule_yaml(text)
