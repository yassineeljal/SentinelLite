from pathlib import Path

import pytest

from sentinel_core.detection.rules import load_rules
from sentinel_core.detection.scenarios import (
    ScenarioError,
    discover_scenarios,
    parse_scenario,
    run_scenario,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
RULES = load_rules(REPO_ROOT / "rules")

FAILED = (
    "2026-09-24T15:00:0{i}+00:00 host sshd[1]: "
    "Failed password for root from 203.0.113.7 port {i} ssh2"
)
ROOT_OK = (
    "2026-09-24T15:00:09+00:00 host sshd[2]: "
    "Accepted password for root from 203.0.113.7 port 9 ssh2"
)


def scenario_file(tmp_path: Path, name: str, body: str, rule: str = "ssh-root-login") -> Path:
    directory = tmp_path / rule
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text(body)
    return path


def test_a_scenario_is_parsed_with_its_headers_and_only_its_log_lines(tmp_path: Path) -> None:
    path = scenario_file(
        tmp_path,
        "attack-two.log",
        "# expect: 2\n# also: ssh-bruteforce=1, other-rule=3\n# description: two logins\n"
        "# Free text comment: not a header key\n\n" + ROOT_OK + "\n\n",
    )

    scenario = parse_scenario(path, "ssh-root-login")

    assert (scenario.rule_id, scenario.name, scenario.kind) == (
        "ssh-root-login",
        "attack-two",
        "attack",
    )
    assert scenario.expect == 2
    assert scenario.also == {"ssh-bruteforce": 1, "other-rule": 3}
    assert scenario.description == "two logins"
    assert scenario.lines == (ROOT_OK,)
    assert scenario.source == "linux.auth"


@pytest.mark.parametrize(
    ("body", "problem"),
    [
        ("line only\n", "expect"),
        ("# expect: 0\nx\n", "attack"),  # an attack that expects nothing hides a broken rule
        ("# expect: many\nx\n", "expect"),
        ("# expect: 1\n# expet: 2\nx\n", "unknown header"),  # a typo must not pass silently
        ("# expect: 1\n# also: rule\nx\n", "also"),
        ("# expect: 1\n# also: rule=x\nx\n", "also"),
        ("# expect: 1\n# source: windows.sysmon\nx\n", "source"),
        ("# expect: 1\n", "no log lines"),
    ],
)
def test_invalid_attack_scenarios_are_refused(tmp_path: Path, body: str, problem: str) -> None:
    path = scenario_file(tmp_path, "attack.log", body)

    with pytest.raises(ScenarioError, match=problem):
        parse_scenario(path, "ssh-root-login")


def test_a_benign_scenario_must_expect_nothing(tmp_path: Path) -> None:
    path = scenario_file(tmp_path, "benign.log", "# expect: 1\nx\n")

    with pytest.raises(ScenarioError, match="benign"):
        parse_scenario(path, "ssh-root-login")


def test_scenario_names_must_start_with_attack_or_benign(tmp_path: Path) -> None:
    path = scenario_file(tmp_path, "weird.log", "# expect: 1\nx\n")

    with pytest.raises(ScenarioError, match=r"attack.*benign"):
        parse_scenario(path, "ssh-root-login")


def test_discovery_returns_every_scenario_in_a_stable_order(tmp_path: Path) -> None:
    for rule in ("ssh-root-login", "ssh-bruteforce"):
        scenario_file(tmp_path, "attack-b.log", "# expect: 1\nx\n", rule)
        scenario_file(tmp_path, "attack-a.log", "# expect: 1\nx\n", rule)
        scenario_file(tmp_path, "benign.log", "# expect: 0\nx\n", rule)

    found = discover_scenarios(tmp_path, ["ssh-bruteforce", "ssh-root-login"])

    assert [(s.rule_id, s.name) for s in found] == [
        ("ssh-bruteforce", "attack-a"),
        ("ssh-bruteforce", "attack-b"),
        ("ssh-bruteforce", "benign"),
        ("ssh-root-login", "attack-a"),
        ("ssh-root-login", "attack-b"),
        ("ssh-root-login", "benign"),
    ]


def test_every_rule_needs_at_least_one_attack_and_one_benign_scenario(tmp_path: Path) -> None:
    scenario_file(tmp_path, "attack.log", "# expect: 1\nx\n")

    with pytest.raises(ScenarioError, match=r"ssh-root-login.*benign"):
        discover_scenarios(tmp_path, ["ssh-root-login"])
    with pytest.raises(ScenarioError, match=r"ssh-bruteforce.*attack"):
        discover_scenarios(tmp_path, ["ssh-root-login", "ssh-bruteforce"])


def test_a_dataset_folder_for_an_unknown_rule_is_refused(tmp_path: Path) -> None:
    scenario_file(tmp_path, "attack.log", "# expect: 1\nx\n", "ghost-rule")
    scenario_file(tmp_path, "benign.log", "# expect: 0\nx\n", "ghost-rule")

    with pytest.raises(ScenarioError, match="ghost-rule"):
        discover_scenarios(tmp_path, [])


async def test_running_an_attack_scenario_counts_events_and_alerts(tmp_path: Path) -> None:
    path = scenario_file(
        tmp_path, "attack.log", "# expect: 1\n" + ROOT_OK + "\n# comment\nnot syslog\n"
    )

    result = await run_scenario(parse_scenario(path, "ssh-root-login"), RULES)

    assert result.passed and result.problems == []
    assert result.alerts == {"ssh-root-login": 1}
    assert result.events == 1  # the malformed line produced no event


async def test_a_wrong_alert_count_is_reported_as_a_problem(tmp_path: Path) -> None:
    path = scenario_file(tmp_path, "attack.log", "# expect: 3\n" + ROOT_OK + "\n")

    result = await run_scenario(parse_scenario(path, "ssh-root-login"), RULES)

    assert not result.passed
    assert any("expected 3" in p and "got 1" in p for p in result.problems)


async def test_alerts_of_other_rules_must_be_declared(tmp_path: Path) -> None:
    lines = "\n".join([FAILED.format(i=i) for i in range(5)] + [ROOT_OK])
    undeclared = scenario_file(tmp_path, "attack.log", f"# expect: 1\n{lines}\n")
    declared = scenario_file(
        tmp_path,
        "attack-declared.log",
        f"# expect: 1\n# also: ssh-bruteforce=1, ssh-success-after-failures=1\n{lines}\n",
    )

    silent = await run_scenario(parse_scenario(undeclared, "ssh-root-login"), RULES)
    ok = await run_scenario(parse_scenario(declared, "ssh-root-login"), RULES)

    assert not silent.passed and any("ssh-bruteforce" in p for p in silent.problems)
    assert ok.passed


async def test_any_alert_on_a_benign_scenario_is_a_false_positive(tmp_path: Path) -> None:
    path = scenario_file(tmp_path, "benign.log", "# expect: 0\n" + ROOT_OK + "\n")

    result = await run_scenario(parse_scenario(path, "ssh-root-login"), RULES)

    assert not result.passed
    assert any("false positive" in p and "ssh-root-login" in p for p in result.problems)


async def test_a_benign_scenario_that_stays_silent_passes(tmp_path: Path) -> None:
    lines = "\n".join(FAILED.format(i=i) for i in range(4))
    path = scenario_file(tmp_path, "benign.log", f"# expect: 0\n{lines}\n")

    result = await run_scenario(parse_scenario(path, "ssh-bruteforce"), RULES)

    assert result.passed and result.alerts == {} and result.events == 4


def test_the_shared_folder_holds_benign_scenarios_that_no_rule_may_alert_on(tmp_path: Path) -> None:
    for rule in ("ssh-root-login",):
        scenario_file(tmp_path, "attack.log", "# expect: 1\nx\n", rule)
        scenario_file(tmp_path, "benign.log", "# expect: 0\nx\n", rule)
    scenario_file(tmp_path, "benign-day.log", "# expect: 0\nx\n", "_shared")

    found = discover_scenarios(tmp_path, ["ssh-root-login"])

    assert ("_shared", "benign-day") in [(s.rule_id, s.name) for s in found]


def test_an_attack_in_the_shared_folder_is_refused(tmp_path: Path) -> None:
    scenario_file(tmp_path, "attack.log", "# expect: 1\nx\n", "ssh-root-login")
    scenario_file(tmp_path, "benign.log", "# expect: 0\nx\n", "ssh-root-login")
    scenario_file(tmp_path, "attack-oops.log", "# expect: 1\nx\n", "_shared")

    with pytest.raises(ScenarioError, match=r"_shared.*benign"):
        discover_scenarios(tmp_path, ["ssh-root-login"])


async def test_a_shared_scenario_fails_if_any_rule_alerts(tmp_path: Path) -> None:
    path = scenario_file(tmp_path, "benign.log", "# expect: 0\n" + ROOT_OK + "\n", "_shared")

    result = await run_scenario(parse_scenario(path, "_shared"), RULES)

    assert not result.passed and "ssh-root-login" in result.problems[0]


def test_folders_without_log_files_are_ignored_but_a_misnamed_rule_folder_is_not(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "generate.py").write_text("print('x')")
    scenario_file(tmp_path, "attack.log", "# expect: 1\nx\n")
    scenario_file(tmp_path, "benign.log", "# expect: 0\nx\n")
    assert len(discover_scenarios(tmp_path, ["ssh-root-login"])) == 2  # tools/ did not matter

    scenario_file(tmp_path, "attack.log", "# expect: 1\nx\n", "ssh-rot-login")  # typo in the id
    with pytest.raises(ScenarioError, match="ssh-rot-login"):
        discover_scenarios(tmp_path, ["ssh-root-login"])


def test_expected_alerts_combine_the_owner_and_the_declared_others(tmp_path: Path) -> None:
    attack = parse_scenario(
        scenario_file(tmp_path, "attack.log", "# expect: 2\n# also: other=1, none=0\nx\n"),
        "ssh-root-login",
    )
    benign = parse_scenario(
        scenario_file(tmp_path, "benign.log", "# expect: 0\nx\n"), "ssh-root-login"
    )

    assert attack.expected_alerts == {"ssh-root-login": 2, "other": 1}
    assert benign.expected_alerts == {}


# --- negative scenarios: the owner must stay silent, related rules may fire as declared ---------


def test_a_negative_scenario_expects_zero_from_its_owner_and_may_declare_others(
    tmp_path: Path,
) -> None:
    path = scenario_file(
        tmp_path,
        "negative-late.log",
        "# expect: 0\n# also: ssh-bruteforce=1\nx\n",
        "ssh-root-login",
    )

    scenario = parse_scenario(path, "ssh-root-login")

    assert scenario.kind == "negative" and scenario.expect == 0
    assert scenario.expected_alerts == {"ssh-bruteforce": 1}


def test_a_negative_scenario_cannot_expect_alerts_from_its_owner(tmp_path: Path) -> None:
    path = scenario_file(tmp_path, "negative-oops.log", "# expect: 1\nx\n", "ssh-root-login")

    with pytest.raises(ScenarioError, match="negative"):
        parse_scenario(path, "ssh-root-login")


async def test_a_negative_scenario_fails_if_the_owner_fires_or_an_undeclared_rule_does(
    tmp_path: Path,
) -> None:
    failures = "\n".join(
        FAILED.format(i=i) for i in range(5)
    )  # ssh-bruteforce fires, root-login not
    declared = scenario_file(
        tmp_path,
        "negative-a.log",
        f"# expect: 0\n# also: ssh-bruteforce=1\n{failures}\n",
        "ssh-root-login",
    )
    owner_fires = scenario_file(
        tmp_path, "negative-b.log", f"# expect: 0\n{ROOT_OK}\n", "ssh-root-login"
    )
    undeclared = scenario_file(
        tmp_path, "negative-c.log", f"# expect: 0\n{failures}\n", "ssh-root-login"
    )

    good = await run_scenario(parse_scenario(declared, "ssh-root-login"), RULES)
    bad_owner = await run_scenario(parse_scenario(owner_fires, "ssh-root-login"), RULES)
    surprise = await run_scenario(parse_scenario(undeclared, "ssh-root-login"), RULES)

    assert good.passed and good.alerts == {"ssh-bruteforce": 1}
    assert not bad_owner.passed and "ssh-root-login: expected 0" in bad_owner.problems[0]
    assert not surprise.passed and "ssh-bruteforce" in surprise.problems[0]
