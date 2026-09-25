"""Scenario tests: every shipped rule must detect its attack and stay silent on benign traffic.

Convention (enforced here): each rule `rules/<id>.yaml` has `datasets/<id>/attack.log` and
`datasets/<id>/benign.log`: raw log lines with a `# expect: N` header giving the number of
alerts the rule must raise on that file. New rules that skip this fail the build.
"""

import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.rules import Rule, load_rules
from sentinel_core.detection.store import InMemoryWindowStore
from sentinel_core.normalizers.base import RawLog
from sentinel_core.normalizers.registry import NORMALIZERS
from sentinel_core.schema.event import Source

REPO_ROOT = Path(__file__).resolve().parents[3]
RULES = load_rules(REPO_ROOT / "rules")
AGENT = UUID("22222222-2222-2222-2222-222222222222")
RECEIVED_AT = datetime(2026, 9, 25, tzinfo=UTC)  # after every timestamp in the datasets
SCENARIOS = ["attack", "benign"]


def dataset(rule: Rule, scenario: str) -> Path:
    return REPO_ROOT / "datasets" / rule.id / f"{scenario}.log"


def read_dataset(path: Path) -> tuple[int, list[str]]:
    """(expected alert count from the `# expect: N` header, the raw log lines)."""
    lines = path.read_text().splitlines()
    header = next(
        (re.fullmatch(r"# expect: (\d+)", x) for x in lines if x.startswith("# expect")), None
    )
    assert header is not None, f"{path} needs a '# expect: N' header"
    return int(header[1]), [x for x in lines if x and not x.startswith("#")]


async def alerts_for(rule: Rule, path: Path) -> tuple[int, int]:
    """Replay a dataset through the normalizer and the engine (all rules loaded, like in
    production). Returns (expected alerts of `rule`, actual alerts of `rule`)."""
    expected, lines = read_dataset(path)
    normalizer = NORMALIZERS[Source.LINUX_AUTH]
    engine = DetectionEngine(RULES, InMemoryWindowStore())

    raised = 0
    for number, line in enumerate(lines):
        raw = RawLog(
            agent_id=AGENT,
            source=Source.LINUX_AUTH,
            origin=f"{path.name}:{number}",
            line=line,
            received_at=RECEIVED_AT,
        )
        event = normalizer.normalize(raw)
        if event is None:
            continue
        raised += sum(a.rule_id == rule.id for a in await engine.evaluate(event))
    return expected, raised


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_rule_ships_an_attack_and_a_benign_scenario(rule: Rule) -> None:
    missing = [s for s in SCENARIOS if not dataset(rule, s).is_file()]

    assert not missing, f"rule {rule.id!r} lacks datasets/{rule.id}/{{{','.join(missing)}}}.log"


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
async def test_rule_scenarios_produce_the_expected_alerts(rule: Rule, scenario: str) -> None:
    expected, actual = await alerts_for(rule, dataset(rule, scenario))

    assert actual == expected, f"{rule.id}/{scenario}: expected {expected} alert(s), got {actual}"


def test_attack_scenarios_really_expect_alerts_and_benign_ones_none() -> None:
    """Guards against a dataset whose header was edited to hide a broken rule."""
    for rule in RULES:
        attack = dataset(rule, "attack").read_text()
        benign = dataset(rule, "benign").read_text()
        assert not attack.startswith("# expect: 0"), f"{rule.id} attack expects nothing"
        assert benign.startswith("# expect: 0"), f"{rule.id} benign must expect 0 alerts"
