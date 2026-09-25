"""Attack and benign log scenarios: the executable specification (and the benchmark data) of rules.

Layout: `datasets/<rule-id>/<name>.log`, where `<name>` starts with `attack` or `benign`, plus
`datasets/_shared/benign*.log`: benign traffic (e.g. a normal day) that EVERY rule must stay silent
on. Each file
is a series of raw log lines with a header of comment lines:

    # expect: 2                      required. Attack: alerts the owning rule must raise (>= 1).
                                     Benign: must be 0, and NO rule may alert at all.
    # also: other-rule=1, third=2    optional. Alerts other rules legitimately raise on an attack.
    # description: one line          optional, shown in the benchmark report
    # source: linux.auth             optional (default linux.auth): which normalizer reads the lines

Any other comment is free text. A header-looking line with an unknown key is an error, so a typo
cannot silently turn a check off.
"""

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.rules import Rule
from sentinel_core.detection.store import InMemoryWindowStore, WindowStore
from sentinel_core.normalizers.base import ParseError, RawLog
from sentinel_core.normalizers.registry import NORMALIZERS
from sentinel_core.schema.event import Source

SHARED = "_shared"  # pseudo rule id of the benign scenarios that concern all rules
KNOWN_HEADERS = {"expect", "also", "description", "source"}
_HEADER = re.compile(r"^# ([a-z][a-z-]*): ?(.*)$")
_AGENT = UUID("22222222-2222-2222-2222-222222222222")
# After every timestamp of every dataset, so that no line looks "from the future" to the engine.
REPLAY_RECEIVED_AT = datetime(2027, 1, 1, tzinfo=UTC)


class ScenarioError(Exception):
    """A dataset file or layout does not follow the convention."""


@dataclass(frozen=True)
class Scenario:
    rule_id: str
    name: str
    kind: Literal["attack", "benign"]
    expect: int
    lines: tuple[str, ...]
    path: Path
    also: dict[str, int] = field(default_factory=dict)
    description: str = ""
    source: str = "linux.auth"


@dataclass(frozen=True)
class ScenarioResult:
    scenario: Scenario
    events: int  # log lines that the normalizer turned into events
    alerts: dict[str, int]  # alerts per rule id (only rules that alerted)
    problems: list[str]

    @property
    def passed(self) -> bool:
        return not self.problems


def _parse_also(value: str, where: str) -> dict[str, int]:
    also: dict[str, int] = {}
    for item in filter(None, (part.strip() for part in value.split(","))):
        name, _, count = item.partition("=")
        if not name or not count.strip().isdigit():
            raise ScenarioError(f"{where}: bad '# also' entry {item!r} (expected rule-id=count)")
        also[name.strip()] = int(count)
    return also


def parse_scenario(path: Path, rule_id: str) -> Scenario:
    where = str(path)
    name = path.stem
    kind: Literal["attack", "benign"]
    if name.startswith("attack"):
        kind = "attack"
    elif name.startswith("benign"):
        kind = "benign"
    else:
        raise ScenarioError(f"{where}: the file name must start with 'attack' or 'benign'")

    headers: dict[str, str] = {}
    lines: list[str] = []
    for raw in path.read_text().splitlines():
        if not raw.strip():
            continue
        if raw.startswith("#"):
            found = _HEADER.match(raw)
            if found:
                key, value = found.groups()
                if key not in KNOWN_HEADERS:
                    raise ScenarioError(f"{where}: unknown header '# {key}:'")
                headers[key] = value.strip()
        else:
            lines.append(raw)

    if "expect" not in headers or not headers["expect"].isdigit():
        raise ScenarioError(f"{where}: needs a '# expect: N' header (N is a whole number)")
    expect = int(headers["expect"])
    if kind == "attack" and expect < 1:
        raise ScenarioError(f"{where}: an attack scenario must expect at least 1 alert")
    if kind == "benign" and expect != 0:
        raise ScenarioError(f"{where}: a benign scenario must expect 0 alerts")
    if not lines:
        raise ScenarioError(f"{where}: no log lines")
    source = headers.get("source", "linux.auth")
    if source not in {s.value for s in NORMALIZERS}:
        raise ScenarioError(f"{where}: source {source!r} has no normalizer")

    return Scenario(
        rule_id=rule_id,
        name=name,
        kind=kind,
        expect=expect,
        lines=tuple(lines),
        path=path,
        also=_parse_also(headers.get("also", ""), where),
        description=headers.get("description", ""),
        source=source,
    )


def discover_scenarios(datasets_dir: Path, rule_ids: Iterable[str]) -> list[Scenario]:
    """Every scenario under `datasets_dir`; each rule needs one attack and one benign at least."""
    ids = set(rule_ids)
    scenarios: list[Scenario] = []
    problems: list[str] = []
    for directory in sorted(p for p in datasets_dir.iterdir() if p.is_dir()):
        if not any(directory.glob("*.log")):
            continue  # e.g. tools/: scripts that generate datasets
        if directory.name != SHARED and directory.name not in ids:
            problems.append(f"{directory}: no rule has the id {directory.name!r}")
            continue
        for path in sorted(directory.glob("*.log")):
            try:
                scenario = parse_scenario(path, directory.name)
            except ScenarioError as exc:
                problems.append(str(exc))
                continue
            if directory.name == SHARED and scenario.kind != "benign":
                problems.append(f"{path}: the {SHARED} folder only holds benign scenarios")
                continue
            scenarios.append(scenario)
    for rule_id in sorted(ids):
        kinds = {s.kind for s in scenarios if s.rule_id == rule_id}
        missing = [kind for kind in ("attack", "benign") if kind not in kinds]
        if missing:
            problems.append(
                f"rule {rule_id}: needs at least one attack and one benign scenario "
                f"(missing: {', '.join(missing)})"
            )
    if problems:
        raise ScenarioError("; ".join(problems))
    return sorted(scenarios, key=lambda s: (s.rule_id, s.name))


async def run_scenario(
    scenario: Scenario, rules: Sequence[Rule], store: WindowStore | None = None
) -> ScenarioResult:
    """Replay a scenario like production does: normalizer, then the engine with ALL rules loaded.

    `store` defaults to the in-memory reference; the integration tests also replay every scenario
    on the Redis store the detector really uses.
    """
    normalizer = NORMALIZERS[Source(scenario.source)]
    engine = DetectionEngine(rules, store or InMemoryWindowStore())
    alerts: Counter[str] = Counter()
    events = 0
    for number, line in enumerate(scenario.lines):
        raw = RawLog(
            agent_id=_AGENT,
            source=Source(scenario.source),
            origin=f"{scenario.name}:{number}",
            line=line,
            received_at=REPLAY_RECEIVED_AT,
        )
        try:
            event = normalizer.normalize(raw)
        except ParseError:
            continue  # a malformed line is a dead letter in production, not an event
        if event is None:
            continue
        events += 1
        for alert in await engine.evaluate(event):
            alerts[alert.rule_id] += 1

    problems: list[str] = []
    if scenario.kind == "attack":
        for rule_id in sorted(set(alerts) | set(scenario.also) | {scenario.rule_id}):
            wanted = (
                scenario.expect if rule_id == scenario.rule_id else scenario.also.get(rule_id, 0)
            )
            got = alerts.get(rule_id, 0)
            if got != wanted:
                hint = (
                    ""
                    if rule_id == scenario.rule_id
                    else " (other rules must be declared with '# also')"
                )
                problems.append(f"{rule_id}: expected {wanted} alert(s), got {got}{hint}")
    else:
        problems = [
            f"false positive: {rule_id} raised {count} alert(s)"
            for rule_id, count in sorted(alerts.items())
        ]
    return ScenarioResult(scenario, events, dict(alerts), problems)
