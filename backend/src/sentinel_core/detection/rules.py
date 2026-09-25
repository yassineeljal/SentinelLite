"""Detection rules: YAML format, strict validation, loading.

A typo in a rule is the classic silent failure of a detection system (a field that never
matches means an attack that is never seen), so everything is validated at load time: unknown
fields, unknown enum values, bad durations, inconsistent rule types. See docs/DETECTION.md.
"""

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from sentinel_core.schema.event import Action, Category, Outcome, Source


class RuleLoadError(ValueError):
    """A rule file is invalid. The message names every problem found."""


_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_EXTRA_PATH = re.compile(r"^extra\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")

# Event fields a rule may reference (`raw` is deliberately excluded), plus `extra.<path>`.
EVENT_FIELDS = frozenset(
    {
        "source",
        "category",
        "action",
        "outcome",
        "severity",
        "src_ip",
        "dst_ip",
        "dst_port",
        "user_name",
        "host",
        "agent_id",
    }
)
_ENUM_FIELDS: dict[str, type[Source] | type[Category] | type[Action] | type[Outcome]] = {
    "source": Source,
    "category": Category,
    "action": Action,
    "outcome": Outcome,
}

Scalar = str | int | bool
Condition = Scalar | list[Scalar]


def parse_duration(value: object) -> int:
    """'45s' / '5m' / '2h' / '1d' -> seconds. Anything else is an error."""
    if not isinstance(value, str) or not (found := _DURATION.match(value)):
        raise ValueError(f"invalid duration {value!r} (use e.g. 45s, 5m, 2h, 1d)")
    return int(found[1]) * _UNIT_SECONDS[found[2]]


Duration = Annotated[int, BeforeValidator(parse_duration)]


def _check_field(name: str) -> None:
    if name.startswith("extra."):
        if not _EXTRA_PATH.match(name):
            raise ValueError(f"invalid extra field path {name!r}")
    elif name not in EVENT_FIELDS:
        raise ValueError(
            f"unknown field {name!r} (known: {', '.join(sorted(EVENT_FIELDS))}, extra.*)"
        )


# The state store keeps at most 10 000 entries per window (store.py): counts above this could never
# be reached, so they are refused at load time instead of silently never firing.
MAX_COUNT = 5000


def check_conditions(conditions: Mapping[str, Condition]) -> None:
    """Validate the fields and enum values of a `match` / `exclude` mapping."""
    for name, condition in conditions.items():
        _check_field(name)
        values = condition if isinstance(condition, list) else [condition]
        if not values:
            raise ValueError(f"field {name!r}: empty list of values")
        enum = _ENUM_FIELDS.get(name)
        if enum is not None:
            allowed = {member.value for member in enum}
            for value in values:
                if value not in allowed:
                    raise ValueError(
                        f"unknown value {value!r} for field {name!r} "
                        f"(known: {', '.join(sorted(allowed))})"
                    )


class ThresholdSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    count: int = Field(ge=2, le=MAX_COUNT)
    window_seconds: Duration = Field(alias="window", gt=0)
    # Count the DISTINCT values of this field among the matching events instead of the events
    # themselves (e.g. distinct: user_name for user enumeration): a value seen many times counts
    # once.
    distinct: str | None = None

    @field_validator("distinct")
    @classmethod
    def _check_distinct(cls, name: str | None) -> str | None:
        if name is not None:
            _check_field(name)
        return name


class SequenceStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    match: dict[str, Condition]
    exclude: dict[str, Condition] = Field(default_factory=dict)
    count: int = Field(default=1, ge=1, le=MAX_COUNT)

    @field_validator("match", "exclude")
    @classmethod
    def _check(cls, conditions: dict[str, Condition], info: ValidationInfo) -> dict[str, Condition]:
        if info.field_name == "match" and not conditions:
            raise ValueError("a step needs at least one condition in 'match'")
        check_conditions(conditions)
        return conditions


class SequenceSpec(BaseModel):
    """`first` (at least `first.count` events) followed by `then`, within `window`, per group."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    window_seconds: Duration = Field(alias="window", gt=0)
    first: SequenceStep
    then: SequenceStep

    @model_validator(mode="after")
    def _then_has_no_count(self) -> "SequenceSpec":
        if self.then.count != 1:
            raise ValueError(
                "'then' is the event that completes the sequence: it cannot have a count"
            )
        return self


class Rule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    mitre: list[Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]] = Field(min_length=1)
    severity: int = Field(ge=0, le=100)
    type: Literal["match", "threshold", "sequence"]
    match: dict[str, Condition] = Field(default_factory=dict)
    # Events that satisfy ALL these conditions are left out even if `match` holds (e.g. accounts
    # whose shell is nologin). Same syntax as `match`.
    exclude: dict[str, Condition] = Field(default_factory=dict)
    group_by: list[str] = Field(default_factory=list)
    threshold: ThresholdSpec | None = None
    sequence: SequenceSpec | None = None
    cooldown_seconds: Duration = Field(default=0, alias="cooldown", ge=0)
    # Whose events are counted together. "agent" (default): each agent has its own state, so a
    # compromised agent can neither frame an IP nor disturb what other agents report. "global":
    # events of all agents are correlated (e.g. one source spraying many hosts); use it only for
    # rules that need it, because agents then share state.
    scope: Literal["agent", "global"] = "agent"
    enabled: bool = True

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "Rule":
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as exc:
            raise RuleLoadError(_describe(exc)) from exc

    @model_validator(mode="before")
    @classmethod
    def _default_cooldown(cls, data: Any) -> Any:
        # A threshold or sequence rule without an explicit cooldown stays quiet for one window after
        # an alert, so a single attack raises a single alert instead of one per extra event.
        if isinstance(data, Mapping) and "cooldown" not in data and "cooldown_seconds" not in data:
            spec = data.get(str(data.get("type")))
            if data.get("type") in ("threshold", "sequence") and isinstance(spec, Mapping):
                if "window" in spec:
                    return {**data, "cooldown": spec["window"]}
        return data

    @field_validator("match", "exclude")
    @classmethod
    def _check_conditions(cls, conditions: dict[str, Condition]) -> dict[str, Condition]:
        check_conditions(conditions)
        return conditions

    @field_validator("group_by")
    @classmethod
    def _check_group_by(cls, group_by: list[str]) -> list[str]:
        for name in group_by:
            _check_field(name)
        if len(set(group_by)) != len(group_by):
            raise ValueError("group_by contains duplicates")
        return group_by

    @model_validator(mode="after")
    def _check_type_consistency(self) -> "Rule":
        if self.type in ("match", "threshold") and not self.match:
            raise ValueError(f"a {self.type} rule needs at least one condition in 'match'")
        if self.type == "threshold":
            if self.threshold is None:
                raise ValueError("a threshold rule needs a 'threshold' (count and window)")
            if not self.group_by:
                raise ValueError("a threshold rule needs 'group_by' (what to count per)")
        elif self.threshold is not None:
            raise ValueError(f"a {self.type} rule cannot have a 'threshold'")
        if self.type == "sequence":
            if self.sequence is None:
                raise ValueError("a sequence rule needs a 'sequence' (window, first, then)")
            if not self.group_by:
                raise ValueError("a sequence rule needs 'group_by' (what the steps share)")
            if self.match or self.exclude:
                raise ValueError("a sequence rule puts its conditions in the steps, not in 'match'")
        elif self.sequence is not None:
            raise ValueError(f"a {self.type} rule cannot have a 'sequence'")
        return self


def _describe(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(map(str, e['loc'])) or 'rule'}: {e['msg']}"
        for e in exc.errors(include_url=False, include_input=False)
    )


def parse_rule_yaml(text: str) -> Rule:
    try:
        data = yaml.safe_load(text)  # safe_load: rule files must never build Python objects
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleLoadError("a rule file must contain a mapping")
    return Rule.model_validate(data)


def load_rules(directory: Path) -> list[Rule]:
    """Load every `*.yaml` / `*.yml` file of a directory, in file-name order.

    Raises one RuleLoadError listing every faulty file and every duplicate id.
    """
    rules: list[Rule] = []
    errors: list[str] = []
    seen: dict[str, str] = {}
    for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
        try:
            rule = parse_rule_yaml(path.read_text())
        except RuleLoadError as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        if rule.id in seen:
            errors.append(f"duplicate rule id {rule.id!r} in {seen[rule.id]} and {path.name}")
            continue
        seen[rule.id] = path.name
        rules.append(rule)
    if errors:
        raise RuleLoadError("\n".join(errors))
    return rules
