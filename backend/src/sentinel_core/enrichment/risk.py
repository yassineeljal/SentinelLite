"""Risk score of an alert: 0-100, explainable, deterministic.

The rule's severity is the starting point (its author's judgement of the behaviour); context then
moves it a little. Every point comes with a named factor and a reason, and the factors always add
up to the score, so an analyst can see *why* an alert ranks where it does and a reviewer can
challenge a weight instead of trusting a black box. The weights are deliberately small and few:
they are judgement calls, not measurements, and are documented (docs/ENRICHMENT.md).

Not used on purpose: the country (it says nothing about intent, and would make the score biased),
and anything that needs history (impossible travel will be its own rule).
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel_core.enrichment.enricher import Enrichment

# One point per this many points of AbuseIPDB abuse confidence (0-100): up to +25.
REPUTATION_DIVISOR = 4
TOR_POINTS = 5
HOSTING_POINTS = 5
HOSTING_MARKERS = ("data center", "hosting")  # AbuseIPDB usage types, matched case-insensitively

# Fixed boundaries of the levels shown to analysts. "critical" is kept for the rare cases: a rule
# already judged serious (a login that worked after failures is 85) with bad context, or every
# context factor at once. A failed brute force from the worst-reputed Tor exit (60 + 25 + 5 = 90)
# is "high", not critical.
MEDIUM, HIGH, CRITICAL = 40, 70, 95

Level = Literal["low", "medium", "high", "critical"]


class RiskFactor(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    points: int
    reason: str


class RiskAssessment(BaseModel):
    """Stored as JSON on the alert (`risk_score` also has its own column, for sorting)."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    level: Level
    factors: list[RiskFactor]


def level_of(score: int) -> Level:
    if score >= CRITICAL:
        return "critical"
    if score >= HIGH:
        return "high"
    if score >= MEDIUM:
        return "medium"
    return "low"


def assess(severity: int, enrichment: Enrichment | None) -> RiskAssessment:
    factors = [
        RiskFactor(
            name="rule severity", points=severity, reason=f"severity {severity} set by the rule"
        )
    ]
    reputation = enrichment.reputation if enrichment else None
    if reputation is not None:
        if reputation.is_whitelisted:
            pass  # a known-good address: its score (if any) is not held against it
        elif reputation.score // REPUTATION_DIVISOR:
            factors.append(
                RiskFactor(
                    name="reputation",
                    points=reputation.score // REPUTATION_DIVISOR,
                    reason=f"AbuseIPDB abuse confidence {reputation.score}/100 (a quarter of it)",
                )
            )
        if reputation.is_tor:
            factors.append(
                RiskFactor(
                    name="tor exit", points=TOR_POINTS, reason="the source is a Tor exit node"
                )
            )
        usage = (reputation.usage_type or "").lower()
        if any(marker in usage for marker in HOSTING_MARKERS):
            factors.append(
                RiskFactor(
                    name="hosting network",
                    points=HOSTING_POINTS,
                    reason=f"the source belongs to a hosting network ({reputation.usage_type})",
                )
            )

    total = sum(f.points for f in factors)
    if total > 100:
        factors.append(
            RiskFactor(name="cap", points=100 - total, reason="the score is capped at 100")
        )
    score = max(0, min(100, total))
    return RiskAssessment(score=score, level=level_of(score), factors=factors)
