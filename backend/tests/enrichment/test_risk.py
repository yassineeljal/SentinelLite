from datetime import UTC, datetime

import pytest

from sentinel_core.enrichment.abuseipdb import Reputation
from sentinel_core.enrichment.enricher import Enrichment
from sentinel_core.enrichment.geoip import GeoInfo
from sentinel_core.enrichment.risk import assess

CHECKED = datetime(2026, 9, 26, tzinfo=UTC)


def reputation(score: int = 0, **changes: object) -> Reputation:
    data: dict[str, object] = {
        "score": score,
        "total_reports": 10,
        "distinct_reporters": 5,
        "checked_at": CHECKED,
    }
    return Reputation.model_validate(data | changes)


def public(rep: Reputation | None = None, geo: GeoInfo | None = None) -> Enrichment:
    return Enrichment(ip_scope="public", geo=geo, reputation=rep)


def points(severity: int, enrichment: Enrichment | None) -> dict[str, int]:
    return {f.name: f.points for f in assess(severity, enrichment).factors}


def test_without_any_context_the_risk_is_the_rule_severity() -> None:
    for enrichment in (None, Enrichment(ip_scope="non_public"), public()):
        result = assess(60, enrichment)

        assert result.score == 60
        assert [f.name for f in result.factors] == ["rule severity"]


def test_a_bad_reputation_raises_the_risk_in_proportion() -> None:
    scores = [assess(60, public(reputation(s))).score for s in (0, 20, 50, 80, 100)]

    assert scores == [60, 65, 72, 80, 85]  # 0.25 points per reputation point, rounded


def test_a_whitelisted_address_gains_nothing_from_its_score() -> None:
    result = assess(60, public(reputation(90, is_whitelisted=True)))

    assert result.score == 60
    assert "reputation" not in points(60, public(reputation(90, is_whitelisted=True)))


def test_a_tor_exit_adds_a_little() -> None:
    assert points(60, public(reputation(0, is_tor=True))) == {"rule severity": 60, "tor exit": 5}


@pytest.mark.parametrize(
    ("usage_type", "expected"),
    [
        ("Data Center/Web Hosting/Transit", 5),
        ("Web Hosting", 5),
        ("Fixed Line ISP", 0),
        ("University/College/School", 0),
        (None, 0),
    ],
)
def test_hosting_networks_add_a_little(usage_type: str | None, expected: int) -> None:
    factors = points(60, public(reputation(0, usage_type=usage_type)))

    assert factors.get("hosting network", 0) == expected


def test_the_country_is_not_a_risk_signal() -> None:
    france = GeoInfo(country_code="FR", country="France")
    korea = GeoInfo(country_code="KP", country="North Korea")

    assert assess(60, public(geo=france)) == assess(60, public(geo=korea)) == assess(60, public())


def test_a_non_public_source_gets_no_external_adjustment() -> None:
    assert assess(60, Enrichment(ip_scope="non_public")).score == 60


def test_the_score_is_capped_at_100_and_the_factors_still_add_up() -> None:
    result = assess(95, public(reputation(100, is_tor=True, usage_type="Data Center")))

    assert result.score == 100
    assert sum(f.points for f in result.factors) == 100
    assert result.factors[-1].name == "cap"


@pytest.mark.parametrize("severity", [0, 1, 40, 99, 100])
def test_the_factors_always_add_up_to_the_score(severity: int) -> None:
    for score in (0, 33, 100):
        result = assess(severity, public(reputation(score, is_tor=True, usage_type="Hosting")))

        assert sum(f.points for f in result.factors) == result.score
        assert 0 <= result.score <= 100


def test_a_worse_reputation_never_lowers_the_risk() -> None:
    previous = -1
    for score in range(101):
        current = assess(30, public(reputation(score))).score
        assert current >= previous
        previous = current


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, "low"),
        (39, "low"),
        (40, "medium"),
        (69, "medium"),
        (70, "high"),
        (94, "high"),
        (95, "critical"),
        (100, "critical"),
    ],
)
def test_levels_have_fixed_boundaries(score: int, level: str) -> None:
    assert assess(score, None).level == level


def test_every_factor_explains_itself() -> None:
    result = assess(60, public(reputation(88, is_tor=True, usage_type="Data Center")))

    assert all(f.reason for f in result.factors)
    reasons = " | ".join(f.reason for f in result.factors)
    assert "88" in reasons  # the reputation score that produced the points is stated


def test_the_assessment_serialises_to_plain_json() -> None:
    assert assess(60, public(reputation(100))).model_dump(mode="json") == {
        "score": 85,
        "level": "high",
        "factors": [
            {"name": "rule severity", "points": 60, "reason": "severity 60 set by the rule"},
            {
                "name": "reputation",
                "points": 25,
                "reason": "AbuseIPDB abuse confidence 100/100 (a quarter of it)",
            },
        ],
    }


def test_a_failed_brute_force_is_never_critical_but_a_successful_one_from_a_bad_source_is() -> None:
    worst = reputation(100, is_tor=True)

    assert assess(60, public(worst)).level == "high"  # ssh-bruteforce, worst Tor exit: 90
    assert assess(85, public(reputation(50))).level == "critical"  # login success after failures
