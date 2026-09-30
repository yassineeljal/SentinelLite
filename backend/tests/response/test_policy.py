"""The response policy: every guardrail refuses for its own, named reason."""

import ipaddress
from datetime import UTC, datetime

import pytest

from sentinel_core.detection.alerts import Alert
from sentinel_core.response.policy import (
    AUDITED_SKIPS,
    MAX_TTL_SECONDS,
    Reason,
    ResponsePolicy,
    Verdict,
    decide,
    is_allowlisted,
    parse_networks,
)

ATTACKER = "45.83.64.10"  # a global address (not a documentation range: those are never blocked)


def alert(
    *, rule_id: str = "ssh-bruteforce", severity: int = 60, src_ip: str | None = ATTACKER
) -> Alert:
    return Alert(
        alert_id="a" * 64,
        rule_id=rule_id,
        title="t",
        mitre=["T1110"],
        severity=severity,
        ts=datetime(2026, 9, 29, tzinfo=UTC),
        group={"src_ip": src_ip or ""},
        src_ip=src_ip,
        event_ids=[],
        match_count=5,
    )


POLICY = ResponsePolicy()


def test_a_scan_from_a_public_address_is_blocked() -> None:
    decision = decide(alert(), POLICY)
    assert (decision.verdict, decision.reason, decision.address) == (
        Verdict.BLOCK,
        Reason.ELIGIBLE,
        ATTACKER,
    )


@pytest.mark.parametrize(
    "rule_id",
    ["ssh-bruteforce", "ssh-user-enumeration", "ssh-invalid-user-flood", "ssh-slow-scan"],
)
def test_the_default_blocking_rules(rule_id: str) -> None:
    assert decide(alert(rule_id=rule_id), POLICY).verdict is Verdict.BLOCK


@pytest.mark.parametrize(
    "rule_id",
    ["ssh-success-after-failures", "ssh-root-login", "linux-new-account", "sudo-root-shell"],
)
def test_alerts_about_successes_and_accounts_never_block(rule_id: str) -> None:
    # A successful login from that address may be a legitimate user: a lead, not a target.
    decision = decide(alert(rule_id=rule_id, severity=90), POLICY)
    assert decision.reason is Reason.RULE_NOT_ELIGIBLE


def test_below_the_severity_floor() -> None:
    assert decide(alert(severity=39), POLICY).reason is Reason.BELOW_SEVERITY
    assert decide(alert(severity=40), POLICY).verdict is Verdict.BLOCK


def test_no_source_address() -> None:
    assert decide(alert(src_ip=None), POLICY).reason is Reason.NO_SOURCE_ADDRESS
    assert decide(alert(src_ip=""), POLICY).reason is Reason.NO_SOURCE_ADDRESS


@pytest.mark.parametrize(
    "junk", ["not-an-ip", "1.2.3", "1.2.3.4; rm -rf /", "999.1.1.1", "1.2.3.4/8"]
)
def test_an_unparseable_address_is_refused_and_never_reaches_a_firewall(junk: str) -> None:
    decision = decide(alert(src_ip=junk), POLICY)
    assert decision.reason is Reason.INVALID_ADDRESS
    assert decision.address is None


@pytest.mark.parametrize(
    "address",
    [
        "10.0.1.5",  # Docker / private
        "172.16.0.9",
        "192.168.1.20",
        "127.0.0.1",
        "169.254.10.10",  # link-local
        "100.64.0.1",  # carrier-grade NAT
        "203.0.113.7",  # documentation range
        "0.0.0.0",  # noqa: S104 (test data: an address that must be refused)
        "224.0.0.1",  # multicast
        "255.255.255.255",  # broadcast (reserved)
        "240.0.0.1",  # reserved
        "::1",
        "::ffff:10.0.0.1",  # a private IPv4 wrapped in IPv6
        "::ffff:127.0.0.1",
        "::",
        "ff02::1",  # IPv6 multicast
        "fe80::1",
        "fd00::1",
        "2001:db8::1",  # documentation
    ],
)
def test_non_public_addresses_are_never_blocked(address: str) -> None:
    assert decide(alert(src_ip=address), POLICY).reason is Reason.NOT_PUBLIC


def test_the_allowlist_wins_over_everything_else() -> None:
    policy = ResponsePolicy(allowlist=parse_networks(["45.83.64.0/24"]))
    assert decide(alert(severity=100), policy).reason is Reason.ALLOWLISTED


def test_extra_allowlist_entries_from_the_database_apply() -> None:
    extra = parse_networks([ATTACKER])
    assert decide(alert(), POLICY, extra_allowlist=extra).reason is Reason.ALLOWLISTED


def test_a_bare_address_is_a_single_host() -> None:
    (network,) = parse_networks(["45.83.64.10"])
    assert str(network) == "45.83.64.10/32"
    assert decide(alert(src_ip="45.83.64.11"), ResponsePolicy(allowlist=(network,))).verdict is (
        Verdict.BLOCK
    )


def test_an_ipv4_mapped_ipv6_address_cannot_bypass_the_allowlist() -> None:
    policy = ResponsePolicy(allowlist=parse_networks([ATTACKER]))
    mapped = f"::ffff:{ATTACKER}"
    assert decide(alert(src_ip=mapped), policy).reason is Reason.ALLOWLISTED


def test_address_families_never_match_each_other() -> None:
    (v6,) = parse_networks(["2a00:1450::/32"])
    assert not is_allowlisted(ipaddress.ip_address(ATTACKER), [v6])


def test_ipv6_source_is_blocked_and_canonicalised() -> None:
    decision = decide(alert(src_ip="2A00:1450:4001:0000:0000:0000:0000:200E"), POLICY)
    assert decision.verdict is Verdict.BLOCK
    assert decision.address == "2a00:1450:4001::200e"


def test_already_blocked_addresses_are_not_blocked_twice() -> None:
    assert decide(alert(), POLICY, already_blocked=True).reason is Reason.ALREADY_BLOCKED


def test_the_rate_cap_stops_a_runaway() -> None:
    policy = ResponsePolicy(max_blocks_per_minute=3)
    assert decide(alert(), policy, blocks_last_minute=2).verdict is Verdict.BLOCK
    assert decide(alert(), policy, blocks_last_minute=3).reason is Reason.RATE_LIMITED


def test_the_allowlist_is_checked_before_the_rate_cap_and_before_dedup() -> None:
    policy = ResponsePolicy(allowlist=parse_networks([ATTACKER]), max_blocks_per_minute=1)
    decision = decide(alert(), policy, already_blocked=True, blocks_last_minute=99)
    assert decision.reason is Reason.ALLOWLISTED


@pytest.mark.parametrize("ttl", [0, -1, MAX_TTL_SECONDS + 1])
def test_a_ttl_is_mandatory_and_bounded(ttl: int) -> None:
    with pytest.raises(ValueError, match="ttl"):
        ResponsePolicy(ttl_seconds=ttl)


def test_the_rate_cap_must_allow_something() -> None:
    with pytest.raises(ValueError, match="rate cap"):
        ResponsePolicy(max_blocks_per_minute=0)


def test_parse_networks_rejects_garbage_loudly() -> None:
    with pytest.raises(ValueError):
        parse_networks(["not-a-cidr"])
    assert parse_networks(["", "  "]) == ()


def test_only_guardrail_refusals_are_audited() -> None:
    assert Reason.ALLOWLISTED in AUDITED_SKIPS
    assert Reason.RATE_LIMITED in AUDITED_SKIPS
    assert Reason.RULE_NOT_ELIGIBLE not in AUDITED_SKIPS


def test_every_default_blocking_rule_exists_and_can_reach_the_severity_floor() -> None:
    """A typo in the list (or a rule renamed, or one whose severity sits under the floor) would
    silently make an attack unblockable: check the list against the shipped rules."""
    from pathlib import Path

    from sentinel_core.detection.rules import load_rules

    rules = {rule.id: rule for rule in load_rules(Path(__file__).resolve().parents[3] / "rules")}

    for rule_id in POLICY.block_rules:
        assert rule_id in rules, f"{rule_id} is a blocking rule but no such rule is shipped"
        assert rules[rule_id].severity >= POLICY.min_severity, f"{rule_id} is below the floor"
        assert rules[rule_id].enabled
