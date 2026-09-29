"""Response policy: should this alert get its source address blocked?

A pure function of the alert, the configuration and a little state, so that every guardrail can
be tested without Redis, Postgres or a firewall. An automatic block that hits the wrong address is
worse than none (ARCHITECTURE.md section 8), so the answer is "no" unless every condition holds,
and the reason for a refusal is always named.
"""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from sentinel_core.detection.alerts import Alert

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_TTL_SECONDS = 7 * 24 * 3600  # no permanent automatic block, and no week-long one either


class Verdict(StrEnum):
    BLOCK = "block"
    SKIP = "skip"


class Reason(StrEnum):
    ELIGIBLE = "eligible"
    RULE_NOT_ELIGIBLE = "rule_not_eligible"
    BELOW_SEVERITY = "below_severity"
    NO_SOURCE_ADDRESS = "no_source_address"
    INVALID_ADDRESS = "invalid_address"
    NOT_PUBLIC = "not_public"
    ALLOWLISTED = "allowlisted"
    ALREADY_BLOCKED = "already_blocked"
    RATE_LIMITED = "rate_limited"


# Refusals worth an audit line: a guardrail actually protected something. The others are the
# normal, uninteresting case of an alert that was never meant to block (they are only logged).
AUDITED_SKIPS = frozenset({Reason.ALLOWLISTED, Reason.RATE_LIMITED, Reason.INVALID_ADDRESS})


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: Reason
    address: str | None = None  # canonical form, set when the alert has a usable address


@dataclass(frozen=True)
class ResponsePolicy:
    # Only sweeps and guessing block: an alert about a SUCCESSFUL login (or a new account) is a
    # lead for an analyst, and blocking its source could cut a legitimate user off.
    block_rules: frozenset[str] = frozenset(
        {"ssh-bruteforce", "ssh-user-enumeration", "ssh-invalid-user-flood"}
    )
    min_severity: int = 40
    ttl_seconds: int = 3600
    max_blocks_per_minute: int = 10
    allowlist: tuple[Network, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not 0 < self.ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError(f"ttl must be between 1 second and {MAX_TTL_SECONDS} seconds")
        if self.max_blocks_per_minute < 1:
            raise ValueError("the rate cap must allow at least one block a minute")


def parse_networks(values: Iterable[str]) -> tuple[Network, ...]:
    """Parse CIDRs and bare addresses (`203.0.113.7` means `203.0.113.7/32`). Raises ValueError."""
    return tuple(
        ipaddress.ip_network(value.strip(), strict=False) for value in values if value.strip()
    )


def unmap(address: IPAddress) -> IPAddress:
    """An IPv4-mapped IPv6 address (::ffff:1.2.3.4) is the same host as the IPv4 one."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def is_blockable(address: IPAddress) -> bool:
    """Only an ordinary internet host. `is_global` alone is not enough: Python reports multicast
    (224.0.0.0/4) as global, and a mapped private address must be judged as the IPv4 it carries."""
    address = unmap(address)
    return address.is_global and not (
        address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_private
    )


def is_allowlisted(address: IPAddress, allowlist: Iterable[Network]) -> bool:
    # An allowlist entry for 1.2.3.4 must also protect ::ffff:1.2.3.4, otherwise the form of the
    # address would bypass the list.
    candidates: list[IPAddress] = [address, unmap(address)]
    return any(
        candidate.version == network.version and candidate in network
        for network in allowlist
        for candidate in candidates
    )


def decide(
    alert: Alert,
    policy: ResponsePolicy,
    *,
    extra_allowlist: Iterable[Network] = (),
    already_blocked: bool = False,
    blocks_last_minute: int = 0,
) -> Decision:
    """Ordered from the cheapest and most decisive check to the most situational one."""
    if alert.rule_id not in policy.block_rules:
        return Decision(Verdict.SKIP, Reason.RULE_NOT_ELIGIBLE)
    if alert.severity < policy.min_severity:
        return Decision(Verdict.SKIP, Reason.BELOW_SEVERITY)
    if not alert.src_ip:
        return Decision(Verdict.SKIP, Reason.NO_SOURCE_ADDRESS)
    try:
        address = ipaddress.ip_address(alert.src_ip)
    except ValueError:
        return Decision(Verdict.SKIP, Reason.INVALID_ADDRESS)
    canonical = str(address)
    # Private, loopback, link-local, reserved and documentation ranges are never blocked: they are
    # the operator's own network, the Docker bridges, the host itself.
    if not is_blockable(address):
        return Decision(Verdict.SKIP, Reason.NOT_PUBLIC, canonical)
    if is_allowlisted(address, (*policy.allowlist, *extra_allowlist)):
        return Decision(Verdict.SKIP, Reason.ALLOWLISTED, canonical)
    if already_blocked:
        return Decision(Verdict.SKIP, Reason.ALREADY_BLOCKED, canonical)
    if blocks_last_minute >= policy.max_blocks_per_minute:
        return Decision(Verdict.SKIP, Reason.RATE_LIMITED, canonical)
    return Decision(Verdict.BLOCK, Reason.ELIGIBLE, canonical)
