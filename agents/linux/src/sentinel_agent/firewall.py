"""What the enforcer is allowed to do to the firewall, and how.

The platform is not trusted blindly: whatever it asks, an address that is not an ordinary internet
host is refused here (`refusal`), so that a bug or a compromise upstream cannot make the agent cut
its own machine off (loopback, private ranges, the operator's networks in `never_block`).

Rules live in a dedicated chain (`SENTINEL`) that INPUT jumps to first: they are easy to audit
(`iptables -L SENTINEL -n`) and to remove (`iptables -F SENTINEL`), and the agent never touches any
other rule. Commands are run without a shell, with a timeout.
"""

import ipaddress
import logging
import shutil
import subprocess
from collections.abc import Callable, Iterable, Sequence
from typing import Protocol

logger = logging.getLogger("sentinel_agent.firewall")

CHAIN = "SENTINEL"
COMMAND_TIMEOUT_SECONDS = 10
LOCK_WAIT_SECONDS = "5"

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class FirewallError(Exception):
    """The firewall refused or could not run a command."""


class Backend(Protocol):
    def prepare(self) -> None:
        """Create what the rules need. Safe to call again."""
        ...

    def block(self, address: str) -> None:
        """Drop traffic from `address`. Safe to call for an address that is already blocked."""
        ...

    def unblock(self, address: str) -> None:
        """Stop dropping traffic from `address`. Safe when it is not blocked."""
        ...


def parse_address(value: str) -> IPAddress | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def parse_networks(values: Iterable[str]) -> tuple[Network, ...]:
    """Networks or bare addresses; raises ValueError naming the first bad entry."""
    networks: list[Network] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError:
            raise ValueError(f"not a network or address: {value!r}") from None
    return tuple(networks)


def refusal(value: str, never_block: Sequence[Network]) -> str | None:
    """Why this address must not be blocked, or None if it may be."""
    address = parse_address(value)
    if address is None:
        return "not an IP address"
    if not address.is_global or (
        address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_private
    ):
        return "not a public address"
    if any(address.version == n.version and address in n for n in never_block):
        return "listed in never_block"
    return None


Runner = Callable[[list[str]], int]


def run_command(argv: list[str]) -> int:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed program, validated address, no shell
            argv,
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewallError(f"{argv[0]}: {type(exc).__name__}") from exc
    if completed.returncode:
        logger.debug(
            "%s exited %d: %s", " ".join(argv), completed.returncode, completed.stderr[:200]
        )
    return completed.returncode


class IptablesBackend:
    """`iptables` for IPv4 and `ip6tables` for IPv6, through the `SENTINEL` chain."""

    def __init__(self, runner: Runner = run_command) -> None:
        self._run = runner

    @staticmethod
    def program(version: int) -> str:
        name = "iptables" if version == 4 else "ip6tables"
        found = shutil.which(name)
        if found is None:
            raise FirewallError(f"{name} not found")
        return found

    def _cmd(self, version: int, *args: str) -> list[str]:
        return [self.program(version), "-w", LOCK_WAIT_SECONDS, *args]

    def _must(self, version: int, *args: str) -> None:
        if self._run(self._cmd(version, *args)) != 0:
            raise FirewallError(f"{' '.join(args)}: refused by the firewall")

    def prepare(self) -> None:
        for version in (4, 6):
            if self._run(self._cmd(version, "-n", "-L", CHAIN)) != 0:
                self._must(version, "-N", CHAIN)
            if self._run(self._cmd(version, "-C", "INPUT", "-j", CHAIN)) != 0:
                self._must(version, "-I", "INPUT", "1", "-j", CHAIN)

    def block(self, address: str) -> None:
        parsed = parse_address(address)
        if parsed is None:
            raise FirewallError("not an IP address")
        rule = ("-s", str(parsed), "-j", "DROP")
        if self._run(self._cmd(parsed.version, "-C", CHAIN, *rule)) != 0:
            self._must(parsed.version, "-A", CHAIN, *rule)

    def unblock(self, address: str) -> None:
        parsed = parse_address(address)
        if parsed is None:
            raise FirewallError("not an IP address")
        rule = ("-s", str(parsed), "-j", "DROP")
        for _ in range(10):  # a rule added twice by hand is removed twice, never forever
            if self._run(self._cmd(parsed.version, "-C", CHAIN, *rule)) != 0:
                return
            self._must(parsed.version, "-D", CHAIN, *rule)


class LogOnlyBackend:
    """Applies nothing: logs what it would do. To trial the channel before granting privileges."""

    def prepare(self) -> None:
        logger.info("log-only backend: no firewall rule will be created")

    def block(self, address: str) -> None:
        logger.warning("WOULD BLOCK %s", address)

    def unblock(self, address: str) -> None:
        logger.warning("WOULD UNBLOCK %s", address)
