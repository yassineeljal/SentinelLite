"""Normalizer for Linux /var/log/auth.log: sshd, and administrative events (linux_admin)."""

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, tzinfo
from ipaddress import ip_address
from typing import Any

from sentinel_core.normalizers import linux_admin
from sentinel_core.normalizers.base import ParseError, RawLog, make_event_id
from sentinel_core.normalizers.parsed import Parsed
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source

MAX_USER_LENGTH = 256
SSH_PORT = 22

# The process name may be parenthesised: systemd writes "(systemd):" and "(sd-pam):" for the user
# managers it starts, which are well-formed lines, not malformed ones.
_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<proc>[\w./()-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# The username is attacker-controlled and may contain " from X port Y". The real source is
# always the LAST "from <ip> port <n>", so every pattern greedily matches the user and is
# anchored at the end of the line.
_TAIL = r" from (?P<ip>\S+) port (?P<port>\d+)(?: ssh\d)?(?::\s.*)?$"
_FAILED = re.compile(
    r"^Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?(?P<user>.+)" + _TAIL
)
_ACCEPTED = re.compile(r"^Accepted (?P<method>[\w-]+) for (?P<user>.+)" + _TAIL)
_INVALID = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port (?P<port>\d+))?\s*$")

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _parse_timestamp(text: str, received_at: datetime, tz: tzinfo) -> datetime:
    if text[0].isdigit():
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ParseError(f"bad ISO timestamp: {text!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=tz)

    # Traditional syslog has no year: assume the year of receipt, and step back one year
    # if that would put the event in the future (log written just before New Year).
    month, day, clock = text.split()
    hour, minute, second = (int(part) for part in clock.split(":"))
    try:
        parsed = datetime(
            received_at.year, _MONTHS.index(month) + 1, int(day), hour, minute, second, tzinfo=tz
        )
        if parsed > received_at + timedelta(days=1):
            parsed = parsed.replace(year=received_at.year - 1)
    except ValueError as exc:
        raise ParseError(f"bad syslog timestamp: {text!r}") from exc
    return parsed


def parse_sshd(message: str) -> Parsed | None:
    if match := _FAILED.match(message):
        action, outcome, severity = Action.LOGIN_FAILED, Outcome.FAILURE, 20
        extra: dict[str, Any] = {
            "method": match["method"],
            "invalid_user": match["invalid"] is not None,
        }
    elif match := _ACCEPTED.match(message):
        action, outcome, severity = Action.LOGIN_SUCCESS, Outcome.SUCCESS, 10
        extra = {"method": match["method"]}
    elif match := _INVALID.match(message):
        action, outcome, severity = Action.INVALID_USER, Outcome.FAILURE, 25
        extra = {}
    else:
        return None

    src_ip = None
    try:
        src_ip = ip_address(match["ip"])
    except ValueError:
        extra["src_host"] = match["ip"][:255]  # never trust an unparsable address as an IP
    if match["port"] is not None:
        extra["src_port"] = int(match["port"])
    return Parsed(
        Category.AUTHENTICATION,
        action,
        outcome,
        severity,
        match["user"][:MAX_USER_LENGTH],
        extra,
        src_ip=src_ip,
        dst_port=SSH_PORT,
    )


# One parser per syslog process name; every other process is well-formed noise (returns None).
PARSERS: dict[str, Callable[[str], Parsed | None]] = {
    "sshd": parse_sshd,
    "sudo": linux_admin.parse_sudo,
    "useradd": linux_admin.parse_useradd,
    "usermod": linux_admin.parse_usermod,
    "gpasswd": linux_admin.parse_gpasswd,
}


class LinuxAuthNormalizer:
    source = Source.LINUX_AUTH

    def __init__(self, tz: tzinfo = UTC) -> None:
        # Timezone of traditional (offset-less) timestamps; agents on UTC hosts need no config.
        self._tz = tz

    def normalize(self, raw: RawLog) -> Event | None:
        framing = _SYSLOG.match(raw.line)
        if framing is None:
            raise ParseError("line does not match syslog framing")
        parser = PARSERS.get(framing["proc"])
        parsed = parser(framing["msg"]) if parser else None
        if parsed is None:
            return None

        return Event(
            event_id=make_event_id(raw),
            ts=_parse_timestamp(framing["ts"], raw.received_at, self._tz),
            received_at=raw.received_at,
            agent_id=raw.agent_id,
            host=framing["host"],
            source=self.source,
            category=parsed.category,
            action=parsed.action,
            outcome=parsed.outcome,
            severity=parsed.severity,
            src_ip=parsed.src_ip,
            dst_port=parsed.dst_port,
            user_name=parsed.user_name,
            raw=raw.line,
            extra=parsed.extra,
        )
