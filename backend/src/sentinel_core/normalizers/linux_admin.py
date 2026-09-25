"""Administrative events of /var/log/auth.log: sudo, useradd, usermod, gpasswd.

Formats were captured from Ubuntu 24.04 (see tests/normalizers/data). What that showed, and what
the parsers do about it:

* sudo prints no `TTY=` outside a terminal and pads its spacing: everything optional or `\\s+`;
* a sudo failure writes three PAM lines AND a summary line: only the summary is an event, or
  every failure would be counted four times (the PAM lines are ignored);
* usermod writes `add 'u' to group 'g'` and again `add 'u' to shadow group 'g'`: only the first;
* `PWD=` and `COMMAND=` are controlled by the user (see `_choose_segment`).
"""

import re
from typing import Any

from sentinel_core.normalizers.parsed import Parsed
from sentinel_core.schema.event import Action, Category, Outcome

MAX_USER_LENGTH = 256
MAX_COMMAND_LENGTH = 2048
MAX_FIELD_LENGTH = 1024

# Executables that give an interactive root-capable shell: when a sudo line is ambiguous, a
# segment running one of these is preferred, so that a decoy cannot hide it.
SHELL_EXECUTABLES = frozenset(
    f"{prefix}/{name}"
    for prefix in ("/bin", "/usr/bin")
    for name in ("bash", "sh", "dash", "zsh", "fish", "su")
)

_SUDO_HEAD = re.compile(r"^(?P<actor>\S+) : (?P<rest>.*)$")
_SEGMENT = re.compile(r"USER=(?P<target>\S+) ; COMMAND=")
_PREFIX = re.compile(r"^(?:TTY=(?P<tty>.*?) ; )?PWD=(?P<pwd>.*?) ; $")
_ATTEMPTS = re.compile(r"^(?P<n>\d+) incorrect password attempts?$")
_USERADD = re.compile(
    r"^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), "
    r"home=(?P<home>.*), shell=(?P<shell>.*), from=(?P<origin>.*)$"
)
_USERMOD = re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'$")
_GPASSWD = re.compile(r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)$")


def _executable(command: str) -> str:
    return command.split(None, 1)[0] if command.strip() else ""


def _choose_segment(segments: list[tuple[str, str]]) -> tuple[str, str]:
    """Pick the (target user, command) that describes the line.

    PWD and COMMAND are user-controlled and the format is ambiguous: a user can run from a
    directory named `/tmp/x ; USER=nobody ; COMMAND=/bin/ls` (a fake segment BEFORE the real one)
    or append `; USER=nobody ; COMMAND=/bin/ls` to the arguments (AFTER it). The real segment
    cannot be identified from the text, so the choice is conservative: a root segment wins over
    the others, and among root segments one that runs a shell wins. A decoy can then only make
    an event look MORE sensitive than it was, never hide a root shell.
    """
    roots = [segment for segment in segments if segment[0] == "root"]
    pool = roots or segments
    for segment in pool:
        if _executable(segment[1]) in SHELL_EXECUTABLES:
            return segment
    return pool[0]


def _failure_reason(lead: str) -> tuple[str, dict[str, Any]]:
    if lead == "user NOT in sudoers":
        return "user_not_in_sudoers", {}
    if lead == "command not allowed":
        return "command_not_allowed", {}
    if lead == "a password is required":
        return "password_required", {}
    if attempts := _ATTEMPTS.match(lead):
        return "incorrect_password", {"attempts": int(attempts["n"])}
    return "other", {"detail": lead[:100]}


def parse_sudo(message: str) -> Parsed | None:
    head = _SUDO_HEAD.match(message)
    if head is None:  # PAM lines ("pam_unix(sudo:auth): ...") and anything else
        return None
    actor, rest = head["actor"], head["rest"]
    segments = list(_SEGMENT.finditer(rest))
    if not segments:
        return None

    candidates: list[tuple[str, str]] = []
    for index, found in enumerate(segments):
        end = segments[index + 1].start() if index + 1 < len(segments) else len(rest)
        command = rest[found.end() : end]
        if index + 1 < len(segments):
            command = command.removesuffix(" ; ")
        candidates.append((found["target"], command))
    target, command = _choose_segment(candidates)

    extra: dict[str, Any] = {"target_user": target[:MAX_USER_LENGTH]}
    lead_end = segments[0].start()
    prefix = rest[:lead_end]
    lead = prefix.split(" ; ", 1)[0]
    reason: str | None = None
    if not lead.startswith(("TTY=", "PWD=", "USER=")):
        reason, more = _failure_reason(lead)
        extra["reason"] = reason
        extra.update(more)
        prefix = prefix[len(lead) + 3 :]  # what follows the reason: [TTY=...;] PWD=... ;
    fields = _PREFIX.match(prefix)
    if fields:
        extra["pwd"] = fields["pwd"][:MAX_FIELD_LENGTH]
        if fields["tty"]:
            extra["tty"] = fields["tty"][:MAX_FIELD_LENGTH]
    extra["command"] = command[:MAX_COMMAND_LENGTH]
    extra["executable"] = _executable(command)[:MAX_FIELD_LENGTH]
    if len(candidates) > 1:
        extra["ambiguous"] = True

    if reason is None:
        return Parsed(
            Category.PROCESS,
            Action.SUDO_COMMAND,
            Outcome.SUCCESS,
            5,
            actor[:MAX_USER_LENGTH],
            extra,
        )
    return Parsed(
        Category.AUTHENTICATION,
        Action.SUDO_FAILED,
        Outcome.FAILURE,
        25,
        actor[:MAX_USER_LENGTH],
        extra,
    )


def parse_useradd(message: str) -> Parsed | None:
    found = _USERADD.match(message)
    if found is None:  # e.g. "new group: name=..." is part of the same operation
        return None
    extra: dict[str, Any] = {
        "uid": int(found["uid"]),
        "gid": int(found["gid"]),
        "home": found["home"][:MAX_FIELD_LENGTH],
        "shell": found["shell"][:MAX_FIELD_LENGTH],
        "from": found["origin"][:MAX_FIELD_LENGTH],
    }
    return Parsed(
        Category.IAM,
        Action.ACCOUNT_CREATED,
        Outcome.SUCCESS,
        40,
        found["name"][:MAX_USER_LENGTH],
        extra,
    )


def parse_usermod(message: str) -> Parsed | None:
    found = _USERMOD.match(message)  # the "shadow group" twin line does not match: no duplicate
    if found is None:
        return None
    return Parsed(
        Category.IAM,
        Action.GROUP_MEMBER_ADDED,
        Outcome.SUCCESS,
        40,
        found["user"][:MAX_USER_LENGTH],
        {"group": found["group"][:MAX_FIELD_LENGTH], "tool": "usermod"},
    )


def parse_gpasswd(message: str) -> Parsed | None:
    found = _GPASSWD.match(message)
    if found is None:
        return None
    return Parsed(
        Category.IAM,
        Action.GROUP_MEMBER_ADDED,
        Outcome.SUCCESS,
        40,
        found["user"][:MAX_USER_LENGTH],
        {
            "group": found["group"][:MAX_FIELD_LENGTH],
            "tool": "gpasswd",
            "added_by": found["by"][:MAX_USER_LENGTH],
        },
    )
