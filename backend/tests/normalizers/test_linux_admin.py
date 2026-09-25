"""sudo / useradd / usermod / gpasswd events in auth.log.

`data/ubuntu-24.04-admin.log` holds REAL lines captured from Ubuntu 24.04 (user and path
anonymised): the formats differ from what one would write from memory (no TTY field outside a
terminal, padded spacing, three PAM lines plus a summary line per sudo failure, two usermod lines
per group change).
"""

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from sentinel_core.normalizers.base import RawLog
from sentinel_core.normalizers.linux_auth import LinuxAuthNormalizer
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source

DATA = Path(__file__).parent / "data" / "ubuntu-24.04-admin.log"
AGENT = UUID("11111111-1111-1111-1111-111111111111")
RECEIVED = datetime(2026, 9, 26, tzinfo=UTC)
HEAD = "2026-09-25T14:51:39.050008-04:00 sl-target "


def normalize(line: str, origin: str = "1:0") -> Event | None:
    raw = RawLog(
        agent_id=AGENT, source=Source.LINUX_AUTH, origin=origin, line=line, received_at=RECEIVED
    )
    return LinuxAuthNormalizer().normalize(raw)


def event(message: str) -> Event:
    found = normalize(HEAD + message)
    assert found is not None, message
    return found


def test_the_real_capture_yields_exactly_the_expected_events() -> None:
    lines = [x for x in DATA.read_text().splitlines() if x.strip()]

    events = [(line, normalize(line, origin=f"1:{i}")) for i, line in enumerate(lines)]
    counts = Counter(e.action for _, e in events if e is not None)

    assert counts == {
        Action.SUDO_COMMAND: 18,
        Action.SUDO_FAILED: 2,  # one line per failure, not the three PAM lines around it
        Action.ACCOUNT_CREATED: 4,
        Action.GROUP_MEMBER_ADDED: 3,  # 2 usermod (shadow duplicates ignored) + 1 gpasswd
    }
    assert len({e.event_id for _, e in events if e is not None}) == sum(counts.values())


def test_a_sudo_command_without_a_terminal_has_no_tty() -> None:
    e = event(
        "sudo:  alice : PWD=/home/alice/work ; USER=root ; COMMAND=/usr/bin/apt-get --version"
    )

    assert (e.action, e.category, e.outcome) == (
        Action.SUDO_COMMAND,
        Category.PROCESS,
        Outcome.SUCCESS,
    )
    assert e.user_name == "alice" and e.src_ip is None
    assert e.host == "sl-target"
    assert e.extra == {
        "target_user": "root",
        "command": "/usr/bin/apt-get --version",
        "executable": "/usr/bin/apt-get",
        "pwd": "/home/alice/work",
    }


def test_a_sudo_command_from_a_terminal_records_it() -> None:
    e = event("sudo:    bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")

    assert e.user_name == "bob"
    assert e.extra["tty"] == "pts/0" and e.extra["executable"] == "/bin/bash"


def test_sudo_failures_are_one_event_from_the_summary_line() -> None:
    denied = event(
        "sudo:   carol2 : user NOT in sudoers ; PWD=/home/alice/work ; USER=root ; COMMAND=/usr/bin/ls /"
    )
    wrong = event(
        "sudo:     evil : 1 incorrect password attempt ; PWD=/x ; USER=root ; COMMAND=/usr/bin/ls /"
    )
    three = event(
        "sudo: evil : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/x ; USER=root ; COMMAND=/bin/su"
    )

    for e in (denied, wrong, three):
        assert (e.action, e.category, e.outcome) == (
            Action.SUDO_FAILED,
            Category.AUTHENTICATION,
            Outcome.FAILURE,
        )
    assert denied.user_name == "carol2" and denied.extra["reason"] == "user_not_in_sudoers"
    assert wrong.extra["reason"] == "incorrect_password" and wrong.extra["attempts"] == 1
    assert three.extra["attempts"] == 3 and three.extra["tty"] == "pts/1"
    assert denied.extra["target_user"] == "root"


@pytest.mark.parametrize(
    "message",
    [
        "sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty= ruser=carol2 rhost=  user=carol2",
        "sudo: pam_unix(sudo:auth): conversation failed",
        "sudo: pam_unix(sudo:auth): auth could not identify password for [carol2]",
        "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=501)",
        "sudo: pam_unix(sudo:session): session closed for user root",
        "useradd[406]: new group: name=nosudo1, GID=1003",
        "usermod[313]: add 'evil' to shadow group 'sudo'",
        "gpasswd[360]: members of group users set by root to dave",
        "groupadd[332]: new group: name=dave, GID=1002",
        "chfn[352]: changed user 'dave' information",
        "passwd[398]: password for 'evil' changed by 'root'",
        "su[395]: (to root) root on none",
    ],
)
def test_lines_that_would_double_count_or_carry_nothing_we_model_are_ignored(message: str) -> None:
    assert normalize(HEAD + message) is None


def test_a_new_account() -> None:
    e = event(
        "useradd[339]: new user: name=dave, UID=1002, GID=1002, home=/home/dave, "
        "shell=/bin/bash, from=none"
    )

    assert (e.action, e.category, e.outcome) == (
        Action.ACCOUNT_CREATED,
        Category.IAM,
        Outcome.SUCCESS,
    )
    assert e.user_name == "dave"
    assert e.extra == {
        "uid": 1002,
        "gid": 1002,
        "home": "/home/dave",
        "shell": "/bin/bash",
        "from": "none",
    }


def test_a_uid_zero_account_is_recorded_as_such() -> None:
    e = event(
        "useradd[1]: new user: name=toor, UID=0, GID=0, home=/root, shell=/bin/sh, from=/dev/pts/0"
    )

    assert e.extra["uid"] == 0 and e.extra["from"] == "/dev/pts/0"


def test_usermod_adds_a_member_to_a_group() -> None:
    e = event("usermod[313]: add 'evil' to group 'sudo'")

    assert (e.action, e.category, e.outcome) == (
        Action.GROUP_MEMBER_ADDED,
        Category.IAM,
        Outcome.SUCCESS,
    )
    assert e.user_name == "evil" and e.extra == {"group": "sudo", "tool": "usermod"}


def test_gpasswd_records_who_added_the_member() -> None:
    e = event("gpasswd[321]: user carol2 added by root to group adm")

    assert e.user_name == "carol2"
    assert e.extra == {"group": "adm", "tool": "gpasswd", "added_by": "root"}


# --- The sudo format is ambiguous: PWD and COMMAND are user-controlled ------------------------
#
# A user can run from a directory named "/tmp/x ; USER=nobody ; COMMAND=/bin/ls" so that the log
# line contains a fake "USER=... ; COMMAND=..." segment BEFORE the real one, and can append one AFTER
# it through the command's arguments. The real segment cannot be told apart from the text alone, so
# the normalizer must never let a decoy hide a root shell.


def test_a_decoy_before_the_real_segment_cannot_hide_a_root_shell() -> None:
    e = event(
        "sudo:  alice : PWD=/tmp/x ; USER=nobody ; COMMAND=/bin/ls ; USER=root ; COMMAND=/bin/bash"
    )

    assert e.extra["target_user"] == "root" and e.extra["command"] == "/bin/bash"
    assert e.extra["ambiguous"] is True


def test_a_decoy_after_the_real_segment_cannot_hide_it_either() -> None:
    e = event(
        "sudo:  alice : PWD=/x ; USER=root ; COMMAND=/bin/bash ; USER=nobody ; COMMAND=/bin/ls"
    )

    assert e.extra["target_user"] == "root" and e.extra["command"] == "/bin/bash"
    assert e.extra["ambiguous"] is True


def test_a_harmless_root_decoy_cannot_hide_a_root_shell() -> None:
    e = event("sudo:  alice : PWD=/x ; USER=root ; COMMAND=/bin/ls ; USER=root ; COMMAND=/bin/bash")

    assert e.extra["command"] == "/bin/bash"  # among root segments, the shell wins


def test_a_normal_line_is_not_marked_ambiguous() -> None:
    e = event("sudo:  alice : PWD=/x ; USER=root ; COMMAND=/usr/bin/ls -l")

    assert "ambiguous" not in e.extra


def test_the_actor_is_the_first_token_and_cannot_be_forged_from_the_command() -> None:
    e = event(
        "sudo:  alice : PWD=/x ; USER=root ; COMMAND=/bin/echo bob : PWD=/y ; USER=root ; COMMAND=/bin/su"
    )

    assert e.user_name == "alice"


def test_a_very_long_command_is_bounded() -> None:
    e = event("sudo:  alice : PWD=/x ; USER=root ; COMMAND=/bin/echo " + "A" * 5000)

    assert len(e.extra["command"]) <= 2048
    assert e.extra["executable"] == "/bin/echo"


def test_a_sudo_line_without_a_command_segment_is_ignored() -> None:
    assert normalize(HEAD + "sudo:  alice : TTY=pts/0 ; PWD=/x") is None


def test_a_sudo_refusal_we_do_not_know_is_a_failure_not_a_success() -> None:
    """Unknown text before the fields means sudo refused: never count it as a command run."""
    e = event("sudo:  alice : user NOT authorized on host ; PWD=/x ; USER=root ; COMMAND=/bin/ls")

    assert e.action is Action.SUDO_FAILED and e.extra["reason"] == "other"
    assert e.extra["detail"] == "user NOT authorized on host"


@pytest.mark.parametrize("proc", ["(systemd)", "(sd-pam)"])
def test_parenthesised_process_names_are_well_formed_noise_not_parse_errors(proc: str) -> None:
    """Found on a real host: systemd user-manager lines look like `(systemd): pam_unix(...)`.
    Rejecting them as malformed would fill the dead-letter table with ordinary traffic."""
    line = f"2026-09-25T14:51:39.319235-04:00 sl-target {proc}: pam_unix(systemd-user:session): x"

    assert normalize(line) is None
