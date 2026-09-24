from datetime import UTC, datetime
from uuid import UUID

import pytest

from sentinel_core.normalizers.base import ParseError, RawLog
from sentinel_core.normalizers.linux_auth import LinuxAuthNormalizer
from sentinel_core.schema.event import Action, Category, Outcome, Source

AGENT = UUID("11111111-1111-1111-1111-111111111111")
RECEIVED = datetime(2026, 9, 24, 15, 5, 0, tzinfo=UTC)


def raw(line: str, origin: str = "1:100") -> RawLog:
    return RawLog(
        agent_id=AGENT, source=Source.LINUX_AUTH, origin=origin, line=line, received_at=RECEIVED
    )


@pytest.fixture
def normalizer() -> LinuxAuthNormalizer:
    return LinuxAuthNormalizer()


def test_failed_password_for_existing_user(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:05.123456+00:00 ubuntu-01 sshd[812]: "
        "Failed password for root from 203.0.113.7 port 51234 ssh2"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert event.source is Source.LINUX_AUTH
    assert event.category is Category.AUTHENTICATION
    assert event.action is Action.LOGIN_FAILED
    assert event.outcome is Outcome.FAILURE
    assert event.host == "ubuntu-01"
    assert event.user_name == "root"
    assert str(event.src_ip) == "203.0.113.7"
    assert event.dst_port == 22
    assert event.ts == datetime(2026, 9, 24, 15, 4, 5, 123456, tzinfo=UTC)
    assert event.extra == {"method": "password", "src_port": 51234, "invalid_user": False}
    assert event.raw == line


def test_failed_password_for_invalid_user(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:06+00:00 ubuntu-01 sshd[813]: "
        "Failed password for invalid user admin from 198.51.100.9 port 40022 ssh2"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert event.action is Action.LOGIN_FAILED
    assert event.user_name == "admin"
    assert event.extra["invalid_user"] is True


def test_accepted_publickey_ignores_key_fingerprint(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:07+00:00 ubuntu-01 sshd[900]: "
        "Accepted publickey for alice from 10.0.0.5 port 4422 ssh2: RSA SHA256:abc123"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert event.action is Action.LOGIN_SUCCESS
    assert event.outcome is Outcome.SUCCESS
    assert event.user_name == "alice"
    assert str(event.src_ip) == "10.0.0.5"
    assert event.extra["method"] == "publickey"


def test_invalid_user_probe(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:08+00:00 ubuntu-01 sshd[814]: "
        "Invalid user oracle from 198.51.100.9 port 40030"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert event.action is Action.INVALID_USER
    assert event.outcome is Outcome.FAILURE
    assert event.user_name == "oracle"


def test_ipv6_source(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:09+00:00 ubuntu-01 sshd[815]: "
        "Failed password for root from 2001:db8::1 port 5555 ssh2"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert str(event.src_ip) == "2001:db8::1"


def test_traditional_syslog_timestamp_uses_received_year(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "Sep 24 15:04:05 ubuntu-01 sshd[812]: Failed password for root from 203.0.113.7 port 1 ssh2"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert event.ts == datetime(2026, 9, 24, 15, 4, 5, tzinfo=UTC)


def test_traditional_timestamp_across_new_year_uses_previous_year(
    normalizer: LinuxAuthNormalizer,
) -> None:
    line = (
        "Dec 31 23:59:58 ubuntu-01 sshd[812]: Failed password for root from 203.0.113.7 port 1 ssh2"
    )
    received = datetime(2027, 1, 1, 0, 0, 5, tzinfo=UTC)
    log = RawLog(
        agent_id=AGENT, source=Source.LINUX_AUTH, origin="1:1", line=line, received_at=received
    )

    event = normalizer.normalize(log)

    assert event is not None
    assert event.ts == datetime(2026, 12, 31, 23, 59, 58, tzinfo=UTC)


def test_username_cannot_spoof_source_ip(normalizer: LinuxAuthNormalizer) -> None:
    """The attacker controls the username; the real source is always the LAST 'from ... port'."""
    line = (
        "2026-09-24T15:04:10+00:00 ubuntu-01 sshd[816]: "
        "Failed password for invalid user x from 10.0.0.99 port 22 ssh2 "
        "from 203.0.113.7 port 999 ssh2"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert str(event.src_ip) == "203.0.113.7"


def test_oversized_username_is_truncated(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:11+00:00 ubuntu-01 sshd[817]: "
        f"Failed password for {'A' * 1000} from 203.0.113.7 port 1 ssh2"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert event.user_name is not None
    assert len(event.user_name) == 256


def test_unrelated_sshd_and_other_processes_are_ignored(normalizer: LinuxAuthNormalizer) -> None:
    assert (
        normalizer.normalize(
            raw("2026-09-24T15:04:12+00:00 h sshd[1]: Server listening on 0.0.0.0 port 22.")
        )
        is None
    )
    assert (
        normalizer.normalize(
            raw("2026-09-24T15:04:12+00:00 h CRON[2]: pam_unix(cron:session): session opened")
        )
        is None
    )


def test_line_without_syslog_framing_is_a_parse_error(normalizer: LinuxAuthNormalizer) -> None:
    with pytest.raises(ParseError):
        normalizer.normalize(raw("this is not a syslog line"))


def test_unparsable_source_ip_is_dropped_not_trusted(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:13+00:00 ubuntu-01 sshd[818]: "
        "Failed password for root from not-an-ip port 1 ssh2"
    )

    event = normalizer.normalize(raw(line))

    assert event is not None
    assert event.src_ip is None
    assert event.extra["src_host"] == "not-an-ip"


def test_event_id_is_deterministic_and_position_dependent(normalizer: LinuxAuthNormalizer) -> None:
    line = (
        "2026-09-24T15:04:05+00:00 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"
    )

    first = normalizer.normalize(raw(line, origin="1:100"))
    replay = normalizer.normalize(raw(line, origin="1:100"))
    same_text_elsewhere = normalizer.normalize(raw(line, origin="1:200"))

    assert first is not None and replay is not None and same_text_elsewhere is not None
    assert first.event_id == replay.event_id
    assert first.event_id != same_text_elsewhere.event_id
