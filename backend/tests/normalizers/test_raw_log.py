from datetime import UTC, datetime
from uuid import UUID

import pytest

from sentinel_core.normalizers.base import MAX_LINE_LENGTH, RawLog, make_event_id
from sentinel_core.schema.event import Source

AGENT = UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime(2026, 9, 25, tzinfo=UTC)


def raw(line: str, origin: str = "1:0", agent: UUID = AGENT) -> RawLog:
    return RawLog(
        agent_id=agent, source=Source.LINUX_AUTH, origin=origin, line=line, received_at=NOW
    )


def test_nul_bytes_are_made_visible_because_postgres_cannot_store_them() -> None:
    log = raw("Failed password for ro\x00ot", origin="1\x00:0")

    assert log.line == "Failed password for ro\\x00ot"
    assert log.origin == "1\\x00:0"


def test_lone_surrogates_are_escaped_because_they_cannot_be_encoded_as_utf8() -> None:
    log = raw("bad \ud800 surrogate")

    assert log.line == "bad \\ud800 surrogate"
    log.line.encode("utf-8")  # must not raise


def test_the_length_limit_applies_to_the_stored_form() -> None:
    with pytest.raises(ValueError):
        raw("\x00" * (MAX_LINE_LENGTH // 2))  # 4 characters each once escaped


def test_ordinary_text_is_untouched() -> None:
    line = "2026-09-25T10:00:00+00:00 h sshd[1]: Failed password for é中 from 1.2.3.4 port 1 ssh2"

    assert raw(line).line == line


def test_event_id_depends_on_the_line_content() -> None:
    """After log rotation an inode can be reused and offsets repeat: the same origin then
    designates different lines, which must not collapse into one event."""
    assert make_event_id(raw("line A")) != make_event_id(raw("line B"))


def test_event_id_is_stable_for_a_retried_line() -> None:
    later = raw("line A").model_copy(update={"received_at": datetime(2026, 9, 26, tzinfo=UTC)})

    assert make_event_id(raw("line A")) == make_event_id(later)


def test_event_id_is_scoped_to_the_agent_and_the_origin() -> None:
    base = make_event_id(raw("line A"))

    assert base != make_event_id(raw("line A", agent=UUID(int=2)))
    assert base != make_event_id(raw("line A", origin="1:1"))
