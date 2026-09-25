"""Unit tests for the pure part of the normalizer worker: one stream entry -> a decision."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from sentinel_core.normalizers.base import RawLog
from sentinel_core.schema.event import Action, Event, Source
from sentinel_core.workers import normalizer as worker
from sentinel_core.workers.normalizer import (
    BLOCK_MS,
    DeadLetterRecord,
    build_redis,
    process_entry,
)

AGENT = UUID("11111111-1111-1111-1111-111111111111")
RECEIVED = datetime(2026, 9, 24, 15, 5, 0, tzinfo=UTC)
FAILED = (
    "2026-09-24T15:04:05+00:00 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"
)


def entry(
    line: str,
    source: Source = Source.LINUX_AUTH,
    origin: str = "1:0",
    received_at: datetime = RECEIVED,
) -> str:
    raw = RawLog(agent_id=AGENT, source=source, origin=origin, line=line, received_at=received_at)
    return raw.model_dump_json()


def test_valid_line_becomes_an_event() -> None:
    result = process_entry(entry(FAILED))

    assert isinstance(result, Event)
    assert result.action is Action.LOGIN_FAILED
    assert str(result.src_ip) == "203.0.113.7"


def test_line_with_nothing_to_model_is_ignored() -> None:
    cron = "2026-09-24T15:04:12+00:00 h CRON[2]: pam_unix(cron:session): session opened"

    assert process_entry(entry(cron)) is None


def test_malformed_line_goes_to_dead_letter_with_its_context() -> None:
    data = entry("this is not a syslog line", origin="7:42")

    result = process_entry(data)

    assert isinstance(result, DeadLetterRecord)
    assert "syslog" in result.error
    assert result.agent_id == AGENT
    assert result.source == "linux.auth"
    assert result.origin == "7:42"
    assert result.raw == "this is not a syslog line"
    assert result.received_at == RECEIVED


def test_source_without_a_normalizer_goes_to_dead_letter() -> None:
    result = process_entry(entry("anything", source=Source.NGINX_ACCESS))

    assert isinstance(result, DeadLetterRecord)
    assert "no normalizer" in result.error
    assert result.source == "nginx.access"


def test_bad_timestamp_goes_to_dead_letter() -> None:
    line = "2026-13-45T99:99:99+00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"

    result = process_entry(entry(line))

    assert isinstance(result, DeadLetterRecord)


@pytest.mark.parametrize(
    "data",
    [
        "not json at all",
        "{}",
        json.dumps({"agent_id": "nope", "source": "linux.auth"}),
        json.dumps(
            {
                "agent_id": str(AGENT),
                "source": "unknown.source",
                "origin": "1",
                "line": "x",
                "received_at": RECEIVED.isoformat(),
            }
        ),
    ],
)
def test_undecodable_entries_go_to_dead_letter_without_context(data: str) -> None:
    result = process_entry(data)

    assert isinstance(result, DeadLetterRecord)
    assert result.agent_id is None and result.source is None and result.origin is None
    assert result.raw == data
    assert result.error


def test_a_bug_in_a_normalizer_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken:
        source = Source.LINUX_AUTH

        def normalize(self, raw: RawLog) -> None:
            raise RuntimeError("boom " + "x" * 1000)

    monkeypatch.setitem(worker.NORMALIZERS, Source.LINUX_AUTH, Broken())

    result = process_entry(entry(FAILED))

    assert isinstance(result, DeadLetterRecord)
    assert result.error.startswith("unexpected error: RuntimeError")
    assert len(result.error) <= 500  # a hostile line must not bloat the dead-letter table


def test_dedup_key_is_deterministic_and_content_dependent() -> None:
    first = process_entry(entry("bad line", origin="1:0"))
    replay = process_entry(entry("bad line", origin="1:0"))
    other = process_entry(entry("bad line", origin="1:1"))

    assert isinstance(first, DeadLetterRecord)
    assert isinstance(replay, DeadLetterRecord)
    assert isinstance(other, DeadLetterRecord)
    assert first.dedup_key == replay.dedup_key
    assert first.dedup_key != other.dedup_key
    assert len(first.dedup_key) == 64


def test_dead_letters_are_bounded_whatever_the_payload() -> None:
    result = process_entry("x" * 50_000)

    assert isinstance(result, DeadLetterRecord)
    assert len(result.raw) == 16_384
    assert len(result.error) <= 500


def test_dedup_key_survives_an_agent_retry_with_a_new_received_at() -> None:
    """A retried batch reaches the API again and gets a fresh server-side received_at."""
    first = process_entry(entry("bad line", received_at=RECEIVED))
    retry = process_entry(entry("bad line", received_at=RECEIVED + timedelta(minutes=5)))

    assert isinstance(first, DeadLetterRecord) and isinstance(retry, DeadLetterRecord)
    assert first.dedup_key == retry.dedup_key


def test_redis_client_timeout_outlasts_the_blocking_read() -> None:
    client = build_redis("redis://localhost:6379/0")

    timeout = client.connection_pool.connection_kwargs["socket_timeout"]
    assert timeout > BLOCK_MS / 1000
