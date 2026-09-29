import logging
import os
import random
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_agent.client import (
    Accepted,
    Rejected,
    Result,
    RetryAfter,
    TooLarge,
    Unauthorized,
    Unavailable,
)
from sentinel_agent.config import Config, Source
from sentinel_agent.shipper import (
    AuthenticationError,
    ProtocolError,
    Shipper,
    Unreachable,
)
from sentinel_agent.state import StateStore

Lines = Sequence[tuple[str, str]]


class ScriptedClient:
    """Plays scripted results first, then `behaviour` (default: accept everything)."""

    def __init__(
        self, *script: Result, behaviour: Callable[[str, Lines], Result] | None = None
    ) -> None:
        self.script = list(script)
        self.behaviour = behaviour or (lambda source, lines: Accepted(len(lines)))
        self.calls: list[tuple[str, list[tuple[str, str]]]] = []

    def send(self, source: str, lines: Lines) -> Result:
        self.calls.append((source, list(lines)))
        return self.script.pop(0) if self.script else self.behaviour(source, lines)

    @property
    def sent_texts(self) -> list[list[str]]:
        return [[text for _, text in lines] for _, lines in self.calls]


class Harness:
    def __init__(self, tmp_path: Path, batch_lines: int = 200) -> None:
        self.tmp = tmp_path
        self.log = tmp_path / "auth.log"
        self.log.write_text("")
        self.state_file = tmp_path / "state.json"
        self.config = Config(
            server_url="http://server",
            sources=(Source(self.log, "linux.auth"),),
            state_file=self.state_file,
            batch_lines=batch_lines,
            start_at="beginning",
        )
        self.stop = threading.Event()
        self.waits: list[float] = []

    def append(self, *lines: str) -> None:
        with self.log.open("a") as handle:
            handle.write("".join(line + "\n" for line in lines))

    def wait(self, seconds: float) -> bool:
        self.waits.append(seconds)
        return self.stop.is_set()

    def shipper(self, client: ScriptedClient, seed: int = 1) -> Shipper:
        return Shipper(
            self.config,
            client,
            StateStore(self.state_file),
            self.stop,
            wait=self.wait,
            rng=random.Random(seed),
        )

    def committed(self) -> int | None:
        state = StateStore(self.state_file).get(self.log)
        return None if state is None else state.offset


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_lines_are_shipped_in_batches_and_committed_only_after_acceptance(tmp_path: Path) -> None:
    h = Harness(tmp_path, batch_lines=2)
    h.append("l1", "l2", "l3", "l4", "l5")
    seen_during_send: list[int | None] = []

    def watching(source: str, lines: Lines) -> Result:
        seen_during_send.append(h.committed())  # what is stored while the server is still deciding
        return Accepted(len(lines))

    client = ScriptedClient(behaviour=watching)

    h.shipper(client).drain()

    assert client.sent_texts == [["l1", "l2"], ["l3", "l4"], ["l5"]]
    assert seen_during_send == [None, 6, 12]  # never ahead of what was acknowledged
    assert h.committed() == h.log.stat().st_size


def test_nothing_is_sent_when_there_is_nothing_new(harness: Harness) -> None:
    client = ScriptedClient()

    assert harness.shipper(client).drain() == 0
    assert client.calls == []


def test_a_429_waits_for_retry_after_and_resends_the_same_batch(harness: Harness) -> None:
    harness.append("l1", "l2")
    client = ScriptedClient(RetryAfter(3.0))

    harness.shipper(client).drain()

    assert harness.waits == [3.0]
    assert client.calls[0] == client.calls[1]  # the very same batch, same origins
    assert harness.committed() == harness.log.stat().st_size


def test_an_unavailable_server_is_retried_with_capped_exponential_backoff(
    harness: Harness,
) -> None:
    harness.append("l1")
    client = ScriptedClient(*[Unavailable("down")] * 9)

    harness.shipper(client).drain()

    assert len(harness.waits) == 9
    bases = [1, 2, 4, 8, 16, 32, 60, 60, 60]
    for delay, base in zip(harness.waits, bases, strict=True):
        assert base * 0.5 <= delay <= base  # jitter keeps agents from retrying in lockstep
    assert harness.committed() == harness.log.stat().st_size  # delivered in the end


def test_the_backoff_restarts_after_a_success(harness: Harness) -> None:
    harness.append("l1")
    client = ScriptedClient(Unavailable(), Unavailable(), Unavailable())
    shipper = harness.shipper(client)
    shipper.drain()
    harness.append("l2")
    client.script = [Unavailable()]

    shipper.drain()

    assert 0.5 <= harness.waits[-1] <= 1  # back to the first step, not 8 s


def test_a_rejected_batch_is_bisected_to_isolate_the_poison_line(harness: Harness) -> None:
    harness.append("good 1", "good 2", "POISON", "good 3", "good 4")

    def reject_poison(source: str, lines: Lines) -> Result:
        if any("POISON" in text for _, text in lines):
            return Rejected("HTTP 422: bad line")
        return Accepted(len(lines))

    client = ScriptedClient(behaviour=reject_poison)

    shipper = harness.shipper(client)
    shipper.drain()

    delivered = [
        text
        for _, lines in client.calls
        if not any("POISON" in t for _, t in lines)
        for _, text in lines
    ]
    assert delivered == ["good 1", "good 2", "good 3", "good 4"]  # every innocent line, in order
    assert shipper.dropped == 1
    assert harness.committed() == harness.log.stat().st_size  # the agent is not stuck


def test_too_large_batches_are_split(harness: Harness) -> None:
    harness.append(*[f"line {i}" for i in range(8)])

    def small_only(source: str, lines: Lines) -> Result:
        return TooLarge() if len(lines) > 2 else Accepted(len(lines))

    client = ScriptedClient(behaviour=small_only)

    harness.shipper(client).drain()

    flat = [text for _, lines in client.calls if len(lines) <= 2 for _, text in lines]
    assert flat == [f"line {i}" for i in range(8)]


def test_401_stops_the_agent_without_committing_anything(harness: Harness) -> None:
    harness.append("l1")
    client = ScriptedClient(Unauthorized())

    with pytest.raises(AuthenticationError):
        harness.shipper(client).drain()

    assert harness.committed() is None


def test_a_systemic_rejection_stops_the_agent_instead_of_discarding_the_logs(
    harness: Harness,
) -> None:
    """If every line is refused (a contract mismatch after an upgrade, say) the agent must not
    quietly throw the whole log away."""
    harness.append(*[f"line {i}" for i in range(100)])
    client = ScriptedClient(behaviour=lambda source, lines: Rejected("HTTP 422: nope"))
    shipper = harness.shipper(client)

    with pytest.raises(ProtocolError):
        shipper.drain()

    assert shipper.dropped <= 10
    assert (harness.committed() or 0) < harness.log.stat().st_size  # most of the log is still there


def test_a_crash_after_sending_but_before_committing_resends_the_same_origins(
    harness: Harness,
) -> None:
    harness.append("l1", "l2", "l3")
    first_run: list[list[tuple[str, str]]] = []

    def crash_after_the_server_accepted(source: str, lines: Lines) -> Result:
        first_run.append(list(lines))
        raise RuntimeError("agent killed before it could commit")

    with pytest.raises(RuntimeError):
        harness.shipper(ScriptedClient(behaviour=crash_after_the_server_accepted)).drain()
    assert harness.committed() is None

    second = ScriptedClient()
    harness.shipper(second).drain()

    assert second.calls[0][1] == first_run[0]  # identical origins: the server deduplicates


def test_asking_to_stop_during_a_backoff_exits_cleanly_without_committing(
    harness: Harness,
) -> None:
    harness.append("l1")
    client = ScriptedClient(*[Unavailable()] * 50)

    def stop_requested_while_waiting(seconds: float) -> bool:
        harness.stop.set()  # SIGTERM arrives during the wait
        return True

    shipper = Shipper(
        harness.config,
        client,
        StateStore(harness.state_file),
        harness.stop,
        wait=stop_requested_while_waiting,
    )

    shipper.run()  # returns instead of retrying forever

    assert len(client.calls) == 1
    assert harness.committed() is None


def test_every_source_is_sent_separately_with_its_own_source_name(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    web = tmp_path / "access.log"
    web.write_text("GET / 200\n")
    h.config = Config(
        server_url="http://server",
        sources=(Source(h.log, "linux.auth"), Source(web, "nginx.access")),
        state_file=h.state_file,
        start_at="beginning",
    )
    h.append("auth line")
    client = ScriptedClient()

    h.shipper(client).drain()

    assert [(source, [t for _, t in lines]) for source, lines in client.calls] == [
        ("linux.auth", ["auth line"]),
        ("nginx.access", ["GET / 200"]),
    ]


def test_a_rotation_between_two_passes_loses_and_repeats_nothing(harness: Harness) -> None:
    harness.append("before 1")
    client = ScriptedClient()
    shipper = harness.shipper(client)
    shipper.drain()
    harness.append("before 2")
    os.rename(harness.log, harness.tmp / "auth.log.1")
    harness.append("after 1", "after 2")

    shipper.drain()

    assert [t for texts in client.sent_texts for t in texts] == [
        "before 1",
        "before 2",
        "after 1",
        "after 2",
    ]


def test_a_restart_resumes_from_the_acknowledged_position(harness: Harness) -> None:
    harness.append("l1", "l2")
    harness.shipper(ScriptedClient()).drain()
    harness.append("l3")
    client = ScriptedClient()

    harness.shipper(client).drain()  # a brand new process, same state file

    assert client.sent_texts == [["l3"]]


def test_the_key_and_the_lines_are_not_logged_at_info_level(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.append("secret-looking line")
    caplog.set_level(logging.INFO)

    harness.shipper(ScriptedClient(Unavailable("boom"))).drain()

    assert "secret-looking line" not in caplog.text


def test_once_mode_gives_up_when_the_server_stays_unreachable(harness: Harness) -> None:
    harness.append("l1")
    client = ScriptedClient(behaviour=lambda source, lines: Unavailable("down"))
    shipper = Shipper(
        harness.config,
        client,
        StateStore(harness.state_file),
        harness.stop,
        wait=harness.wait,
        max_unavailable=3,
    )

    with pytest.raises(Unreachable):
        shipper.drain()

    assert len(client.calls) == 4  # the first try and three retries
    assert harness.committed() is None  # nothing was lost: it stays in the file


class Clock:
    """A monotonic clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def run_for(
    h: Harness, client: ScriptedClient, beats: Callable[[], Result], seconds: float
) -> None:
    """Run the shipper loop for `seconds` of fake time (each idle wait advances the clock)."""
    clock = Clock()
    poll = h.config.poll_interval

    def wait(delay: float) -> bool:
        clock.now += delay
        if clock.now - 1000.0 >= seconds:
            h.stop.set()
        return h.stop.is_set()

    shipper = Shipper(
        h.config,
        client,
        StateStore(h.state_file),
        h.stop,
        wait=wait,
        rng=random.Random(1),
        heartbeat=beats,
    )
    with patch("sentinel_agent.shipper.time.monotonic", clock):
        assert poll > 0
        shipper.run()


def test_a_heartbeat_is_sent_at_start_then_once_a_minute_even_when_idle(tmp_path: Path) -> None:
    h = Harness(tmp_path)  # nothing to ship at all
    beats: list[int] = []

    def beat() -> Result:
        beats.append(1)
        return Accepted(0)

    run_for(h, ScriptedClient(), beat, seconds=185)

    assert len(beats) == 4  # at 0, 60, 120 and 180 seconds


def test_no_heartbeat_callable_means_none_is_sent(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.append("l1")
    client = ScriptedClient()

    h.shipper(client).drain()  # the --once path

    assert client.sent_texts == [["l1"]]


def test_a_failed_heartbeat_never_stops_the_shipping(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    h = Harness(tmp_path)
    h.append("l1", "l2")
    client = ScriptedClient()

    with caplog.at_level("WARNING"):
        run_for(h, client, lambda: Unavailable("HTTP 503"), seconds=5)

    assert client.sent_texts == [["l1", "l2"]]
    assert "heartbeat not delivered" in caplog.text


def test_a_refused_key_on_a_heartbeat_stops_the_agent(tmp_path: Path) -> None:
    h = Harness(tmp_path)

    with pytest.raises(AuthenticationError):
        run_for(h, ScriptedClient(), lambda: Unauthorized(), seconds=5)
