"""Reads the sources and delivers their lines, whatever the network does.

Delivery is at-least-once: a position is committed only after the server accepted the lines before
it, and the server deduplicates the repeats (the origin of a line never changes). What the shipper
guarantees on top:

* it never gets stuck on one line the server refuses: a refused batch is split until the offending
  line is alone, and that line alone is dropped (logged);
* ... but it never quietly discards a whole log: after 10 refused lines in a row the agent stops
  (ProtocolError) because something systemic is wrong;
* transient failures (network, 5xx) are retried forever with capped exponential backoff and jitter,
  a full queue (429) is waited out, and a rejected key (401) stops the agent for the operator.
"""

import logging
import random
import threading
import time
from collections.abc import Callable, Sequence
from typing import Protocol

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
from sentinel_agent.state import StateStore
from sentinel_agent.tailer import PendingLine, Tailer

logger = logging.getLogger("sentinel_agent.shipper")

MAX_BACKOFF_SECONDS = 60
MAX_CONSECUTIVE_REJECTIONS = 10
STATS_INTERVAL_SECONDS = 60
HEARTBEAT_INTERVAL_SECONDS = 60


class AuthenticationError(Exception):
    """The server does not accept the agent's key (unknown or revoked)."""


class ProtocolError(Exception):
    """The server refuses line after line: something is systematically wrong."""


class Unreachable(Exception):
    """The server stayed unavailable for the whole retry budget (--once mode only)."""


class _Stopping(Exception):
    """A stop was requested while the shipper was waiting."""


class Sender(Protocol):
    def send(self, source: str, lines: Sequence[tuple[str, str]]) -> Result: ...


class Backoff:
    """1 s, 2 s, 4 s ... capped, each with jitter so that agents do not retry in lockstep."""

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self._attempt = 0

    def next_delay(self) -> float:
        base = min(MAX_BACKOFF_SECONDS, 2**self._attempt)
        self._attempt += 1
        return float(base * self._rng.uniform(0.5, 1.0))

    def reset(self) -> None:
        self._attempt = 0


class Shipper:
    def __init__(
        self,
        config: Config,
        client: Sender,
        store: StateStore,
        stop: threading.Event,
        wait: Callable[[float], bool] | None = None,
        rng: random.Random | None = None,
        max_unavailable: int | None = None,
        heartbeat: Callable[[], Result] | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._store = store
        self._stop = stop
        self._wait = wait or stop.wait  # returns True when a stop was requested
        self._backoff = Backoff(rng or random.Random())  # noqa: S311 - jitter, not security
        self._consecutive_rejections = 0
        self._max_unavailable = max_unavailable  # None: retry forever (daemon mode)
        self._unavailable = 0
        self._heartbeat = heartbeat
        self._last_heartbeat: float | None = None
        self._tailers: list[tuple[Source, Tailer]] = [
            (source, Tailer(source.path, store.get(source.path), config.start_at))
            for source in config.sources
        ]
        self.sent = 0
        self.dropped = 0

    # -- public -----------------------------------------------------------------------------

    def run_once(self) -> int:
        """One pass over every source; returns how many lines were delivered."""
        delivered = 0
        for source, tailer in self._tailers:
            lines = tailer.read_batch(self._config.batch_lines, self._config.batch_bytes)
            if lines:
                delivered += self._deliver(source, lines)
        return delivered

    def drain(self) -> int:
        """Deliver everything currently available, then return (used by --once and the tests)."""
        total = 0
        try:
            while delivered := self.run_once():
                total += delivered
        except _Stopping:
            pass
        return total

    def run(self) -> None:
        """Ship until asked to stop."""
        last_stats, sent_then, dropped_then = time.monotonic(), 0, 0
        try:
            while not self._stop.is_set():
                self._maybe_heartbeat()
                if self.run_once() == 0 and self._wait(self._config.poll_interval):
                    break
                if time.monotonic() - last_stats >= STATS_INTERVAL_SECONDS:
                    logger.info(
                        "last minute: %d line(s) delivered, %d dropped",
                        self.sent - sent_then,
                        self.dropped - dropped_then,
                    )
                    last_stats, sent_then, dropped_then = time.monotonic(), self.sent, self.dropped
        except _Stopping:
            pass
        finally:
            for _, tailer in self._tailers:
                tailer.close()

    # -- liveness ---------------------------------------------------------------------------

    def _maybe_heartbeat(self) -> None:
        """Once a minute (and at start): proof of life for the platform's watchdog. A failure is
        only logged, it must never stop the shipping; a refused key is as fatal as for a batch."""
        if self._heartbeat is None:
            return
        now = time.monotonic()
        if (
            self._last_heartbeat is not None
            and now - self._last_heartbeat < HEARTBEAT_INTERVAL_SECONDS
        ):
            return
        self._last_heartbeat = now
        result = self._heartbeat()
        if isinstance(result, Unauthorized):
            raise AuthenticationError("the server refused the agent key (unknown or revoked)")
        if not isinstance(result, Accepted):
            logger.warning("heartbeat not delivered: %s", result)

    # -- delivery ---------------------------------------------------------------------------

    def _pause(self, seconds: float) -> None:
        if self._wait(seconds):
            raise _Stopping

    def _deliver(self, source: Source, lines: list[PendingLine]) -> int:
        """Deliver `lines` (possibly in pieces); returns how many were accepted."""
        while True:
            result = self._client.send(source.source, [(line.origin, line.text) for line in lines])
            if isinstance(result, Accepted):
                self._backoff.reset()
                self._unavailable = 0
                self._consecutive_rejections = 0
                self._store.commit(source.path, lines[-1].position)  # only now
                self.sent += len(lines)
                return len(lines)
            if isinstance(result, RetryAfter):
                logger.warning("server queue full, waiting %.0f s", result.seconds)
                self._pause(result.seconds)
            elif isinstance(result, Unavailable):
                self._unavailable += 1
                if self._max_unavailable is not None and self._unavailable > self._max_unavailable:
                    raise Unreachable(f"server still unavailable ({result.reason})")
                delay = self._backoff.next_delay()
                logger.warning("server unavailable (%s), retrying in %.1f s", result.reason, delay)
                self._pause(delay)
            elif isinstance(result, Unauthorized):
                raise AuthenticationError("the server refused the agent key (unknown or revoked)")
            elif isinstance(result, TooLarge | Rejected):
                return self._split_or_drop(source, lines, result)
            else:  # pragma: no cover - the union is exhaustive
                raise ProtocolError(f"unexpected result {result!r}")

    def _split_or_drop(
        self, source: Source, lines: list[PendingLine], result: TooLarge | Rejected
    ) -> int:
        if len(lines) > 1:
            middle = len(lines) // 2
            return self._deliver(source, lines[:middle]) + self._deliver(source, lines[middle:])
        if self._consecutive_rejections >= MAX_CONSECUTIVE_REJECTIONS:
            raise ProtocolError(
                f"the server refused {self._consecutive_rejections} lines in a row "
                f"(last: {result.detail}); stopping instead of discarding the log"
            )
        line = lines[0]
        logger.error("dropping line %s: refused by the server (%s)", line.origin, result.detail)
        self._consecutive_rejections += 1
        self.dropped += 1
        self._store.commit(source.path, line.position)  # skip past it: never stay stuck
        return 0
