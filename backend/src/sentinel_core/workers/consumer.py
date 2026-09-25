"""Shared plumbing of the stream workers (normalizer, detector).

Delivery is at-least-once and safe to repeat:
  1. read a batch through a consumer group (plus entries abandoned by crashed consumers),
  2. `process_batch` does the work and persists it (idempotently),
  3. only then the entries are acknowledged and deleted from the stream.
A crash between 2 and 3 redelivers the batch; idempotent processing absorbs the repeat.
"""

import asyncio
import logging
import signal
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.exc import DataError, SQLAlchemyError

from sentinel_core.bus.client import build_redis as _build_redis

BLOCK_MS = 5000  # how long a read waits for new entries
# Must exceed BLOCK_MS: the client's default read timeout is close to it, so an idle worker
# would otherwise drop its connection and log an error every few seconds.
SOCKET_TIMEOUT_SECONDS = BLOCK_MS / 1000 + 10
RETRY_DELAY_SECONDS = 2.0
NOT_READY_DELAY_SECONDS = 0.5

Entry = tuple[str, dict[str, str] | None]  # (stream entry id, fields; None if deleted meanwhile)


def build_redis(url: str) -> Redis:
    return _build_redis(url, SOCKET_TIMEOUT_SECONDS)


def install_stop_signals(stop: asyncio.Event) -> None:
    """Set `stop` on SIGINT / SIGTERM so that a worker finishes its batch and exits."""
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)


class StreamConsumer:
    def __init__(
        self,
        redis: Redis,
        *,
        stream: str,
        group: str,
        consumer: str,
        logger: logging.Logger,
        batch_size: int = 100,
        claim_idle_ms: int = 60_000,
    ) -> None:
        self._redis = redis
        self._stream = stream
        self._group = group
        self._consumer = consumer
        self._logger = logger
        self._batch_size = batch_size
        self._claim_idle_ms = claim_idle_ms
        self._claim_cursor = "0-0"  # where the next scan of the pending list resumes

    # -- hooks ------------------------------------------------------------------------------

    async def process_batch(self, entries: list[Entry]) -> None:
        """Handle and persist a batch. Raise to leave every entry pending (they are retried)."""
        raise NotImplementedError

    async def quarantine(self, entry: Entry, exc: DataError) -> None:
        """Record an entry that the database deterministically rejects (retrying it can never
        succeed), so that it stops blocking the entries around it."""
        raise NotImplementedError

    async def ready(self) -> bool:
        """Downstream backpressure: when False, no new work is read (the backlog builds up
        upstream, where it is bounded and visible)."""
        return True

    async def on_tick(self) -> None:
        """Called after each successful loop iteration (periodic maintenance)."""

    # -- machinery --------------------------------------------------------------------------

    async def setup(self) -> None:
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):  # the group already exists: fine
                raise

    async def run_once(self, block_ms: int | None = None) -> int:
        """Handle one batch. Returns the number of stream entries handled (0 if none)."""
        if not await self.ready():
            await asyncio.sleep(NOT_READY_DELAY_SECONDS)
            return 0
        entries = await self._claim_stale()
        if len(entries) < self._batch_size:
            # Work already in hand must not wait for the blocking read of new entries.
            wait = None if entries else block_ms
            entries += await self._read_new(wait, self._batch_size - len(entries))
        if not entries:
            return 0

        try:
            await self.process_batch(entries)  # other errors leave every entry pending: retried
        except DataError:
            # A deterministic storage error would fail on every retry of this batch and hold
            # back all the entries around the offender: isolate it.
            await self._process_one_by_one(entries)

        ids = [entry_id for entry_id, _ in entries]
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.xack(self._stream, self._group, *ids)
            pipe.xdel(self._stream, *ids)  # else the stream would grow without bound
            await pipe.execute()
        return len(entries)

    async def _process_one_by_one(self, entries: list[Entry]) -> None:
        self._logger.warning("batch rejected by the database: isolating the offending entries")
        for entry in entries:
            try:
                await self.process_batch([entry])
            except DataError as exc:
                self._logger.error("quarantining entry %s (%s)", entry[0], type(exc).__name__)
                await self.quarantine(entry, exc)

    async def run(self, stop: asyncio.Event, block_ms: int = BLOCK_MS) -> None:
        await self.setup()
        self._logger.info("%s started (stream=%s)", self._consumer, self._stream)
        while not stop.is_set():
            try:
                await self.run_once(block_ms)
                await self.on_tick()
            except (RedisError, SQLAlchemyError, OSError):
                # Entries were not acknowledged: they stay pending and will be redelivered.
                self._logger.exception("batch failed; retrying in %.0fs", RETRY_DELAY_SECONDS)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=RETRY_DELAY_SECONDS)
                except TimeoutError:
                    pass
        self._logger.info("%s stopped", self._consumer)

    async def _claim_stale(self) -> list[Entry]:
        """Take over entries delivered to a consumer that never acknowledged them."""
        response: Any = await self._redis.xautoclaim(
            self._stream,
            self._group,
            self._consumer,
            min_idle_time=self._claim_idle_ms,
            start_id=self._claim_cursor,
            count=self._batch_size,
        )
        # Redis scans a bounded part of the pending list per call and returns where to resume;
        # "0-0" means the end was reached, so the next scan starts over.
        self._claim_cursor = str(response[0])
        return [(entry[0], entry[1]) for entry in response[1]]

    async def _read_new(self, block_ms: int | None, count: int) -> list[Entry]:
        response: Any = await self._redis.xreadgroup(
            self._group, self._consumer, {self._stream: ">"}, count=count, block=block_ms
        )
        if not response:
            return []
        return [(entry[0], entry[1]) for entry in response[0][1]]
