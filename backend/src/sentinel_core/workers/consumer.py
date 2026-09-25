"""Shared plumbing of the stream workers (normalizer, detector).

Delivery is at-least-once and safe to repeat:
  1. read a batch through a consumer group (plus entries abandoned by crashed consumers),
  2. `process_batch` does the work and persists it (idempotently),
  3. only then the entries are acknowledged and deleted from the stream.
A crash between 2 and 3 redelivers the batch; idempotent processing absorbs the repeat.
"""

import asyncio
import logging
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.exc import SQLAlchemyError

BLOCK_MS = 5000  # how long a read waits for new entries
# Must exceed BLOCK_MS: the client's default read timeout is close to it, so an idle worker
# would otherwise drop its connection and log an error every few seconds.
SOCKET_TIMEOUT_SECONDS = BLOCK_MS / 1000 + 10
RETRY_DELAY_SECONDS = 2.0
NOT_READY_DELAY_SECONDS = 0.5

Entry = tuple[str, dict[str, str] | None]  # (stream entry id, fields; None if deleted meanwhile)


def build_redis(url: str) -> Redis:
    return Redis.from_url(
        url,
        decode_responses=True,
        socket_timeout=SOCKET_TIMEOUT_SECONDS,
        socket_connect_timeout=5,
    )


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

    # -- hooks ------------------------------------------------------------------------------

    async def process_batch(self, entries: list[Entry]) -> None:
        """Handle and persist a batch. Raise to leave every entry pending (they are retried)."""
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
            entries += await self._read_new(block_ms, self._batch_size - len(entries))
        if not entries:
            return 0

        await self.process_batch(entries)  # raises on failure: entries stay pending

        ids = [entry_id for entry_id, _ in entries]
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.xack(self._stream, self._group, *ids)
            pipe.xdel(self._stream, *ids)  # else the stream would grow without bound
            await pipe.execute()
        return len(entries)

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
            start_id="0-0",
            count=self._batch_size,
        )
        return [(entry[0], entry[1]) for entry in response[1]]

    async def _read_new(self, block_ms: int | None, count: int) -> list[Entry]:
        response: Any = await self._redis.xreadgroup(
            self._group, self._consumer, {self._stream: ">"}, count=count, block=block_ms
        )
        if not response:
            return []
        return [(entry[0], entry[1]) for entry in response[0][1]]
