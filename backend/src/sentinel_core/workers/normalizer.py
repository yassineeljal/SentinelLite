"""Normalizer worker: `events.raw` (Redis) -> `events` / `events_dead_letter` (Postgres).

Delivery is at-least-once and safe to repeat:
  1. read a batch through a consumer group (plus entries abandoned by crashed consumers),
  2. write events and dead letters in one database transaction (idempotent inserts),
  3. only then acknowledge and delete the entries from the stream.
A crash between 2 and 3 redelivers the batch; the idempotent inserts absorb the repeat.
"""

import asyncio
import logging
import os
import signal
import socket
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from time import monotonic
from typing import Any

from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.bus.raw_stream import DATA_FIELD, RAW_STREAM
from sentinel_core.config import get_settings
from sentinel_core.db.events import ensure_event_partitions, insert_dead_letters, insert_events
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.normalizers.base import ParseError, RawLog, make_event_id
from sentinel_core.normalizers.dead_letter import DeadLetterRecord
from sentinel_core.normalizers.registry import NORMALIZERS
from sentinel_core.schema.event import Event

logger = logging.getLogger("sentinel.normalizer")

GROUP = "normalizers"
PARTITIONS_BEHIND = 1  # days before today
PARTITIONS_AHEAD = 7  # days after today
PARTITION_REFRESH_SECONDS = 3600
RETRY_DELAY_SECONDS = 2.0
BLOCK_MS = 5000  # how long a read waits for new entries
# Must exceed BLOCK_MS: the client's default read timeout is close to it, so an idle worker
# would otherwise drop its connection and log an error every few seconds.
SOCKET_TIMEOUT_SECONDS = BLOCK_MS / 1000 + 10
MAX_ERROR_LENGTH = 500
MAX_RAW_LENGTH = 16_384

__all__ = ["GROUP", "NORMALIZERS", "DeadLetterRecord", "NormalizerWorker", "process_entry"]


def _dead_letter(data: str, error: str, raw_log: RawLog | None = None) -> DeadLetterRecord:
    # Same identity as the event id: a batch retried by the agent gets a new received_at (so a
    # different payload) but must not create a second dead letter. Undecodable entries have no
    # identity, so their payload is all we can hash.
    dedup_key = make_event_id(raw_log) if raw_log else sha256(data.encode()).hexdigest()
    return DeadLetterRecord(
        dedup_key=dedup_key,
        # Bounded: the payload is untrusted, the dead-letter table must not be a sink for it.
        raw=(raw_log.line if raw_log else data)[:MAX_RAW_LENGTH],
        error=error[:MAX_ERROR_LENGTH],
        agent_id=raw_log.agent_id if raw_log else None,
        source=raw_log.source.value if raw_log else None,
        origin=raw_log.origin if raw_log else None,
        received_at=raw_log.received_at if raw_log else None,
    )


def process_entry(data: str) -> Event | DeadLetterRecord | None:
    """Decide what one stream entry becomes: an Event, a DeadLetterRecord, or None (ignored)."""
    try:
        raw_log = RawLog.model_validate_json(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'entry'}: {e['msg']}"
            for e in exc.errors(include_input=False)
        )
        return _dead_letter(data, f"undecodable entry: {problems}")

    normalizer = NORMALIZERS.get(raw_log.source)
    if normalizer is None:
        return _dead_letter(data, f"no normalizer for source {raw_log.source}", raw_log)
    try:
        return normalizer.normalize(raw_log)
    except (ParseError, ValidationError) as exc:
        return _dead_letter(data, str(exc), raw_log)
    except Exception as exc:  # a bug in one parser must not take the whole worker down
        return _dead_letter(data, f"unexpected error: {type(exc).__name__}: {exc}", raw_log)


class NormalizerWorker:
    def __init__(
        self,
        redis: Redis,
        sessions: async_sessionmaker[AsyncSession],
        *,
        consumer: str,
        stream: str = RAW_STREAM,
        group: str = GROUP,
        batch_size: int = 100,
        claim_idle_ms: int = 60_000,
    ) -> None:
        self._redis = redis
        self._sessions = sessions
        self._consumer = consumer
        self._stream = stream
        self._group = group
        self._batch_size = batch_size
        self._claim_idle_ms = claim_idle_ms

    async def setup(self) -> None:
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):  # the group already exists: fine
                raise
        await self.ensure_partitions()

    async def ensure_partitions(self) -> None:
        today = datetime.now(UTC).date()
        async with self._sessions.begin() as session:
            await ensure_event_partitions(
                session,
                start=today - timedelta(days=PARTITIONS_BEHIND),
                days=PARTITIONS_BEHIND + 1 + PARTITIONS_AHEAD,
            )

    async def run(self, stop: asyncio.Event, block_ms: int = BLOCK_MS) -> None:
        await self.setup()
        logger.info("normalizer %s started (stream=%s)", self._consumer, self._stream)
        last_partition_check = monotonic()
        while not stop.is_set():
            try:
                await self.run_once(block_ms)
                if monotonic() - last_partition_check > PARTITION_REFRESH_SECONDS:
                    await self.ensure_partitions()
                    last_partition_check = monotonic()
            except (RedisError, SQLAlchemyError, OSError):
                # Entries were not acknowledged: they stay pending and will be redelivered.
                logger.exception("batch failed; retrying in %.0fs", RETRY_DELAY_SECONDS)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=RETRY_DELAY_SECONDS)
                except TimeoutError:
                    pass
        logger.info("normalizer %s stopped", self._consumer)

    async def run_once(self, block_ms: int | None = None) -> int:
        """Handle one batch. Returns the number of stream entries handled (0 if none)."""
        entries = await self._claim_stale()
        if len(entries) < self._batch_size:
            entries += await self._read_new(block_ms, self._batch_size - len(entries))
        if not entries:
            return 0

        events: list[Event] = []
        letters: list[DeadLetterRecord] = []
        for _, fields in entries:
            if fields is None:  # entry deleted while still pending: nothing left to process
                continue
            result = process_entry(fields.get(DATA_FIELD) or repr(fields))
            if isinstance(result, Event):
                events.append(result)
            elif isinstance(result, DeadLetterRecord):
                letters.append(result)

        await self._persist(events, letters)  # raises on failure: entries stay pending
        ids = [entry_id for entry_id, _ in entries]
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.xack(self._stream, self._group, *ids)
            pipe.xdel(self._stream, *ids)  # else the stream length would hit the API watermark
            await pipe.execute()

        logger.info(
            "batch: %d entries -> %d events, %d dead letters, %d ignored",
            len(entries),
            len(events),
            len(letters),
            len(entries) - len(events) - len(letters),
        )
        return len(entries)

    async def _persist(self, events: list[Event], letters: list[DeadLetterRecord]) -> None:
        async with self._sessions.begin() as session:
            await insert_events(session, events)
            await insert_dead_letters(session, letters)

    async def _claim_stale(self) -> list[tuple[str, dict[str, str] | None]]:
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

    async def _read_new(
        self, block_ms: int | None, count: int
    ) -> list[tuple[str, dict[str, str] | None]]:
        response: Any = await self._redis.xreadgroup(
            self._group, self._consumer, {self._stream: ">"}, count=count, block=block_ms
        )
        if not response:
            return []
        return [(entry[0], entry[1]) for entry in response[0][1]]


def build_redis(url: str) -> Redis:
    return Redis.from_url(
        url,
        decode_responses=True,
        socket_timeout=SOCKET_TIMEOUT_SECONDS,
        socket_connect_timeout=5,
    )


async def amain() -> None:
    settings = get_settings()
    redis = build_redis(settings.redis_url)
    engine = create_engine(settings)
    worker = NormalizerWorker(
        redis,
        create_sessionmaker(engine),
        consumer=f"{socket.gethostname()}-{os.getpid()}",
        batch_size=settings.normalizer_batch_size,
        claim_idle_ms=settings.normalizer_claim_idle_ms,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    try:
        await worker.run(stop)
    finally:
        await redis.aclose()
        await engine.dispose()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(amain())


if __name__ == "__main__":
    main()
