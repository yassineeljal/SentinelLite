"""Normalizer worker: `events.raw` (Redis) -> `events` / `events_dead_letter` (Postgres),
and `events.normalized` (Redis) for the detector.

Per batch: classify every entry, write events and dead letters in one database transaction
(idempotent inserts), publish the events downstream, and only then let the base class acknowledge
and delete the raw entries (see `consumer.py`). Events are published even when the insert found
them already stored: a crash between persisting and publishing must not hide an event from the
detector, and the detector is idempotent.
"""

import asyncio
import logging
import os
import socket
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from time import monotonic

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy.exc import DataError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.bus.normalized_stream import RedisNormalizedPublisher
from sentinel_core.bus.raw_stream import DATA_FIELD, RAW_STREAM
from sentinel_core.config import get_settings
from sentinel_core.db.events import ensure_event_partitions, insert_dead_letters, insert_events
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.normalizers.base import ParseError, RawLog, make_event_id
from sentinel_core.normalizers.dead_letter import DeadLetterRecord, make_dead_letter
from sentinel_core.normalizers.registry import NORMALIZERS
from sentinel_core.schema.event import Event
from sentinel_core.workers.consumer import (
    BLOCK_MS,
    Entry,
    StreamConsumer,
    build_redis,
    install_stop_signals,
)

logger = logging.getLogger("sentinel.normalizer")

GROUP = "normalizers"
PARTITIONS_BEHIND = 1  # days before today
PARTITIONS_AHEAD = 7  # days after today
PARTITION_REFRESH_SECONDS = 3600
__all__ = [
    "BLOCK_MS",
    "GROUP",
    "NORMALIZERS",
    "DeadLetterRecord",
    "NormalizerWorker",
    "build_redis",
    "process_entry",
]


def _dead_letter(data: str, error: str, raw_log: RawLog | None = None) -> DeadLetterRecord:
    # Same identity as the event id: a batch retried by the agent gets a new received_at (so a
    # different payload) but must not create a second dead letter. Undecodable entries have no
    # identity, so their payload is all we can hash.
    dedup_key = (
        make_event_id(raw_log) if raw_log else sha256(data.encode(errors="replace")).hexdigest()
    )
    return make_dead_letter(
        dedup_key=dedup_key,
        raw=raw_log.line if raw_log else data,
        error=error,
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


class NormalizerWorker(StreamConsumer):
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
        publisher: RedisNormalizedPublisher | None = None,
    ) -> None:
        super().__init__(
            redis,
            stream=stream,
            group=group,
            consumer=consumer,
            logger=logger,
            batch_size=batch_size,
            claim_idle_ms=claim_idle_ms,
        )
        self._sessions = sessions
        self._publisher = publisher
        self._last_partition_check = monotonic()

    async def setup(self) -> None:
        await super().setup()
        await self.ensure_partitions()

    async def ensure_partitions(self) -> None:
        today = datetime.now(UTC).date()
        async with self._sessions.begin() as session:
            await ensure_event_partitions(
                session,
                start=today - timedelta(days=PARTITIONS_BEHIND),
                days=PARTITIONS_BEHIND + 1 + PARTITIONS_AHEAD,
            )

    async def on_tick(self) -> None:
        if monotonic() - self._last_partition_check > PARTITION_REFRESH_SECONDS:
            # Counted before the attempt: a failing refresh is retried at the next interval, not
            # on every loop iteration (which would also slow down normalization).
            self._last_partition_check = monotonic()
            await self.ensure_partitions()

    async def ready(self) -> bool:
        # Stop reading raw lines while the detector is behind: the backlog stays in
        # `events.raw`, where it is bounded and turned into 429s by the API.
        return self._publisher is None or not await self._publisher.is_full()

    async def process_batch(self, entries: list[Entry]) -> None:
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

        await self._persist(events, letters)
        if self._publisher is not None:
            await self._publisher.publish(events)

        logger.info(
            "batch: %d entries -> %d events, %d dead letters, %d ignored",
            len(entries),
            len(events),
            len(letters),
            len(entries) - len(events) - len(letters),
        )

    async def quarantine(self, entry: Entry, exc: DataError) -> None:
        _, fields = entry
        data = (fields or {}).get(DATA_FIELD) or repr(fields)
        try:  # keep the context (agent, origin) when the entry is decodable
            raw_log: RawLog | None = RawLog.model_validate_json(data)
        except ValidationError:
            raw_log = None
        letter = _dead_letter(data, f"unstorable entry: {type(exc).__name__}", raw_log)
        # ASCII-only payload: recording the failure must not fail for the same reason.
        letter = replace(letter, raw=letter.raw.encode("unicode_escape").decode("ascii"))
        await self._persist([], [letter])

    async def _persist(self, events: list[Event], letters: list[DeadLetterRecord]) -> None:
        async with self._sessions.begin() as session:
            await insert_events(session, events)
            await insert_dead_letters(session, letters)


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
        publisher=RedisNormalizedPublisher(
            redis, high_watermark=settings.normalized_stream_high_watermark
        ),
    )
    stop = asyncio.Event()
    install_stop_signals(stop)
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
