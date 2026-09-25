"""Detector worker: `events.normalized` (Redis) -> engine -> `alerts` (Postgres).

Per batch: evaluate every event, persist the alerts (and dead letters) in one transaction, and
only then let the base class acknowledge and delete the entries (see `consumer.py`).
Redelivery is safe: window state is idempotent per event, alert ids are deterministic, and the
event that raised an alert re-raises it (see detection/store.py), so a crash between evaluating
and persisting never loses an alert nor duplicates one.
"""

import asyncio
import logging
import os
import signal
import socket
import sys
from hashlib import sha256

from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.bus.normalized_stream import NORMALIZED_STREAM
from sentinel_core.bus.raw_stream import DATA_FIELD
from sentinel_core.config import get_settings
from sentinel_core.db.alerts import insert_alerts
from sentinel_core.db.events import insert_dead_letters
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.engine import DetectionEngine
from sentinel_core.detection.rules import RuleLoadError, load_rules
from sentinel_core.detection.store import RedisWindowStore
from sentinel_core.normalizers.dead_letter import DeadLetterRecord
from sentinel_core.schema.event import Event
from sentinel_core.workers.consumer import Entry, StreamConsumer, build_redis

logger = logging.getLogger("sentinel.detector")

GROUP = "detectors"
STAGE = "events.normalized"  # recorded as the `source` of this worker's dead letters
MAX_ERROR_LENGTH = 500
MAX_RAW_LENGTH = 16_384


class DetectorWorker(StreamConsumer):
    def __init__(
        self,
        redis: Redis,
        sessions: async_sessionmaker[AsyncSession],
        engine: DetectionEngine,
        *,
        consumer: str,
        stream: str = NORMALIZED_STREAM,
        group: str = GROUP,
        batch_size: int = 100,
        claim_idle_ms: int = 60_000,
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
        self._engine = engine

    async def process_batch(self, entries: list[Entry]) -> None:
        alerts: list[Alert] = []
        letters: list[DeadLetterRecord] = []
        for _, fields in entries:
            if fields is None:  # entry deleted while still pending: nothing left to process
                continue
            data = fields.get(DATA_FIELD) or repr(fields)
            try:
                event = Event.model_validate_json(data)
            except ValidationError as exc:
                letters.append(
                    _letter(data, f"undecodable normalized event: {exc.error_count()} error(s)")
                )
                continue
            try:
                alerts.extend(await self._engine.evaluate(event))
            except RedisError:
                raise  # infrastructure problem: leave the batch pending and retry
            except Exception as exc:  # a bug in one rule must not wedge the whole stream
                logger.exception("rule evaluation failed for event %s", event.event_id)
                letters.append(
                    _letter(
                        data,
                        f"detection error: {type(exc).__name__}: {exc}",
                        dedup=event.event_id,
                        raw=event.raw,
                    )
                )

        await self._persist(alerts, letters)
        for alert in alerts:
            logger.info(
                "ALERT %s severity=%d group=%s count=%d id=%s",
                alert.rule_id,
                alert.severity,
                alert.group,
                alert.match_count,
                alert.alert_id[:12],
            )
        logger.info(
            "batch: %d events evaluated -> %d alerts, %d dead letters",
            len(entries),
            len(alerts),
            len(letters),
        )

    async def _persist(self, alerts: list[Alert], letters: list[DeadLetterRecord]) -> None:
        async with self._sessions.begin() as session:
            await insert_alerts(session, alerts)
            await insert_dead_letters(session, letters)


def _letter(
    data: str, error: str, *, dedup: str | None = None, raw: str | None = None
) -> DeadLetterRecord:
    return DeadLetterRecord(
        dedup_key=dedup or sha256(data.encode()).hexdigest(),
        raw=(raw if raw is not None else data)[:MAX_RAW_LENGTH],  # untrusted: bounded
        error=error[:MAX_ERROR_LENGTH],
        source=STAGE,
    )


async def amain() -> int:
    settings = get_settings()
    try:
        rules = load_rules(settings.rules_dir)
    except RuleLoadError as exc:  # fail fast and loudly: never run with a broken rule set
        logger.error("cannot load rules from %s:\n%s", settings.rules_dir, exc)
        return 1
    if not rules:
        logger.error(
            "no rules found in %s: refusing to start a detector that detects nothing",
            settings.rules_dir,
        )
        return 1
    logger.info("loaded %d rule(s): %s", len(rules), ", ".join(rule.id for rule in rules))

    redis = build_redis(settings.redis_url)
    engine = create_engine(settings)
    worker = DetectorWorker(
        redis,
        create_sessionmaker(engine),
        DetectionEngine(rules, RedisWindowStore(redis)),
        consumer=f"{socket.gethostname()}-{os.getpid()}",
        batch_size=settings.detector_batch_size,
        claim_idle_ms=settings.detector_claim_idle_ms,
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
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
