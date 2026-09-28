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
import socket
import sys
from dataclasses import replace
from hashlib import sha256

from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import DataError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.bus.alerts_stream import RedisAlertPublisher
from sentinel_core.bus.normalized_stream import NORMALIZED_STREAM
from sentinel_core.bus.raw_stream import DATA_FIELD
from sentinel_core.config import get_settings
from sentinel_core.db.alerts import insert_alerts
from sentinel_core.db.events import insert_dead_letters
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.detection.alerts import Alert
from sentinel_core.detection.engine import DetectionEngine, MissingGeoIp, RuleErrorHandler
from sentinel_core.detection.rules import Rule, RuleLoadError, load_rules
from sentinel_core.detection.store import RedisWindowStore
from sentinel_core.enrichment.geoip import GeoIpError, GeoIpResolver
from sentinel_core.normalizers.dead_letter import DeadLetterRecord, make_dead_letter
from sentinel_core.schema.event import Event
from sentinel_core.workers.consumer import (
    Entry,
    StreamConsumer,
    build_redis,
    install_stop_signals,
)

logger = logging.getLogger("sentinel.detector")

GROUP = "detectors"
STAGE = "events.normalized"  # recorded as the `source` of this worker's dead letters


class DetectorWorker(StreamConsumer):
    def __init__(
        self,
        redis: Redis,
        sessions: async_sessionmaker[AsyncSession],
        engine: DetectionEngine,
        *,
        alert_publisher: RedisAlertPublisher | None = None,
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
        self._alert_publisher = alert_publisher

    async def process_batch(self, entries: list[Entry]) -> None:
        letters: list[DeadLetterRecord] = []
        raised = 0
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
                alerts = await self._engine.evaluate(
                    event, on_rule_error=_rule_failed(data, letters)
                )
            except RedisError:
                raise  # infrastructure problem: leave the batch pending and retry
            except Exception as exc:  # defensive: the engine already isolates rule failures
                logger.exception("evaluation failed for event %s", event.event_id)
                letters.append(
                    _letter(
                        data,
                        f"detection error: {type(exc).__name__}: {exc}",
                        dedup=event.event_id,
                        raw=event.raw,
                    )
                )
                continue

            if alerts:
                # Persist NOW, before evaluating the next event. The detection state has already
                # moved on for this event; if the batch were persisted only at its end, a crash
                # would redeliver it, later events would have advanced the windows past this one,
                # and its alert could not be raised again. Persisting per event leaves at most
                # the event in flight unpersisted, and that one may re-raise its alert.
                await self._persist(alerts, [])
                if self._alert_publisher is not None:
                    # After the commit, so the enricher always finds the alert. A failure here
                    # leaves the batch pending: the redelivered trigger re-raises the same alert
                    # (a no-op in the table) and announces it again.
                    await self._alert_publisher.publish(alerts)
                raised += len(alerts)
                for alert in alerts:
                    logger.info(
                        "ALERT %s severity=%d group=%s count=%d id=%s",
                        alert.rule_id,
                        alert.severity,
                        alert.group,
                        alert.match_count,
                        alert.alert_id[:12],
                    )

        if letters:
            await self._persist([], letters)
        logger.info(
            "batch: %d events evaluated -> %d alerts, %d dead letters",
            len(entries),
            raised,
            len(letters),
        )

    async def quarantine(self, entry: Entry, exc: DataError) -> None:
        _, fields = entry
        data = (fields or {}).get(DATA_FIELD) or repr(fields)
        letter = _letter(data, f"unstorable entry: {type(exc).__name__}")
        # ASCII-only payload: recording the failure must not fail for the same reason.
        letter = replace(letter, raw=letter.raw.encode("unicode_escape").decode("ascii"))
        await self._persist([], [letter])

    async def _persist(self, alerts: list[Alert], letters: list[DeadLetterRecord]) -> None:
        async with self._sessions.begin() as session:
            await insert_alerts(session, alerts)
            await insert_dead_letters(session, letters)


def _rule_failed(data: str, letters: list[DeadLetterRecord]) -> RuleErrorHandler:
    """Handler that records a failing rule as a dead letter, bound to this entry."""

    def handler(rule: Rule, event: Event, exc: Exception) -> None:
        logger.error("rule %s failed on event %s: %r", rule.id, event.event_id, exc)
        letters.append(
            _letter(
                data,
                f"detection error in rule {rule.id}: {type(exc).__name__}: {exc}",
                dedup=_digest(event.event_id, rule.id),
                raw=event.raw,
            )
        )

    return handler


def _digest(*parts: str) -> str:
    return sha256("|".join(parts).encode()).hexdigest()


def _letter(
    data: str, error: str, *, dedup: str | None = None, raw: str | None = None
) -> DeadLetterRecord:
    return make_dead_letter(
        dedup_key=dedup or sha256(data.encode(errors="replace")).hexdigest(),
        raw=raw if raw is not None else data,
        error=error,
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

    # Only a `type: stateful` rule needs GeoIP, and only if it is enabled: most deployments load
    # none, so this stays optional and the geoip files are the same ones enrichment uses.
    geoip: GeoIpResolver | None = None
    if any(rule.enabled and rule.type == "stateful" for rule in rules):
        try:
            geoip = GeoIpResolver(settings.geoip_city_db, settings.geoip_asn_db)
        except GeoIpError as exc:
            logger.error("cannot start: a stateful rule is enabled but %s", exc)
            return 1

    redis = build_redis(settings.redis_url)
    engine = create_engine(settings)
    try:
        detection_engine = DetectionEngine(rules, RedisWindowStore(redis), geoip=geoip)
    except (
        MissingGeoIp
    ) as exc:  # cannot happen given the check above; kept as a second line of defence
        logger.error("cannot start: %s", exc)
        return 1
    worker = DetectorWorker(
        redis,
        create_sessionmaker(engine),
        detection_engine,
        alert_publisher=(
            RedisAlertPublisher(redis, maxlen=settings.alerts_stream_maxlen)
            if settings.enrichment_enabled
            else None
        ),
        consumer=f"{socket.gethostname()}-{os.getpid()}",
        batch_size=settings.detector_batch_size,
        claim_idle_ms=settings.detector_claim_idle_ms,
    )
    stop = asyncio.Event()
    install_stop_signals(stop)
    try:
        await worker.run(stop)
    finally:
        if geoip is not None:
            geoip.close()
        await redis.aclose()
        await engine.dispose()
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
