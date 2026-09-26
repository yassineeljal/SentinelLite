"""Enricher worker: `alerts.new` (Redis) -> context added to the stored alert (Postgres).

The detector stores an alert BEFORE announcing it, so the alert always exists here and enrichment
can only add to it. Delivery is at-least-once and enrichment is a pure function of the alert's
source address and the databases, so a redelivered entry simply rewrites the same result.
An alert that cannot be enriched is left as it is: it is never retried forever and never lost.
"""

import asyncio
import logging
import os
import socket
import sys

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy.exc import DataError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.bus.alerts_stream import ALERTS_NEW_STREAM
from sentinel_core.bus.raw_stream import DATA_FIELD
from sentinel_core.config import get_settings
from sentinel_core.db.alerts import set_enrichment
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.detection.alerts import Alert
from sentinel_core.enrichment.enricher import Enricher, Enrichment
from sentinel_core.enrichment.geoip import GeoIpError, GeoIpResolver
from sentinel_core.workers.consumer import (
    Entry,
    StreamConsumer,
    build_redis,
    install_stop_signals,
)

logger = logging.getLogger("sentinel.enricher")

GROUP = "enrichers"


class EnricherWorker(StreamConsumer):
    def __init__(
        self,
        redis: Redis,
        sessions: async_sessionmaker[AsyncSession],
        enricher: Enricher,
        *,
        consumer: str,
        stream: str = ALERTS_NEW_STREAM,
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
        self._enricher = enricher

    async def process_batch(self, entries: list[Entry]) -> None:
        results: list[tuple[str, Enrichment]] = []
        unusable = no_address = 0
        for entry_id, fields in entries:
            if fields is None:  # entry deleted while still pending
                continue
            try:
                alert = Alert.model_validate_json(fields.get(DATA_FIELD, ""))
            except ValidationError:
                logger.error("entry %s is not an alert: skipped", entry_id)
                unusable += 1
                continue
            try:
                enrichment = self._enricher.enrich(alert.src_ip)
            except Exception:  # a bad record must not block the alerts behind it
                logger.exception("cannot enrich alert %s: left as it is", alert.alert_id[:12])
                unusable += 1
                continue
            if enrichment is None:
                no_address += 1
            else:
                results.append((alert.alert_id, enrichment))

        missing = 0
        if results:
            async with self._sessions.begin() as session:
                for alert_id, enrichment in results:
                    if not await set_enrichment(session, alert_id, enrichment):
                        missing += 1
        logger.info(
            "batch: %d enriched, %d without source address, %d unusable, %d not in the database",
            len(results) - missing,
            no_address,
            unusable,
            missing,
        )

    async def quarantine(self, entry: Entry, exc: DataError) -> None:
        # Enrichment is rebuildable context: an entry the database rejects is only reported.
        logger.error(
            "dropping entry %s: the database rejected it (%s)", entry[0], type(exc).__name__
        )


async def amain() -> int:
    settings = get_settings()
    if not settings.enrichment_enabled:
        logger.error("enrichment is disabled (SENTINEL_ENRICHMENT_ENABLED=false): nothing to do")
        return 1
    try:
        geoip = GeoIpResolver(settings.geoip_city_db, settings.geoip_asn_db)
    except GeoIpError as exc:  # fail fast: an enricher without data would silently do nothing
        logger.error("cannot start: %s", exc)
        return 1
    logger.info(
        "GeoIP databases: city=%s asn=%s",
        settings.geoip_city_db or "-",
        settings.geoip_asn_db or "-",
    )

    redis = build_redis(settings.redis_url)
    engine = create_engine(settings)
    worker = EnricherWorker(
        redis,
        create_sessionmaker(engine),
        Enricher(geoip),
        consumer=f"{socket.gethostname()}-{os.getpid()}",
        batch_size=settings.enricher_batch_size,
        claim_idle_ms=settings.enricher_claim_idle_ms,
    )
    stop = asyncio.Event()
    install_stop_signals(stop)
    try:
        await worker.run(stop)
    finally:
        geoip.close()
        await redis.aclose()
        await engine.dispose()
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
