"""New-alert stream (`alerts.new`): detector -> enricher (and, later, the responder)."""

from redis.asyncio import Redis

from sentinel_core.bus.raw_stream import DATA_FIELD
from sentinel_core.detection.alerts import Alert

ALERTS_NEW_STREAM = "alerts.new"
# A second copy for the responder: a stream has ONE consumer group here (consumers delete what they
# acknowledge), so each consumer of alerts gets its own stream, fed by the detector.
ALERTS_RESPOND_STREAM = "alerts.respond"
# Alerts are already stored in PostgreSQL when they are published here, so the stream only carries
# work that can be redone (enrichment). It is capped instead of exerting backpressure: if the
# enricher is down for long, the oldest notifications are dropped and those alerts stay without
# context, but detection and storage are never slowed down and memory stays bounded.
DEFAULT_MAXLEN = 100_000


class RedisAlertPublisher:
    def __init__(
        self, client: Redis, stream: str = ALERTS_NEW_STREAM, maxlen: int = DEFAULT_MAXLEN
    ) -> None:
        self._client = client
        self._stream = stream
        self._maxlen = maxlen

    async def publish(self, alerts: list[Alert]) -> None:
        if not alerts:
            return
        async with self._client.pipeline(transaction=True) as pipe:
            for alert in alerts:
                pipe.xadd(
                    self._stream,
                    {DATA_FIELD: alert.model_dump_json()},
                    maxlen=self._maxlen,
                    approximate=True,
                )
            await pipe.execute()
