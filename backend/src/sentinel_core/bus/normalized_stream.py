"""Normalized event stream (`events.normalized`): normalizer -> detector."""

from redis.asyncio import Redis

from sentinel_core.bus.raw_stream import DATA_FIELD
from sentinel_core.schema.event import Event

NORMALIZED_STREAM = "events.normalized"


class RedisNormalizedPublisher:
    """One entry per event, JSON in a single field.

    Backpressure is done by the producer: the normalizer stops reading `events.raw` while this
    stream is above its high watermark (`is_full`), so the backlog builds up upstream, where the
    API turns it into an explicit 429 instead of the stream growing without bound in memory.
    """

    def __init__(
        self, client: Redis, stream: str = NORMALIZED_STREAM, high_watermark: int = 100_000
    ) -> None:
        self._client = client
        self._stream = stream
        self._high_watermark = high_watermark

    async def is_full(self) -> bool:
        return int(await self._client.xlen(self._stream)) >= self._high_watermark

    async def publish(self, events: list[Event]) -> None:
        if not events:
            return
        async with self._client.pipeline(transaction=True) as pipe:
            for event in events:
                pipe.xadd(self._stream, {DATA_FIELD: event.model_dump_json()})
            await pipe.execute()
