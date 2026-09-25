"""Raw log stream (`events.raw`) on Redis Streams."""

from typing import Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from sentinel_core.normalizers.base import RawLog

RAW_STREAM = "events.raw"
DATA_FIELD = "data"  # each entry holds one RawLog serialized as JSON


class BusFull(Exception):
    """The stream is above its high watermark: the producer must retry later."""


class BusUnavailable(Exception):
    """The bus cannot be reached."""


class RawLogPublisher(Protocol):
    async def publish(self, logs: list[RawLog]) -> None:
        """Publish a batch atomically: all lines are written or none.

        Raises BusFull or BusUnavailable.
        """
        ...


class RedisRawLogPublisher:
    """Writes one stream entry per line so consumers can share the work in a consumer group.

    Backpressure is explicit (BusFull -> HTTP 429) rather than trimming the stream, which
    would silently drop events that were never processed. Consumers must delete entries once
    acknowledged, otherwise the watermark eventually blocks ingestion.
    """

    def __init__(
        self, client: Redis, stream: str = RAW_STREAM, high_watermark: int = 100_000
    ) -> None:
        self._client = client
        self._stream = stream
        self._high_watermark = high_watermark

    async def publish(self, logs: list[RawLog]) -> None:
        try:
            # Best-effort check: two concurrent batches may overshoot the watermark slightly,
            # which is acceptable for a soft limit.
            if await self._client.xlen(self._stream) + len(logs) > self._high_watermark:
                raise BusFull
            async with self._client.pipeline(transaction=True) as pipe:  # MULTI/EXEC
                for log in logs:
                    pipe.xadd(self._stream, {DATA_FIELD: log.model_dump_json()})
                await pipe.execute()
        except RedisError as exc:
            raise BusUnavailable from exc
