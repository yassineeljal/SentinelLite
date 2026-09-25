"""Test doubles shared across test modules."""

from sentinel_core.bus.raw_stream import BusFull, BusUnavailable
from sentinel_core.normalizers.base import RawLog


class InMemoryPublisher:
    """Records published batches; can simulate a full or a broken bus."""

    def __init__(self) -> None:
        self.batches: list[list[RawLog]] = []
        self.error: BusFull | BusUnavailable | None = None

    async def publish(self, logs: list[RawLog]) -> None:
        if self.error is not None:
            raise self.error
        self.batches.append(list(logs))

    @property
    def logs(self) -> list[RawLog]:
        return [log for batch in self.batches for log in batch]
