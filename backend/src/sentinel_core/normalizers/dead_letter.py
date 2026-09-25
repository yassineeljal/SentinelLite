from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True)
class DeadLetterRecord:
    """A stream entry that could not be turned into an event, with the reason."""

    dedup_key: str
    raw: str
    error: str
    agent_id: UUID | None = None
    source: str | None = None
    origin: str | None = None
    received_at: datetime | None = None
