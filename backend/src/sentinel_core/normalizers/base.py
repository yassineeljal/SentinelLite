from hashlib import sha256
from typing import Protocol
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from sentinel_core.schema.event import Event, Source

MAX_LINE_LENGTH = 8192


class RawLog(BaseModel):
    """One raw log line exactly as shipped by an agent."""

    model_config = ConfigDict(frozen=True)

    agent_id: UUID
    source: Source
    origin: str = Field(
        max_length=128,
        description="Stable position of the line in its source, e.g. '<inode>:<byte offset>'",
    )
    line: str = Field(max_length=MAX_LINE_LENGTH)
    received_at: AwareDatetime


class ParseError(ValueError):
    """The line does not have the shape this source must have (goes to dead letter)."""


class Normalizer(Protocol):
    """Turns raw lines of one source into events.

    Returns None for well-formed lines that carry no security event we model
    (e.g. cron noise). Raises ParseError for lines that are malformed.
    """

    source: Source

    def normalize(self, raw: RawLog) -> Event | None: ...


def make_event_id(raw: RawLog) -> str:
    """Deterministic id: replaying the same line from the same place yields the same id."""
    return sha256(f"{raw.agent_id}|{raw.source}|{raw.origin}".encode()).hexdigest()
