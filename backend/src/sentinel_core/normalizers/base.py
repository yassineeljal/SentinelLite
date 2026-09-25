from hashlib import sha256
from typing import Protocol
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from sentinel_core.schema.event import Event, Source
from sentinel_core.text import storable

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

    @field_validator("origin", "line", mode="before")
    @classmethod
    def _neutralise(cls, value: object) -> object:
        # Before the length check, so that the limit applies to the form that is stored.
        return storable(value) if isinstance(value, str) else value


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
    """Deterministic id: replaying the same line from the same place yields the same id.

    The content is part of it: after a log rotation an inode can be reused and offsets repeat,
    so one origin can designate different lines, which must stay different events.
    """
    content = sha256(raw.line.encode()).hexdigest()
    return sha256(f"{raw.agent_id}|{raw.source}|{raw.origin}|{content}".encode()).hexdigest()
