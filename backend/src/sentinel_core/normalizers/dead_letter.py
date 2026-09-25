from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel_core.text import storable

MAX_ERROR_LENGTH = 500
MAX_RAW_LENGTH = 16_384


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


def make_dead_letter(
    *,
    dedup_key: str,
    raw: str,
    error: str,
    agent_id: UUID | None = None,
    source: str | None = None,
    origin: str | None = None,
    received_at: datetime | None = None,
) -> DeadLetterRecord:
    """Build a dead letter that can always be stored.

    The payload is untrusted: it is neutralised (NUL, lone surrogates) so that recording a
    failure can never itself fail, and bounded so that the table is not a sink for it.
    """
    return DeadLetterRecord(
        dedup_key=dedup_key,
        raw=storable(raw)[:MAX_RAW_LENGTH],
        error=storable(error)[:MAX_ERROR_LENGTH],
        agent_id=agent_id,
        source=source,
        origin=origin,
        received_at=received_at,
    )
