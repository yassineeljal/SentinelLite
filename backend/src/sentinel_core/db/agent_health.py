"""Agent liveness: heartbeats in, silence and recovery out (used by the watchdog worker)."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class SilentAgent:
    id: UUID
    name: str
    last_seen_at: datetime


@dataclass(frozen=True)
class RecoveredAgent:
    id: UUID
    name: str


async def record_heartbeat(session: AsyncSession, agent_id: UUID, now: datetime) -> None:
    await session.execute(
        text("UPDATE agents SET last_seen_at = :now WHERE id = :id AND revoked_at IS NULL"),
        {"now": now, "id": agent_id},
    )


async def mark_silent(
    session: AsyncSession, now: datetime, silence: timedelta
) -> list[SilentAgent]:
    """Agents that reported before but have not for `silence`, and were not already known as
    silent. Returned once each (the update is the announcement's ticket), so two watchdogs or a
    restart never announce the same silence twice. An agent that never reported is not silent: it
    has simply not been deployed yet."""
    rows = await session.execute(
        text(
            "UPDATE agents SET silent_since = :now WHERE revoked_at IS NULL "
            "AND last_seen_at IS NOT NULL AND silent_since IS NULL "
            "AND last_seen_at < :limit RETURNING id, name, last_seen_at"
        ),
        {"now": now, "limit": now - silence},
    )
    return [SilentAgent(r[0], r[1], r[2]) for r in rows]


async def mark_recovered(session: AsyncSession) -> list[RecoveredAgent]:
    """Silent agents that have reported since (or were revoked meanwhile: nothing to announce)."""
    rows = await session.execute(
        text(
            "UPDATE agents SET silent_since = NULL WHERE silent_since IS NOT NULL "
            "AND (last_seen_at > silent_since OR revoked_at IS NOT NULL) "
            "RETURNING id, name, revoked_at"
        )
    )
    return [RecoveredAgent(r[0], r[1]) for r in rows if r[2] is None]
