"""Persistence of the actions queued for agents (block / unblock an address on their firewall)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

MAX_PENDING_PER_FETCH = 100
MAX_DETAIL = 500


@dataclass(frozen=True)
class PendingAction:
    id: int
    kind: str
    ip: str
    expires_at: datetime


async def block_id_for_alert(session: AsyncSession, alert_id: str) -> int | None:
    row = await session.execute(
        text("SELECT id FROM blocked_ips WHERE alert_id = :alert_id"), {"alert_id": alert_id}
    )
    found = row.scalar_one_or_none()
    return int(found) if found is not None else None


async def agents_for_events(session: AsyncSession, event_ids: Sequence[str]) -> list[UUID]:
    """Active Linux agents that reported these events: the machines the attacker was talking to,
    and so the ones whose firewall should refuse them."""
    if not event_ids:
        return []
    rows = await session.execute(
        text(
            "SELECT DISTINCT e.agent_id FROM events e JOIN agents a ON a.id = e.agent_id "
            "WHERE e.event_id = ANY(CAST(:ids AS text[])) AND a.revoked_at IS NULL "
            "AND a.os = 'linux' ORDER BY e.agent_id"
        ),
        {"ids": list(event_ids)},
    )
    return [row[0] for row in rows]


async def enqueue_action(
    session: AsyncSession,
    *,
    kind: str,
    block_id: int,
    agent_id: UUID,
    ip: str,
    expires_at: datetime,
) -> bool:
    """Queue one action. False if this block already has this action for this agent."""
    result = await session.execute(
        text(
            "INSERT INTO agent_actions (agent_id, block_id, kind, ip, expires_at) "
            "VALUES (:agent_id, :block_id, :kind, CAST(:ip AS inet), :expires_at) "
            "ON CONFLICT (block_id, agent_id, kind) DO NOTHING"
        ),
        {
            "agent_id": agent_id,
            "block_id": block_id,
            "kind": kind,
            "ip": ip,
            "expires_at": expires_at,
        },
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


async def pending_actions(
    session: AsyncSession, agent_id: UUID, now: datetime
) -> list[PendingAction]:
    """What an agent still has to do. A block that has already expired is not handed out: there
    is nothing left to block."""
    rows = await session.execute(
        text(
            "SELECT id, kind, host(ip), expires_at FROM agent_actions "
            "WHERE agent_id = :agent_id AND status = 'pending' "
            "AND (kind = 'unblock' OR expires_at > :now) ORDER BY id LIMIT :limit"
        ),
        {"agent_id": agent_id, "now": now, "limit": MAX_PENDING_PER_FETCH},
    )
    return [PendingAction(*row) for row in rows]


async def acknowledge_action(
    session: AsyncSession,
    *,
    agent_id: UUID,
    action_id: int,
    status: str,
    detail: str,
    now: datetime,
) -> bool:
    """Record the agent's outcome. Only the agent the action belongs to can, and only once."""
    result = await session.execute(
        text(
            "UPDATE agent_actions SET status = :status, detail = :detail, acked_at = :now "
            "WHERE id = :id AND agent_id = :agent_id AND status = 'pending'"
        ),
        {
            "status": status,
            "detail": detail[:MAX_DETAIL],
            "now": now,
            "id": action_id,
            "agent_id": agent_id,
        },
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class ExpiredBlock:
    id: int
    ip: str


async def release_expired_blocks(
    session: AsyncSession, now: datetime, actor: str, limit: int = 100
) -> list[ExpiredBlock]:
    """Mark the enforced blocks whose time is up as released and queue an `unblock` for every
    agent that was told to apply them. Returns what was released.

    The agent lifts a block by itself at `expires_at`; the explicit unblock is the platform's
    side of the same promise, and makes the release visible in the audit trail.
    """
    rows = await session.execute(
        text(
            "UPDATE blocked_ips SET released_at = :now, released_by = :actor WHERE id IN ("
            "  SELECT id FROM blocked_ips WHERE mode = 'enforce' AND released_at IS NULL "
            "  AND expires_at <= :now ORDER BY id LIMIT :limit FOR UPDATE SKIP LOCKED"
            ") RETURNING id, host(ip)"
        ),
        {"now": now, "actor": actor, "limit": limit},
    )
    released = [ExpiredBlock(int(r[0]), str(r[1])) for r in rows]
    for block in released:
        await session.execute(
            text(
                "INSERT INTO agent_actions (agent_id, block_id, kind, ip, expires_at) "
                "SELECT agent_id, block_id, 'unblock', ip, :now FROM agent_actions "
                "WHERE block_id = :block_id AND kind = 'block' AND status IN ('pending', 'done') "
                "ON CONFLICT (block_id, agent_id, kind) DO NOTHING"
            ),
            {"now": now, "block_id": block.id},
        )
    return released
