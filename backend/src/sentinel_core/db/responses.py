"""Persistence for the automated response: blocked addresses, allowlist, audit log."""

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.db.models import AllowlistEntry, AuditLogEntry, BlockedIp
from sentinel_core.response.policy import Network, parse_networks


class AllowlistEntryExists(Exception):
    """This network is already on the allowlist."""


@dataclass(frozen=True)
class BlockSummary:
    id: int
    ip: str
    rule_id: str
    reason: str
    mode: str
    created_at: datetime
    expires_at: datetime
    released_at: datetime | None


@dataclass(frozen=True)
class AllowlistSummary:
    cidr: str
    note: str
    created_by: str
    created_at: datetime


async def load_allowlist(session: AsyncSession) -> tuple[Network, ...]:
    rows = await session.execute(text("SELECT cidr::text FROM allowlist"))
    return parse_networks(str(row[0]) for row in rows)


async def add_allowlist(session: AsyncSession, cidr: str, note: str, actor: str) -> str:
    """Add a network (a bare address means a single host). Raises ValueError on garbage."""
    (network,) = parse_networks([cidr])
    try:
        async with session.begin_nested():
            session.add(AllowlistEntry(cidr=str(network), note=note, created_by=actor))
            await session.flush()
    except IntegrityError:
        raise AllowlistEntryExists(str(network)) from None
    await record_audit(session, actor, "allowlist.add", str(network), {"note": note})
    return str(network)


async def remove_allowlist(session: AsyncSession, cidr: str, actor: str) -> bool:
    (network,) = parse_networks([cidr])
    result = await session.execute(
        text("DELETE FROM allowlist WHERE cidr = CAST(:cidr AS cidr)"), {"cidr": str(network)}
    )
    removed = bool(result.rowcount)  # type: ignore[attr-defined]
    if removed:
        await record_audit(session, actor, "allowlist.remove", str(network), {})
    return removed


async def list_allowlist(session: AsyncSession) -> list[AllowlistSummary]:
    rows = await session.execute(
        text("SELECT cidr::text, note, created_by, created_at FROM allowlist ORDER BY id")
    )
    return [AllowlistSummary(str(r[0]), r[1], r[2], r[3]) for r in rows]


async def is_blocked(session: AsyncSession, ip: str, mode: str, now: datetime) -> bool:
    """True if an active (unexpired, unreleased) block of this mode already covers `ip`."""
    row = await session.execute(
        text(
            "SELECT 1 FROM blocked_ips WHERE ip = CAST(:ip AS inet) AND mode = :mode "
            "AND released_at IS NULL AND expires_at > :now LIMIT 1"
        ),
        {"ip": ip, "mode": mode, "now": now},
    )
    return row.first() is not None


async def count_blocks_since(session: AsyncSession, mode: str, since: datetime) -> int:
    row = await session.execute(
        text("SELECT count(*) FROM blocked_ips WHERE mode = :mode AND created_at >= :since"),
        {"mode": mode, "since": since},
    )
    return int(row.scalar_one())


async def record_block(
    session: AsyncSession,
    *,
    ip: str,
    alert_id: str,
    rule_id: str,
    reason: str,
    mode: str,
    now: datetime,
    ttl: timedelta,
) -> bool:
    """Record a block. False if this alert already produced one (a redelivered stream entry)."""
    statement = (
        pg_insert(BlockedIp)
        .values(
            ip=ip,
            alert_id=alert_id,
            rule_id=rule_id,
            reason=reason,
            mode=mode,
            created_at=now,
            expires_at=now + ttl,
        )
        .on_conflict_do_nothing(index_elements=["alert_id"])
        .returning(BlockedIp.id)
    )
    return (await session.execute(statement)).first() is not None


async def record_audit(
    session: AsyncSession, actor: str, action: str, target: str, details: dict[str, Any]
) -> None:
    session.add(AuditLogEntry(actor=actor, action=action, target=target, details=details))
    await session.flush()


async def list_blocks(session: AsyncSession, limit: int = 20) -> list[BlockSummary]:
    rows = await session.execute(
        text(
            "SELECT id, host(ip), rule_id, reason, mode, created_at, expires_at, released_at "
            "FROM blocked_ips ORDER BY created_at DESC, id DESC LIMIT :limit"
        ),
        {"limit": limit},
    )
    return [BlockSummary(*r) for r in rows]


def canonical(address: str) -> str:
    return str(ipaddress.ip_address(address))
