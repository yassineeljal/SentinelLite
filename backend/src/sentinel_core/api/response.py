"""Dashboard view of the automated response: what is blocked, and the allowlist.

Every signed-in account can look. Changing anything (lifting a block, editing the allowlist) needs
the `admin` role, and each change is written to the append-only audit log under the account that
made it, exactly like the CLI (`sentinel unblock`, `sentinel allowlist`).
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.api.alerts import get_sessionmaker
from sentinel_core.api.auth import authenticate_user
from sentinel_core.auth.user_registry import UserInfo
from sentinel_core.db.actions import release_blocks_for_ip
from sentinel_core.db.responses import (
    AllowlistEntryExists,
    add_allowlist,
    canonical,
    list_allowlist,
    list_blocks,
    record_audit,
    remove_allowlist,
)

router = APIRouter(
    prefix="/v1/response", tags=["response"], dependencies=[Depends(authenticate_user)]
)

Sessions = Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)]
Note = Annotated[
    str, StringConstraints(strip_whitespace=True, max_length=500, pattern=r"^[^\x00]*$")
]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


async def require_admin(user: Annotated[UserInfo, Depends(authenticate_user)]) -> UserInfo:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="This action needs the admin role")
    return user


Admin = Annotated[UserInfo, Depends(require_admin)]


def actor(user: UserInfo) -> str:
    return f"user:{user.email}"[:128]


class BlockOut(BaseModel):
    id: int
    ip: str
    rule_id: str
    reason: str
    mode: str
    created_at: datetime
    expires_at: datetime
    released_at: datetime | None
    released_by: str | None
    state: str  # active | expired | released


class AllowlistOut(BaseModel):
    cidr: str
    note: str
    created_by: str
    created_at: datetime


class UnblockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: Text


class AllowlistAdd(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: Text
    note: Note = ""


def _state(released_at: datetime | None, expires_at: datetime, now: datetime) -> str:
    if released_at is not None:
        return "released"
    return "expired" if expires_at <= now else "active"


@router.get("/blocks")
async def blocks(
    sessions: Sessions, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[BlockOut]:
    now = datetime.now(UTC)
    async with sessions() as session:
        found = await list_blocks(session, limit=limit)
    return [
        BlockOut(
            id=b.id,
            ip=b.ip,
            rule_id=b.rule_id,
            reason=b.reason,
            mode=b.mode,
            created_at=b.created_at,
            expires_at=b.expires_at,
            released_at=b.released_at,
            released_by=b.released_by,
            state=_state(b.released_at, b.expires_at, now),
        )
        for b in found
    ]


@router.post("/blocks/unblock", status_code=204)
async def unblock(body: UnblockRequest, user: Admin, sessions: Sessions) -> None:
    try:
        ip = canonical(body.address)
    except ValueError:
        raise HTTPException(status_code=422, detail="Not an IP address") from None
    async with sessions.begin() as session:
        released = await release_blocks_for_ip(session, ip, actor(user), datetime.now(UTC))
        if not released:
            raise HTTPException(status_code=404, detail="No active block for this address")
        await record_audit(session, actor(user), "unblock.manual", ip, {"block_ids": released})


@router.get("/allowlist")
async def allowlist(sessions: Sessions) -> list[AllowlistOut]:
    async with sessions() as session:
        entries = await list_allowlist(session)
    return [
        AllowlistOut(cidr=e.cidr, note=e.note, created_by=e.created_by, created_at=e.created_at)
        for e in entries
    ]


@router.post("/allowlist", status_code=201)
async def allowlist_add(body: AllowlistAdd, user: Admin, sessions: Sessions) -> AllowlistOut:
    try:
        async with sessions.begin() as session:
            cidr = await add_allowlist(session, body.cidr, body.note, actor(user))
            entries = [e for e in await list_allowlist(session) if e.cidr == cidr]
    except AllowlistEntryExists:
        raise HTTPException(status_code=409, detail="Already on the allowlist") from None
    except ValueError:
        raise HTTPException(status_code=422, detail="Not a valid address or network") from None
    (entry,) = entries
    return AllowlistOut(
        cidr=entry.cidr, note=entry.note, created_by=entry.created_by, created_at=entry.created_at
    )


@router.delete("/allowlist", status_code=204)
async def allowlist_remove(user: Admin, sessions: Sessions, cidr: Text) -> None:
    try:
        async with sessions.begin() as session:
            removed = await remove_allowlist(session, cidr, actor(user))
    except ValueError:
        raise HTTPException(status_code=422, detail="Not a valid address or network") from None
    if not removed:
        raise HTTPException(status_code=404, detail="Not on the allowlist")
