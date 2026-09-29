"""Actions for an agent: it polls for them and reports what it did (no inbound connection).

The agent is identified by its API key, exactly as for ingestion; it can only see and answer its
own actions.
"""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.api.alerts import get_sessionmaker
from sentinel_core.api.ingest import authenticate_agent
from sentinel_core.db import actions as db
from sentinel_core.text import storable

router = APIRouter(prefix="/v1/agents/me", tags=["agent-actions"])

Detail = Annotated[str, StringConstraints(max_length=db.MAX_DETAIL)]


class ActionOut(BaseModel):
    id: int
    kind: Literal["block", "unblock"]
    ip: str
    expires_at: datetime


class ActionList(BaseModel):
    actions: list[ActionOut]


class Ack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["done", "failed"]
    detail: Detail = ""


@router.get("/actions")
async def fetch_actions(
    agent_id: Annotated[UUID, Depends(authenticate_agent)],
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
) -> ActionList:
    async with sessions() as session:
        found = await db.pending_actions(session, agent_id, datetime.now(UTC))
    return ActionList(
        actions=[ActionOut(id=a.id, kind=a.kind, ip=a.ip, expires_at=a.expires_at) for a in found]
    )


@router.post("/actions/{action_id}/ack", status_code=204)
async def acknowledge(
    action_id: int,
    body: Ack,
    agent_id: Annotated[UUID, Depends(authenticate_agent)],
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
) -> None:
    if not 0 < action_id < 2**63:
        raise HTTPException(status_code=404, detail="action not found")
    async with sessions.begin() as session:
        updated = await db.acknowledge_action(
            session,
            agent_id=agent_id,
            action_id=action_id,
            status=body.status,
            detail=storable(body.detail),
            now=datetime.now(UTC),
        )
    if not updated:
        # Unknown, somebody else's, or already answered: the same answer for all three.
        raise HTTPException(status_code=404, detail="action not found")
