"""An agent's heartbeat: proof of life even when it has no log line to ship.

Without it, silence would prove nothing: a quiet host ships nothing for hours. Authenticated with
the agent key, like ingestion; it only ever updates the calling agent's own row.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.api.alerts import get_sessionmaker
from sentinel_core.api.ingest import authenticate_agent
from sentinel_core.db.agent_health import record_heartbeat

router = APIRouter(prefix="/v1/agents/me", tags=["agent-health"])


@router.post("/heartbeat", status_code=204)
async def heartbeat(
    agent_id: Annotated[UUID, Depends(authenticate_agent)],
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
) -> None:
    async with sessions.begin() as session:
        await record_heartbeat(session, agent_id, datetime.now(UTC))
