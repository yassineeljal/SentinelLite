"""Postgres-backed agent registry: verification (used by the API) and administration (CLI)."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.auth.agent_keys import generate_agent_key
from sentinel_core.db.models import Agent

VALID_OS = ("linux", "windows")
MAX_NAME_LENGTH = 128


class AgentNameTaken(Exception):
    """An agent with this name already exists."""


@dataclass(frozen=True)
class AgentInfo:
    """Public view of an agent. Deliberately carries no key material."""

    id: UUID
    name: str
    os: str
    created_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True)
class CreatedAgent:
    agent: AgentInfo
    token: str  # the plaintext key: returned once, never stored


def _info(row: Agent) -> AgentInfo:
    return AgentInfo(
        id=row.id,
        name=row.name,
        os=row.os,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
    )


class PostgresAgentRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def get_key_hash(self, agent_id: UUID) -> str | None:
        """Hash of an active agent's key; None if unknown or revoked."""
        async with self._sessions() as session:
            return await session.scalar(
                select(Agent.key_hash).where(Agent.id == agent_id, Agent.revoked_at.is_(None))
            )

    async def create_agent(self, name: str, os: str) -> CreatedAgent:
        name = name.strip()
        if not 0 < len(name) <= MAX_NAME_LENGTH:
            raise ValueError(f"name must be 1-{MAX_NAME_LENGTH} characters")
        if os not in VALID_OS:
            raise ValueError(f"os must be one of {VALID_OS}")

        agent_id = uuid4()
        key = generate_agent_key(agent_id)
        row = Agent(id=agent_id, name=name, os=os, key_hash=key.secret_hash)
        async with self._sessions() as session:
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as exc:
                raise AgentNameTaken(name) from exc
            await session.refresh(row)  # loads the server-side created_at
            return CreatedAgent(agent=_info(row), token=key.token)

    async def revoke_agent(self, agent_id: UUID) -> bool:
        """Revoke an active agent. False if it does not exist or is already revoked."""
        async with self._sessions() as session:
            revoked = await session.scalar(
                update(Agent)
                .where(Agent.id == agent_id, Agent.revoked_at.is_(None))
                .values(revoked_at=func.now())
                .returning(Agent.id)
            )
            await session.commit()
            return revoked is not None

    async def list_agents(self) -> list[AgentInfo]:
        async with self._sessions() as session:
            rows = await session.scalars(select(Agent).order_by(Agent.name))
            return [_info(row) for row in rows]
