"""Agent API keys.

A key is `<agent_uuid>.<secret>` sent as `Authorization: Bearer <key>`. The secret is 256 bits
of randomness, so a fast hash (SHA-256) is sufficient: there is nothing to brute-force, unlike
a human password. Only the hash is stored; the plaintext key is shown once at creation.
"""

import re
import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol
from uuid import UUID

_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


@dataclass(frozen=True)
class AgentCredentials:
    agent_id: UUID
    secret: str


@dataclass(frozen=True)
class GeneratedKey:
    token: str  # what the agent is given (shown once)
    secret_hash: str  # what the server stores


class AgentRepository(Protocol):
    async def get_key_hash(self, agent_id: UUID) -> str | None:
        """Hash of the agent's key, or None if unknown or revoked."""
        ...


def hash_secret(secret: str) -> str:
    return sha256(secret.encode()).hexdigest()


def generate_agent_key(agent_id: UUID) -> GeneratedKey:
    secret = secrets.token_urlsafe(32)  # 256 bits, url-safe alphabet never contains "."
    return GeneratedKey(token=f"{agent_id}.{secret}", secret_hash=hash_secret(secret))


def parse_bearer_token(header: str | None) -> AgentCredentials | None:
    """Parse an Authorization header. Returns None for anything malformed."""
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    raw_id, _, secret = token.strip().partition(".")
    if not _SECRET_PATTERN.match(secret):
        return None
    try:
        return AgentCredentials(agent_id=UUID(raw_id), secret=secret)
    except ValueError:
        return None


class DenyAllAgentRepository:
    """Fail-closed default: no agent is known until a real registry is configured."""

    async def get_key_hash(self, agent_id: UUID) -> str | None:
        return None


class InMemoryAgentRepository:
    """For tests and local experiments only."""

    def __init__(self) -> None:
        self._hashes: dict[UUID, str] = {}

    def add(self, agent_id: UUID, secret_hash: str) -> None:
        self._hashes[agent_id] = secret_hash

    def revoke(self, agent_id: UUID) -> None:
        self._hashes.pop(agent_id, None)

    async def get_key_hash(self, agent_id: UUID) -> str | None:
        return self._hashes.get(agent_id)
