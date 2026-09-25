import hmac
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from sentinel_core.auth.agent_keys import AgentRepository, hash_secret, parse_bearer_token
from sentinel_core.bus.raw_stream import BusFull, BusUnavailable, RawLogPublisher
from sentinel_core.normalizers.base import MAX_LINE_LENGTH, RawLog
from sentinel_core.schema.event import Source

MAX_BATCH_LINES = 500
RETRY_AFTER_SECONDS = 5

router = APIRouter(prefix="/v1", tags=["ingestion"])

# Compared against when the agent is unknown, so both failure paths do the same work.
_DUMMY_HASH = hash_secret("dummy")


class IngestLine(BaseModel):
    model_config = ConfigDict(extra="forbid")

    origin: str = Field(min_length=1, max_length=128)
    line: str = Field(max_length=MAX_LINE_LENGTH)


class IngestRequest(BaseModel):
    # extra="forbid": the agent identity comes from the API key, never from the body.
    model_config = ConfigDict(extra="forbid")

    source: Source
    lines: list[IngestLine] = Field(min_length=1, max_length=MAX_BATCH_LINES)


class IngestResponse(BaseModel):
    accepted: int


async def authenticate_agent(request: Request) -> UUID:
    credentials = parse_bearer_token(request.headers.get("authorization"))
    repository: AgentRepository = request.app.state.agents

    stored = await repository.get_key_hash(credentials.agent_id) if credentials else None
    candidate = hash_secret(credentials.secret) if credentials else _DUMMY_HASH
    matches = hmac.compare_digest(candidate, stored or _DUMMY_HASH)

    if credentials is None or stored is None or not matches:
        # One generic answer for every failure: no hint whether the agent id exists.
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing agent credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.agent_id


def get_publisher(request: Request) -> RawLogPublisher:
    publisher: RawLogPublisher = request.app.state.publisher
    return publisher


@router.post("/ingest", status_code=202)
async def ingest(
    body: IngestRequest,
    agent_id: Annotated[UUID, Depends(authenticate_agent)],
    publisher: Annotated[RawLogPublisher, Depends(get_publisher)],
) -> IngestResponse:
    received_at = datetime.now(UTC)  # server clock, never trusted from the agent
    logs = [
        RawLog(
            agent_id=agent_id,
            source=body.source,
            origin=item.origin,
            line=item.line,
            received_at=received_at,
        )
        for item in body.lines
    ]
    try:
        await publisher.publish(logs)
    except BusFull as exc:
        raise HTTPException(
            status_code=429,
            detail="Ingestion queue is full, retry later",
            headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
        ) from exc
    except BusUnavailable as exc:
        raise HTTPException(status_code=503, detail="Ingestion queue unavailable") from exc
    return IngestResponse(accepted=len(logs))
