"""Shared incident triage for authenticated analysts and admins.

Assignees and note authors come from the session, never from client-supplied user ids.
"""

from collections.abc import AsyncGenerator
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.api.alerts import get_sessionmaker
from sentinel_core.api.auth import authenticate_user
from sentinel_core.auth.user_registry import UserInfo
from sentinel_core.db import incidents as db

router = APIRouter(
    prefix="/v1/incidents", tags=["incidents"], dependencies=[Depends(authenticate_user)]
)
Status = Literal["new", "investigating", "closed"]
AlertId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Title = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=200, pattern=r"^[^\x00]*$"),
]
Note = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=4000, pattern=r"^[^\x00]*$"),
]


class CreateIncident(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Title
    alert_ids: list[AlertId] = Field(default_factory=list, max_length=200)


class ChangeStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Status


class AddNote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: Note


class LinkAlerts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_ids: list[AlertId] = Field(min_length=1, max_length=200)


async def incident_session(
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
) -> AsyncGenerator[AsyncSession]:
    async with sessions() as session:
        try:
            yield session
        except db.IncidentNotFound:
            raise HTTPException(status_code=404, detail="incident not found") from None
        except db.AlertLinkError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None


Session = Annotated[AsyncSession, Depends(incident_session)]
User = Annotated[UserInfo, Depends(authenticate_user)]


@router.get("")
async def list_incidents(
    session: Session,
    status: Status | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[db.IncidentSummary]:
    return await db.list_incidents(session, status=status, limit=limit)


@router.post("", status_code=201)
async def create_incident(body: CreateIncident, session: Session) -> db.IncidentSummary:
    return await db.create_incident(session, body.title, alert_ids=body.alert_ids)


@router.get("/{incident_id}")
async def get_incident(incident_id: UUID, session: Session) -> db.IncidentDetail:
    detail = await db.get_incident(session, incident_id)
    if detail is None:
        raise db.IncidentNotFound(incident_id)
    return detail


@router.patch("/{incident_id}", status_code=204)
async def change_status(incident_id: UUID, body: ChangeStatus, session: Session) -> None:
    await db.set_status(session, incident_id, body.status)


@router.post("/{incident_id}/claim", status_code=204)
async def claim(incident_id: UUID, session: Session, user: User) -> None:
    await db.claim_incident(session, incident_id, user.id)


@router.delete("/{incident_id}/assignee", status_code=204)
async def unassign(incident_id: UUID, session: Session) -> None:
    await db.unassign_incident(session, incident_id)


@router.post("/{incident_id}/notes", status_code=204)
async def add_note(incident_id: UUID, body: AddNote, session: Session, user: User) -> None:
    await db.add_note(session, incident_id, user.id, body.body)


@router.post("/{incident_id}/alerts", status_code=204)
async def link_alerts(incident_id: UUID, body: LinkAlerts, session: Session) -> None:
    await db.link_alerts(session, incident_id, body.alert_ids)


@router.delete("/{incident_id}/alerts/{alert_id}", status_code=204)
async def unlink_alert(incident_id: UUID, alert_id: AlertId, session: Session) -> None:
    await db.unlink_alert(session, incident_id, alert_id)
