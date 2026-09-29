"""Aggregate views over alerts, behind user authentication. A separate router (and URL prefix,
`/v1/stats`, distinct from `/v1/alerts/{id}`) on purpose: an aggregate is not "one more alert
route", and keeping it apart avoids any ambiguity with the alert-detail catch-all path.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.api.auth import authenticate_user
from sentinel_core.db.alerts import geo_summary, mitre_summary

router = APIRouter(prefix="/v1/stats", tags=["stats"], dependencies=[Depends(authenticate_user)])


class MitreSummaryResponse(BaseModel):
    technique: str
    count: int
    latest_ts: datetime


class GeoSummaryResponse(BaseModel):
    country_code: str | None
    country: str | None
    city: str | None
    latitude: float
    longitude: float
    count: int
    max_risk_score: int | None
    latest_ts: datetime


def get_sessionmaker(request: Request) -> async_sessionmaker[AsyncSession]:
    sessions: async_sessionmaker[AsyncSession] = request.app.state.db_sessions
    return sessions


@router.get("/mitre")
async def mitre_summary_route(
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> list[MitreSummaryResponse]:
    async with sessions() as session:
        rows = await mitre_summary(session, days=days)
    return [
        MitreSummaryResponse(technique=r.technique, count=r.count, latest_ts=r.latest_ts)
        for r in rows
    ]


@router.get("/geo")
async def geo_summary_route(
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> list[GeoSummaryResponse]:
    async with sessions() as session:
        rows = await geo_summary(session, days=days)
    return [
        GeoSummaryResponse(
            country_code=r.country_code,
            country=r.country,
            city=r.city,
            latitude=r.latitude,
            longitude=r.longitude,
            count=r.count,
            max_risk_score=r.max_risk_score,
            latest_ts=r.latest_ts,
        )
        for r in rows
    ]
