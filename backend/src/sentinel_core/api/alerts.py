"""Dashboard alerts API: the first read endpoint behind user authentication.

Kept deliberately small (list only, no evidence) for now: it exists to prove the auth wiring end
to end and give the frontend something to render. `sentinel alerts show` remains the way to see
evidence until a dedicated endpoint is built alongside the rest of the dashboard.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.api.auth import authenticate_user
from sentinel_core.db.alerts import AlertSummary, list_alerts

router = APIRouter(prefix="/v1/alerts", tags=["alerts"], dependencies=[Depends(authenticate_user)])


class AlertResponse(BaseModel):
    alert_id: str
    rule_id: str
    title: str
    severity: int
    ts: datetime
    created_at: datetime
    src_ip: str | None
    host: str | None
    user_name: str | None
    match_count: int
    country_code: str | None
    abuse_score: int | None
    risk_score: int | None


def _response(summary: AlertSummary) -> AlertResponse:
    return AlertResponse(
        alert_id=summary.alert_id,
        rule_id=summary.rule_id,
        title=summary.title,
        severity=summary.severity,
        ts=summary.ts,
        created_at=summary.created_at,
        src_ip=summary.src_ip,
        host=summary.host,
        user_name=summary.user_name,
        match_count=summary.match_count,
        country_code=summary.country_code,
        abuse_score=summary.abuse_score,
        risk_score=summary.risk_score,
    )


def get_sessionmaker(request: Request) -> async_sessionmaker[AsyncSession]:
    sessions: async_sessionmaker[AsyncSession] = request.app.state.db_sessions
    return sessions


@router.get("")
async def list_alerts_route(
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    rule: str | None = None,
) -> list[AlertResponse]:
    async with sessions() as session:
        summaries = await list_alerts(session, limit=limit, rule_id=rule)
    return [_response(s) for s in summaries]
