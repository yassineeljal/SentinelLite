"""Dashboard alerts API, behind user authentication: the list view and one alert's full detail
(evidence, detection latency, enrichment, risk factors) — the same information `sentinel alerts
show` prints, so the CLI and the dashboard are two views of the same data, not two implementations.
"""

import re
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.api.auth import authenticate_user
from sentinel_core.db.alerts import (
    AlertDetail,
    AlertSummary,
    AmbiguousAlertId,
    get_alert,
    list_alerts,
)

router = APIRouter(prefix="/v1/alerts", tags=["alerts"], dependencies=[Depends(authenticate_user)])

# An id prefix is used in a LIKE pattern server-side (db/alerts.py): only hexadecimal is accepted
# (no wildcards), same rule as the CLI (cli.py's _HEX).
_HEX = re.compile(r"^[0-9a-f]{6,64}$")


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


class EvidenceEventResponse(BaseModel):
    ts: datetime
    received_at: datetime
    action: str
    user_name: str | None
    src_ip: str | None
    raw: str


class AlertDetailResponse(BaseModel):
    alert: AlertResponse
    mitre: list[str]
    group: dict[str, Any]
    evidence: list[EvidenceEventResponse]  # oldest first
    detection_latency_ms: float | None
    enrichment: dict[str, Any] | None
    risk: dict[str, Any] | None


def _detail_response(detail: AlertDetail) -> AlertDetailResponse:
    latency = detail.detection_latency
    return AlertDetailResponse(
        alert=_response(detail.summary),
        mitre=detail.mitre,
        group=detail.group,
        evidence=[
            EvidenceEventResponse(
                ts=e.ts,
                received_at=e.received_at,
                action=e.action,
                user_name=e.user_name,
                src_ip=e.src_ip,
                raw=e.raw,
            )
            for e in detail.evidence
        ],
        detection_latency_ms=latency.total_seconds() * 1000 if latency is not None else None,
        enrichment=detail.enrichment,
        risk=detail.risk,
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


@router.get("/{alert_id_prefix}")
async def show_alert_route(
    alert_id_prefix: str,
    sessions: Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)],
) -> AlertDetailResponse:
    if not _HEX.fullmatch(alert_id_prefix):
        raise HTTPException(status_code=400, detail="the alert id must be hexadecimal (>= 6 chars)")
    async with sessions() as session:
        try:
            detail = await get_alert(session, alert_id_prefix)
        except AmbiguousAlertId:
            raise HTTPException(
                status_code=400, detail="ambiguous id prefix, give more characters"
            ) from None
    if detail is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return _detail_response(detail)
