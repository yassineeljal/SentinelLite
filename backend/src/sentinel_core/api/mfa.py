"""Self-service TOTP setup and management, with session-bound enrollment and reauthentication."""

from collections.abc import AsyncGenerator
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from sentinel_core.api.auth import COOKIE_NAME, authenticate_user, set_session_cookie
from sentinel_core.api.security import limit_auth, no_store
from sentinel_core.auth.mfa import (
    InvalidMFACredentials,
    MFAManager,
    MFASetup,
    MFAStateConflict,
    MFAStatus,
)
from sentinel_core.auth.totp import MFAUnavailable, SecretBox
from sentinel_core.auth.user_registry import UserInfo
from sentinel_core.config import Settings

router = APIRouter(prefix="/v1/auth/2fa", tags=["two-factor"], dependencies=[Depends(no_store)])
User = Annotated[UserInfo, Depends(authenticate_user)]


class PasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=1024)


class FactorRequest(PasswordRequest):
    code: str = Field(min_length=1, max_length=64)


class RecoveryCodes(BaseModel):
    recovery_codes: list[str]


async def manager(request: Request) -> AsyncGenerator[MFAManager]:
    settings: Settings = request.app.state.settings
    service = MFAManager(request.app.state.db_sessions, SecretBox(settings.mfa_encryption_key))
    try:
        yield service
    except InvalidMFACredentials:
        raise HTTPException(
            status_code=401,
            detail="Invalid password, code or expired setup. Try again.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except MFAStateConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except MFAUnavailable:
        raise HTTPException(
            status_code=503,
            detail="Two-factor setup is unavailable. Contact your administrator.",
        ) from None


Manager = Annotated[MFAManager, Depends(manager)]


async def manage_limit(request: Request, user: User) -> None:
    await limit_auth(request, f"manage:{user.id}")


@router.get("")
async def status(user: User, service: Manager) -> MFAStatus:
    return await service.status(user.id)


@router.post("/setup", dependencies=[Depends(manage_limit)])
async def setup(body: PasswordRequest, request: Request, user: User, service: Manager) -> MFASetup:
    return await service.start(user.id, request.cookies[COOKIE_NAME], body.password)


@router.post("/confirm", dependencies=[Depends(manage_limit)])
async def confirm(
    body: FactorRequest,
    request: Request,
    response: Response,
    user: User,
    service: Manager,
) -> RecoveryCodes:
    settings: Settings = request.app.state.settings
    codes, token = await service.confirm(
        user.id,
        request.cookies[COOKIE_NAME],
        body.password,
        body.code,
        timedelta(hours=settings.session_ttl_hours),
    )
    set_session_cookie(response, token, settings)
    return RecoveryCodes(recovery_codes=codes)


@router.post("/recovery-codes", dependencies=[Depends(manage_limit)])
async def regenerate(
    body: FactorRequest,
    request: Request,
    response: Response,
    user: User,
    service: Manager,
) -> RecoveryCodes:
    settings: Settings = request.app.state.settings
    codes, token = await service.change(
        user.id,
        request.cookies[COOKIE_NAME],
        body.password,
        body.code,
        timedelta(hours=settings.session_ttl_hours),
        disable=False,
    )
    set_session_cookie(response, token, settings)
    return RecoveryCodes(recovery_codes=codes)


@router.post("/disable", status_code=204, dependencies=[Depends(manage_limit)])
async def disable(
    body: FactorRequest,
    request: Request,
    response: Response,
    user: User,
    service: Manager,
) -> None:
    settings: Settings = request.app.state.settings
    _, token = await service.change(
        user.id,
        request.cookies[COOKIE_NAME],
        body.password,
        body.code,
        timedelta(hours=settings.session_ttl_hours),
        disable=True,
    )
    set_session_cookie(response, token, settings)
