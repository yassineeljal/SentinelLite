"""Dashboard authentication: login, logout, "who am I", and the session dependency other
dashboard routes use.

Sessions are cookies, not bearer tokens: the dashboard is a same-origin single-page app, and a
cookie the browser handles automatically (HttpOnly, so client-side script can never read it) is
simpler and safer here than a token the frontend would have to store and attach itself. CSRF is
mitigated by `SameSite=Strict` (no state-changing request from another site's page ever carries
the cookie); there is deliberately no separate CSRF token on top of it (see docs/OPERATIONS.md).
"""

from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel_core.auth.user_registry import EMAIL_PATTERN, PostgresUserRepository, UserInfo
from sentinel_core.config import Settings

router = APIRouter(prefix="/v1/auth", tags=["dashboard-auth"])

COOKIE_NAME = "sl_session"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=255)
    password: str = Field(max_length=1024)

    @field_validator("email")
    @classmethod
    def _check_email_shape(cls, value: str) -> str:
        # A generic 401 on login already hides whether an email exists; this only rejects
        # obviously-not-an-email input early, with the same shape check the repository uses.
        if not EMAIL_PATTERN.match(value.strip()):
            raise ValueError("not a valid email address")
        return value


class UserResponse(BaseModel):
    id: UUID
    email: str
    role: str


def get_user_repository(request: Request) -> PostgresUserRepository:
    repo: PostgresUserRepository = request.app.state.users
    return repo


async def authenticate_user(request: Request) -> UserInfo:
    token = request.cookies.get(COOKIE_NAME)
    users: PostgresUserRepository = request.app.state.users
    user = await users.resolve_session(token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@router.post("/login")
async def login(
    body: LoginRequest,
    response: Response,
    request: Request,
    users: Annotated[PostgresUserRepository, Depends(get_user_repository)],
) -> UserResponse:
    settings: Settings = request.app.state.settings
    user = await users.authenticate(body.email, body.password)
    if user is None:
        # One generic answer: never reveals whether the email exists.
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = await users.create_session(user.id, timedelta(hours=settings.session_ttl_hours))
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        path="/",
    )
    return UserResponse(id=user.id, email=user.email, role=user.role)


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    users: Annotated[PostgresUserRepository, Depends(get_user_repository)],
) -> None:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        await users.revoke_session(token)
    settings: Settings = request.app.state.settings
    response.delete_cookie(
        COOKIE_NAME, path="/", secure=settings.session_cookie_secure, samesite="strict"
    )


@router.get("/me")
async def me(user: Annotated[UserInfo, Depends(authenticate_user)]) -> UserResponse:
    return UserResponse(id=user.id, email=user.email, role=user.role)
