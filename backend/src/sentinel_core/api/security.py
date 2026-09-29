"""Shared attempt limits and no-store responses for authentication endpoints."""

from fastapi import HTTPException, Request, Response
from sqlalchemy.exc import SQLAlchemyError

from sentinel_core.auth.rate_limit import TooManyAttempts, check_attempts
from sentinel_core.config import Settings


async def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


async def limit_auth(request: Request, principal: str) -> None:
    settings: Settings = request.app.state.settings
    # Never read X-Forwarded-For here. The shipped server disables proxy headers; operators
    # adding a reverse proxy must explicitly constrain its trusted peers (OPERATIONS.md).
    peer = request.client.host if request.client else "unknown"
    try:
        await check_attempts(
            request.app.state.db_sessions,
            {
                f"principal:{principal}": settings.auth_account_attempts,
                f"peer:{peer}": settings.auth_ip_attempts,
            },
            settings.auth_window_seconds,
        )
    except TooManyAttempts as exc:
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Try again in {exc.retry_after} seconds.",
            headers={"Retry-After": str(exc.retry_after), "Cache-Control": "no-store"},
        ) from None
    except SQLAlchemyError:
        # Do not fall back to per-process counters (or no limit) when the shared store fails.
        raise HTTPException(
            status_code=503,
            detail="Authentication temporarily unavailable",
            headers={"Cache-Control": "no-store"},
        ) from None
