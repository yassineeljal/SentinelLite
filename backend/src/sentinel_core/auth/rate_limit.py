"""Atomic, persistent fixed-window attempt budgets, shared by all API processes.

Count all attempts, including successful ones. Never reset on success: an attacker with one
valid credential must not use it to reset the source budget. Blocked attempts do not extend TTL.
"""

from hashlib import sha256

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class TooManyAttempts(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after


async def check_attempts(
    sessions: async_sessionmaker[AsyncSession],
    budgets: dict[str, int],
    window_seconds: int,
) -> None:
    retry_after = 0
    async with sessions.begin() as session:
        # Indexed cleanup bounds retained identifiers. Fixed windows use the database's clock.
        await session.execute(text("DELETE FROM auth_rate_limits WHERE expires_at <= now()"))
        # Stable ordering also prevents deadlocks when requests share more than one bucket.
        for scope, limit in sorted(budgets.items()):
            result = await session.execute(
                text(
                    "INSERT INTO auth_rate_limits (scope_hash, attempts, expires_at) "
                    "VALUES (:key, 1, now() + make_interval(secs => :window)) "
                    "ON CONFLICT (scope_hash) DO UPDATE SET "
                    "attempts = CASE WHEN auth_rate_limits.expires_at <= now() THEN 1 "
                    "ELSE least(auth_rate_limits.attempts + 1, 1000000) END, "
                    "expires_at = CASE WHEN auth_rate_limits.expires_at <= now() "
                    "THEN EXCLUDED.expires_at ELSE auth_rate_limits.expires_at END "
                    "RETURNING attempts, ceil(extract(epoch FROM expires_at - now()))::int AS wait"
                ),
                {"key": sha256(scope.encode()).hexdigest(), "window": window_seconds},
            )
            row = result.one()
            if row.attempts > limit:
                retry_after = max(retry_after, row.wait, 1)
    # Raise AFTER commit: rolling back would make parallel rejected attempts invisible.
    if retry_after:
        raise TooManyAttempts(retry_after)
