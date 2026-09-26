"""Reputation lookups with a cache, a daily budget and a circuit breaker (state in Redis).

The provider's free plan allows 1000 requests a day and every alert source may repeat many times,
so a lookup is served, in this order, from the cache (24 h by default, shared by all enricher
workers), refused while a block is active, refused once the local daily budget is spent (kept
below the plan's limit), and only then sent. Blocks are what stop a quota, a revoked key or an
outage from costing one timeout per alert. Everything that can go wrong ends as `None`: an alert
without a reputation is normal, a stuck or failing enricher is not.

Redis errors are NOT swallowed: the caller retries the batch, as everywhere else.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from pydantic import ValidationError
from redis.asyncio import Redis

from sentinel_core.enrichment.abuseipdb import (
    AuthRejected,
    BadRequest,
    CheckResult,
    QuotaExceeded,
    Reputation,
    Unavailable,
    seconds_until_midnight,
)

logger = logging.getLogger("sentinel.reputation")

AUTH_BLOCK_SECONDS = 3600  # a refused key: look again in an hour, without hammering the API
UNAVAILABLE_BLOCK_SECONDS = 60  # an outage must not cost a timeout for every alert


class ReputationLookup(Protocol):
    """What the enricher needs: the reputation of a PUBLIC address, or None."""

    async def lookup(self, ip: str) -> Reputation | None: ...


class ReputationClient(Protocol):
    async def check(self, ip: str) -> CheckResult: ...


def _now() -> datetime:
    return datetime.now(UTC)


class ReputationService:
    def __init__(
        self,
        client: ReputationClient,
        redis: Redis,
        *,
        cache_ttl_seconds: int = 24 * 3600,
        daily_limit: int = 900,
        key_prefix: str = "sl:rep:",
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._client = client
        self._redis = redis
        self._ttl = cache_ttl_seconds
        self._limit = daily_limit
        self._prefix = key_prefix
        self._clock = clock

    async def lookup(self, ip: str) -> Reputation | None:
        cache_key = f"{self._prefix}abuseipdb:{ip}"
        if (cached := await self._cached(cache_key)) is not None:
            return cached
        if await self._redis.exists(f"{self._prefix}blocked"):
            return None
        now = self._clock()
        quota_key = f"{self._prefix}quota:{now:%Y%m%d}"
        used = int(await self._redis.incr(quota_key))
        await self._redis.expire(quota_key, 2 * 24 * 3600)
        if used > self._limit:
            await self._block("daily budget spent", seconds_until_midnight(now))
            return None

        try:
            result = await self._client.check(ip)
        except QuotaExceeded as exc:
            await self._block("provider quota exceeded", exc.retry_after_seconds)
            return None
        except AuthRejected as exc:
            await self._block(f"{exc}", AUTH_BLOCK_SECONDS, level=logging.ERROR)
            return None
        except Unavailable as exc:
            await self._block(f"provider unavailable ({exc})", UNAVAILABLE_BLOCK_SECONDS)
            return None
        except BadRequest:
            return None  # this address only; nothing wrong with the provider

        await self._redis.set(cache_key, result.reputation.model_dump_json(), ex=self._ttl)
        if result.remaining is not None and result.remaining <= 0:
            seconds = (
                max(1, int((result.reset_at - now).total_seconds()))
                if result.reset_at
                else seconds_until_midnight(now)
            )
            await self._block("provider quota reached", seconds)
        return result.reputation

    async def _cached(self, key: str) -> Reputation | None:
        raw = await self._redis.get(key)
        if raw is None:
            return None
        try:
            return Reputation.model_validate_json(raw)
        except ValidationError:
            return None  # a corrupt entry is simply asked again

    async def _block(self, reason: str, seconds: int, *, level: int = logging.WARNING) -> None:
        """Stop asking for `seconds`; log only when the block is new (not once per alert)."""
        seconds = max(1, seconds)
        if await self._redis.set(f"{self._prefix}blocked", reason, ex=seconds, nx=True):
            logger.log(level, "reputation lookups paused for %ds: %s", seconds, reason)
