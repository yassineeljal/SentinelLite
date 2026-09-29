"""Responder worker: `alerts.respond` (Redis) -> block decisions (Postgres) -> agent actions.

For every alert it applies the policy of response/policy.py and records what it decided. In
`dry_run` a decision is stored as "would block" and logged, and nothing else happens. In `enforce`
the block is also queued as an action for the agent(s) that saw the attacker; they fetch it by
polling and apply it to their firewall (docs/AGENT.md). Blocks whose time is up are released and
an `unblock` is queued for the same agents.

Delivery is at-least-once: the block row is unique per alert, so a redelivered alert changes
nothing, and its audit line is written only by the delivery that inserted the row.
"""

import asyncio
import logging
import os
import socket
import sys
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy.exc import DataError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.bus.alerts_stream import ALERTS_RESPOND_STREAM
from sentinel_core.bus.raw_stream import DATA_FIELD
from sentinel_core.config import build_response_policy, get_settings
from sentinel_core.db.actions import (
    agents_for_events,
    block_id_for_alert,
    enqueue_action,
    release_expired_blocks,
)
from sentinel_core.db.responses import (
    canonical,
    count_blocks_since,
    is_blocked,
    load_allowlist,
    record_audit,
    record_block,
)
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.detection.alerts import Alert
from sentinel_core.notify.discord import DiscordNotifier, block_line, release_line
from sentinel_core.response.policy import AUDITED_SKIPS, Reason, ResponsePolicy, Verdict, decide
from sentinel_core.terminal import sanitize
from sentinel_core.workers.consumer import (
    Entry,
    StreamConsumer,
    build_redis,
    install_stop_signals,
)

logger = logging.getLogger("sentinel.responder")

GROUP = "responders"
ACTOR = "responder"
AUDIT_TARGET_MAX = 128
RELEASE_INTERVAL_SECONDS = 30.0


class ResponderWorker(StreamConsumer):
    def __init__(
        self,
        redis: Redis,
        sessions: async_sessionmaker[AsyncSession],
        policy: ResponsePolicy,
        *,
        mode: str = "dry_run",
        consumer: str,
        stream: str = ALERTS_RESPOND_STREAM,
        group: str = GROUP,
        batch_size: int = 100,
        claim_idle_ms: int = 60_000,
        release_interval: float = RELEASE_INTERVAL_SECONDS,
        notifier: DiscordNotifier | None = None,
    ) -> None:
        super().__init__(
            redis,
            stream=stream,
            group=group,
            consumer=consumer,
            logger=logger,
            batch_size=batch_size,
            claim_idle_ms=claim_idle_ms,
        )
        self._sessions = sessions
        self._policy = policy
        self._mode = mode
        self._release_interval = release_interval
        self._notifier = notifier
        self._pending_notes: list[str] = []
        self._next_release = 0.0

    async def process_batch(self, entries: list[Entry]) -> None:
        self._pending_notes.clear()  # a retried batch (after an error) starts clean
        alerts: list[Alert] = []
        for entry_id, fields in entries:
            if fields is None:  # entry deleted while still pending
                continue
            try:
                alerts.append(Alert.model_validate_json(fields.get(DATA_FIELD, "")))
            except ValidationError:
                logger.error("entry %s is not an alert: skipped", entry_id)
        if not alerts:
            return

        now = datetime.now(UTC)
        blocked = skipped = 0
        async with self._sessions.begin() as session:
            allowlist = await load_allowlist(session)
            recent = await count_blocks_since(session, self._mode, now - timedelta(minutes=1))
            for alert in alerts:
                address = alert.src_ip or ""
                decision = decide(
                    alert,
                    self._policy,
                    extra_allowlist=allowlist,
                    already_blocked=bool(address)
                    and await self._already_blocked(session, address, now),
                    blocks_last_minute=recent + blocked,
                )
                if decision.verdict is Verdict.BLOCK and decision.address is not None:
                    if await self._block(session, alert, decision.address, now):
                        blocked += 1
                    continue
                skipped += 1
                if decision.reason in AUDITED_SKIPS:
                    await self._audit_skip(session, alert, decision.reason)
        await (
            self._flush_notes()
        )  # after the commit: never announce a decision that was rolled back
        logger.info("batch: %d block(s) recorded, %d alert(s) not blocked", blocked, skipped)

    async def _already_blocked(self, session: AsyncSession, address: str, now: datetime) -> bool:
        # The policy re-validates the address; a value that is not an address cannot be blocked
        # already, and must not reach a query that casts it (that would fail the whole batch).
        try:
            return await is_blocked(session, canonical(address), self._mode, now)
        except ValueError:
            return False

    async def _block(
        self, session: AsyncSession, alert: Alert, address: str, now: datetime
    ) -> bool:
        reason = (
            f"{alert.rule_id}: {alert.title} "
            f"({alert.match_count} event(s), severity {alert.severity})"
        )
        inserted = await record_block(
            session,
            ip=address,
            alert_id=alert.alert_id,
            rule_id=alert.rule_id,
            reason=reason,
            mode=self._mode,
            now=now,
            ttl=timedelta(seconds=self._policy.ttl_seconds),
        )
        if not inserted:  # a redelivered alert: already decided
            return False
        queued = await self._queue_for_agents(session, alert, address, now)
        await record_audit(
            session,
            ACTOR,
            f"block.{self._mode}",
            address,
            {
                "rule_id": alert.rule_id,
                "alert_id": alert.alert_id,
                "severity": alert.severity,
                "ttl_seconds": self._policy.ttl_seconds,
                "agents": queued,
            },
        )
        self._pending_notes.append(
            block_line(
                address=address,
                mode=self._mode,
                rule_id=alert.rule_id,
                match_count=alert.match_count,
                severity=alert.severity,
                ttl_seconds=self._policy.ttl_seconds,
            )
        )
        logger.warning(
            "%s %s for %ds (%s, alert %s)",
            "WOULD BLOCK" if self._mode == "dry_run" else "BLOCK",
            address,
            self._policy.ttl_seconds,
            alert.rule_id,
            alert.alert_id[:12],
        )
        return True

    async def _queue_for_agents(
        self, session: AsyncSession, alert: Alert, address: str, now: datetime
    ) -> int:
        """In enforce mode, tell the agents that saw this attacker to block it. Returns how many."""
        if self._mode != "enforce":
            return 0
        block_id = await block_id_for_alert(session, alert.alert_id)
        if block_id is None:  # cannot happen: the row was just inserted in this transaction
            return 0
        agents = await agents_for_events(session, alert.event_ids)
        if not agents:
            logger.warning("no active agent saw the events of alert %s", alert.alert_id[:12])
        expires_at = now + timedelta(seconds=self._policy.ttl_seconds)
        for agent_id in agents:
            await enqueue_action(
                session,
                kind="block",
                block_id=block_id,
                agent_id=agent_id,
                ip=address,
                expires_at=expires_at,
            )
        return len(agents)

    async def on_tick(self) -> None:
        if self._mode != "enforce":
            return
        loop_time = asyncio.get_running_loop().time()
        if loop_time < self._next_release:
            return
        self._next_release = loop_time + self._release_interval
        async with self._sessions.begin() as session:
            for block in await release_expired_blocks(session, datetime.now(UTC), ACTOR):
                await record_audit(session, ACTOR, "unblock", block.ip, {"block_id": block.id})
                self._pending_notes.append(release_line(address=block.ip))
                logger.info("released %s (block %d expired)", block.ip, block.id)
        await self._flush_notes()

    async def _flush_notes(self) -> None:
        notes, self._pending_notes = self._pending_notes, []
        if notes and self._notifier is not None:
            await self._notifier.send(notes)

    async def _audit_skip(self, session: AsyncSession, alert: Alert, reason: Reason) -> None:
        # Untrusted text (the address may be malformed) is cut and sanitised before it is stored.
        await record_audit(
            session,
            ACTOR,
            f"skip.{reason.value}",
            sanitize(alert.src_ip or "")[:AUDIT_TARGET_MAX],
            {"rule_id": alert.rule_id, "alert_id": alert.alert_id, "severity": alert.severity},
        )

    async def quarantine(self, entry: Entry, exc: DataError) -> None:
        # A decision that cannot be stored is reported and dropped: the alert itself is safe in
        # the alerts table, and a stuck entry must not hold back the alerts behind it.
        logger.error(
            "dropping entry %s: the database rejected it (%s)", entry[0], type(exc).__name__
        )


async def amain() -> int:
    settings = get_settings()
    if not settings.responder_enabled:
        logger.error("the responder is disabled (SENTINEL_RESPONDER_ENABLED=false): nothing to do")
        return 1
    try:
        policy = build_response_policy(settings)
    except ValueError as exc:
        logger.error("invalid responder configuration: %s", exc)
        return 1
    logger.info(
        "%s: blocking rules=%s min_severity=%d ttl=%ds cap=%d/min, %d configured allowlist entr%s",
        "ENFORCE (agents will block)" if settings.responder_mode == "enforce" else "DRY RUN",
        ",".join(sorted(policy.block_rules)),
        policy.min_severity,
        policy.ttl_seconds,
        policy.max_blocks_per_minute,
        len(policy.allowlist),
        "y" if len(policy.allowlist) == 1 else "ies",
    )
    notifier: DiscordNotifier | None = None
    if settings.discord_webhook_url is not None:
        try:
            notifier = DiscordNotifier(settings.discord_webhook_url.get_secret_value())
        except ValueError as exc:  # the message never contains the URL
            logger.error("invalid SENTINEL_DISCORD_WEBHOOK_URL: %s", exc)
            return 1
        logger.info("Discord notifications on")
    redis = build_redis(settings.redis_url)
    engine = create_engine(settings)
    worker = ResponderWorker(
        redis,
        create_sessionmaker(engine),
        policy,
        mode=settings.responder_mode,
        consumer=f"{socket.gethostname()}-{os.getpid()}",
        batch_size=settings.responder_batch_size,
        claim_idle_ms=settings.responder_claim_idle_ms,
        notifier=notifier,
    )
    stop = asyncio.Event()
    install_stop_signals(stop)
    try:
        await worker.run(stop)
    finally:
        if notifier is not None:
            await notifier.aclose()
        await redis.aclose()
        await engine.dispose()
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
