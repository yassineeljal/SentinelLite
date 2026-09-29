"""Agent watchdog: announces an agent that stopped reporting, and again when it is back.

Detection is only as good as the logs that reach it: an agent that dies makes the platform blind
without any error anywhere. Every agent sends a heartbeat once a minute (even with nothing to
ship); this worker looks for the ones that have not, for `SENTINEL_WATCHDOG_SILENCE_SECONDS`.
Announcements go to Discord (when configured) and to the log. It is best effort and idempotent:
the database update that marks an agent silent is the ticket to announce it, so a restart or a
second watchdog never repeats a message.
"""

import asyncio
import logging
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.config import get_settings
from sentinel_core.db.agent_health import mark_recovered, mark_silent
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.notify.discord import DiscordNotifier, back_line, silent_line
from sentinel_core.workers.consumer import install_stop_signals

logger = logging.getLogger("sentinel.watchdog")


class Watchdog:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        silence: timedelta,
        notifier: DiscordNotifier | None = None,
    ) -> None:
        self._sessions = sessions
        self._silence = silence
        self._notifier = notifier

    async def check(self, now: datetime | None = None) -> list[str]:
        """One pass. Returns the announcements made (also sent to Discord when configured)."""
        now = now or datetime.now(UTC)
        notes: list[str] = []
        async with self._sessions.begin() as session:
            for back in await mark_recovered(session):
                notes.append(back_line(name=back.name))
                logger.warning("agent %s is reporting again", back.name)
            for agent in await mark_silent(session, now, self._silence):
                minutes = int((now - agent.last_seen_at).total_seconds() // 60)
                notes.append(
                    silent_line(
                        name=agent.name,
                        last_seen=f"{agent.last_seen_at:%Y-%m-%d %H:%M:%S}",
                        minutes=minutes,
                    )
                )
                logger.error("agent %s is SILENT (last seen %s)", agent.name, agent.last_seen_at)
        if notes and self._notifier is not None:  # after the commit: never announce a rollback
            await self._notifier.send(notes)
        return notes

    async def run(self, stop: asyncio.Event, interval: float) -> None:
        while not stop.is_set():
            try:
                await self.check()
            except Exception:  # a failed pass must not end the watchdog
                logger.exception("watchdog pass failed; retrying")
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                pass


async def amain() -> int:
    settings = get_settings()
    notifier: DiscordNotifier | None = None
    if settings.discord_webhook_url is not None:
        try:
            notifier = DiscordNotifier(settings.discord_webhook_url.get_secret_value())
        except ValueError as exc:  # the message never contains the URL
            logger.error("invalid SENTINEL_DISCORD_WEBHOOK_URL: %s", exc)
            return 1
    engine = create_engine(settings)
    watchdog = Watchdog(
        create_sessionmaker(engine),
        timedelta(seconds=settings.watchdog_silence_seconds),
        notifier,
    )
    stop = asyncio.Event()
    install_stop_signals(stop)
    logger.info(
        "watchdog: an agent silent for %ds is announced (%s)",
        settings.watchdog_silence_seconds,
        "Discord and log" if notifier else "log only",
    )
    try:
        await watchdog.run(stop, settings.watchdog_interval_seconds)
    finally:
        if notifier is not None:
            await notifier.aclose()
        await engine.dispose()
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
