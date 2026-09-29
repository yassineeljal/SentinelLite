"""Applies the platform's block / unblock actions to the local firewall.

One `step()` = lift what has expired, fetch the pending actions, apply each one, report the
outcome. Every action is idempotent (a block already in place is acknowledged, an unblock of an
unknown address too), so a lost acknowledgment or a redelivery is harmless.

The platform is asked, not obeyed: `firewall.refusal` rejects addresses that must never be
blocked, the number of active blocks is capped, and no block outlives `max_ttl` even if the
platform asks for more.
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sentinel_agent.actions import Acknowledged, Action, ActionClient, Fetched, Gone
from sentinel_agent.blocks import BlockStore
from sentinel_agent.client import Unauthorized
from sentinel_agent.firewall import Backend, FirewallError, Network, parse_address, refusal

logger = logging.getLogger("sentinel_agent.enforcer")


class AuthenticationError(Exception):
    """The platform does not accept the agent's key (unknown or revoked)."""


@dataclass
class Enforcer:
    client: ActionClient
    backend: Backend
    store: BlockStore
    never_block: tuple[Network, ...] = ()
    max_blocks: int = 100
    max_ttl: timedelta = timedelta(hours=24)
    applied: int = field(default=0, init=False)
    lifted: int = field(default=0, init=False)
    refused: int = field(default=0, init=False)

    def start(self, now: datetime | None = None) -> None:
        """Create the chain, then re-apply the blocks that survived a reboot."""
        now = now or datetime.now(UTC)
        self.backend.prepare()
        for address, end in self.store.items():
            if end <= now:
                continue  # `step` lifts it
            try:
                self.backend.block(address)
            except FirewallError as exc:
                logger.error("could not restore the block of %s: %s", address, exc)
        logger.info("restored %d block(s)", len(self.store))

    def step(self, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        self._lift_expired(now)
        fetched = self.client.fetch()
        if isinstance(fetched, Unauthorized):
            raise AuthenticationError("the platform refused the agent key")
        if not isinstance(fetched, Fetched):
            logger.warning("cannot fetch actions: %s", fetched)
            return
        for action in fetched.actions:
            self._handle(action, now)

    # -- internals --------------------------------------------------------------------------

    def _lift_expired(self, now: datetime) -> None:
        for address in self.store.expired(now):
            try:
                self.backend.unblock(address)
            except FirewallError as exc:
                logger.error("could not lift the block of %s: %s (will retry)", address, exc)
                continue
            self.store.remove(address)
            self.lifted += 1
            logger.warning("UNBLOCK %s (expired)", address)

    def _handle(self, action: Action, now: datetime) -> None:
        if action.kind == "block":
            status, detail = self._block(action, now)
        else:
            status, detail = self._unblock(action)
        result = self.client.acknowledge(action.id, status, detail)
        if isinstance(result, Unauthorized):
            raise AuthenticationError("the platform refused the agent key")
        if not isinstance(result, Acknowledged | Gone):
            logger.warning("could not acknowledge action %d: %s", action.id, result)

    def _block(self, action: Action, now: datetime) -> tuple[str, str]:
        parsed = parse_address(action.ip)
        reason = refusal(action.ip, self.never_block)
        if parsed is None or reason is not None:
            self.refused += 1
            logger.error("REFUSED to block %r: %s", action.ip[:64], reason)
            return "failed", f"refused: {reason}"
        address = str(parsed)
        end = min(action.expires_at, now + self.max_ttl)
        if end <= now:
            return "failed", "refused: already expired"
        if address not in self.store and len(self.store) >= self.max_blocks:
            self.refused += 1
            logger.error("REFUSED to block %s: %d blocks already active", address, len(self.store))
            return "failed", "refused: too many active blocks"
        try:
            self.backend.block(address)
        except FirewallError as exc:
            logger.error("could not block %s: %s", address, exc)
            return "failed", f"firewall error: {exc}"[:500]
        # Recorded after the rule exists: a crash in between leaves a rule the next start finds
        # nothing to expire for, never a record without a rule.
        self.store.add(address, end)
        self.applied += 1
        logger.warning("BLOCK %s until %s", address, end.isoformat(timespec="seconds"))
        return "done", ""

    def _unblock(self, action: Action) -> tuple[str, str]:
        parsed = parse_address(action.ip)
        if parsed is None:
            return "failed", "refused: not an IP address"
        address = str(parsed)
        try:
            self.backend.unblock(address)
        except FirewallError as exc:
            logger.error("could not unblock %s: %s", address, exc)
            return "failed", f"firewall error: {exc}"[:500]
        self.store.remove(address)
        self.lifted += 1
        logger.warning("UNBLOCK %s", address)
        return "done", ""

    def run(self, stop: threading.Event, interval: float) -> None:
        self.start()
        while not stop.is_set():
            self.step()
            stop.wait(interval)
