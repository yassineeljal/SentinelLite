"""The blocks this agent has applied, on disk.

Firewall rules do not survive a reboot but this file does, so on start the enforcer re-applies the
blocks that have not expired. Every block carries its own end time: the agent lifts it by itself
when it passes, whether or not the platform can be reached. The write is atomic.
"""

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("sentinel_agent.blocks")


class BlockStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._blocks: dict[str, datetime] = self._load()

    def __len__(self) -> int:
        return len(self._blocks)

    def __contains__(self, address: str) -> bool:
        return address in self._blocks

    def items(self) -> list[tuple[str, datetime]]:
        return list(self._blocks.items())

    def add(self, address: str, expires_at: datetime) -> None:
        self._blocks[address] = expires_at
        self._write()

    def remove(self, address: str) -> None:
        if self._blocks.pop(address, None) is not None:
            self._write()

    def expired(self, now: datetime) -> list[str]:
        return [address for address, end in self._blocks.items() if end <= now]

    def _load(self) -> dict[str, datetime]:
        try:
            entries = json.loads(self._path.read_text())["blocks"]
            if not isinstance(entries, dict):
                raise TypeError("'blocks' is not a mapping")
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("ignoring unreadable block file %s (%s)", self._path, exc)
            return {}
        blocks: dict[str, datetime] = {}
        for address, end in entries.items():
            try:
                parsed = datetime.fromisoformat(end)
                blocks[str(address)] = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except (TypeError, ValueError):
                logger.warning("ignoring invalid block entry for %s", address)
        return blocks

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {"blocks": {a: end.isoformat() for a, end in self._blocks.items()}}
        temporary = self._path.with_name(self._path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(payload, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
