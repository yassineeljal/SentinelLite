"""Persistent read positions: what the server has acknowledged, per file.

A position is only stored AFTER the server accepted the lines before it (at-least-once
delivery). The write is atomic (temporary file, fsync, rename): a crash leaves either the old or
the new state, never a corrupted one.
"""

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("sentinel_agent.state")


@dataclass(frozen=True)
class FileState:
    inode: int
    offset: int  # byte offset of the first line not yet acknowledged
    # Fingerprint of the first bytes of the file, once the offset is past them. An inode number
    # can be recycled (file deleted, another created): the fingerprint tells them apart.
    head: str = ""


class StateStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._files: dict[str, FileState] = self._load()

    def get(self, file: Path) -> FileState | None:
        return self._files.get(str(file))

    def commit(self, file: Path, state: FileState) -> None:
        self._files[str(file)] = state
        self._write()

    def _load(self) -> dict[str, FileState]:
        try:
            data = json.loads(self._path.read_text())
            entries = data["files"]
            if not isinstance(entries, dict):
                raise TypeError("'files' is not a mapping")
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # Not fatal: the agent falls back to its start_at policy instead of refusing to run.
            logger.warning("ignoring unreadable state file %s (%s)", self._path, exc)
            return {}
        files: dict[str, FileState] = {}
        for name, entry in entries.items():
            try:
                files[name] = FileState(
                    int(entry["inode"]), int(entry["offset"]), str(entry.get("head", ""))
                )
            except (KeyError, TypeError, ValueError):
                logger.warning("ignoring invalid state entry for %s", name)
        return files

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {
            "files": {
                name: {"inode": state.inode, "offset": state.offset}
                | ({"head": state.head} if state.head else {})
                for name, state in self._files.items()
            }
        }
        temporary = self._path.with_name(self._path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(payload, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path)  # the atomic commit point
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
