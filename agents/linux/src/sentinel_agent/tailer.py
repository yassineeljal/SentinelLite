"""Follows one log file: complete lines only, robust to rotation, truncation and hostile bytes.

The reader never decides what is acknowledged: every line carries the position to store once the
server has accepted it (see state.py). Rotation is handled the way `tail -F` does it: the old file
stays open until it is drained, then the new one is followed from its start.
"""

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from sentinel_agent.state import FileState

logger = logging.getLogger("sentinel_agent.tailer")

# The API refuses lines above 8192 characters (after NUL bytes are escaped, which the server does
# too): one such line would make its whole batch fail forever, so it is truncated here.
MAX_LINE_CHARS = 8192
TRUNCATION_SUFFIX = "…[truncated]"
MAX_RAW_LINE_BYTES = 65_536  # bytes of one line ever held in memory
HEAD_BYTES = 256
_COMPRESSED_SUFFIXES = {".gz", ".bz2", ".xz", ".zst", ".zip"}


@dataclass(frozen=True)
class PendingLine:
    origin: str  # "<inode>:<byte offset of the line start>": stable, the server's idempotency key
    text: str
    position: FileState  # what to persist once the server has accepted this line


def prepare_line(raw: bytes) -> str:
    """Bytes of one line -> the text to ship. Never raises, whatever the bytes are."""
    text = raw.rstrip(b"\r\n").decode("utf-8", errors="replace").replace("\x00", "\\x00")
    if len(text) > MAX_LINE_CHARS:
        text = text[: MAX_LINE_CHARS - len(TRUNCATION_SUFFIX)] + TRUNCATION_SUFFIX
    return text


def _fingerprint(handle: BinaryIO) -> str:
    head = os.pread(handle.fileno(), HEAD_BYTES, 0)
    return hashlib.sha256(head).hexdigest()[:16] if len(head) == HEAD_BYTES else ""


class Tailer:
    def __init__(self, path: Path, saved: FileState | None, start_at: str = "end") -> None:
        self._path = path
        self._handle: BinaryIO | None = None
        self._inode = 0
        self._offset = 0  # next unread byte of the open file
        self._head = ""
        self._open_initial(saved, start_at)

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    # -- public -----------------------------------------------------------------------------

    def read_batch(self, max_lines: int, max_bytes: int) -> list[PendingLine]:
        """Up to `max_lines` lines (and about `max_bytes`); at least one if any is available."""
        self._check_integrity()
        lines: list[PendingLine] = []
        total = 0
        while len(lines) < max_lines and (total < max_bytes or not lines):
            line = self._next_line()
            if line is None:
                break
            lines.append(line)
            total += len(line.text.encode())
        return lines

    # -- opening ----------------------------------------------------------------------------

    def _stat_path(self) -> os.stat_result | None:
        try:
            return self._path.stat()
        except FileNotFoundError:
            return None

    def _attach(self, path: Path, offset: int) -> None:
        self.close()
        self._handle = path.open("rb")
        self._inode = os.fstat(self._handle.fileno()).st_ino
        self._offset = offset
        self._head = _fingerprint(self._handle)

    def _open_initial(self, saved: FileState | None, start_at: str) -> None:
        current = self._stat_path()
        if saved is None:
            if current is not None:
                self._attach(self._path, current.st_size if start_at == "end" else 0)
            return  # a file that appears later is followed from its start

        candidate = self._path if current is not None and current.st_ino == saved.inode else None
        if candidate is None:
            candidate = self._find_rotated(saved.inode)
            if candidate is None:
                logger.warning(
                    "%s: the file at the saved position is gone, following the current file from "
                    "its start",
                    self._path,
                )
        if candidate is not None:
            self._attach(candidate, saved.offset)
            if saved.head and self._head != saved.head:
                logger.warning("%s: content changed under a reused inode, restarting", candidate)
                self._offset = 0
            elif saved.offset > os.fstat(self._handle_or_fail().fileno()).st_size:
                logger.warning("%s: truncated since the saved position, restarting", candidate)
                self._offset = 0
        elif current is not None:
            self._attach(self._path, 0)

    def _find_rotated(self, inode: int) -> Path | None:
        """The file a rotation renamed away while the agent was not running, found by inode."""
        for candidate in sorted(self._path.parent.glob(self._path.name + "*")):
            if candidate == self._path or candidate.suffix in _COMPRESSED_SUFFIXES:
                continue
            try:
                if candidate.stat().st_ino == inode:
                    return candidate
            except OSError:
                continue
        return None

    def _handle_or_fail(self) -> BinaryIO:
        if self._handle is None:
            raise RuntimeError("no open file")
        return self._handle

    # -- reading ----------------------------------------------------------------------------

    def _check_integrity(self) -> None:
        """Detect copytruncate (smaller file) and a rewritten file (changed head) once per batch."""
        if self._handle is None:
            return
        size = os.fstat(self._handle.fileno()).st_size
        if size < self._offset:
            logger.warning("%s: truncated, restarting from the top", self._path)
            self._offset, self._head = 0, ""
        elif self._head and _fingerprint(self._handle) != self._head:
            logger.warning("%s: rewritten in place, restarting from the top", self._path)
            self._offset, self._head = 0, ""

    def _file_replaced(self) -> bool:
        """True once the open file is no longer what `path` designates (rotated or deleted)."""
        handle = self._handle_or_fail()
        if os.fstat(handle.fileno()).st_nlink == 0:  # deleted: any file at `path` is another one
            return True
        current = self._stat_path()
        return current is not None and current.st_ino != self._inode

    def _next_line(self) -> PendingLine | None:
        while True:
            if self._handle is None:
                current = self._stat_path()
                if current is None:
                    return None
                self._attach(self._path, 0)
            found = self._read_complete_line()
            if found is not None:
                raw, start, following = found
                self._offset = following
                text = prepare_line(raw)
                if not text.strip():
                    continue  # blank line: nothing to ship, the read pointer moves on
                return self._pending(text, start, following)
            if not self._file_replaced():
                return None  # nothing more for now
            # The old file is drained; whatever is left is a last line nobody will complete.
            tail = self._read_tail()
            self.close()
            if tail is not None:
                raw, start, following = tail
                text = prepare_line(raw)
                if text.strip():
                    return self._pending(text, start, following)

    def _pending(self, text: str, start: int, following: int) -> PendingLine:
        head = ""
        if following >= HEAD_BYTES:
            self._head = self._head or _fingerprint(self._handle_or_fail())
            head = self._head
        return PendingLine(
            origin=f"{self._inode}:{start}",
            text=text,
            position=FileState(self._inode, following, head),
        )

    def _read_complete_line(self) -> tuple[bytes, int, int] | None:
        """(line bytes, start offset, offset after it) of the next COMPLETE line, else None."""
        handle = self._handle_or_fail()
        start = self._offset
        handle.seek(start)
        chunk = handle.readline(MAX_RAW_LINE_BYTES + 1)
        if not chunk:
            return None
        if chunk.endswith(b"\n"):
            return chunk, start, start + len(chunk)
        if len(chunk) <= MAX_RAW_LINE_BYTES:
            return None  # a partial line: its newline has not been written yet
        length = len(chunk)  # overlong line: keep its beginning, skip the rest up to the newline
        while True:
            more = handle.readline(MAX_RAW_LINE_BYTES)
            if not more:
                return None  # still being written: do not consume anything yet
            length += len(more)
            if more.endswith(b"\n"):
                return chunk[:MAX_RAW_LINE_BYTES], start, start + length

    def _read_tail(self) -> tuple[bytes, int, int] | None:
        handle = self._handle_or_fail()
        start = self._offset
        handle.seek(start)
        remaining = os.fstat(handle.fileno()).st_size - start
        if remaining <= 0:
            return None
        return handle.read(min(remaining, MAX_RAW_LINE_BYTES)), start, start + remaining
