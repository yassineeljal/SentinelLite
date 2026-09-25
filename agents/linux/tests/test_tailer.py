import os
from pathlib import Path

import pytest

from sentinel_agent.state import FileState
from sentinel_agent.tailer import MAX_LINE_CHARS, Tailer


def append(path: Path, data: bytes | str) -> None:
    with path.open("ab") as handle:
        handle.write(data.encode() if isinstance(data, str) else data)


def texts(lines: list) -> list[str]:  # type: ignore[type-arg]
    return [line.text for line in lines]


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "auth.log"
    path.write_text("")
    return path


def read_all(tailer: Tailer) -> list:  # type: ignore[type-arg]
    return tailer.read_batch(10_000, 10_000_000)


def test_complete_lines_are_returned_once_with_a_stable_origin(log: Path) -> None:
    append(log, "first\nsecond\n")
    tailer = Tailer(log, saved=None, start_at="beginning")

    lines = read_all(tailer)

    inode = log.stat().st_ino
    assert texts(lines) == ["first", "second"]
    assert [line.origin for line in lines] == [f"{inode}:0", f"{inode}:6"]
    assert [line.position.offset for line in lines] == [6, 13]  # where to resume once acknowledged
    assert read_all(tailer) == []  # nothing new
    append(log, "third\n")
    assert texts(read_all(tailer)) == ["third"]


def test_a_partial_line_waits_for_its_newline(log: Path) -> None:
    append(log, "complete\nhalf a li")
    tailer = Tailer(log, saved=None, start_at="beginning")

    assert texts(read_all(tailer)) == ["complete"]
    assert read_all(tailer) == []
    append(log, "ne\n")
    assert texts(read_all(tailer)) == ["half a line"]


def test_start_at_end_skips_history_and_beginning_ships_it(log: Path) -> None:
    append(log, "old 1\nold 2\n")

    at_end = Tailer(log, saved=None, start_at="end")
    from_start = Tailer(log, saved=None, start_at="beginning")
    append(log, "new\n")

    assert texts(read_all(at_end)) == ["new"]
    assert texts(read_all(from_start)) == ["old 1", "old 2", "new"]


def test_a_saved_position_resumes_exactly_where_it_stopped(log: Path) -> None:
    append(log, "one\ntwo\nthree\n")
    first = Tailer(log, saved=None, start_at="beginning")
    acknowledged = first.read_batch(2, 10_000)[-1].position  # the server accepted two lines

    resumed = Tailer(log, saved=acknowledged, start_at="end")

    assert texts(read_all(resumed)) == ["three"]


def test_a_saved_offset_beyond_the_file_means_it_was_truncated(log: Path) -> None:
    append(log, "short\n")
    saved = FileState(log.stat().st_ino, 9999)

    assert texts(read_all(Tailer(log, saved=saved, start_at="end"))) == ["short"]


def test_copytruncate_is_detected_and_reading_restarts_at_the_top(log: Path) -> None:
    append(log, "a fairly long first line\nanother long line\n")
    tailer = Tailer(log, saved=None, start_at="beginning")
    read_all(tailer)

    log.write_text("new\n")  # same inode, smaller size: copytruncate

    assert texts(read_all(tailer)) == ["new"]


def test_rotation_by_rename_drains_the_old_file_then_follows_the_new_one(
    log: Path, tmp_path: Path
) -> None:
    append(log, "before 1\n")
    tailer = Tailer(log, saved=None, start_at="beginning")
    assert texts(read_all(tailer)) == ["before 1"]
    old_inode = log.stat().st_ino
    append(log, "before 2\nunfinished")  # written just before the rotation, last line incomplete

    os.rename(log, tmp_path / "auth.log.1")
    append(log, "after 1\n")
    lines = read_all(tailer)

    assert texts(lines) == ["before 2", "unfinished", "after 1"]  # nothing lost, in order
    assert lines[0].position.inode == old_inode
    assert lines[2].position.inode == log.stat().st_ino != old_inode
    assert lines[2].origin == f"{log.stat().st_ino}:0"


def test_a_deleted_file_is_still_drained_and_a_recreated_one_followed(log: Path) -> None:
    append(log, "one\n")
    tailer = Tailer(log, saved=None, start_at="beginning")
    read_all(tailer)
    append(log, "two\n")

    log.unlink()
    append(log, "three\n")  # may even reuse the inode number: the deletion is what matters

    assert texts(read_all(tailer)) == ["two", "three"]


def test_a_file_that_does_not_exist_yet_is_followed_from_its_start(tmp_path: Path) -> None:
    path = tmp_path / "later.log"
    tailer = Tailer(path, saved=None, start_at="end")
    assert read_all(tailer) == []

    append(path, "hello\n")

    assert texts(read_all(tailer)) == ["hello"]


def test_after_a_restart_the_rotated_file_is_found_by_its_inode(log: Path, tmp_path: Path) -> None:
    append(log, "one\ntwo\nthree\n")
    first = Tailer(log, saved=None, start_at="beginning")
    acknowledged = first.read_batch(1, 10_000)[-1].position  # only "one" was acknowledged
    first.close()
    os.rename(log, tmp_path / "auth.log.1")  # logrotate ran while the agent was down
    append(log, "four\n")

    resumed = Tailer(log, saved=acknowledged, start_at="end")

    assert texts(read_all(resumed)) == ["two", "three", "four"]


def test_compressed_rotations_are_not_searched(log: Path, tmp_path: Path) -> None:
    append(log, "one\n")
    saved = Tailer(log, saved=None, start_at="beginning").read_batch(1, 100)[-1].position
    os.rename(log, tmp_path / "auth.log.1.gz")  # cannot be tailed
    append(log, "fresh\n")

    assert texts(read_all(Tailer(log, saved=saved, start_at="end"))) == ["fresh"]


def test_a_recycled_inode_is_recognised_by_the_head_fingerprint(log: Path) -> None:
    """An inode number can be reused after a file is deleted and another created."""
    append(log, "x" * 300 + "\n" + "second line of the old file\n")
    tailer = Tailer(log, saved=None, start_at="beginning")
    saved = tailer.read_batch(1, 10_000)[-1].position
    assert saved.head  # offset >= 256: the fingerprint is recorded
    tailer.close()

    log.write_text("y" * 300 + "\nentirely different file\n")  # same inode, different content

    assert (
        texts(read_all(Tailer(log, saved=saved, start_at="end")))[-1] == "entirely different file"
    )
    assert len(texts(read_all(Tailer(log, saved=saved, start_at="end")))) == 2  # from the top


def test_invalid_utf8_nul_and_crlf_are_neutralised(log: Path) -> None:
    append(log, b"bad \xff\xfe bytes\nnul \x00 inside\r\nwindows line\r\n")
    tailer = Tailer(log, saved=None, start_at="beginning")

    assert texts(read_all(tailer)) == ["bad �� bytes", "nul \\x00 inside", "windows line"]


def test_blank_lines_are_not_shipped(log: Path) -> None:
    append(log, "one\n\n\ntwo\n")

    assert texts(read_all(Tailer(log, saved=None, start_at="beginning"))) == ["one", "two"]


def test_a_very_long_line_is_truncated_and_its_remainder_skipped(log: Path) -> None:
    append(log, "A" * 200_000 + "\nnext line\n")
    tailer = Tailer(log, saved=None, start_at="beginning")

    lines = read_all(tailer)

    assert len(lines) == 2  # the remainder of the long line is not shipped as extra lines
    assert len(lines[0].text) == MAX_LINE_CHARS
    assert lines[0].text.endswith("[truncated]")
    assert lines[1].text == "next line"


def test_the_length_limit_counts_the_escaped_form(log: Path) -> None:
    append(log, b"\x00" * 5000 + b"\n")  # each NUL becomes 4 characters

    (line,) = read_all(Tailer(log, saved=None, start_at="beginning"))

    assert len(line.text) <= MAX_LINE_CHARS


def test_batches_are_bounded_by_lines_and_by_bytes(log: Path) -> None:
    append(log, "".join(f"line number {i:04d}\n" for i in range(50)))
    tailer = Tailer(log, saved=None, start_at="beginning")

    assert len(tailer.read_batch(10, 1_000_000)) == 10
    by_bytes = tailer.read_batch(1000, 100)
    assert 1 <= len(by_bytes) <= 7  # ~16 bytes each; the limit stops it soon after 100 bytes
    assert len(read_all(tailer)) == 50 - 10 - len(by_bytes)


def test_a_single_line_larger_than_the_byte_limit_is_still_returned(log: Path) -> None:
    append(log, "z" * 500 + "\n")

    assert len(Tailer(log, saved=None, start_at="beginning").read_batch(10, 50)) == 1
