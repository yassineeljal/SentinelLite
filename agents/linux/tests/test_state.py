import json
import stat
from pathlib import Path

import pytest

from sentinel_agent.state import FileState, StateStore


def test_a_position_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    StateStore(path).commit(Path("/var/log/auth.log"), FileState(inode=42, offset=1234))

    restored = StateStore(path).get(Path("/var/log/auth.log"))

    assert restored == FileState(inode=42, offset=1234)


def test_unknown_files_have_no_position(tmp_path: Path) -> None:
    assert StateStore(tmp_path / "state.json").get(Path("/var/log/other.log")) is None


def test_positions_of_several_files_are_independent(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    store.commit(Path("/a.log"), FileState(1, 10))
    store.commit(Path("/b.log"), FileState(2, 20))
    store.commit(Path("/a.log"), FileState(1, 30))

    reloaded = StateStore(tmp_path / "state.json")
    assert reloaded.get(Path("/a.log")) == FileState(1, 30)
    assert reloaded.get(Path("/b.log")) == FileState(2, 20)


def test_the_state_file_is_private_and_no_temporary_file_is_left(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    StateStore(path).commit(Path("/a.log"), FileState(1, 10))

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_a_crash_while_writing_never_corrupts_the_previous_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.commit(Path("/a.log"), FileState(1, 10))

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("os.replace", fail)  # the atomic rename is the commit point
    with pytest.raises(OSError):
        store.commit(Path("/a.log"), FileState(1, 999))
    monkeypatch.undo()

    assert StateStore(path).get(Path("/a.log")) == FileState(1, 10)


@pytest.mark.parametrize("content", ["", "not json", "[]", '{"files": 3}', '{"files": {"/a": 1}}'])
def test_a_corrupted_state_is_ignored_not_fatal(tmp_path: Path, content: str) -> None:
    path = tmp_path / "state.json"
    path.write_text(content)

    assert StateStore(path).get(Path("/a")) is None  # the agent restarts from its start_at policy


def test_the_parent_directory_is_created(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "state.json"

    StateStore(path).commit(Path("/a.log"), FileState(1, 10))

    assert json.loads(path.read_text())["files"]["/a.log"] == {"inode": 1, "offset": 10}


def test_the_head_fingerprint_is_persisted_when_present(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    StateStore(path).commit(Path("/a.log"), FileState(1, 500, head="abc123"))

    assert StateStore(path).get(Path("/a.log")) == FileState(1, 500, head="abc123")
