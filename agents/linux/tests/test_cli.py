import json
from collections.abc import Generator
from pathlib import Path

import pytest

from sentinel_agent.cli import main
from tests.fake_server import FakeServer, Reply

KEY = "11111111-1111-1111-1111-111111111111." + "k" * 43


class Setup:
    def __init__(self, tmp_path: Path, server_url: str) -> None:
        self.tmp = tmp_path
        self.log = tmp_path / "auth.log"
        self.log.write_text(
            "Sep 25 10:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n"
        )
        key_file = tmp_path / "key"
        key_file.write_text(KEY)
        key_file.chmod(0o600)
        self.state = tmp_path / "state.json"
        self.config = tmp_path / "agent.toml"
        self.config.write_text(
            f"""
[server]
url = "{server_url}"
key_file = "{key_file}"

[agent]
state_file = "{self.state}"
start_at = "beginning"

[[sources]]
path = "{self.log}"
source = "linux.auth"
"""
        )


@pytest.fixture
def server() -> Generator[FakeServer]:
    with FakeServer() as running:
        yield running


def test_once_ships_what_is_available_and_exits_zero(
    tmp_path: Path, server: FakeServer, capsys: pytest.CaptureFixture[str]
) -> None:
    setup = Setup(tmp_path, server.url)

    assert main(["--config", str(setup.config), "--once"]) == 0

    (request,) = server.requests
    assert request.body["source"] == "linux.auth"
    assert "Failed password for root" in request.body["lines"][0]["line"]
    assert json.loads(setup.state.read_text())["files"][str(setup.log)]["offset"] > 0
    assert KEY not in capsys.readouterr().err


def test_a_second_run_sends_nothing_because_the_position_was_committed(
    tmp_path: Path, server: FakeServer
) -> None:
    setup = Setup(tmp_path, server.url)
    main(["--config", str(setup.config), "--once"])

    assert main(["--config", str(setup.config), "--once"]) == 0

    assert len(server.requests) == 1


def test_a_configuration_error_exits_1_with_a_message_and_no_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--config", str(tmp_path / "missing.toml"), "--once"]) == 1

    err = capsys.readouterr().err
    assert "cannot read" in err and "Traceback" not in err


def test_a_rejected_key_exits_2(tmp_path: Path, server: FakeServer) -> None:
    server.default = Reply(401, {"detail": "Invalid or missing agent credentials"})
    setup = Setup(tmp_path, server.url)

    assert main(["--config", str(setup.config), "--once"]) == 2
    assert not setup.state.exists()  # nothing was acknowledged


def test_a_systematically_refused_log_exits_3(tmp_path: Path, server: FakeServer) -> None:
    server.default = Reply(422, {"detail": "nope"})
    setup = Setup(tmp_path, server.url)
    setup.log.write_text("".join(f"line {i}\n" for i in range(50)))

    assert main(["--config", str(setup.config), "--once"]) == 3


def test_an_unreachable_server_in_once_mode_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sentinel_agent.shipper.MAX_BACKOFF_SECONDS", 0.01)
    setup = Setup(tmp_path, "http://127.0.0.1:1")  # nothing listens there

    assert main(["--config", str(setup.config), "--once", "--retries", "2"]) == 4


def test_a_plaintext_remote_server_is_warned_about(
    tmp_path: Path, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    from sentinel_agent.cli import transport_warning

    assert transport_warning("http://127.0.0.1:8000") is None
    assert transport_warning("https://siem.example.org") is None
    assert "plaintext" in (transport_warning("http://192.168.64.1:8000") or "")
