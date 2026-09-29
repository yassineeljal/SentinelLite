from pathlib import Path

import pytest

from sentinel_agent.enforcer_cli import main

KEY = "11111111-1111-1111-1111-111111111111." + "k" * 43


def config(tmp_path: Path, response: str) -> Path:
    key_file = tmp_path / "key"
    key_file.write_text(KEY)
    key_file.chmod(0o600)
    path = tmp_path / "agent.toml"
    path.write_text(
        f'[server]\nurl = "http://127.0.0.1:9"\nkey_file = "{key_file}"\n'
        f'[[sources]]\npath = "/var/log/auth.log"\nsource = "linux.auth"\n{response}'
    )
    return path


def test_without_a_response_section_it_refuses_to_start(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--config", str(config(tmp_path, ""))]) == 1
    assert "no [response] section" in capsys.readouterr().err


def test_a_bad_configuration_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = config(tmp_path, '[response]\nbackend = "iptables"\n')

    assert main(["--config", str(path)]) == 1
    assert "never_block" in capsys.readouterr().err


def test_a_revoked_key_exits_with_code_2(tmp_path: Path) -> None:
    from tests.fake_server import FakeServer, Reply

    with FakeServer() as server:
        server.default = Reply(401, {})
        blocks = tmp_path / "b.json"
        path = config(
            tmp_path,
            f'[response]\nbackend = "log"\nnever_block = []\nstate_file = "{blocks}"\n',
        )
        path.write_text(path.read_text().replace("http://127.0.0.1:9", server.url))

        assert main(["--config", str(path)]) == 2
