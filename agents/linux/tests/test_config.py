import os
from pathlib import Path

import pytest

from sentinel_agent.config import ConfigError, load_config

KEY = "11111111-1111-1111-1111-111111111111." + "a" * 43

VALID = """
[server]
url = "http://192.168.64.1:8000"
key_file = "{key_file}"

[agent]
state_file = "{state_file}"

[[sources]]
path = "/var/log/auth.log"
source = "linux.auth"
"""


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / "key"
    path.write_text(KEY + "\n")
    path.chmod(0o600)
    return path


def write(tmp_path: Path, key_file: Path, extra: str = "", body: str = VALID) -> Path:
    config = tmp_path / "agent.toml"
    config.write_text(body.format(key_file=key_file, state_file=tmp_path / "state.json") + extra)
    return config


def test_a_valid_configuration_is_loaded_with_defaults(tmp_path: Path, key_file: Path) -> None:
    config = load_config(write(tmp_path, key_file), environ={})

    assert config.server_url == "http://192.168.64.1:8000"
    assert config.key == KEY  # surrounding whitespace stripped
    assert [(s.path, s.source) for s in config.sources] == [
        (Path("/var/log/auth.log"), "linux.auth")
    ]
    assert (config.batch_lines, config.batch_bytes) == (200, 1_048_576)
    assert config.start_at == "end"
    assert config.poll_interval == 0.5


def test_the_key_can_come_from_the_environment(tmp_path: Path) -> None:
    body = VALID.replace('key_file = "{key_file}"\n', "")
    config = load_config(write(tmp_path, tmp_path, body=body), environ={"SENTINEL_AGENT_KEY": KEY})

    assert config.key == KEY


def test_the_key_is_never_accepted_inline_in_the_configuration(
    tmp_path: Path, key_file: Path
) -> None:
    with pytest.raises(ConfigError, match="key"):
        load_config(write(tmp_path, key_file, body=VALID.replace("url =", f'key = "{KEY}"\nurl =')))


def test_a_missing_key_is_an_error(tmp_path: Path) -> None:
    body = VALID.replace('key_file = "{key_file}"\n', "")

    with pytest.raises(ConfigError, match="key"):
        load_config(write(tmp_path, tmp_path, body=body), environ={})


def test_a_key_file_readable_by_others_is_refused(tmp_path: Path, key_file: Path) -> None:
    key_file.chmod(0o644)

    with pytest.raises(ConfigError, match="permissions"):
        load_config(write(tmp_path, key_file), environ={})


def test_a_malformed_key_is_refused(tmp_path: Path, key_file: Path) -> None:
    key_file.write_text("not-a-key")

    with pytest.raises(ConfigError, match="key"):
        load_config(write(tmp_path, key_file), environ={})


@pytest.mark.parametrize(
    "url", ["ftp://host", "192.168.64.1:8000", "http://", "http://host/with/path?x=1", ""]
)
def test_bad_server_urls_are_refused(tmp_path: Path, key_file: Path, url: str) -> None:
    body = VALID.replace("http://192.168.64.1:8000", url)

    with pytest.raises(ConfigError, match="url"):
        load_config(write(tmp_path, key_file, body=body), environ={})


@pytest.mark.parametrize(
    "extra",
    [
        '\n[[sources]]\npath = "/var/log/x.log"\nsource = "windows.sysmon"\n',  # not a Linux source
        '\n[[sources]]\npath = "/var/log/auth.log"\nsource = "linux.auth"\n',  # duplicate path
        '\n[[sources]]\npath = "relative.log"\nsource = "linux.auth"\n',  # not absolute
    ],
)
def test_bad_sources_are_refused(tmp_path: Path, key_file: Path, extra: str) -> None:
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, key_file, extra), environ={})


def test_at_least_one_source_is_required(tmp_path: Path, key_file: Path) -> None:
    body = VALID.split("[[sources]]")[0]

    with pytest.raises(ConfigError, match="source"):
        load_config(write(tmp_path, key_file, body=body), environ={})


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("batch_lines", 0),
        ("batch_lines", 501),  # the API accepts at most 500 lines per request
        ("batch_bytes", 100),
        ("batch_bytes", 8_000_000),  # the API rejects bodies above 8 MiB
        ("poll_interval", 0),
        ("start_at", '"middle"'),
    ],
)
def test_out_of_range_settings_are_refused(
    tmp_path: Path, key_file: Path, setting: str, value: object
) -> None:
    body = VALID.replace("[[sources]]", f"{setting} = {value}\n\n[[sources]]", 1)

    with pytest.raises(ConfigError, match=setting):
        load_config(write(tmp_path, key_file, body=body), environ={})


def test_unknown_keys_are_refused_so_typos_do_not_pass_silently(
    tmp_path: Path, key_file: Path
) -> None:
    body = VALID.replace("[[sources]]", "batchlines = 10\n\n[[sources]]", 1)

    with pytest.raises(ConfigError, match="batchlines"):
        load_config(write(tmp_path, key_file, body=body), environ={})


def test_a_missing_or_invalid_file_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.toml", environ={})
    broken = tmp_path / "broken.toml"
    broken.write_text("this is [not toml")
    with pytest.raises(ConfigError, match="TOML"):
        load_config(broken, environ={})


def test_the_environment_is_the_real_one_by_default(
    tmp_path: Path, key_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = VALID.replace('key_file = "{key_file}"\n', "")
    monkeypatch.setenv("SENTINEL_AGENT_KEY", KEY)

    assert load_config(write(tmp_path, tmp_path, body=body)).key == KEY
    assert os.environ["SENTINEL_AGENT_KEY"] == KEY
