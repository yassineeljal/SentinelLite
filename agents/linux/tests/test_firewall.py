import pytest

from sentinel_agent.firewall import (
    CHAIN,
    FirewallError,
    IptablesBackend,
    LogOnlyBackend,
    parse_networks,
    refusal,
)


@pytest.mark.parametrize("address", ["45.83.64.10", "2a00:1450:4007:80f::200e", "8.8.8.8"])
def test_ordinary_internet_hosts_may_be_blocked(address: str) -> None:
    assert refusal(address, ()) is None


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "10.0.1.5",
        "192.168.1.1",
        "172.16.0.9",
        "169.254.1.1",
        "0.0.0.0",  # noqa: S104
        "224.0.0.1",
        "255.255.255.255",
        "203.0.113.7",  # documentation range
        "::ffff:10.0.0.1",  # a private IPv4 in disguise
        "fe80::1",
        "fc00::1",
    ],
)
def test_other_addresses_are_never_blocked(address: str) -> None:
    assert refusal(address, ()) == "not a public address"


@pytest.mark.parametrize("value", ["", "not-an-ip", "1.2.3", "1.2.3.4; reboot", "1.2.3.4/24", " "])
def test_garbage_is_not_an_address(value: str) -> None:
    assert refusal(value, ()) == "not an IP address"


def test_never_block_wins_and_sees_through_the_ipv4_mapped_form() -> None:
    operator = parse_networks(["45.83.64.0/24"])

    assert refusal("45.83.64.10", operator) == "listed in never_block"
    assert refusal("::ffff:45.83.64.10", operator) == "listed in never_block"
    assert refusal("45.83.65.10", operator) is None


def test_a_bad_never_block_entry_is_named() -> None:
    with pytest.raises(ValueError, match="oops"):
        parse_networks(["10.0.0.0/8", "oops"])


class Recorder:
    """Plays iptables: keeps a set of rules and answers -C / -A / -D / -N / -L / -I."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.rules: set[tuple[str, ...]] = set()
        self.chains: set[tuple[str, str]] = set()
        self.fail_on = fail_on

    def __call__(self, argv: list[str]) -> int:
        self.calls.append(argv)
        program = argv[0].rsplit("/", 1)[-1]
        args = tuple(argv[3:])  # skip program, -w, 5
        if self.fail_on and self.fail_on in args:
            return 1
        key = (program, *args[1:])
        match args[0]:
            case "-n":  # -n -L CHAIN
                return 0 if (program, args[2]) in self.chains else 1
            case "-N":
                self.chains.add((program, args[1]))
                return 0
            case "-C":
                return 0 if key in self.rules else 1
            case "-I" | "-A":
                self.rules.add((program, "-C", *args[1:]) if args[0] == "-I" else key)
                return 0
            case "-D":
                self.rules.discard((program, "-C", *args[1:]))
                self.rules.discard(key)
                return 0
        return 1


@pytest.fixture(autouse=True)
def _fake_programs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/sbin/{name}")


def test_rules_go_through_a_dedicated_chain_and_use_no_shell() -> None:
    run = Recorder()
    backend = IptablesBackend(run)

    backend.prepare()
    backend.block("45.83.64.10")

    added = [c for c in run.calls if "-A" in c]
    assert added == [
        ["/usr/sbin/iptables", "-w", "5", "-A", CHAIN, "-s", "45.83.64.10", "-j", "DROP"]
    ]
    assert any(c[3:] == ["-I", "INPUT", "1", "-j", CHAIN] for c in run.calls)


def test_ipv6_uses_ip6tables_and_the_mapped_form_uses_ipv4() -> None:
    run = Recorder()
    backend = IptablesBackend(run)

    backend.block("2a00:1450:4007:80f::200e")
    backend.block("::ffff:45.83.64.10")

    programs = [c[0].rsplit("/", 1)[-1] for c in run.calls if "-A" in c]
    assert programs == ["ip6tables", "iptables"]
    assert any("45.83.64.10" in c and "::ffff" not in " ".join(c) for c in run.calls)


def test_block_is_idempotent_and_unblock_removes_the_rule() -> None:
    run = Recorder()
    backend = IptablesBackend(run)

    backend.block("45.83.64.10")
    backend.block("45.83.64.10")
    assert sum("-A" in c for c in run.calls) == 1

    backend.unblock("45.83.64.10")
    backend.unblock("45.83.64.10")  # not blocked any more: nothing to do
    assert sum("-D" in c for c in run.calls) == 1


def test_a_refusal_by_the_firewall_is_an_error() -> None:
    backend = IptablesBackend(Recorder(fail_on="-A"))

    with pytest.raises(FirewallError):
        backend.block("45.83.64.10")


def test_a_missing_program_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)

    with pytest.raises(FirewallError, match="not found"):
        IptablesBackend(Recorder()).block("45.83.64.10")


def test_the_backend_refuses_anything_that_is_not_an_address() -> None:
    run = Recorder()
    with pytest.raises(FirewallError):
        IptablesBackend(run).block("1.2.3.4; reboot")
    assert run.calls == []


def test_the_log_only_backend_touches_nothing(caplog: pytest.LogCaptureFixture) -> None:
    backend = LogOnlyBackend()
    with caplog.at_level("WARNING"):
        backend.block("45.83.64.10")
        backend.unblock("45.83.64.10")
    assert "WOULD BLOCK 45.83.64.10" in caplog.text
