import json
import threading
import time
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel_agent.actions import ActionClient
from sentinel_agent.blocks import BlockStore
from sentinel_agent.enforcer import AuthenticationError, Enforcer
from sentinel_agent.firewall import FirewallError, parse_networks
from tests.fake_server import FakeServer, Reply

KEY = "11111111-1111-1111-1111-111111111111." + "s" * 43
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
ATTACKER = "45.83.64.10"


class FakeBackend:
    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.log: list[str] = []
        self.fail = False

    def prepare(self) -> None:
        self.log.append("prepare")

    def block(self, address: str) -> None:
        if self.fail:
            raise FirewallError("boom")
        self.blocked.add(address)
        self.log.append(f"block {address}")

    def unblock(self, address: str) -> None:
        if self.fail:
            raise FirewallError("boom")
        self.blocked.discard(address)
        self.log.append(f"unblock {address}")


def action(
    id: int = 1, kind: str = "block", ip: str = ATTACKER, ends: timedelta = timedelta(hours=1)
) -> dict[str, object]:
    return {"id": id, "kind": kind, "ip": ip, "expires_at": (NOW + ends).isoformat()}


@pytest.fixture
def server() -> Generator[FakeServer]:
    with FakeServer() as running:
        yield running


class Rig:
    def __init__(self, server: FakeServer, tmp_path: Path, **options: object) -> None:
        self.server = server
        self.backend = FakeBackend()
        self.store = BlockStore(tmp_path / "blocks.json")
        self.path = tmp_path / "blocks.json"
        self.enforcer = Enforcer(
            ActionClient(server.url, KEY),
            self.backend,
            self.store,
            **options,  # type: ignore[arg-type]
        )

    def offer(self, *actions: dict[str, object]) -> None:
        self.server.default = Reply(200, {"actions": list(actions)})
        # acknowledgments are POSTs to .../ack: a 204 answers them
        self.server.replies = []

    def acks(self) -> list[tuple[str, dict[str, object]]]:
        return [(r.path, r.body) for r in self.server.requests if r.method == "POST"]


@pytest.fixture
def rig(server: FakeServer, tmp_path: Path) -> Rig:
    return Rig(server, tmp_path, never_block=parse_networks(["45.83.99.0/24"]))


def step(rig: Rig, now: datetime = NOW) -> None:
    # One GET answered with the actions, then a 204 for each acknowledgment.
    listing = rig.server.default
    rig.server.replies = [listing] + [Reply(204)] * 10
    rig.enforcer.step(now)


def test_a_block_is_applied_recorded_and_acknowledged(rig: Rig) -> None:
    rig.offer(action())

    step(rig)

    assert rig.backend.blocked == {ATTACKER}
    assert rig.enforcer.store.items() == [(ATTACKER, NOW + timedelta(hours=1))]
    assert rig.acks() == [("/v1/agents/me/actions/1/ack", {"status": "done", "detail": ""})]
    assert rig.server.requests[0].headers["authorization"] == f"Bearer {KEY}"


def test_a_block_that_is_already_in_place_is_acknowledged_again(rig: Rig) -> None:
    rig.offer(action())
    step(rig)
    step(rig)  # the acknowledgment was lost: the same action comes back

    assert rig.backend.blocked == {ATTACKER}
    assert len(rig.enforcer.store) == 1
    assert [a[1]["status"] for a in rig.acks()] == ["done", "done"]


@pytest.mark.parametrize(
    ("ip", "why"),
    [
        ("127.0.0.1", "not a public address"),
        ("10.1.2.3", "not a public address"),
        ("::ffff:192.168.0.1", "not a public address"),
        ("not-an-ip", "not an IP address"),
        ("1.2.3.4; rm -rf /", "not an IP address"),
        ("45.83.99.7", "listed in never_block"),
    ],
)
def test_addresses_that_must_never_be_blocked_are_refused_whoever_asks(
    rig: Rig, ip: str, why: str
) -> None:
    rig.offer(action(ip=ip))

    step(rig)

    assert rig.backend.blocked == set()
    assert len(rig.enforcer.store) == 0
    ((_, body),) = rig.acks()
    assert body == {"status": "failed", "detail": f"refused: {why}"}
    assert rig.enforcer.refused == 1


def test_no_block_outlives_max_ttl(server: FakeServer, tmp_path: Path) -> None:
    rig = Rig(server, tmp_path, max_ttl=timedelta(minutes=10))
    rig.offer(action(ends=timedelta(days=30)))

    step(rig)

    assert rig.enforcer.store.items() == [(ATTACKER, NOW + timedelta(minutes=10))]


def test_the_number_of_active_blocks_is_capped(server: FakeServer, tmp_path: Path) -> None:
    rig = Rig(server, tmp_path, max_blocks=1)
    rig.offer(action(1, ip="45.83.64.1"), action(2, ip="45.83.64.2"), action(3, ip="45.83.64.1"))

    step(rig)

    assert rig.backend.blocked == {"45.83.64.1"}
    assert [a[1]["status"] for a in rig.acks()] == ["done", "failed", "done"]


def test_a_firewall_error_is_reported_and_nothing_is_recorded(rig: Rig) -> None:
    rig.backend.fail = True
    rig.offer(action())

    step(rig)

    assert len(rig.enforcer.store) == 0
    ((_, body),) = rig.acks()
    assert body["status"] == "failed" and "boom" in str(body["detail"])


def test_an_unblock_lifts_the_block(rig: Rig) -> None:
    rig.offer(action())
    step(rig)
    rig.offer(action(2, "unblock"))
    step(rig)

    assert rig.backend.blocked == set()
    assert len(rig.enforcer.store) == 0
    assert rig.acks()[-1][1]["status"] == "done"


def test_an_expired_block_is_lifted_even_when_the_platform_is_unreachable(rig: Rig) -> None:
    rig.offer(action())
    step(rig)
    rig.server.default = Reply(503)

    step(rig, NOW + timedelta(hours=1, seconds=1))

    assert rig.backend.blocked == set()
    assert len(rig.enforcer.store) == 0


def test_a_block_that_cannot_be_lifted_is_kept_and_retried(rig: Rig) -> None:
    rig.offer(action())
    step(rig)
    rig.backend.fail = True
    rig.server.default = Reply(200, {"actions": []})
    later = NOW + timedelta(hours=2)

    step(rig, later)
    assert len(rig.enforcer.store) == 1

    rig.backend.fail = False
    step(rig, later)
    assert len(rig.enforcer.store) == 0


def test_a_revoked_key_stops_the_enforcer(rig: Rig) -> None:
    rig.server.default = Reply(401, {})

    with pytest.raises(AuthenticationError):
        rig.enforcer.step(NOW)


@pytest.mark.parametrize(
    "reply", [Reply(500), Reply(200, {"nope": 1}), Reply(200, {"actions": [{"id": 1}]})]
)
def test_an_unusable_answer_changes_nothing(rig: Rig, reply: Reply) -> None:
    rig.server.default = reply

    rig.enforcer.step(NOW)

    assert rig.backend.log == []
    assert rig.acks() == []


def test_an_unknown_kind_is_never_acted_upon(rig: Rig) -> None:
    rig.offer(action(kind="reboot"))

    rig.enforcer.step(NOW)

    assert rig.backend.log == []


def test_blocks_survive_a_restart_and_are_reapplied(server: FakeServer, tmp_path: Path) -> None:
    first = Rig(server, tmp_path)
    first.offer(action(1), action(2, ip="45.83.64.2", ends=timedelta(seconds=30)))
    step(first)

    second = Rig(server, tmp_path)  # the process restarted, the firewall was reset by a reboot
    second.enforcer.start(NOW + timedelta(minutes=1))

    assert second.backend.blocked == {ATTACKER}  # the one that had not expired
    assert second.backend.log[0] == "prepare"


def test_the_block_file_is_private_and_atomic(server: FakeServer, tmp_path: Path) -> None:
    rig = Rig(server, tmp_path)
    rig.offer(action())
    step(rig)

    assert oct(rig.path.stat().st_mode & 0o777) == "0o600"
    assert json.loads(rig.path.read_text())["blocks"] == {
        ATTACKER: (NOW + timedelta(hours=1)).isoformat()
    }
    assert not list(tmp_path.glob("*.tmp"))


def test_an_unreadable_block_file_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "blocks.json").write_text("{not json")

    assert len(BlockStore(tmp_path / "blocks.json")) == 0


def test_run_loops_until_stopped(rig: Rig) -> None:
    rig.server.default = Reply(200, {"actions": []})
    stop = threading.Event()
    thread = threading.Thread(target=rig.enforcer.run, args=(stop, 0.01))
    thread.start()
    deadline = time.monotonic() + 5
    while len(rig.server.requests) < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert rig.backend.log[0] == "prepare"
