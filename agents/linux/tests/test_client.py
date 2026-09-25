import logging
import socket
from collections.abc import Generator

import pytest

from sentinel_agent.client import (
    Accepted,
    IngestClient,
    Rejected,
    RetryAfter,
    TooLarge,
    Unauthorized,
    Unavailable,
)
from tests.fake_server import FakeServer, Reply

KEY = "11111111-1111-1111-1111-111111111111." + "s" * 43
LINES = [("12:0", "first line"), ("12:11", "second line")]


@pytest.fixture
def server() -> Generator[FakeServer]:
    with FakeServer() as running:
        yield running


def client(server: FakeServer, timeout: float = 5.0) -> IngestClient:
    return IngestClient(server.url, KEY, timeout=timeout)


def test_a_batch_is_posted_with_the_documented_contract(server: FakeServer) -> None:
    server.default = Reply(202, {"accepted": 2})

    result = client(server).send("linux.auth", LINES)

    assert result == Accepted(2)
    (request,) = server.requests
    assert (request.method, request.path) == ("POST", "/v1/ingest")
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["content-type"] == "application/json"
    assert "sentinel-agent" in request.headers["user-agent"]
    assert request.body == {
        "source": "linux.auth",
        "lines": [
            {"origin": "12:0", "line": "first line"},
            {"origin": "12:11", "line": "second line"},
        ],
    }


def test_non_ascii_and_control_characters_survive_the_round_trip(server: FakeServer) -> None:
    text = "café 中文 tab\there \x1b[31m"

    client(server).send("linux.auth", [("1:0", text)])

    assert server.requests[0].body["lines"][0]["line"] == text


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"Retry-After": "7"}, 7.0),
        ({}, 5.0),
        ({"Retry-After": "99999"}, 300.0),
        ({"Retry-After": "x"}, 5.0),
    ],
)
def test_429_asks_the_agent_to_wait(
    server: FakeServer, headers: dict[str, str], expected: float
) -> None:
    server.default = Reply(429, {"detail": "queue full"}, headers)

    assert client(server).send("linux.auth", LINES) == RetryAfter(expected)


def test_401_is_reported_as_unauthorized(server: FakeServer) -> None:
    server.default = Reply(401, {"detail": "Invalid or missing agent credentials"})

    assert client(server).send("linux.auth", LINES) == Unauthorized()


def test_413_means_the_batch_is_too_large(server: FakeServer) -> None:
    server.default = Reply(413, {"detail": "Request body too large"})

    assert isinstance(client(server).send("linux.auth", LINES), TooLarge)


@pytest.mark.parametrize("status", [400, 404, 422])
def test_other_client_errors_mean_this_payload_cannot_be_accepted(
    server: FakeServer, status: int
) -> None:
    server.default = Reply(status, {"detail": "x" * 5000})

    result = client(server).send("linux.auth", LINES)

    assert isinstance(result, Rejected)
    assert len(result.detail) <= 300  # bounded: it goes to the logs


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_errors_are_retryable(server: FakeServer, status: int) -> None:
    server.default = Reply(status, {"detail": "boom"})

    assert isinstance(client(server).send("linux.auth", LINES), Unavailable)


def test_a_refused_connection_is_retryable() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    # nothing listens on `port` any more

    result = IngestClient(f"http://127.0.0.1:{port}", KEY, timeout=2).send("linux.auth", LINES)

    assert isinstance(result, Unavailable)


def test_a_server_that_does_not_answer_is_retryable(server: FakeServer) -> None:
    server.default = Reply(202, delay=1.5)

    assert isinstance(client(server, timeout=0.3).send("linux.auth", LINES), Unavailable)


def test_redirects_are_never_followed_so_the_key_cannot_leak(server: FakeServer) -> None:
    server.default = Reply(302, {}, {"Location": "http://elsewhere.invalid/v1/ingest"})

    result = client(server).send("linux.auth", LINES)

    assert isinstance(result, Unavailable)
    assert len(server.requests) == 1


def test_the_key_never_appears_in_logs_or_representations(
    server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    server.default = Reply(500, {"detail": "boom"})
    caplog.set_level(logging.DEBUG)

    http_client = client(server)
    http_client.send("linux.auth", LINES)

    assert KEY not in repr(http_client) and KEY not in caplog.text
    assert "s" * 43 not in caplog.text
