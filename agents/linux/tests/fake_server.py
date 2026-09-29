"""A real HTTP server (in a thread) that plays back scripted answers and records requests."""

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class Reply:
    status: int = 202
    body: dict[str, Any] = field(default_factory=lambda: {"accepted": 0})
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


class FakeServer:
    def __init__(self) -> None:
        self.requests: list[Recorded] = []
        self.replies: list[Reply] = []  # consumed in order; the last one repeats
        self.default = Reply()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._serve("GET")

            def do_POST(self) -> None:
                self._serve("POST")

            def _serve(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = raw
                outer.requests.append(
                    Recorded(
                        method, self.path, {k.lower(): v for k, v in self.headers.items()}, body
                    )
                )
                reply = outer.replies.pop(0) if outer.replies else outer.default
                if reply.delay:
                    time.sleep(reply.delay)
                payload = b"" if reply.status == 204 else json.dumps(reply.body).encode()
                self.send_response(reply.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for name, value in reply.headers.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except OSError:
                    pass  # the client gave up (timeout test)

            def log_message(self, *args: object) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.02), daemon=True
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "FakeServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
