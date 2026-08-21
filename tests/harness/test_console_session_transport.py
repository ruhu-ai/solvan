"""The console proxy, exercised as the process that ships (specification 05 §4.2).

The deployed console could not sign anybody in, and no test noticed. The proxy
forwarded neither the browser's cookies nor the headers that authorize a
mutation, and returned neither `Set-Cookie` nor `Location` — so sign-in could
not start, a session could not be established, and every later request arrived
unauthenticated. Development did not reproduce it because the console called the
API's own origin directly and skipped this proxy entirely.

These start the real `server.mjs` against a stub upstream and assert the round
trip. Reading the source for a string would pass against a proxy that never ran.
"""

from __future__ import annotations

import base64
import json
import socket
import subprocess
import time
from collections.abc import Iterator
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import ClassVar
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

CONSOLE = Path(__file__).parents[2] / "apps" / "console"
#: `server.mjs` parses the identity token's payload for its expiry, so the stub
#: must return something shaped like a JWT rather than an opaque string.
_PAYLOAD = (
    base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + 3600}).encode())
    .decode()
    .rstrip("=")
)
FAKE_IDENTITY_TOKEN = f"header.{_PAYLOAD}.signature"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _Upstream(BaseHTTPRequestHandler):
    """Stands in for the metadata server and the API, recording what it is sent."""

    seen: ClassVar[dict[str, str]] = {}

    def do_GET(self) -> None:
        if self.path.startswith("/computeMetadata"):
            self._respond(200, FAKE_IDENTITY_TOKEN.encode(), {})
            return
        type(self).seen = {key.lower(): value for key, value in self.headers.items()}
        if self.path.startswith("/api/auth/callback"):
            # Exactly what the real callback returns: a redirect that also sets
            # the session and the double-submit token together.
            self._respond(
                303,
                b"",
                {
                    "Location": "/incidents",
                    "Set-Cookie": [
                        "__Host-solvan_session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax",
                        "__Host-solvan_csrf=double-submit; Path=/; Secure; SameSite=Lax",
                    ],
                },
            )
            return
        self._respond(200, b'{"ok":true}', {"Content-Type": "application/json"})

    def do_POST(self) -> None:
        self.do_GET()

    def _respond(self, status: int, body: bytes, headers: dict[str, object]) -> None:
        self.send_response(status)
        for name, value in headers.items():
            for item in value if isinstance(value, list) else [value]:
                self.send_header(name, str(item))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def console() -> Iterator[str]:
    """The real console process, proxying to a stub upstream."""

    upstream_port, console_port = _free_port(), _free_port()
    upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), _Upstream)
    Thread(target=upstream.serve_forever, daemon=True).start()
    process = subprocess.Popen(
        ["node", "server.mjs"],
        cwd=CONSOLE,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "PORT": str(console_port),
            "SOLVAN_API_UPSTREAM": f"http://127.0.0.1:{upstream_port}",
            "SOLVAN_API_AUDIENCE": "console-test-audience",
            "GCE_METADATA_HOST": f"127.0.0.1:{upstream_port}",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{console_port}"
    for _ in range(100):
        if process.poll() is not None:
            pytest.fail(f"console exited: {process.communicate()[1].decode()}")
        try:
            urlopen(f"{base}/api/ping", timeout=1).read()
            break
        except HTTPError:
            break
        except OSError:
            time.sleep(0.05)
    try:
        yield base
    finally:
        process.terminate()
        process.wait(timeout=10)
        upstream.shutdown()


def test_the_callback_returns_every_cookie_and_its_redirect(console: str) -> None:
    """Sign-in is a redirect that sets two cookies. Dropping either ends the flow.

    `Headers.get("set-cookie")` joins repeated headers with a comma, which is
    also legal inside a cookie's `Expires`, so a proxy reading it that way hands
    the browser one malformed cookie instead of two good ones.
    """

    # A raw connection, because the redirect itself is the thing under test and
    # every convenience client follows it before it can be inspected.
    host, port = console.removeprefix("http://").split(":")
    connection = HTTPConnection(host, int(port), timeout=10)
    connection.request("GET", "/api/auth/callback?code=x&state=y")
    response = connection.getresponse()
    cookies = response.headers.get_all("Set-Cookie") or []
    location = response.headers.get("Location")
    response.read()
    connection.close()

    assert response.status == 303
    assert location == "/incidents", "the browser is left with nowhere to go"
    names = {cookie.split("=", 1)[0] for cookie in cookies}
    assert names == {"__Host-solvan_session", "__Host-solvan_csrf"}


def test_the_session_cookie_and_action_headers_reach_the_api(console: str) -> None:
    """Carrying these only on the handshake left every later request anonymous."""

    request = Request(
        f"{console}/api/auth/session",
        headers={
            "Cookie": "__Host-solvan_session=opaque; __Host-solvan_csrf=double-submit",
            "X-Solvan-CSRF": "double-submit",
            "X-Solvan-Challenge": "chg_example",
        },
    )
    urlopen(request, timeout=10).read()

    seen = _Upstream.seen
    assert "__Host-solvan_session=opaque" in seen.get("cookie", "")
    # Without these the API refuses every mutation as cross-site before it runs.
    assert seen.get("x-solvan-csrf") == "double-submit"
    assert seen.get("x-solvan-challenge") == "chg_example"
