"""The session seam every reader route consumes (specification 05 §4.2).

A reader route resolves who is asking session-first, and the resolution must
cost nothing when no session is offered: a cookie-less request never opens a
query, because every unauthenticated request before this one proved that the
expensive ordering is the one that leaks work.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import Request

from apps.api.session_authorization import SESSION_COOKIE, session_reader_principal


def _request(cookie: str | None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if cookie is not None:
        headers.append((b"cookie", f"{SESSION_COOKIE}={cookie}".encode()))
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


class _UnusedConnection:
    def execute(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("a request offering no session must run no query")


class _Result:
    def __init__(self, row: Any) -> None:
        self._row = row

    def fetchone(self) -> Any:
        return self._row


class _IdentityConnection:
    """Answers the one identity lookup `recorded_principal` performs."""

    def __init__(self, row: Any) -> None:
        self._row = row
        self.queries: list[str] = []

    def execute(self, query: str, _params: Any = None) -> _Result:
        self.queries.append(query)
        return _Result(self._row)


def _sessions(monkeypatch: pytest.MonkeyPatch, live: Any) -> None:
    class _Store:
        def __init__(self, _connection: Any) -> None: ...

        def touch(self, *, credential_hash: str, now: Any) -> Any:
            return live

    monkeypatch.setattr("apps.api.session_authorization.OperatorSessionStore", _Store)


def test_no_session_cookie_resolves_nothing_and_costs_nothing() -> None:
    assert session_reader_principal(_UnusedConnection(), _request(None)) is None  # type: ignore[arg-type]


def test_a_live_session_resolves_the_recorded_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sessions(monkeypatch, SimpleNamespace(actor_id="act_1", session_id="ses_1"))
    connection = _IdentityConnection(("reader@example.com",))

    principal = session_reader_principal(connection, _request("credential"))  # type: ignore[arg-type]

    assert principal == "user:reader@example.com"
    assert len(connection.queries) == 1


def test_a_dead_session_resolves_nothing_without_an_identity_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sessions(monkeypatch, None)
    connection = _IdentityConnection(("reader@example.com",))

    assert session_reader_principal(connection, _request("credential")) is None  # type: ignore[arg-type]
    assert connection.queries == []


def test_an_actor_without_an_identity_row_falls_back_to_the_actor_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sessions(monkeypatch, SimpleNamespace(actor_id="act_1", session_id="ses_1"))

    principal = session_reader_principal(_IdentityConnection(None), _request("credential"))  # type: ignore[arg-type]

    assert principal == "actor:act_1"
