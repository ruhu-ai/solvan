from __future__ import annotations

from typing import Any

import pytest

from solvan.platform.database import (
    DatabasePoolSettings,
    DatabaseSettings,
    connect_database,
    create_database_pool,
)


class FakeTokenProvider:
    def __init__(self) -> None:
        self.calls = 0

    def token(self) -> str:
        self.calls += 1
        return "short-lived-login-token"


class RotatingTokenProvider:
    def __init__(self) -> None:
        self.calls = 0

    def token(self) -> str:
        self.calls += 1
        return f"short-lived-login-token-{self.calls}"


def test_cloud_sql_iam_connection_uses_unix_socket_and_short_lived_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_connect(*args: Any, **kwargs: Any) -> Any:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr("solvan.platform.database.psycopg.connect", fake_connect)
    settings = DatabaseSettings(
        database_url=None,
        cloud_sql_instance="project:europe-west1:solvan-control",
        database_name="solvan",
        database_user="solvan-actuator@project.iam",
    )

    connect_database(settings, token_provider=FakeTokenProvider())

    assert captured["args"] == ()
    assert captured["kwargs"]["host"] == "/cloudsql/project:europe-west1:solvan-control"
    assert captured["kwargs"]["password"] == "short-lived-login-token"
    assert captured["kwargs"]["sslmode"] == "disable"
    assert "statement_timeout=30000" in captured["kwargs"]["options"]


def test_cloud_sql_bootstrap_connection_uses_explicit_password_without_iam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_connect(*args: Any, **kwargs: Any) -> Any:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr("solvan.platform.database.psycopg.connect", fake_connect)
    settings = DatabaseSettings(
        database_url=None,
        cloud_sql_instance="project:europe-west1:solvan-control",
        database_name="solvan",
        database_user="postgres",
        database_password="bootstrap-only",
    )

    connect_database(settings, token_provider=FakeTokenProvider())

    assert captured["kwargs"]["password"] == "bootstrap-only"


def test_local_url_and_cloud_settings_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        DatabaseSettings(
            database_url="postgresql://localhost/solvan",
            cloud_sql_instance="project:region:instance",
            database_name="solvan",
            database_user="solvan",
        )


def test_incomplete_cloud_sql_settings_fail_closed() -> None:
    with pytest.raises(ValueError, match="complete Cloud SQL"):
        DatabaseSettings(
            database_url=None,
            cloud_sql_instance="project:region:instance",
            database_name=None,
            database_user="solvan",
        )


def test_database_settings_read_local_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLVAN_DATABASE_URL", "postgresql://localhost/solvan")
    settings = DatabaseSettings.from_environment()
    assert settings.database_url == "postgresql://localhost/solvan"
    assert settings.options == (
        "-c statement_timeout=30000 -c lock_timeout=5000 "
        "-c idle_in_transaction_session_timeout=30000"
    )


def test_pool_environment_rejects_non_finite_operands(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "SOLVAN_DB_POOL_MIN_SIZE": "1",
        "SOLVAN_DB_POOL_MAX_SIZE": "4",
        "SOLVAN_DB_POOL_ACQUISITION_TIMEOUT_SECONDS": "5",
        "SOLVAN_DB_POOL_IDLE_LIFETIME_SECONDS": "300",
        "SOLVAN_DB_POOL_MAX_CONNECTION_LIFETIME_SECONDS": "900",
        "SOLVAN_DB_POOL_IAM_TOKEN_LIFETIME_SECONDS": "3600",
        "SOLVAN_DB_POOL_IDENTITY_SAFETY_MARGIN_SECONDS": "nan",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match="finite"):
        DatabasePoolSettings.from_environment()


def _pool_settings() -> DatabasePoolSettings:
    return DatabasePoolSettings(
        min_size=0,
        max_size=4,
        acquisition_timeout_seconds=2,
        idle_lifetime_seconds=60,
        max_connection_lifetime_seconds=300,
        iam_token_lifetime_seconds=3600,
        identity_safety_margin_seconds=60,
    )


def test_pool_settings_require_a_bound_shorter_than_iam_lifetime() -> None:
    with pytest.raises(ValueError, match="lifetime"):
        DatabasePoolSettings(
            min_size=1,
            max_size=1,
            acquisition_timeout_seconds=1,
            idle_lifetime_seconds=1,
            max_connection_lifetime_seconds=60,
            iam_token_lifetime_seconds=60,
            identity_safety_margin_seconds=1,
        )


def test_database_pool_uses_bounded_settings_and_refreshable_password_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakePool:
        def __init__(self, conninfo: str, **kwargs: object) -> None:
            captured["conninfo"] = conninfo
            captured.update(kwargs)

        def open(self, *, wait: bool) -> None:
            captured["wait"] = wait

    monkeypatch.setattr("solvan.platform.database.ConnectionPool", FakePool)
    provider = FakeTokenProvider()
    pool = create_database_pool(
        DatabaseSettings(
            database_url=None,
            cloud_sql_instance="project:europe-west1:solvan-control",
            database_name="solvan",
            database_user="solvan-actuator@project.iam",
        ),
        pool=_pool_settings(),
        token_provider=provider,
    )

    assert pool is not None
    assert captured["max_size"] == 4
    assert captured["min_size"] == 0
    assert captured["max_lifetime"] == 300
    assert captured["max_idle"] == 60
    assert captured["wait"] is False
    assert captured["kwargs"]["host"] == "/cloudsql/project:europe-west1:solvan-control"  # type: ignore[index]
    connection_class = captured["connection_class"]
    assert connection_class is not None
    assert "password" not in captured["kwargs"]  # type: ignore[operator]

    from solvan.platform.database import Connection, _iam_token_connection_class

    calls: dict[str, object] = {}

    def fake_connect(cls: type[Connection[object]], conninfo: str = "", **kwargs: object) -> object:
        calls["conninfo"] = conninfo
        calls["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(Connection, "connect", classmethod(fake_connect))
    _iam_token_connection_class(provider).connect("", host="/cloudsql/test")
    assert calls["kwargs"] == {
        "host": "/cloudsql/test",
        "password": "short-lived-login-token",
    }
    assert provider.calls == 1


def test_local_database_pool_keeps_url_and_base_connection_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakePool:
        def __init__(self, conninfo: str, **kwargs: object) -> None:
            captured["conninfo"] = conninfo
            captured.update(kwargs)

        def open(self, *, wait: bool) -> None:
            captured["wait"] = wait

    monkeypatch.setattr("solvan.platform.database.ConnectionPool", FakePool)
    pool = create_database_pool(
        DatabaseSettings(
            database_url="postgresql://localhost/solvan",
            cloud_sql_instance=None,
            database_name=None,
            database_user=None,
        ),
        pool=_pool_settings(),
    )

    assert pool is not None
    assert captured["conninfo"] == "postgresql://localhost/solvan"
    assert captured["connection_class"] is not None
    assert captured["wait"] is False


def test_cloud_pool_reconnect_mints_a_new_iam_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from solvan.platform.database import Connection, _iam_token_connection_class

    provider = RotatingTokenProvider()
    connection_class = _iam_token_connection_class(provider)
    captured: list[str] = []

    def fake_connect(cls: type[Connection[object]], conninfo: str = "", **kwargs: object) -> object:
        captured.append(str(kwargs["password"]))
        return object()

    monkeypatch.setattr(Connection, "connect", classmethod(fake_connect))
    connection_class.connect("", host="/cloudsql/test")
    connection_class.connect("", host="/cloudsql/test")

    assert captured == [
        "short-lived-login-token-1",
        "short-lived-login-token-2",
    ]


def test_pool_reset_rolls_back_and_clears_session_state() -> None:
    class FakeConnection:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def rollback(self) -> None:
            self.calls.append("rollback")

        def execute(self, statement: str) -> None:
            self.calls.append(statement)

    connection = FakeConnection()
    from solvan.platform.database import _reset_pooled_connection

    _reset_pooled_connection(connection)  # type: ignore[arg-type]
    assert connection.calls == ["rollback", "RESET ALL"]


def test_pool_reset_reinstalls_application_timeouts_after_reset() -> None:
    class FakeConnection:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def rollback(self) -> None:
            self.calls.append(("rollback", None))

        def execute(self, statement: str, params: object = None) -> None:
            self.calls.append((statement, params))

    connection = FakeConnection()
    from solvan.platform.database import _reset_pooled_connection

    settings = DatabaseSettings(
        database_url="postgresql://localhost/solvan",
        cloud_sql_instance=None,
        database_name=None,
        database_user=None,
        statement_timeout_ms=1_000,
        lock_timeout_ms=200,
        idle_transaction_timeout_ms=3_000,
    )
    _reset_pooled_connection(connection, settings=settings)  # type: ignore[arg-type]
    assert connection.calls == [
        ("rollback", None),
        ("RESET ALL", None),
        ("SELECT set_config('statement_timeout', %s, false)", ("1000ms",)),
        ("SELECT set_config('lock_timeout', %s, false)", ("200ms",)),
        (
            "SELECT set_config('idle_in_transaction_session_timeout', %s, false)",
            ("3000ms",),
        ),
        ("SELECT set_config('application_name', %s, false)", ("solvan",)),
    ]
