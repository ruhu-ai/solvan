"""Cloud SQL IAM and local PostgreSQL connection composition."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any, Protocol, cast

import google.auth
import psycopg
from google.auth.transport.requests import Request as GoogleAuthRequest
from psycopg import Connection
from psycopg_pool import ConnectionPool

SQL_LOGIN_SCOPE = "https://www.googleapis.com/auth/sqlservice.login"


class SqlLoginTokenProvider(Protocol):
    def token(self) -> str: ...


class GoogleSqlLoginTokenProvider:
    """Mint a short-lived password accepted by Cloud SQL IAM DB auth."""

    def token(self) -> str:
        credentials, _project = google.auth.default(scopes=[SQL_LOGIN_SCOPE])
        credentials.refresh(GoogleAuthRequest())  # type: ignore[no-untyped-call]
        if not credentials.token:
            raise RuntimeError("Google credentials returned no SQL login token")
        return cast(str, credentials.token)


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    database_url: str | None
    cloud_sql_instance: str | None
    database_name: str | None
    database_user: str | None
    database_password: str | None = None
    statement_timeout_ms: int = 30_000
    lock_timeout_ms: int = 5_000
    idle_transaction_timeout_ms: int = 30_000

    def __post_init__(self) -> None:
        cloud_values = (self.cloud_sql_instance, self.database_name, self.database_user)
        if self.database_url and any(cloud_values):
            raise ValueError("database URL and Cloud SQL IAM settings are mutually exclusive")
        if not self.database_url and not all(cloud_values):
            raise ValueError("database URL or complete Cloud SQL IAM settings are required")
        if (
            min(
                self.statement_timeout_ms,
                self.lock_timeout_ms,
                self.idle_transaction_timeout_ms,
            )
            < 1
        ):
            raise ValueError("database timeouts must be positive")

    @classmethod
    def from_environment(cls) -> DatabaseSettings:
        database_url = os.environ.get("SOLVAN_DATABASE_URL")
        return cls(
            database_url=database_url,
            cloud_sql_instance=None
            if database_url
            else os.environ.get("SOLVAN_CLOUD_SQL_INSTANCE"),
            database_name=None if database_url else os.environ.get("SOLVAN_DATABASE_NAME"),
            database_user=None if database_url else os.environ.get("SOLVAN_DATABASE_USER"),
            database_password=None if database_url else os.environ.get("SOLVAN_DATABASE_PASSWORD"),
        )

    @property
    def options(self) -> str:
        return " ".join(
            (
                f"-c statement_timeout={self.statement_timeout_ms}",
                f"-c lock_timeout={self.lock_timeout_ms}",
                f"-c idle_in_transaction_session_timeout={self.idle_transaction_timeout_ms}",
            )
        )


@dataclass(frozen=True, slots=True)
class DatabasePoolSettings:
    """Immutable bounded-pool operands from the active cell profile."""

    min_size: int
    max_size: int
    acquisition_timeout_seconds: float
    idle_lifetime_seconds: float
    max_connection_lifetime_seconds: float
    iam_token_lifetime_seconds: float
    identity_safety_margin_seconds: float

    @classmethod
    def from_environment(cls) -> DatabasePoolSettings:
        """Load an immutable pool profile; missing production operands refuse."""

        def required(name: str) -> str:
            value = os.environ.get(name)
            if value is None or not value.strip():
                raise ValueError(f"{name} is required for bounded database pools")
            return value

        def integer(name: str) -> int:
            try:
                return int(required(name))
            except ValueError as error:
                raise ValueError(f"{name} must be an integer") from error

        def number(name: str) -> float:
            try:
                value = float(required(name))
            except ValueError as error:
                raise ValueError(f"{name} must be numeric") from error
            if not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
            return value

        return cls(
            min_size=integer("SOLVAN_DB_POOL_MIN_SIZE"),
            max_size=integer("SOLVAN_DB_POOL_MAX_SIZE"),
            acquisition_timeout_seconds=number("SOLVAN_DB_POOL_ACQUISITION_TIMEOUT_SECONDS"),
            idle_lifetime_seconds=number("SOLVAN_DB_POOL_IDLE_LIFETIME_SECONDS"),
            max_connection_lifetime_seconds=number(
                "SOLVAN_DB_POOL_MAX_CONNECTION_LIFETIME_SECONDS"
            ),
            iam_token_lifetime_seconds=number("SOLVAN_DB_POOL_IAM_TOKEN_LIFETIME_SECONDS"),
            identity_safety_margin_seconds=number("SOLVAN_DB_POOL_IDENTITY_SAFETY_MARGIN_SECONDS"),
        )

    def __post_init__(self) -> None:
        if self.min_size < 0 or self.max_size <= 0 or self.min_size > self.max_size:
            raise ValueError("database pool bounds are invalid")
        if (
            min(
                self.acquisition_timeout_seconds,
                self.idle_lifetime_seconds,
                self.max_connection_lifetime_seconds,
                self.iam_token_lifetime_seconds,
                self.identity_safety_margin_seconds,
            )
            <= 0
        ):
            raise ValueError("database pool lifetimes and timeout must be positive")
        if (
            self.max_connection_lifetime_seconds + self.identity_safety_margin_seconds
            >= self.iam_token_lifetime_seconds
        ):
            raise ValueError("pooled connection lifetime must precede IAM token expiry")


def connect_database(
    settings: DatabaseSettings | None = None,
    *,
    token_provider: SqlLoginTokenProvider | None = None,
) -> Connection[Any]:
    """Open one bounded connection without retaining a token past its lifetime."""

    resolved = settings or DatabaseSettings.from_environment()
    common: dict[str, Any] = {
        "connect_timeout": 10,
        "options": resolved.options,
        "application_name": "solvan",
    }
    if resolved.database_url:
        return psycopg.connect(resolved.database_url, **common)
    if resolved.database_password is not None:
        return psycopg.connect(
            host=f"/cloudsql/{resolved.cloud_sql_instance}",
            dbname=resolved.database_name,
            user=resolved.database_user,
            password=resolved.database_password,
            sslmode="disable",
            **common,
        )
    provider = token_provider or GoogleSqlLoginTokenProvider()
    return psycopg.connect(
        host=f"/cloudsql/{resolved.cloud_sql_instance}",
        dbname=resolved.database_name,
        user=resolved.database_user,
        password=provider.token(),
        sslmode="disable",
        **common,
    )


def _reset_pooled_connection(
    connection: Connection[Any], *, settings: DatabaseSettings | None = None
) -> None:
    """Destroy session-local authority before a connection can be reused."""

    try:
        connection.rollback()
        # Application code must use SET LOCAL for tenant context.  RESET ALL
        # is a final defense against a connector or future code accidentally
        # leaving session state on a pooled connection.
        connection.execute("RESET ALL")
        if settings is None:
            return
        restored = settings
        connection.execute(
            "SELECT set_config('statement_timeout', %s, false)",
            (f"{restored.statement_timeout_ms}ms",),
        )
        connection.execute(
            "SELECT set_config('lock_timeout', %s, false)",
            (f"{restored.lock_timeout_ms}ms",),
        )
        connection.execute(
            "SELECT set_config('idle_in_transaction_session_timeout', %s, false)",
            (f"{restored.idle_transaction_timeout_ms}ms",),
        )
        connection.execute(
            "SELECT set_config('application_name', %s, false)",
            ("solvan",),
        )
    except Exception:
        # psycopg-pool treats an exception from reset as a broken connection
        # and discards it rather than returning dirty authority to the pool.
        raise


def _iam_token_connection_class(provider: SqlLoginTokenProvider) -> type[Connection[Any]]:
    """Build a psycopg connection class that mints IAM per connection."""

    class IamTokenConnection(Connection[Any]):
        @classmethod
        def connect(  # type: ignore[override]
            cls,
            conninfo: str = "",
            **kwargs: Any,
        ) -> Connection[Any]:
            params = dict(kwargs)
            params["password"] = provider.token()
            return super().connect(conninfo, **params)

    return IamTokenConnection


def create_database_pool(
    settings: DatabaseSettings | None = None,
    *,
    pool: DatabasePoolSettings,
    token_provider: SqlLoginTokenProvider | None = None,
) -> ConnectionPool[Any]:
    """Create an opened, bounded pool with per-connection IAM token minting.

    ``psycopg`` does not accept a password callback: it would serialize a
    callable's repr into conninfo.  The Cloud SQL path therefore supplies a
    small connection subclass whose ``connect`` method mints a fresh IAM
    login token for every replacement connection.  The pool's maximum
    lifetime remains below the token lifetime and configured safety margin.
    """

    resolved = settings or DatabaseSettings.from_environment()
    common: dict[str, Any] = {
        "connect_timeout": 10,
        "options": resolved.options,
        "application_name": "solvan",
    }
    if resolved.database_url:
        conninfo = resolved.database_url
        connection_class: type[Connection[Any]] = Connection
    elif resolved.database_password is not None:
        conninfo = ""
        common.update(
            {
                "host": f"/cloudsql/{resolved.cloud_sql_instance}",
                "dbname": resolved.database_name,
                "user": resolved.database_user,
                "password": resolved.database_password,
                "sslmode": "disable",
            }
        )
        connection_class = Connection
    else:
        provider = token_provider or GoogleSqlLoginTokenProvider()
        conninfo = ""
        common.update(
            {
                "host": f"/cloudsql/{resolved.cloud_sql_instance}",
                "dbname": resolved.database_name,
                "user": resolved.database_user,
                "sslmode": "disable",
            }
        )

        connection_class = _iam_token_connection_class(provider)
    result: ConnectionPool[Any] = ConnectionPool(
        conninfo,
        connection_class=connection_class,
        kwargs=common,
        min_size=pool.min_size,
        max_size=pool.max_size,
        timeout=pool.acquisition_timeout_seconds,
        max_lifetime=pool.max_connection_lifetime_seconds,
        max_idle=pool.idle_lifetime_seconds,
        reset=lambda connection: _reset_pooled_connection(connection, settings=resolved),
        open=False,
        name="solvan",
    )
    result.open(wait=False)
    return result


class DatabasePoolConnectionFactory:
    """Lifecycle-owned connection context factory for a service composition root."""

    def __init__(
        self,
        settings: DatabaseSettings | None = None,
        *,
        pool: DatabasePoolSettings,
        token_provider: SqlLoginTokenProvider | None = None,
    ) -> None:
        self._pool = create_database_pool(settings, pool=pool, token_provider=token_provider)

    def __call__(self) -> Any:
        return self._pool.connection()

    def close(self) -> None:
        self._pool.close()
