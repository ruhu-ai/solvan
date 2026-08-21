"""Real PostgreSQL pool behavior for healthy and connection-leaking revisions."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from psycopg import Connection
from psycopg.errors import UndefinedTable
from psycopg_pool import PoolTimeout


class PaymentUnavailable(RuntimeError):
    """The fixture cannot obtain a database connection within its bounded timeout."""


class PoolPreconditionFailed(RuntimeError):
    """The caller observed a different pool generation before requesting recycle."""


class PoolLike(Protocol):
    def getconn(self, timeout: float | None = None) -> Connection[Any]: ...

    def putconn(self, connection: Connection[Any]) -> None: ...

    def close(self) -> None: ...


class BoundedConnectionPool:
    """Small pool that obtains a fresh IAM token whenever it opens a connection."""

    def __init__(
        self,
        *,
        connection_factory: Callable[[], Connection[Any]],
        min_size: int = 1,
        max_size: int = 4,
    ) -> None:
        if min_size < 0 or max_size < 1 or min_size > max_size:
            raise ValueError("connection pool size is invalid")
        self._connection_factory = connection_factory
        self._max_size = max_size
        self._condition = threading.Condition(threading.RLock())
        self._available: list[Connection[Any]] = []
        self._created = 0
        self._closed = False
        for _index in range(min_size):
            self._available.append(connection_factory())
            self._created += 1

    def getconn(self, timeout: float | None = None) -> Connection[Any]:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            create = False
            with self._condition:
                if self._closed:
                    raise RuntimeError("connection pool is closed")
                while self._available:
                    connection = self._available.pop()
                    if connection.closed:
                        self._created -= 1
                        continue
                    return connection
                if self._created < self._max_size:
                    self._created += 1
                    create = True
                else:
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        raise PoolTimeout("connection pool exhausted")
                    self._condition.wait(remaining)
            if create:
                try:
                    return self._connection_factory()
                except Exception:
                    with self._condition:
                        self._created -= 1
                        self._condition.notify()
                    raise

    def putconn(self, connection: Connection[Any]) -> None:
        with self._condition:
            if self._closed or connection.closed:
                if not connection.closed:
                    connection.close()
                self._created -= 1
            else:
                self._available.append(connection)
            self._condition.notify()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            for connection in self._available:
                connection.close()
            self._created -= len(self._available)
            self._available.clear()
            self._condition.notify_all()


@dataclass(frozen=True, slots=True)
class PaymentResult:
    payment_id: str
    duplicate: bool
    revision: str


@dataclass(frozen=True, slots=True)
class RecycleResult:
    action_id: str
    request_id: str
    before_generation: str
    after_generation: str
    duplicate: bool


class PaymentsFixtureService:
    """One-instance demo service whose bad revision leaks checked-out connections."""

    def __init__(
        self,
        *,
        database_url: str | None,
        revision: str,
        connection_factory: Callable[[], Connection[Any]] | None = None,
        pool_factory: Callable[[], PoolLike] | None = None,
        checkout_timeout_seconds: float = 0.25,
    ) -> None:
        if connection_factory is None:
            if database_url is None:
                raise ValueError("database URL or connection factory is required")

            def local_connection() -> Connection[Any]:
                return Connection.connect(database_url)

            connection_factory = local_connection
        self._connection_factory = connection_factory
        self._revision = revision
        self._defective = revision == "v2.8.1"
        self._pool_factory = pool_factory or (
            lambda: BoundedConnectionPool(
                connection_factory=self._connection_factory,
                min_size=1,
                max_size=4,
            )
        )
        self._checkout_timeout_seconds = checkout_timeout_seconds
        self._lock = threading.RLock()
        self._pool = self._pool_factory()
        self._leaked: list[Connection[Any]] = []
        self._generation = 1
        self._schema_ready = False

    @property
    def revision(self) -> str:
        return self._revision

    @property
    def pool_generation(self) -> str:
        with self._lock:
            return f"pool-generation-{self._generation}"

    @property
    def leaked_connection_count(self) -> int:
        with self._lock:
            return len(self._leaked)

    def initialize_schema(self) -> None:
        with self._connection_factory() as connection:
            row = connection.execute(
                """SELECT state_value FROM solvan.fixture_runtime_state
                  WHERE state_key = 'pool_generation'"""
            ).fetchone()
            if row is None:  # pragma: no cover - row was inserted in this transaction
                raise RuntimeError("pool generation state is missing")
            self._generation = int(row[0])
        with self._lock:
            self._schema_ready = True

    def ensure_initialized(self) -> None:
        """Read the generation now if startup could not.

        The release creates this service before it runs the migration that
        creates solvan.fixture_runtime_state, so a cold start can legitimately
        find no table. Refusing to start there would mean the revision never
        becomes ready and the release never reaches the migration at all, so the
        read is retried here and the request is refused until it succeeds.
        """

        with self._lock:
            if self._schema_ready:
                return
        try:
            self.initialize_schema()
        except UndefinedTable as error:
            raise PaymentUnavailable("payments fixture schema is not migrated yet") from error

    def create_synthetic_payment(
        self, *, idempotency_key: str, payment_id: str, amount_minor: int
    ) -> PaymentResult:
        if amount_minor < 1:
            raise ValueError("synthetic amount must be positive")
        self.ensure_initialized()
        try:
            connection = self._pool.getconn(timeout=self._checkout_timeout_seconds)
        except PoolTimeout as error:
            raise PaymentUnavailable("payments connection pool exhausted") from error
        duplicate = False
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO solvan.fixture_payments
                      (idempotency_key, payment_id, fixture_tenant, amount_minor, revision)
                      VALUES (%s, %s, 'solvan-synthetic', %s, %s)
                      ON CONFLICT (idempotency_key) DO NOTHING
                      RETURNING payment_id""",
                    (idempotency_key, payment_id, amount_minor, self._revision),
                )
                duplicate = cursor.fetchone() is None
                if duplicate:
                    cursor.execute(
                        """SELECT payment_id FROM solvan.fixture_payments
                          WHERE idempotency_key = %s""",
                        (idempotency_key,),
                    )
                    existing = cursor.fetchone()
                    if existing is None:  # pragma: no cover - unique row just conflicted
                        raise RuntimeError("idempotent payment row disappeared")
                    payment_id = str(existing[0])
            connection.commit()
            return PaymentResult(payment_id, duplicate, self._revision)
        finally:
            if self._defective:
                with self._lock:
                    self._leaked.append(connection)
            else:
                self._pool.putconn(connection)

    def recycle_pool(
        self,
        *,
        action_id: str,
        idempotency_key: str,
        expected_generation: str,
        request_id: str,
    ) -> RecycleResult:
        with self._lock:
            existing = self._load_recycle(idempotency_key)
            if existing is not None:
                return existing
            before = self.pool_generation
            if before != expected_generation:
                raise PoolPreconditionFailed(
                    f"expected {expected_generation}; current generation is {before}"
                )
            for connection in self._leaked:
                connection.close()
            self._leaked.clear()
            self._pool.close()
            self._pool = self._pool_factory()
            self._generation += 1
            after = self.pool_generation
            with self._connection_factory() as connection:
                connection.execute(
                    """INSERT INTO solvan.fixture_admin_actions
                      (idempotency_key, action_id, request_id, before_generation,
                       after_generation, result)
                      VALUES (%s, %s, %s, %s, %s, 'EFFECT_CONFIRMED')""",
                    (idempotency_key, action_id, request_id, before, after),
                )
                connection.execute(
                    """UPDATE solvan.fixture_runtime_state
                      SET state_value = %s, updated_at = now()
                      WHERE state_key = 'pool_generation'""",
                    (self._generation,),
                )
            return RecycleResult(action_id, request_id, before, after, False)

    def action_status(self, action_id: str) -> RecycleResult | None:
        with self._connection_factory() as connection:
            row = connection.execute(
                """SELECT action_id, request_id, before_generation, after_generation
                  FROM solvan.fixture_admin_actions WHERE action_id = %s""",
                (action_id,),
            ).fetchone()
        if row is None:
            return None
        return RecycleResult(str(row[0]), str(row[1]), str(row[2]), str(row[3]), True)

    def close(self) -> None:
        with self._lock:
            for connection in self._leaked:
                connection.close()
            self._leaked.clear()
            self._pool.close()

    def _load_recycle(self, idempotency_key: str) -> RecycleResult | None:
        with self._connection_factory() as connection:
            row = connection.execute(
                """SELECT action_id, request_id, before_generation, after_generation
                  FROM solvan.fixture_admin_actions WHERE idempotency_key = %s""",
                (idempotency_key,),
            ).fetchone()
        if row is None:
            return None
        return RecycleResult(str(row[0]), str(row[1]), str(row[2]), str(row[3]), True)
