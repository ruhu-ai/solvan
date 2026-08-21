from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.skills_governance import RepositoryObservation
from solvan.domain import Scope
from solvan.persistence.skills_interchange_store import PostgresRefreshLedger


class Cursor:
    rowcount = 1

    def __init__(self, results: list[object] | None = None) -> None:
        self.calls: list[tuple[str, object]] = []
        self._results = list(results or [])

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, params: object = None) -> None:
        self.calls.append((statement, params))

    def fetchone(self) -> object:
        return self._results.pop(0) if self._results else None


class Connection:
    def __init__(self, *results: object) -> None:
        self.cursor_value = Cursor(list(results))

    def transaction(self) -> Connection:
        return self

    def cursor(self) -> Cursor:
        return self.cursor_value

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def scope() -> Scope:
    return Scope(
        "org_01J4QZK8Q4J8Q6B95KQY4M9R2S",
        "prj_01J4QZK8Q4J8Q6B95KQY4M9R2S",
        "env_01J4QZK8Q4J8Q6B95KQY4M9R2S",
    )


def test_postgres_ledger_acquires_and_releases_a_fenced_lease() -> None:
    now = datetime(2026, 8, 13, tzinfo=UTC)
    connection = Connection(None, ("lease-token", now + timedelta(minutes=5)))
    ledger = PostgresRefreshLedger(connection, scope=scope())

    lease = ledger.acquire("reliability.demo", now=now)
    assert lease.token == "lease-token"
    ledger.release("reliability.demo", token=lease.token)
    assert any("lease_token=NULL" in statement for statement, _ in connection.cursor_value.calls)


@pytest.mark.parametrize(
    "existing, code",
    [
        (
            (datetime(2026, 8, 13, 12, 5, tzinfo=UTC), datetime(2026, 8, 13, 10, tzinfo=UTC), 0),
            "REFRESH_LEASE_HELD",
        ),
        ((None, datetime(2026, 8, 13, 11, 30, tzinfo=UTC), 0), "REFRESH_CADENCE_LIMIT"),
        ((None, datetime(2026, 8, 13, 10, 0, tzinfo=UTC), 3), "REFRESH_RETRY_LIMIT"),
    ],
)
def test_postgres_ledger_refuses_unsafe_cadence_or_retry_state(
    existing: tuple[object, ...], code: str
) -> None:
    connection = Connection(existing)
    ledger = PostgresRefreshLedger(connection, scope=scope())
    with pytest.raises(ValueError, match=code):
        ledger.acquire("reliability.demo", now=datetime(2026, 8, 13, 12, tzinfo=UTC))


def test_successful_observation_resets_failure_budget() -> None:
    connection = Connection()
    ledger = PostgresRefreshLedger(connection, scope=scope())
    ledger.record(
        "reliability.demo",
        upstream_ref="refs/heads/main",
        observation=RepositoryObservation(commit_sha="a" * 40, subtree_hash="sha256:" + "1" * 64),
        outcome="UNCHANGED",
        now=datetime(2026, 8, 13, tzinfo=UTC),
    )
    statement, _ = connection.cursor_value.calls[-1]
    assert "failure_count=0" in statement


def test_changed_observation_binds_the_notice_to_the_observed_ref() -> None:
    connection = Connection()
    ledger = PostgresRefreshLedger(connection, scope=scope())
    ledger.record(
        "reliability.demo",
        upstream_ref="refs/heads/main",
        observation=RepositoryObservation(commit_sha="a" * 40, subtree_hash="sha256:" + "1" * 64),
        outcome="CHANGED",
        now=datetime(2026, 8, 13, tzinfo=UTC),
    )
    statement, params = connection.cursor_value.calls[-1]
    assert "skill_upstream_change_notices" in statement
    assert isinstance(params, dict)
    assert params["upstream_ref"] == "refs/heads/main"
    assert params["commit"] == "a" * 40
    assert params["tree"] == "sha256:" + "1" * 64


def test_record_failure_increments_durable_failure_budget() -> None:
    connection = Connection()
    ledger = PostgresRefreshLedger(connection, scope=scope())
    ledger.record_failure("reliability.demo", now=datetime(2026, 8, 13, tzinfo=UTC))
    statement, _ = connection.cursor_value.calls[-1]
    assert "failure_count=failure_count+1" in statement
