from __future__ import annotations

import pytest

from solvan.domain import ActionPolicyError, Scope
from solvan.persistence.action_invocation import ActionInvocationMixin


class _Result:
    def __init__(self, row: tuple[str, str, str] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[str, str, str] | None:
        return self._row


class _Connection:
    def __init__(self, row: tuple[str, str, str] | None) -> None:
        self.row = row
        self.statement = ""

    def execute(self, statement: str) -> _Result:
        self.statement = statement
        return _Result(self.row)


class _Store(ActionInvocationMixin):
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection  # type: ignore[assignment]


def test_actuator_scope_is_derived_from_database_role_binding() -> None:
    row = (
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    connection = _Connection(row)

    assert _Store(connection).bound_scope() == Scope(*row)
    assert "database_role=current_user" in connection.statement


def test_unbound_database_identity_refuses_instead_of_accepting_caller_scope() -> None:
    with pytest.raises(ActionPolicyError, match="actuator_database_identity_has_no_scope"):
        _Store(_Connection(None)).bound_scope()
