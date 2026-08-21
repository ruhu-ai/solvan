from __future__ import annotations

import pytest

from solvan.domain import Scope
from solvan.persistence.release_rollout_store import (
    PostgresReleaseRolloutStore,
    ReleaseRolloutConflict,
)


class _Cursor:
    def __init__(self, *, request_state: str = "VERIFYING") -> None:
        self.request_state = request_state
        self.statements: list[tuple[str, dict[str, object]]] = []
        self.rowcount = 0
        self._first = True

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, values: dict[str, object]) -> None:
        self.statements.append((statement, values))
        self.rowcount = 1

    def fetchone(self) -> dict[str, object] | None:
        if not self._first:
            return None
        self._first = False
        return {
            "deployment_rollout_id": "dro_00000000000000000000000000",
            "operation_kind": "PROMOTE_CANARY",
            "target_reservation_id": "rtr_00000000000000000000000000",
            "code_change_request_id": "ccr_00000000000000000000000000",
            "sequence_no": 8,
            "state": self.request_state,
        }


class _Connection:
    def __init__(self, *, request_state: str = "VERIFYING") -> None:
        self.issued = _Cursor(request_state=request_state)

    def cursor(self, **_: object) -> _Cursor:
        return self.issued


def _scope() -> Scope:
    return Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )


@pytest.mark.parametrize(
    ("request_state", "terminal_state"),
    [
        ("CANARY_DEPLOYING", "BLOCKED"),
        ("VERIFYING", "BLOCKED"),
        ("ROLLING_BACK", "ROLLBACK_AMBIGUOUS"),
    ],
)
def test_post_issue_ambiguity_is_terminal_and_keeps_reconciliation_fence(
    request_state: str, terminal_state: str
) -> None:
    connection = _Connection(request_state=request_state)
    store = PostgresReleaseRolloutStore(connection)  # type: ignore[arg-type]

    store.mark_operation_ambiguous(
        scope=_scope(),
        operation_id="dgo_00000000000000000000000000",
        response_ref="gs://evidence/ambiguous.json",
        response_hash="sha256:" + "a" * 64,
        error_class="PROVIDER_RESULT_TARGET_NOT_EXACT",
        controller_identity="serviceAccount:controller@example.iam.gserviceaccount.com",
    )

    statements = connection.issued.statements
    assert len(statements) == 5
    assert "SET status='RECONCILING'" in statements[1][0]
    assert "SET status='AMBIGUOUS'" in statements[2][0]
    assert "deployment_rollouts SET status='AMBIGUOUS'" in statements[3][0]
    assert statements[4][1]["from_state"] == request_state
    assert statements[4][1]["to_state"] == terminal_state


def test_ambiguity_receipt_must_be_content_addressed_evidence() -> None:
    store = PostgresReleaseRolloutStore(_Connection())  # type: ignore[arg-type]
    with pytest.raises(ReleaseRolloutConflict, match="receipt is malformed"):
        store.mark_operation_ambiguous(
            scope=_scope(),
            operation_id="dgo_00000000000000000000000000",
            response_ref="https://example.invalid/receipt",
            response_hash="not-a-hash",
            error_class="PROVIDER_RESULT_TARGET_NOT_EXACT",
            controller_identity="serviceAccount:controller@example.iam.gserviceaccount.com",
        )
