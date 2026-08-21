from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandStatus,
    DeliveryOutcome,
    DeliveryReasonCode,
    PrivateCommandRecord,
    PrivateCommandResponse,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.persistence.delivery_command_store import (
    DeliveryCommandConflict,
    PostgresDeliveryCommandStore,
)
from tests.unit.test_delivery_commands import _record


class Cursor:
    def __init__(self, rows: list[dict[str, object]], rowcounts: list[int]) -> None:
        self.rows = rows
        self.rowcounts = rowcounts
        self.rowcount = 0
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, params: dict[str, object]) -> None:
        self.calls.append((statement, params))
        self.rowcount = self.rowcounts.pop(0) if self.rowcounts else 0

    def fetchone(self) -> dict[str, object] | None:
        return self.rows.pop(0) if self.rows else None


class Connection:
    def __init__(self, cursor: Cursor) -> None:
        self.cursor_value = cursor

    def transaction(self) -> Connection:
        return self

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self, **_kwargs: Any) -> Cursor:
        return self.cursor_value


class PayloadReader:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, int]] = []

    def get_json(self, *, uri: str, expected_hash: str, max_bytes: int) -> object:
        self.calls.append((uri, expected_hash, max_bytes))
        return self.payload


def _prepared_row(command: PrivateCommandRecord | None = None) -> dict[str, object]:
    command = _record() if command is None else command
    workspace_tool = command.command_kind.value == "WORKSPACE_TOOL_INVOKE"
    return {
        **command.scope.canonical_dict(),
        "command_kind": command.command_kind.value,
        "subject_id": command.subject_id,
        "material_hash": command.material_hash,
        "idempotency_key": command.idempotency_key,
        "payload_ref": command.payload_ref,
        "payload_hash": command.payload_hash,
        "payload_schema_hash": command.payload_schema_hash,
        "admitted_caller_identity": command.admitted_caller_identity,
        "admitted_audience_hash": command.admitted_audience_hash,
        "deadline": command.deadline,
        "operation_key": command.payload["tool_revision"] if workspace_tool else None,
        "operation_ordinal": command.payload["call_ordinal"] if workspace_tool else None,
        "status": DeliveryCommandStatus.PREPARED.value,
    }


def _load_row(command: PrivateCommandRecord | None = None) -> dict[str, object]:
    command = _record() if command is None else command
    return {"id": command.command_id, **_prepared_row(command)}


def test_prepare_accepts_once_and_returns_false_for_an_exact_replay() -> None:
    command = _record()
    inserted = Cursor([], [1])
    assert PostgresDeliveryCommandStore(Connection(inserted)).prepare(command)

    replayed = Cursor([_prepared_row(command)], [0, 0])
    assert not PostgresDeliveryCommandStore(Connection(replayed)).prepare(command)
    assert "ON CONFLICT DO NOTHING" in replayed.calls[0][0]


def test_prepare_refuses_a_conflicting_existing_command() -> None:
    conflicting = _prepared_row() | {"material_hash": "sha256:" + "e" * 64}
    with pytest.raises(DeliveryCommandConflict):
        PostgresDeliveryCommandStore(Connection(Cursor([conflicting], [0, 0]))).prepare(_record())


def test_completion_cannot_replace_a_previous_terminal_outcome() -> None:
    response = PrivateCommandResponse(
        command_id=_record().command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref="gs://solvan-private/receipts/one.json",
        receipt_hash="sha256:" + "f" * 64,
        observed_at=datetime.now(UTC),
    )
    existing = {"status": "REFUSED", "response_ref": None, "response_hash": None}
    with pytest.raises(DeliveryCommandConflict):
        PostgresDeliveryCommandStore(Connection(Cursor([existing], [0, 0]))).complete(
            response,
            response_ref="gs://solvan-private/responses/one.json",
            response_hash=canonical_sha256(response.model_dump(mode="json")),
        )


def test_load_uses_the_hash_bound_payload_instead_of_the_private_request() -> None:
    command = _record()
    reader = PayloadReader(command.payload)
    loaded = PostgresDeliveryCommandStore(Connection(Cursor([_load_row(command)], [0]))).load(
        command_id=command.command_id, payload_reader=reader
    )

    assert loaded == command
    assert reader.calls == [(command.payload_ref, command.payload_hash, 16_384)]


def test_load_refuses_a_payload_that_is_not_a_closed_command_object() -> None:
    payload = {"candidate_tree_hash": ["not-a-scalar"]}
    row = _load_row() | {"payload_hash": canonical_sha256(payload)}
    with pytest.raises(DeliveryCommandError, match="malformed"):
        PostgresDeliveryCommandStore(Connection(Cursor([row], [0]))).load(
            command_id=_record().command_id,
            payload_reader=PayloadReader(payload),
        )


def test_load_refuses_a_payload_with_a_hash_that_does_not_match_the_record() -> None:
    with pytest.raises(DeliveryCommandError, match="hash does not match"):
        PostgresDeliveryCommandStore(Connection(Cursor([_load_row()], [0]))).load(
            command_id=_record().command_id,
            payload_reader=PayloadReader(
                {
                    "test_command_id": "rcc_01J00000000000000000000000",
                    "candidate_tree_hash": "sha256:" + "b" * 64,
                }
            ),
        )


@pytest.mark.parametrize(
    ("method", "expected", "status"),
    [
        ("claim_for_issue", ("PREPARED",), "ISSUED"),
        ("begin_reconciliation", ("ISSUED",), "RECONCILING"),
        ("expire_prepared", ("PREPARED",), "EXPIRED"),
    ],
)
def test_transition_claims_are_compare_and_set(
    method: str, expected: tuple[str, ...], status: str
) -> None:
    cursor = Cursor([], [1])
    store = PostgresDeliveryCommandStore(Connection(cursor))
    assert getattr(store, method)(command_id=_record().command_id)
    _statement, params = cursor.calls[0]
    assert params["expected"] == expected
    assert params["status"] == status


def test_claim_returns_false_when_another_worker_already_owns_the_effect() -> None:
    assert not PostgresDeliveryCommandStore(Connection(Cursor([], [0]))).claim_for_issue(
        command_id=_record().command_id
    )
