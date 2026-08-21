from __future__ import annotations

import hashlib

import pytest

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope, new_identifier
from solvan.persistence.operational_guidance_annotations import OperationalGuidanceAnnotationsMixin


class _Cursor:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows
        self.statements: list[str] = []

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, _parameters: object = None) -> None:
        self.statements.append(statement)

    def fetchone(self) -> object:
        return self._rows.pop(0) if self._rows else None


class _Connection:
    def __init__(self, rows: list[object] | None = None) -> None:
        self.rows: list[object] = list(rows or [])
        self.cursors: list[_Cursor] = []

    def cursor(self, **_kwargs: object) -> _Cursor:
        cursor = _Cursor(self.rows)
        self.cursors.append(cursor)
        return cursor


class _Store(OperationalGuidanceAnnotationsMixin):
    pass


SCOPE = Scope(
    organization_id=new_identifier("org"),
    project_id=new_identifier("prj"),
    environment_id=new_identifier("env"),
)
GUIDANCE_KEY = "reliability.triage-latency"
VERSION = "1"


def _analytics_audit_row(
    *,
    entity_ref: str = f"guidance-analytics:{GUIDANCE_KEY}@{VERSION}",
    selection_reason: str = "OPERATOR_INVOKED",
    outcome_code: str = "SELECTED",
) -> dict[str, str]:
    material = "\n".join((GUIDANCE_KEY, VERSION, selection_reason, outcome_code))
    return {
        "entity_ref": entity_ref,
        "material_digest": f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}",
        "principal": "service:coordinator",
        "event_type": "GUIDANCE_SELECTION_COUNTED",
    }


def test_operator_note_is_bounded_and_analytics_are_content_free() -> None:
    connection = _Connection([{"invocation_request_id": "gir_01"}])
    store = _Store(connection)
    store.record_operator_note(
        scope=SCOPE,
        invocation_request_id="gir_01",
        note="Check the bounded latency window.",
        classification="INTERNAL",
        author_principal="user:operator@example.com",
    )
    store.record_selection_analytics(
        scope=SCOPE,
        guidance_key=GUIDANCE_KEY,
        version=VERSION,
        selection_reason="OPERATOR_INVOKED",
        outcome_code="SELECTED",
        delivery_request_id="gir_01",
    )


def test_replayed_operator_note_is_idempotent_and_a_different_note_refuses() -> None:
    stored = {
        "note_text": "Check the bounded latency window.",
        "note_classification": "INTERNAL",
        "author_principal": "user:operator@example.com",
        "access_mode": "SELECTION_READERS",
    }
    replay = _Store(_Connection([None, dict(stored)]))
    replay.record_operator_note(
        scope=SCOPE,
        invocation_request_id="gir_01",
        note="Check the bounded latency window.",
        classification="INTERNAL",
        author_principal="user:operator@example.com",
    )

    mismatch = _Store(_Connection([None, dict(stored)]))
    with pytest.raises(GuidanceError, match="OPERATOR_NOTE_IDEMPOTENCY_MISMATCH"):
        mismatch.record_operator_note(
            scope=SCOPE,
            invocation_request_id="gir_01",
            note="A different operator note.",
            classification="INTERNAL",
            author_principal="user:operator@example.com",
        )


def test_replayed_delivery_does_not_count_again() -> None:
    connection = _Connection([_analytics_audit_row()])
    store = _Store(connection)
    store.record_selection_analytics(
        scope=SCOPE,
        guidance_key=GUIDANCE_KEY,
        version=VERSION,
        selection_reason="OPERATOR_INVOKED",
        outcome_code="SELECTED",
        delivery_request_id="gir_01",
    )
    statements = [statement for cursor in connection.cursors for statement in cursor.statements]
    assert len(statements) == 1
    assert "guidance_selection_analytics" not in statements[0]


def test_replayed_delivery_with_different_material_refuses() -> None:
    store = _Store(_Connection([_analytics_audit_row(outcome_code="WITHHELD")]))
    with pytest.raises(GuidanceError, match="guidance idempotency material mismatch"):
        store.record_selection_analytics(
            scope=SCOPE,
            guidance_key=GUIDANCE_KEY,
            version=VERSION,
            selection_reason="OPERATOR_INVOKED",
            outcome_code="SELECTED",
            delivery_request_id="gir_01",
        )


@pytest.mark.parametrize(
    ("method", "kwargs", "message"),
    [
        (
            "record_operator_note",
            {"note": "", "classification": "INTERNAL"},
            "OPERATOR_NOTE_INVALID",
        ),
        (
            "record_operator_note",
            {"note": "x", "classification": "PUBLIC"},
            "OPERATOR_NOTE_CLASSIFICATION_INVALID",
        ),
        (
            "record_selection_analytics",
            {"selection_reason": "OTHER", "outcome_code": "x"},
            "SELECTION_REASON_INVALID",
        ),
        (
            "record_selection_analytics",
            {"selection_reason": "OPERATOR_INVOKED", "outcome_code": ""},
            "SELECTION_OUTCOME_INVALID",
        ),
    ],
)
def test_annotation_contracts_fail_closed(
    method: str, kwargs: dict[str, str], message: str
) -> None:
    store = _Store(_Connection())
    with pytest.raises(GuidanceError, match=message):
        if method == "record_operator_note":
            store.record_operator_note(
                scope=SCOPE,
                invocation_request_id="gir_01",
                author_principal="user:operator@example.com",
                **kwargs,
            )
        else:
            store.record_selection_analytics(
                scope=SCOPE,
                guidance_key=GUIDANCE_KEY,
                version=VERSION,
                delivery_request_id="gir_01",
                **kwargs,
            )


def test_delivery_request_id_is_required_material() -> None:
    store = _Store(_Connection())
    with pytest.raises(GuidanceError, match="SELECTION_DELIVERY_INVALID"):
        store.record_selection_analytics(
            scope=SCOPE,
            guidance_key=GUIDANCE_KEY,
            version=VERSION,
            selection_reason="OPERATOR_INVOKED",
            outcome_code="SELECTED",
            delivery_request_id="   ",
        )
