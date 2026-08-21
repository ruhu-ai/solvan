"""The conversation API answers from the ledger, and refuses everything else.

These cover the surface a channel or a browser actually touches: the anchor
must resolve, the question must be one the system can answer from committed
records, and a hostile question must reach no capability at all.

Specification 14 §22, cases 3, 7, 12, and the escalation valve of §4.1.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from apps.api.console_fixture import console_snapshot
from apps.api.main import create_app


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(
        create_app(enable_local_maintenance=False, snapshot_provider=console_snapshot)
    ) as test_client:
        yield test_client


def _ask(client: TestClient, question: str, record_id: str = "INC-1042"):
    return client.post(
        "/api/v1/liaison:ask",
        json={
            "schema_version": 1,
            "question": question,
            "anchor_record_type": "incident",
            "anchor_record_id": record_id,
        },
    )


def test_suggested_questions_come_from_the_records_state(client: TestClient) -> None:
    response = client.get(
        "/api/v1/liaison/questions",
        params={"record_type": "incident", "record_id": "INC-1042"},
    )
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()["questions"]}
    # MITIGATED still needs a person, so the attention question is offered.
    assert "WHAT_NEEDS_ME" in ids
    assert "IS_IT_FIXED" in ids


def test_questions_about_an_unaddressable_record_are_refused(client: TestClient) -> None:
    response = client.get(
        "/api/v1/liaison/questions",
        params={"record_type": "incident", "record_id": "INC-0000"},
    )
    assert response.status_code == 404


def test_an_anchor_that_does_not_resolve_is_refused_before_any_read(client: TestClient) -> None:
    response = _ask(client, "What happened?", record_id="INC-9999")
    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "INVALID_REQUEST",
            "message": "The request is invalid.",
            "retryable": False,
        }
    }


def test_a_request_cannot_assert_its_own_principal_or_scope(client: TestClient) -> None:
    """Fixture 9: identity comes from a grant minted server-side, never a body."""

    response = client.post(
        "/api/v1/liaison:ask",
        json={
            "schema_version": 1,
            "question": "Is it fixed?",
            "anchor_record_type": "incident",
            "anchor_record_id": "INC-1042",
            "principal": "someone-else@example.com",
            "organization_id": "org_00000000000000000000000000",
        },
    )
    # `extra="forbid"` means the smuggled fields are a validation failure, not
    # silently-ignored input.
    assert response.status_code == 422
