from __future__ import annotations

from contextlib import nullcontext
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.alert_console import alert_console_router
from solvan.application.alert_list import AlertListFilter
from solvan.domain import Scope


class _UnusedConnection:
    def __enter__(self) -> _UnusedConnection:
        raise AssertionError("the local development Alert API must not touch Cloud SQL")

    def __exit__(self, *args: object) -> None:
        return None

    def transaction(self) -> Any:
        return nullcontext()


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(
        alert_console_router(
            scope_provider=lambda: Scope(
                "org_00000000000000000000000000",
                "prj_00000000000000000000000000",
                "env_00000000000000000000000000",
            ),
            principal_provider=lambda _token: "local-reader",
            connect=_UnusedConnection,
            local_mode_provider=lambda: True,
            cursor_signing_key_provider=lambda: b"test-alert-cursor-signing-key-0001",
        )
    )
    return TestClient(app)


def test_alert_queue_and_report_are_closed_non_authoritative_projections() -> None:
    with _client() as client:
        listing = client.get("/api/alerts")
        episode_id = listing.json()["rows"][0]["alert_episode_id"]
        detail = client.get(f"/api/alerts/{episode_id}")

    assert listing.status_code == detail.status_code == 200
    assert listing.headers["cache-control"] == "private, no-store"
    assert listing.json()["data_status"] == "SCRIPTED_RELEASE_FIXTURE"
    assert detail.json()["authority"] == "NO_PRODUCTION_AUTHORITY"
    assert [section["section_id"] for section in detail.json()["sections"]] == [
        "WHAT_HAPPENED",
        "IMPACT",
        "LIKELY_CAUSE",
        "KEY_EVIDENCE",
        "NEXT_STEP",
    ]
    assert all(section["claims"][0]["citation_refs"] for section in detail.json()["sections"])


def test_the_scripted_fixture_never_demands_an_identity() -> None:
    """The fixture carries no customer data, so it asks for nobody.

    Resolving the reader before the fixture branch is what 401'd every Alert
    read on a connected host: `_reader_principal` demanded a verified Google
    identity token no console component sends, in front of a projection that
    needs no identity at all. This pins the ordering so the branch that serves
    nothing sensitive is the branch that asks for nothing.
    """

    def _refuse(_token: str | None) -> str:
        raise AssertionError("the fixture must not resolve a reader identity")

    app = FastAPI()
    app.include_router(
        alert_console_router(
            scope_provider=lambda: Scope(
                "org_00000000000000000000000000",
                "prj_00000000000000000000000000",
                "env_00000000000000000000000000",
            ),
            principal_provider=_refuse,
            connect=_UnusedConnection,
            local_mode_provider=lambda: True,
            cursor_signing_key_provider=lambda: b"test-alert-cursor-signing-key-0001",
        )
    )
    with TestClient(app) as client:
        listing = client.get("/api/alerts")
        detail = client.get("/api/alerts/aep_00000000000000000000000001")
        policies = client.get("/api/fleet/alert-policies")
        capacity = client.get("/api/fleet/alert-capacity")
        templates = client.get("/api/fleet/alert-policy-templates")
        recommendations = client.get("/api/fleet/alert-policy-recommendations")
        revision = client.get("/api/fleet/alert-policies/payments-http-errors/revisions/4")
        related = client.get("/api/incidents/inc_01J4QZK8Q4J8Q6B95KQY4M9R2S/related-alerts")
        events = client.get("/api/alerts/aep_00000000000000000000000001/events")

    assert listing.status_code == detail.status_code == 200
    assert policies.status_code == capacity.status_code == 200
    assert templates.status_code == recommendations.status_code == 200
    assert revision.status_code == related.status_code == events.status_code == 200


def test_alert_queue_refuses_unknown_or_duplicate_scalar_filters() -> None:
    with _client() as client:
        unknown = client.get("/api/alerts?service=payments-api")
        duplicate = client.get("/api/alerts?filter=first&filter=second")
        invalid = client.get("/api/alerts?filter=not-base64!")

    assert unknown.status_code == duplicate.status_code == invalid.status_code == 422
    assert unknown.json()["detail"] == "INVALID_ALERT_FILTER"


def test_alert_queue_accepts_canonical_filter_and_applies_server_search() -> None:
    encoded = AlertListFilter(view="ALL", query="payments").encoded()
    with _client() as client:
        response = client.get("/api/alerts", params={"filter": encoded})
    assert response.status_code == 200
    assert response.json()["filter"]["query"] == "payments"
    assert all("payment" in row["title"].lower() for row in response.json()["rows"])


def test_alert_detail_does_not_disclose_unknown_record_existence() -> None:
    with _client() as client:
        missing = client.get("/api/alerts/aep_00000000000000000000000009")
    assert missing.status_code == 404


def test_alert_detail_explains_committed_decision_and_related_alerts_separately() -> None:
    with _client() as client:
        detail = client.get("/api/alerts/aep_00000000000000000000000001")
        related = client.get("/api/incidents/inc_01J4QZK8Q4J8Q6B95KQY4M9R2S/related-alerts")
    assert detail.status_code == related.status_code == 200
    assert detail.json()["decision_explanation"]["kind"] == "COMMITTED_DECISION"
    assert detail.json()["decision_explanation"]["result"] == "ESCALATED"
    row = related.json()["rows"][0]
    assert row["relation"] == "CREATED"
    assert row["provider_status_label"] == "ACTIVE_AT_SOURCE"
    assert row["recovery_status"] == "INDEPENDENTLY_VERIFIED"


def test_policy_templates_recommendations_and_simulation_are_typed() -> None:
    command = {
        "schema_version": 1,
        "draft_policy_key": "payments-http-errors",
        "draft_version": "5",
        "sample_provider_generation_id": "alg_01K2M7Y8F90H6J1K3M5N7P9QRS",
        "expected_draft_digest": "sha256:" + "1" * 64,
        "expected_sample_digest": "sha256:" + "2" * 64,
        "idempotency_key": "simulation-request-1",
    }
    with _client() as client:
        templates = client.get("/api/fleet/alert-policy-templates")
        recommendations = client.get("/api/fleet/alert-policy-recommendations")
        simulation = client.post("/api/fleet/alert-policy-simulations", json=command)
    assert templates.json()["rows"][0]["creates"] == "DRAFT_ONLY"
    assert "NOT A DEFAULT" in templates.json()["rows"][0]["example_values_label"]
    assert recommendations.json()["label"] == "Machine-proposed — requires author review"
    assert simulation.status_code == 201
    assert simulation.json()["kind"] == "HYPOTHETICAL_NO_WORKFLOW_EFFECT"
