from __future__ import annotations

import base64
import json
from contextlib import nullcontext
from typing import Any, ClassVar

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.alerts import alert_ingress_router
from apps.api.operational_guidance_admin import (
    GuidanceContentInspection,
    operational_guidance_router,
)
from solvan.application.alert_triage import (
    AlertIngressError,
    AlertIngressReceipt,
    CloudMonitoringSourceBinding,
    VerifiedPushIdentity,
)
from solvan.application.guidance_evaluation import UnavailableGuidanceEvaluationVerifier
from solvan.domain import Scope
from solvan.persistence.alert_triage import AlertPolicyDraftCommit
from solvan.persistence.trigger_policy_types import TriggerPolicyLifecycleCommit

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


class _Connection:
    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def transaction(self):
        return nullcontext()


class _Verifier:
    def __init__(self, *, refuse: bool = False) -> None:
        self._refuse = refuse

    def verify(self, *, authorization: str | None, binding: CloudMonitoringSourceBinding):
        if self._refuse:
            raise AlertIngressError("PUSH_IDENTITY_INVALID")
        return VerifiedPushIdentity(
            "https://accounts.google.com",
            "123",
            binding.push_principal,
            binding.oidc_audience,
        )


class _Repository:
    selected: ClassVar[list[bool]] = []
    projected: ClassVar[list[str]] = []

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def source_binding(self, *, scope: Scope, connection_id: str, require_qualified: bool = True):
        return CloudMonitoringSourceBinding(
            scope=scope,
            source_identity_id="asi_00000000000000000000000001",
            connection_id=connection_id,
            connection_epoch=1,
            continuity_epoch=1,
            cell_id="cell_alert",
            placement_epoch=1,
            scoping_project_id="metrics-scope",
            topic_name="projects/metrics-scope/topics/alerts",
            topic_binding_receipt_ref="ref_topic",
            subscription_name="projects/metrics-scope/subscriptions/solvan-alerts",
            push_principal="push@metrics-scope.iam.gserviceaccount.com",
            oidc_audience="https://alerts.example/internal",
            payload_schema_version="1.2",
            source_material_hash="sha256:" + "1" * 64,
            classification="INTERNAL",
            retention_policy_revision="retention/alert-v1",
        )

    def record_committed_delivery(self, **kwargs: Any) -> AlertIngressReceipt:
        return AlertIngressReceipt(
            "ald_00000000000000000000000001",
            "ala_00000000000000000000000001",
            "ale_00000000000000000000000001",
            "alg_00000000000000000000000001",
            "COMMITTED",
            "SEMANTIC_EVENT_COMMITTED",
            True,
        )

    def record_refused_delivery(self, **kwargs: Any) -> AlertIngressReceipt:
        return AlertIngressReceipt(
            "ald_00000000000000000000000002",
            "ala_00000000000000000000000002",
            None,
            None,
            "REFUSED",
            str(kwargs["reason_code"]),
            True,
        )

    def project_provider_generation(self, *, scope: Scope, provider_generation_id: str) -> object:
        self.projected.append(provider_generation_id)
        return object()

    def record_alert_policy_subtype(self, **kwargs: Any) -> AlertPolicyDraftCommit:
        policy = kwargs["policy"]
        return AlertPolicyDraftCommit(
            policy.policy_key,
            policy.version,
            str(kwargs["generic_policy_hash"]),
            policy.alert_material_hash,
            True,
        )

    def record_response_selected(
        self, *, scope: Scope, receipt: AlertIngressReceipt, success: bool
    ) -> str:
        self.selected.append(success)
        return "alr_00000000000000000000000001"


def _body() -> bytes:
    payload = {
        "version": "1.2",
        "incident": {
            "incident_id": "incident-1",
            "state": "open",
            "started_at": "2026-08-13T12:00:00Z",
            "scoping_project_id": "metrics-scope",
            "resource": {
                "type": "cloud_run_revision",
                "labels": {"project_id": "payments-prod"},
            },
            "policy_name": "errors",
            "condition_name": "http-5xx",
            "severity": "critical",
        },
    }
    return json.dumps(
        {
            "message": {
                "messageId": "message-1",
                "data": base64.b64encode(json.dumps(payload).encode()).decode(),
            },
            "subscription": "projects/metrics-scope/subscriptions/solvan-alerts",
        }
    ).encode()


def _client(monkeypatch: pytest.MonkeyPatch, *, refuse: bool = False) -> TestClient:
    monkeypatch.setattr("apps.api.alerts.AlertTriageRepository", _Repository)
    _Repository.selected = []
    _Repository.projected = []
    app = FastAPI()
    app.include_router(
        alert_ingress_router(
            scope_provider=lambda: SCOPE,
            connect=_Connection,
            identity_verifier=_Verifier(refuse=refuse),
        )
    )
    return TestClient(app)


class _TriggerStore:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def create_draft(self, **kwargs: Any) -> TriggerPolicyLifecycleCommit:
        policy = kwargs["policy"]
        return TriggerPolicyLifecycleCommit(
            policy.policy_key,
            policy.version,
            "DRAFT",
            policy.policy_hash,
            None,
            True,
        )


def _policy_body() -> dict[str, Any]:
    budget = {
        "maximum_starts_per_hour": 10,
        "maximum_starts_per_day": 100,
        "maximum_concurrent_runs": 2,
        "maximum_model_calls": 4,
        "maximum_tool_calls": 12,
        "maximum_runtime_seconds": 300,
        "maximum_queue_age_ms": 60_000,
        "maximum_connection_requests": 12,
    }
    return {
        "schema_version": 1,
        "policy_key": "payments.http-errors",
        "version": "1",
        "owner_department": "Payments SRE",
        "source_connection_id": "con_00000000000000000000000001",
        "source_connection_epoch": 1,
        "source_capability_tool_ref": "cloud_monitoring_query@1",
        "source_capability_agent_key": "evidence-agent",
        "source_capability_identity_ref": "identity://evidence-agent/1",
        "selector": {
            "combine": "ALL_OF",
            "clauses": [{"field": "SOURCE_STATE", "values": ["OPEN"]}],
            "fingerprint_fields": ["resource_identifier"],
        },
        "target_mapping": {"kind": "EXACT_NODE", "node_key": "service/payments"},
        "severity_mapping": {
            "entries": [{"provider_value": "CRITICAL", "solvan_severity": "SEV1"}],
            "unknown_behavior": "BLOCKED",
        },
        "incident_class": "service_error_rate",
        "mode": "TRIAGE",
        "triage_profile_ref": "alert-triage-read-compute-v1@1",
        "incident_profile_ref": "incident-investigation-v1@1",
        "triage_budget": budget,
        "incident_admission_budget": budget,
        "cooldown_ms": 60_000,
        "maximum_pending_per_target": 3,
        "supersession": "LATEST_WAITING_PER_TARGET",
        "episode_horizon_ms": 86_400_000,
        "region": "europe-west1",
        "classification_ceiling": "INTERNAL",
    }


def test_push_returns_only_after_durable_success_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(monkeypatch) as client:
        response = client.post(
            "/api/internal/alert-sources/cloud-monitoring/pubsub-push/con_00000000000000000000000001",
            content=_body(),
            headers={"Authorization": "Bearer signed", "Content-Type": "application/json"},
        )
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["x-solvan-receipt-id"].startswith("ald_")
    assert _Repository.selected == [True]
    assert _Repository.projected == ["alg_00000000000000000000000001"]


def test_push_refusal_is_opaque_and_durable(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(monkeypatch, refuse=True) as client:
        response = client.post(
            "/api/internal/alert-sources/cloud-monitoring/pubsub-push/con_00000000000000000000000001",
            content=_body(),
            headers={"Authorization": "Bearer attacker", "Content-Type": "application/json"},
        )
    assert response.status_code == 401
    assert response.json() == {"accepted": False}
    assert "reason" not in response.text
    assert _Repository.selected == [False]
    assert _Repository.projected == []


def test_alert_policy_draft_atomically_uses_identity_derived_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "apps.api.operational_trigger_policy_admin.AlertTriageRepository", _Repository
    )
    monkeypatch.setattr(
        "apps.api.operational_trigger_policy_admin.PostgresTriggerPolicyStore", _TriggerStore
    )
    app = FastAPI()
    app.include_router(
        operational_guidance_router(
            principal_provider=lambda token: f"verified:{token}",
            reader_principal_provider=lambda token: f"verified:{token}",
            scope_provider=lambda: SCOPE,
            connect=_Connection,
            content_inspector=lambda revision: GuidanceContentInspection(True, ()),
            known_predicates=frozenset(),
            evaluation_verifier=UnavailableGuidanceEvaluationVerifier(),
        )
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/admin/trigger-policies/drafts",
            json=_policy_body(),
            headers={
                "X-Solvan-Approval-Token": "human-claim",
                "Idempotency-Key": "alert-policy-0001",
            },
        )
    assert response.status_code == 200
    assert response.json()["generic_policy"]["lifecycle"] == "DRAFT"
    assert response.json()["alert_policy"]["alert_material_hash"].startswith("sha256:")
