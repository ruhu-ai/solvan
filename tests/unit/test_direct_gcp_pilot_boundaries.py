"""Boundaries for the production Direct GCP Alert Triage pilot services."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from apps.direct_gcp_reader.main import ProbeCommand
from apps.direct_gcp_reader.main import app as reader_app
from apps.pilot_qualification_verifier.main import QualificationCommand, _validate_receipt


def test_direct_reader_exposes_only_private_probes_and_liveness() -> None:
    """The reader observes and reports; it never gains a second kind of verb.

    Both routes are bounded read-only observations under the same caller check.
    The connection probe answers "can this credential reach this capability
    class", the Tool probe answers "can it perform this Tool's exact declared
    capability", and neither commits anything.
    """

    routes = {route.path for route in reader_app.routes}
    assert routes == {
        "/internal/v1/connections:probe",
        "/internal/v1/tools:probe",
        "/internal/v1/detections:observe",
        "/healthz",
    }


def test_reader_command_refuses_unrecognized_connection_material() -> None:
    with pytest.raises(ValidationError):
        ProbeCommand(
            schema_version=1,
            connection_id="con_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
            connection_epoch=1,
            provider="CLOUD_MONITORING",
            authentication_mode="GCP_SERVICE_ACCOUNT_IMPERSONATION",
            solvan_delegator_principal="serviceAccount:reader@solvan.iam.gserviceaccount.com",
            customer_reader_principal="serviceAccount:reader@customer.iam.gserviceaccount.com",
            token_lifetime_seconds=300,
            resource_kind="GCP_PROJECT",
            resource_id="customer-project",
            customer_project_id="another-project",
        )


def test_reader_has_no_database_writer_or_connection_state_authority() -> None:
    reader_source = Path("apps/direct_gcp_reader/main.py").read_text(encoding="utf-8")
    assert "PostgresConnectionStore" not in reader_source
    assert "connect_database" not in reader_source


def test_qualification_command_names_only_durable_records() -> None:
    with pytest.raises(ValidationError):
        QualificationCommand(
            schema_version=1,
            connection_id="con_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
            source_binding_id="asb_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
            source_binding_epoch=1,
            claimed_result="QUALIFIED",
        )


def test_qualification_issuance_is_serialized_and_one_current_receipt_is_enforced() -> None:
    verifier_source = Path("apps/pilot_qualification_verifier/main.py").read_text(encoding="utf-8")
    target_migration = Path("specs/artifacts/alert-triage-schema.target.v7.sql").read_text(
        encoding="utf-8"
    )
    assert "pg_advisory_lock(hashtext(%s))" in verifier_source
    assert "_current_receipt" in verifier_source
    assert "direct_gcp_pilot_one_current_receipt_per_source_epoch" in target_migration
    assert "WHERE superseded_at IS NULL" in target_migration


def test_receipt_schema_accepts_the_complete_independent_evidence_shape() -> None:
    now = datetime.now(UTC).isoformat()
    _validate_receipt(
        {
            "schema_version": 1,
            "kind": "SOLVAN_DIRECT_GCP_PILOT_QUALIFICATION",
            "receipt_id": "pgq_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
            "issued_at": now,
            "expires_at": "2030-01-01T00:00:00+00:00",
            "deployment": {
                "control_project_id": "solvan-control",
                "region": "europe-west1",
                "source_commit": "a" * 40,
                "alert_ingress_revision": "solvan-dev-alert-ingress-00001",
                "api_revision": "solvan-dev-api-00001",
                "coordinator_revision": "solvan-dev-coordinator-00001",
                "qualification_verifier_revision": "solvan-dev-verifier-00001",
            },
            "direct_connection": {
                "connection_id": "con_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
                "connection_epoch": 1,
                "authentication_mode": "GCP_SERVICE_ACCOUNT_IMPERSONATION",
                "solvan_delegator_principal": (
                    "serviceAccount:reader@solvan.iam.gserviceaccount.com"
                ),
                "customer_reader_principal": (
                    "serviceAccount:reader@customer.iam.gserviceaccount.com"
                ),
                "delegation_condition_digest": "sha256:" + "a" * 64,
                "capability_receipt_ref": "probe://cloud-monitoring/metrics.read#sha256:abc",
            },
            "alert_source": {
                "source_binding_id": "asb_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
                "source_binding_epoch": 1,
                "configuration_digest": "sha256:" + "b" * 64,
                "subscription": "projects/customer/subscriptions/solvan-alerts",
                "push_service_account": "serviceAccount:push@customer.iam.gserviceaccount.com",
                "oidc_audience": "https://alert-ingress.example.run.app",
                "qualification_delivery_ref": "sql://alert-source-qualification-deliveries/aqd_01",
            },
            "results": {
                "delegation_verified": True,
                "ingress_isolation_verified": True,
                "authenticated_delivery_verified": True,
                "read_only_triage_verified": True,
                "operator_continuation_verified": True,
            },
            "manual_continuation": {
                "operator_principal_ref": "principal://user:operator@example.com",
                "continuation_receipt_ref": "sql://alert-operator-requests/aor_01",
            },
            "independent_verification": {
                "verifier_principal": "serviceAccount:verifier@solvan.iam.gserviceaccount.com",
                "verifier_revision": "solvan-dev-verifier-00001",
                "kms_key_version": (
                    "projects/solvan/locations/europe-west1/keyRings/pilot/cryptoKeys/"
                    "sign/cryptoKeyVersions/1"
                ),
                "signature_digest": "sha256:" + "c" * 64,
                "evidence_refs": ["gs://receipts/receipt.sig"],
            },
        }
    )
