from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from solvan.domain import (
    RelayAdapter,
    RelayEnrollmentRegistration,
    RelayEnrollmentState,
    RelayIdentityBinding,
    RelaySourceBindingRegistration,
    Scope,
)
from solvan.persistence.relay_store import PostgresRelayStore, RelayConflict

HASH = "sha256:" + "1" * 64


class Result:
    def __init__(self, row: object = None) -> None:
        self.row = row

    def fetchone(self) -> object:
        return self.row


class Cursor:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, object]] = []
        self.rowcount = 1

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, params: object = None) -> None:
        self.calls.append((statement, params))

    def fetchone(self) -> Any:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[Any]:
        rows = list(self.rows)
        self.rows.clear()
        return rows


class Connection:
    def __init__(self, *, direct: list[object] | None = None, cursor: list[object] | None = None):
        self.direct = list(direct or [])
        self.cursor_value = Cursor(list(cursor or []))
        self.calls: list[tuple[str, object]] = []

    def transaction(self) -> Connection:
        return self

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, params: object = None) -> Result:
        self.calls.append((statement, params))
        return Result(self.direct.pop(0) if self.direct else None)

    def cursor(self, **_kwargs: object) -> Cursor:
        return self.cursor_value


def scope() -> Scope:
    return Scope(
        "org_" + "0" * 26,
        "prj_" + "0" * 26,
        "env_" + "0" * 26,
    )


def test_ready_binding_requires_both_ready_lifecycles_and_fresh_receipt() -> None:
    row = (
        "rsb_" + "0" * 26,
        "ren_" + "0" * 26,
        2,
        "source-1",
        3,
        "cloud-monitoring.v1",
        "1",
        "cap-1",
        HASH,
        "europe-west1",
        "CONFIDENTIAL",
    )
    connection = Connection(direct=[row])
    binding = PostgresRelayStore(connection).resolve_ready_source_binding(
        scope=scope(), source_connection_id="source-1", source_connection_epoch=3
    )
    assert binding is not None
    assert binding.adapter_key is RelayAdapter.CLOUD_MONITORING
    statement, params = connection.calls[0]
    assert "r.expires_at > clock_timestamp()" in statement
    assert params["organization_id"] == "org_" + "0" * 26


def test_claim_replays_same_nonce_without_writing_a_second_transition() -> None:
    expires = datetime(2026, 8, 13, 10, 1, tzinfo=UTC)
    connection = Connection(
        cursor=[
            {
                "state": "CLAIMED",
                "workflow_version": 1,
                "claim_request_nonce": "nonce-1",
                "claim_token": UUID("00000000-0000-0000-0000-000000000001"),
                "attempt_id": "rat_" + "0" * 26,
                "attempt_number": 1,
                "lease_expires_at": expires,
            }
        ]
    )
    claim = PostgresRelayStore(connection).claim_job(
        scope=scope(),
        enrollment_id="ren_" + "0" * 26,
        collection_job_id="rcj_" + "0" * 26,
        job_digest=HASH,
        claim_request_nonce="nonce-1",
        process_boot_id="boot-1",
        accepted_at=expires - timedelta(seconds=30),
    )
    assert claim.workflow_version == 1
    assert len(connection.cursor_value.calls) == 1


def test_claim_rejects_different_nonce_after_claim() -> None:
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    connection = Connection(
        cursor=[
            {
                "state": "CLAIMED",
                "workflow_version": 1,
                "claim_request_nonce": "other",
                "claim_token": UUID("00000000-0000-0000-0000-000000000001"),
                "attempt_id": "rat_" + "0" * 26,
                "attempt_number": 1,
                "lease_expires_at": now + timedelta(seconds=30),
            }
        ]
    )
    with pytest.raises(RelayConflict, match="another nonce"):
        PostgresRelayStore(connection).claim_job(
            scope=scope(),
            enrollment_id="ren_" + "0" * 26,
            collection_job_id="rcj_" + "0" * 26,
            job_digest=HASH,
            claim_request_nonce="nonce-1",
            process_boot_id="boot-1",
            accepted_at=now,
        )


def test_claim_commits_transition_before_compare_and_set() -> None:
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    connection = Connection(
        cursor=[
            {
                "state": "PENDING",
                "workflow_version": 0,
                "claim_request_nonce": None,
                "claim_token": None,
                "lease_expires_at": None,
            },
            {
                "claim_token": UUID("00000000-0000-0000-0000-000000000001"),
                "lease_expires_at": now + timedelta(seconds=60),
                "workflow_version": 1,
            },
        ]
    )
    claim = PostgresRelayStore(connection).claim_job(
        scope=scope(),
        enrollment_id="ren_" + "0" * 26,
        collection_job_id="rcj_" + "0" * 26,
        job_digest=HASH,
        claim_request_nonce="nonce-1",
        process_boot_id="boot-1",
        accepted_at=now,
    )
    assert claim.workflow_version == 1
    statements = [item[0] for item in connection.cursor_value.calls]
    assert "INSERT INTO solvan_relay.collection_job_transitions" in statements[1]
    assert "UPDATE solvan_relay.collection_jobs" in statements[2]


def test_readiness_challenge_derives_all_authority_from_identity_and_registration() -> None:
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    connection = Connection(
        cursor=[
            {
                "placement_epoch": 3,
                "cell_id": "cell-europe",
                "local_policy_digest": HASH,
                "connector_catalog_digest": HASH,
                "redaction_revision": "relay-redaction.v1",
                "region": "europe-west1",
                "classification_ceiling": "INTERNAL",
                "policy_key_id": "policy-v1",
                "runtime_proof_key_id": "runtime-v1",
                "runtime_proof_key_digest": HASH,
                "signing_key_id": "control-v1",
            }
        ]
    )
    identity = RelayIdentityBinding(
        "org_" + "0" * 26,
        "prj_" + "0" * 26,
        "env_" + "0" * 26,
        "ren_" + "0" * 26,
        2,
        "https://relay-control.example",
        RelayEnrollmentState.REGISTERED,
    )
    issued = PostgresRelayStore(connection).issue_readiness_challenge(
        scope=scope(),
        identity=identity,
        issuer="https://issuer.example",
        subject="relay-subject",
        process_boot_id="boot-1",
        relay_version="1.0.0",
        image_digest=HASH,
        runtime_proof_key_id="runtime-v1",
        issued_at=now,
    )
    assert issued.challenge.enrollment_id == identity.enrollment_id
    assert issued.challenge.placement_epoch == 3
    assert issued.challenge.expires_at == now + timedelta(seconds=60)
    assert len(issued.nonce) >= 32
    statement, params = connection.cursor_value.calls[0]
    assert "e.principal_issuer=%(issuer)s" in statement
    assert "rk.public_key_ref IS NOT NULL" in statement
    assert params["organization_id"] == scope().organization_id
    assert len(connection.cursor_value.calls) == 2


def test_poll_does_not_lease_work_and_requires_a_fresh_readiness_receipt() -> None:
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    connection = Connection(cursor=[None])
    result = PostgresRelayStore(connection).poll_signed_job(
        scope=scope(), enrollment_id="ren_" + "0" * 26, now=now
    )
    assert result is None
    statement, params = connection.cursor_value.calls[0]
    assert "j.state='PENDING'" in statement
    assert "r.expires_at > %(now)s" in statement
    assert "FOR SHARE" in statement
    assert params["enrollment_id"] == "ren_" + "0" * 26


def test_poll_readiness_refuses_when_any_registered_binding_is_stale() -> None:
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    connection = Connection(cursor=[None])
    identity = RelayIdentityBinding(
        scope().organization_id,
        scope().project_id,
        scope().environment_id,
        "ren_" + "0" * 26,
        1,
        "https://relay-control.example",
        RelayEnrollmentState.REGISTERED,
    )
    with pytest.raises(RelayConflict, match="registration"):
        PostgresRelayStore(connection).record_poll_readiness(
            scope=scope(),
            identity=identity,
            relay_version="1.0.0",
            process_boot_id="boot-1",
            image_digest=HASH,
            image_attestation_digest=HASH,
            local_policy_id="rpol_" + "0" * 26,
            local_policy_digest=HASH,
            runtime_policy_proof_id="rpf_" + "0" * 26,
            runtime_policy_proof_digest=HASH,
            connector_catalog_digest=HASH,
            relay_connection_epoch=1,
            enrollment_epoch=1,
            declared_adapter_revisions=("1",),
            observed_at=now,
        )
    statement, params = connection.cursor_value.calls[0]
    assert "ia.attestation_digest=%(image_attestation_digest)s" in statement
    assert "p.process_boot_id=%(process_boot_id)s" in statement
    assert params["expected_audience"] == identity.expected_audience


def test_upload_grant_refuses_without_a_live_claimed_attempt() -> None:
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    connection = Connection(cursor=[None])
    with pytest.raises(RelayConflict, match="live claimed"):
        PostgresRelayStore(connection).create_upload_grant(
            scope=scope(),
            enrollment_id="ren_" + "0" * 26,
            collection_job_id="rcj_" + "0" * 26,
            job_digest=HASH,
            claim_token="00000000-0000-0000-0000-000000000001",
            attempt_id="rat_" + "0" * 26,
            attempt_number=1,
            process_boot_id="boot-1",
            attempt_outcome_hash=HASH,
            local_result_hash=HASH,
            content_hash=HASH,
            evidence_manifest_hash=HASH,
            redaction_manifest_hash=HASH,
            resource_binding_hash=HASH,
            classification="INTERNAL",
            residency_region="europe-west1",
            content_type="application/json",
            content_length=42,
            object_ref="gs://relay-evidence/tenant/object.json",
            cmek_digest=HASH,
            requested_at=now,
        )
    statement, params = connection.cursor_value.calls[0]
    assert "j.lease_expires_at > %(requested_at)s" in statement
    assert "a.attempt_number=%(attempt_number)s" in statement
    assert params["request_digest"].startswith("sha256:")


def test_success_receipt_refuses_without_the_exact_stored_result() -> None:
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    connection = Connection(cursor=[None])
    with pytest.raises(RelayConflict, match="stored result"):
        PostgresRelayStore(connection).commit_success_receipt(
            scope=scope(),
            enrollment_id="ren_" + "0" * 26,
            collection_job_id="rcj_" + "0" * 26,
            job_digest=HASH,
            claim_token="00000000-0000-0000-0000-000000000001",
            attempt_id="rat_" + "0" * 26,
            attempt_number=1,
            process_boot_id="boot-1",
            input_hash=HASH,
            attempt_outcome_hash=HASH,
            local_result_hash=HASH,
            content_hash=HASH,
            evidence_manifest_hash=HASH,
            redaction_manifest_hash=HASH,
            resource_binding_hash=HASH,
            classification="INTERNAL",
            residency_region="europe-west1",
            upload_grant_id="rug_" + "0" * 26,
            upload_grant_digest=HASH,
            object_ref="gs://relay-evidence/tenant/object.json",
            object_generation="1",
            object_metadata_hash=HASH,
            item_count=1,
            page_count=1,
            byte_count=42,
            call_count=1,
            started_at=now,
            completed_at=now,
            receipt_nonce="receipt-1",
        )
    statement, _params = connection.cursor_value.calls[0]
    assert "j.state='RESULT_STORED'" in statement
    assert "FOR UPDATE OF j,g" in statement


def test_coordinator_reconciles_an_expired_claim_as_ambiguous() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    connection = Connection(
        cursor=[
            {
                "id": "rcj_" + "0" * 26,
                "state": "CLAIMED",
                "workflow_version": 1,
                "claim_token": UUID("00000000-0000-0000-0000-000000000001"),
            }
        ]
    )
    assert PostgresRelayStore(connection).reconcile_expired_claims(scope=scope(), now=now) == 1
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "FOR UPDATE SKIP LOCKED" in statements[0]
    _statement, transition_params = connection.cursor_value.calls[1]
    assert isinstance(transition_params, dict)
    assert transition_params["event"] == "CLAIM_EXPIRED_AMBIGUOUS"
    assert "state='AMBIGUOUS'" in statements[2]


def test_coordinator_expires_unclaimed_job_and_closes_tool_reservation() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    connection = Connection(
        cursor=[
            {
                "id": "rcj_" + "0" * 26,
                "tool_call_id": "tcl_" + "0" * 26,
                "workflow_version": 0,
            }
        ]
    )
    assert PostgresRelayStore(connection).expire_unclaimed_jobs(scope=scope(), now=now) == 1
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "j.state='PENDING' AND j.expires_at <= %(now)s" in statements[0]
    assert "'PENDING','EXPIRED','EXPIRED'" in statements[1]
    assert "state='EXPIRED'" in statements[2]
    assert "status='FAILED',error_class='RELAY_JOB_EXPIRED'" in statements[3]
    assert "tool_call_receipts" in statements[4]


def test_admin_cancellation_terminalizes_only_an_unclaimed_job() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    connection = Connection(
        cursor=[
            {
                "state": "PENDING",
                "workflow_version": 0,
                "claim_token": None,
                "cancel_requested_at": None,
            }
        ]
    )
    result = PostgresRelayStore(connection).request_job_cancellation(
        scope=scope(),
        collection_job_id="rcj_" + "0" * 26,
        principal="user:admin@example.test",
        requested_at=now,
    )
    assert result == "CANCELLED"
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "'PENDING','CANCELLED','CANCELLED'" in statements[1]
    assert "state='CANCELLED'" in statements[2]


def test_administrator_registers_fail_closed_enrollment_with_runtime_proof_key() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    registration = RelayEnrollmentRegistration(
        relay_connection_id="con_" + "0" * 26,
        host_kind="GKE",
        risk_acceptance_ref=None,
        principal_subject="relay@example.test",
        principal_issuer="https://issuer.example",
        expected_audience="https://relay-control.example",
        image_digest=HASH,
        image_attestation_id="ria_" + "0" * 26,
        local_policy_digest=HASH,
        connector_catalog_digest=HASH,
        redaction_revision="relay-redaction-v1",
        region="europe-west1",
        classification_ceiling="INTERNAL",
        relay_version="1.0.0",
        runtime_proof_key_id="runtime-v1",
        runtime_proof_public_key_ref="gs://customer-keys/relay.pub",
        runtime_proof_public_key_digest=HASH,
    )
    connection = Connection(cursor=[{"placement_epoch": 2, "cell_id": "cell-europe"}])
    enrollment_id = PostgresRelayStore(connection).register_enrollment(
        scope=scope(),
        registration=registration,
        principal="user:admin@example.test",
        registered_at=now,
    )
    assert enrollment_id.startswith("ren_")
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "c.credential_posture='CUSTOMER_SIDE_NONE'" in statements[0]
    assert "'REGISTERED','AWAITING_RUNTIME_POLICY_PROOF'" in statements[1]
    assert "relay_runtime_proof_key_revisions" in statements[2]


def test_administrator_consumes_a_fresh_profile_without_browser_supplied_authority() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    profile = {
        "relay_connection_id": "con_" + "0" * 26,
        "host_kind": "GKE",
        "principal_subject": "relay@example.test",
        "principal_issuer": "https://issuer.example",
        "expected_audience": "https://relay-control.example",
        "image_digest": HASH,
        "image_attestation_id": "ria_" + "0" * 26,
        "local_policy_digest": HASH,
        "connector_catalog_digest": HASH,
        "redaction_revision": "relay-redaction-v1",
        "region": "europe-west1",
        "classification_ceiling": "INTERNAL",
        "relay_version": "1.0.0",
        "runtime_proof_key_id": "runtime-v1",
        "runtime_proof_public_key_ref": "gs://customer-keys/relay.pub",
        "runtime_proof_public_key_digest": HASH,
        "local_binding_digest": HASH,
        "review_state": "PENDING_REVIEW",
        "expires_at": now + timedelta(hours=1),
    }
    connection = Connection(cursor=[profile, {"placement_epoch": 2, "cell_id": "cell-europe"}])
    enrollment_id = PostgresRelayStore(connection).approve_deployment_profile(
        scope=scope(),
        deployment_profile_id="rdp_" + "0" * 26,
        principal="user:admin@example.test",
        approved_at=now,
    )
    assert enrollment_id.startswith("ren_")
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "relay_deployment_profiles" in statements[0]
    assert "deployment_profile_id" in statements[-2]
    assert "review_state='CONSUMED'" in statements[-1]


def test_administrator_registers_only_a_probed_closed_monitoring_binding() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    binding = RelaySourceBindingRegistration(
        source_connection_id="con_" + "0" * 26,
        source_connection_epoch=1,
        adapter_key=RelayAdapter.CLOUD_MONITORING,
        adapter_revision="1",
        local_binding_digest=HASH,
        capability_receipt_id="cap-monitoring-v1",
        capability_receipt_hash=HASH,
        region="europe-west1",
        classification_ceiling="INTERNAL",
    )
    connection = Connection(
        cursor=[
            {
                "enrollment_epoch": 1,
                "region": "europe-west1",
                "classification_ceiling": "INTERNAL",
                "connection_epoch": 1,
            }
        ]
    )
    binding_id = PostgresRelayStore(connection).register_source_binding(
        scope=scope(),
        enrollment_id="ren_" + "0" * 26,
        registration=binding,
        principal="user:admin@example.test",
        registered_at=now,
    )
    assert binding_id.startswith("rsb_")
    statement, _params = connection.cursor_value.calls[0]
    assert "capability.capability='metrics.read'" in statement


def test_administrator_disable_uses_the_enrollment_transition_machine() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    connection = Connection(
        cursor=[{"lifecycle": "READY", "workflow_version": 1, "enrollment_epoch": 1}]
    )
    lifecycle = PostgresRelayStore(connection).transition_enrollment_administratively(
        scope=scope(),
        enrollment_id="ren_" + "0" * 26,
        action="DISABLE",
        principal="user:admin@example.test",
        occurred_at=now,
    )
    assert lifecycle == "DISABLED"
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "relay_enrollment_transitions" in statements[1]
    _statement, transition_params = connection.cursor_value.calls[1]
    assert isinstance(transition_params, dict)
    assert transition_params["event"] == "ADMIN_DISABLED"


def test_administrator_reenable_advances_epoch_and_requires_new_runtime_proof() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    registration = RelayEnrollmentRegistration(
        relay_connection_id="con_" + "0" * 26,
        host_kind="GKE",
        risk_acceptance_ref=None,
        principal_subject="relay@example.test",
        principal_issuer="https://issuer.example",
        expected_audience="https://relay-control.example",
        image_digest=HASH,
        image_attestation_id="ria_" + "0" * 26,
        local_policy_digest=HASH,
        connector_catalog_digest=HASH,
        redaction_revision="relay-redaction-v1",
        region="europe-west1",
        classification_ceiling="INTERNAL",
        relay_version="1.0.0",
        runtime_proof_key_id="runtime-v2",
        runtime_proof_public_key_ref="gs://customer-keys/relay-v2.pub",
        runtime_proof_public_key_digest=HASH,
    )
    connection = Connection(
        cursor=[
            {
                "lifecycle": "DISABLED",
                "workflow_version": 4,
                "enrollment_epoch": 1,
                "relay_connection_id": registration.relay_connection_id,
                "principal_subject": registration.principal_subject,
                "principal_issuer": registration.principal_issuer,
                "connection_epoch": 2,
                "placement_epoch": 3,
                "cell_id": "cell-europe",
            }
        ]
    )
    lifecycle = PostgresRelayStore(connection).reenable_enrollment(
        scope=scope(),
        enrollment_id="ren_" + "0" * 26,
        registration=registration,
        principal="user:admin@example.test",
        occurred_at=now,
    )
    assert lifecycle == "REGISTERED"
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "ADMIN_REENABLED" in statements[1]
    assert "relay_runtime_proof_key_revisions" in statements[3]
    _statement, update_params = connection.cursor_value.calls[2]
    assert isinstance(update_params, dict)
    assert update_params["enrollment_epoch"] == 2


def test_stale_enrollment_requires_and_records_fresh_reattestation() -> None:
    now = datetime(2026, 8, 15, 10, tzinfo=UTC)
    identity = RelayIdentityBinding(
        scope_organization_id="org_" + "0" * 26,
        scope_project_id="prj_" + "0" * 26,
        scope_environment_id="env_" + "0" * 26,
        enrollment_id="ren_" + "0" * 26,
        enrollment_epoch=2,
        expected_audience="https://relay-control.example",
        lifecycle=RelayEnrollmentState.STALE,
    )
    connection = Connection(
        cursor=[
            {
                "lifecycle": "STALE",
                "workflow_version": 4,
                "enrollment_epoch": 2,
                "placement_epoch": 3,
                "cell_id": "cell-europe",
                "relay_connection_id": "con_" + "0" * 26,
                "expected_audience": identity.expected_audience,
                "image_attestation_id": "ria_" + "0" * 26,
                "policy_key_digest": HASH,
                "principal_claims_hash": HASH,
                "local_policy_signature_digest": HASH,
                "policy_key_id": "policy-v1",
                "redaction_revision": "relay-redaction-v1",
                "region": "europe-west1",
                "classification_ceiling": "INTERNAL",
                "expires_at": now + timedelta(minutes=1),
            }
        ]
    )
    PostgresRelayStore(connection).record_poll_readiness(
        scope=scope(),
        identity=identity,
        relay_version="1.0.0",
        process_boot_id="boot-1",
        image_digest=HASH,
        image_attestation_digest=HASH,
        local_policy_id="policy-1",
        local_policy_digest=HASH,
        runtime_policy_proof_id="rpp_" + "0" * 26,
        runtime_policy_proof_digest=HASH,
        connector_catalog_digest=HASH,
        relay_connection_epoch=1,
        enrollment_epoch=2,
        declared_adapter_revisions=("1",),
        observed_at=now,
    )
    statements = [statement for statement, _params in connection.cursor_value.calls]
    assert "'STALE'" in statements[0]
    assert any("relay.readiness" in statement for statement in statements)
    transition_index = next(
        index
        for index, statement in enumerate(statements)
        if "relay_enrollment_transitions" in statement
    )
    _statement, transition_params = connection.cursor_value.calls[transition_index]
    assert isinstance(transition_params, dict)
    assert transition_params["event"] == "REATTESTED"
