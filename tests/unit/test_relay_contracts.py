from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from solvan.domain import (
    CollectionJobMaterial,
    RelayAdapter,
    RelayContractError,
    RelayEnrollmentRegistration,
    RelaySourceBindingRegistration,
    Scope,
    canonical_digest,
)

HASH = "sha256:" + "1" * 64


def _id(prefix: str) -> str:
    return prefix + "_" + "0" * 26


def material() -> CollectionJobMaterial:
    issued = datetime(2026, 8, 13, 10, tzinfo=UTC)
    parameters = {"metric_type": "run.googleapis.com/request_count", "alignment_seconds": 60}
    value = CollectionJobMaterial(
        collection_job_id=_id("rcj"),
        enrollment_id=_id("ren"),
        enrollment_epoch=2,
        relay_connection_id="con_relay",
        relay_connection_epoch=4,
        source_binding_id=_id("rsb"),
        source_connection_id="con_monitoring",
        source_connection_epoch=5,
        placement_epoch=3,
        cell_id="cell_europe_west1",
        agent_run_id="run_1",
        tool_call_id="tcl_1",
        tool_arguments_hash=HASH,
        incident_id="inc_1",
        profile_key="gcp-observe",
        profile_version="1",
        profile_material_hash=HASH,
        profile_ordinal=1,
        tool_key="monitoring.time-series.read.v1",
        tool_version="1",
        capability_receipt_id="cap_1",
        capability_receipt_hash=HASH,
        connector_catalog_digest=HASH,
        adapter_key=RelayAdapter.CLOUD_MONITORING,
        adapter_revision="1",
        operation="monitoring.time-series.read.v1",
        typed_parameters=parameters,
        parameters_hash=canonical_digest(parameters),
        resource_binding_id=_id("pgn"),
        graph_snapshot_id=_id("pgs"),
        resource_binding_hash=HASH,
        window_start=issued - timedelta(minutes=5),
        window_end=issued,
        maximum_pages=2,
        maximum_items=100,
        maximum_bytes=100_000,
        maximum_calls=2,
        maximum_attempts=2,
        redaction_revision="relay-redaction-v1",
        classification_ceiling="CONFIDENTIAL",
        residency_region="europe-west1",
        input_hash=HASH,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=90),
        job_digest=HASH,
        job_nonce="nonce-1",
        signing_key_id="relay-signing-v1",
        signature_base64="c2lnbmF0dXJl",
    )
    return replace(
        value,
        job_digest=canonical_digest(
            value.signed_projection(scope=Scope(_id("org"), _id("prj"), _id("env")))
        ),
    )


def test_relay_job_material_accepts_only_closed_bounded_operation() -> None:
    value = material()
    assert value.adapter_key is RelayAdapter.CLOUD_MONITORING
    with pytest.raises(RelayContractError, match="outside the closed catalog"):
        replace(value, operation="http.get")


def test_relay_job_material_binds_typed_parameters_and_short_expiry() -> None:
    value = material()
    with pytest.raises(RelayContractError, match="parameters_hash"):
        replace(value, parameters_hash=HASH)
    with pytest.raises(RelayContractError, match="within 120 seconds"):
        replace(value, expires_at=value.issued_at + timedelta(seconds=121))


def test_relay_job_digest_binds_the_full_signed_projection() -> None:
    value = material()
    scope = Scope(_id("org"), _id("prj"), _id("env"))
    value.require_signed_digest(scope=scope)
    with pytest.raises(RelayContractError, match="job_digest"):
        replace(value, maximum_calls=1).require_signed_digest(scope=scope)


def test_relay_job_material_rejects_open_ended_window_or_oversized_output() -> None:
    value = material()
    with pytest.raises(RelayContractError, match="complete or absent"):
        replace(value, window_end=None)
    with pytest.raises(RelayContractError, match="maximum_bytes"):
        replace(value, maximum_bytes=1_048_577)


def test_enrollment_registration_is_closed_and_requires_keyfile_risk_acceptance() -> None:
    common = dict(
        relay_connection_id=_id("con"),
        risk_acceptance_ref=None,
        principal_subject="service-account@example.test",
        principal_issuer="https://issuer.example",
        expected_audience="https://relay-control.example",
        image_digest=HASH,
        image_attestation_id=_id("ria"),
        local_policy_digest=HASH,
        connector_catalog_digest=HASH,
        redaction_revision="relay-redaction-v1",
        region="europe-west1",
        classification_ceiling="INTERNAL",
        relay_version="1.0.0",
        runtime_proof_key_id="customer-runtime-v1",
        runtime_proof_public_key_ref="gs://customer-bucket/relay/runtime.pub",
        runtime_proof_public_key_digest=HASH,
    )
    with pytest.raises(RelayContractError, match="risk acceptance"):
        RelayEnrollmentRegistration(host_kind="ONPREM_KEYFILE", **common)
    registration = RelayEnrollmentRegistration(host_kind="GKE", **common)
    assert registration.runtime_proof_public_key_ref.startswith("gs://")


def test_source_binding_registration_has_no_endpoint_or_query_surface() -> None:
    binding = RelaySourceBindingRegistration(
        source_connection_id=_id("con"),
        source_connection_epoch=1,
        adapter_key=RelayAdapter.CLOUD_MONITORING,
        adapter_revision="1",
        local_binding_digest=HASH,
        capability_receipt_id="cap-monitoring-v1",
        capability_receipt_hash=HASH,
        region="europe-west1",
        classification_ceiling="INTERNAL",
    )
    assert binding.adapter_key is RelayAdapter.CLOUD_MONITORING
