"""Deterministic contracts for the customer-resident Solvant Relay."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

import rfc8785

from solvan.domain.identifiers import validate_identifier
from solvan.domain.scope import Scope

_DIGEST_PREFIX = "sha256:"


class RelayContractError(ValueError):
    """Raised when Relay material is not in the closed deterministic contract."""


class RelayEnrollmentState(StrEnum):
    REGISTERED = "REGISTERED"
    READY = "READY"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    DISABLED = "DISABLED"
    REVOKED = "REVOKED"


class CollectionJobState(StrEnum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    EXECUTING = "EXECUTING"
    RETRY_WAIT = "RETRY_WAIT"
    RESULT_STORED = "RESULT_STORED"
    AMBIGUOUS = "AMBIGUOUS"
    ACCEPTED = "ACCEPTED"
    REFUSED = "REFUSED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class RelayAdapter(StrEnum):
    CLOUD_MONITORING = "cloud-monitoring.v1"
    MANAGED_PROMETHEUS = "managed-prometheus.v1"
    CLOUD_LOGGING = "cloud-logging.v1"
    CLOUD_TRACE = "cloud-trace.v1"
    KUBERNETES_METADATA = "kubernetes-metadata.v1"


@dataclass(frozen=True, slots=True)
class RelayEnrollmentRegistration:
    """Administrator-supplied enrollment metadata; it cannot assert readiness."""

    relay_connection_id: str
    host_kind: str
    risk_acceptance_ref: str | None
    principal_subject: str
    principal_issuer: str
    expected_audience: str
    image_digest: str
    image_attestation_id: str
    local_policy_digest: str
    connector_catalog_digest: str
    redaction_revision: str
    region: str
    classification_ceiling: str
    relay_version: str
    runtime_proof_key_id: str
    runtime_proof_public_key_ref: str
    runtime_proof_public_key_digest: str

    def __post_init__(self) -> None:
        validate_identifier(self.relay_connection_id, expected_prefix="con")
        validate_identifier(self.image_attestation_id, expected_prefix="ria")
        if self.host_kind not in {
            "CLOUD_RUN_WORKER_POOL",
            "GKE",
            "ONPREM_FEDERATED",
            "ONPREM_KEYFILE",
            "DEV_LOCAL",
        }:
            raise RelayContractError("Relay host kind is outside the closed vocabulary")
        if self.host_kind == "ONPREM_KEYFILE" and not self.risk_acceptance_ref:
            raise RelayContractError("key-file Relay enrollment requires risk acceptance")
        if (
            not self.principal_subject
            or not self.principal_issuer.startswith("https://")
            or not self.expected_audience.startswith("https://")
            or not self.runtime_proof_key_id
            or not self.runtime_proof_public_key_ref.startswith("gs://")
            or not self.redaction_revision
            or not self.region
            or not self.relay_version
            or self.classification_ceiling
            not in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
        ):
            raise RelayContractError("Relay enrollment registration is malformed")
        for value, field in (
            (self.image_digest, "image_digest"),
            (self.local_policy_digest, "local_policy_digest"),
            (self.connector_catalog_digest, "connector_catalog_digest"),
            (self.runtime_proof_public_key_digest, "runtime_proof_public_key_digest"),
        ):
            require_digest(value, field=field)


@dataclass(frozen=True, slots=True)
class RelaySourceBindingRegistration:
    """One closed adapter binding to a customer-side source connection."""

    source_connection_id: str
    source_connection_epoch: int
    adapter_key: RelayAdapter
    adapter_revision: str
    local_binding_digest: str
    capability_receipt_id: str
    capability_receipt_hash: str
    region: str
    classification_ceiling: str

    def __post_init__(self) -> None:
        validate_identifier(self.source_connection_id, expected_prefix="con")
        if self.source_connection_epoch < 1 or not self.adapter_revision or not self.region:
            raise RelayContractError("Relay source binding registration is malformed")
        if self.classification_ceiling not in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
            raise RelayContractError("Relay source binding classification is invalid")
        require_digest(self.local_binding_digest, field="local_binding_digest")
        require_digest(self.capability_receipt_hash, field="capability_receipt_hash")


_OPERATIONS = frozenset(
    {
        "monitoring.time-series.read.v1",
        "monitoring.metric-descriptors.read.v1",
        "prometheus.registered-range.read.v1",
        "logging.entries.read.v1",
        "trace.spans.read.v1",
        "kubernetes.metadata.list.v1",
    }
)


def require_digest(value: str, *, field: str) -> str:
    if len(value) != 71 or not value.startswith(_DIGEST_PREFIX):
        raise RelayContractError(f"{field} must be a lowercase SHA-256 digest")
    try:
        bytes.fromhex(value.removeprefix(_DIGEST_PREFIX))
    except ValueError as error:
        raise RelayContractError(f"{field} must be a lowercase SHA-256 digest") from error
    if value != value.lower():
        raise RelayContractError(f"{field} must be a lowercase SHA-256 digest")
    return value


def canonical_digest(value: Mapping[str, Any]) -> str:
    """Return the normative RFC-8785/SHA-256 material digest."""

    try:
        payload = rfc8785.dumps(dict(value))
    except (TypeError, ValueError) as error:
        raise RelayContractError("Relay material is not RFC-8785 canonicalizable") from error
    return _DIGEST_PREFIX + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class RelaySourceBinding:
    binding_id: str
    enrollment_id: str
    enrollment_epoch: int
    source_connection_id: str
    source_connection_epoch: int
    adapter_key: RelayAdapter
    adapter_revision: str
    capability_receipt_id: str
    capability_receipt_hash: str
    region: str
    classification_ceiling: str

    def __post_init__(self) -> None:
        validate_identifier(self.binding_id, expected_prefix="rsb")
        validate_identifier(self.enrollment_id, expected_prefix="ren")
        if self.enrollment_epoch < 1 or self.source_connection_epoch < 1:
            raise RelayContractError("Relay source binding epochs must be positive")
        require_digest(self.capability_receipt_hash, field="capability_receipt_hash")


@dataclass(frozen=True, slots=True)
class CollectionJobMaterial:
    """Coordinator-derived inputs required before the signed job can be persisted."""

    collection_job_id: str
    enrollment_id: str
    enrollment_epoch: int
    relay_connection_id: str
    relay_connection_epoch: int
    source_binding_id: str
    source_connection_id: str
    source_connection_epoch: int
    placement_epoch: int
    cell_id: str
    agent_run_id: str
    tool_call_id: str
    tool_arguments_hash: str
    incident_id: str
    profile_key: str
    profile_version: str
    profile_material_hash: str
    profile_ordinal: int
    tool_key: str
    tool_version: str
    capability_receipt_id: str
    capability_receipt_hash: str
    connector_catalog_digest: str
    adapter_key: RelayAdapter
    adapter_revision: str
    operation: str
    typed_parameters: Mapping[str, Any]
    parameters_hash: str
    resource_binding_id: str
    graph_snapshot_id: str
    resource_binding_hash: str
    window_start: datetime | None
    window_end: datetime | None
    maximum_pages: int
    maximum_items: int
    maximum_bytes: int
    maximum_calls: int
    maximum_attempts: int
    redaction_revision: str
    classification_ceiling: str
    residency_region: str
    input_hash: str
    issued_at: datetime
    expires_at: datetime
    job_digest: str
    job_nonce: str
    signing_key_id: str
    signature_base64: str

    def __post_init__(self) -> None:
        for value, prefix in (
            (self.collection_job_id, "rcj"),
            (self.enrollment_id, "ren"),
            (self.resource_binding_id, "pgn"),
            (self.graph_snapshot_id, "pgs"),
        ):
            validate_identifier(value, expected_prefix=prefix)
        for value, field in (
            (self.tool_arguments_hash, "tool_arguments_hash"),
            (self.profile_material_hash, "profile_material_hash"),
            (self.capability_receipt_hash, "capability_receipt_hash"),
            (self.connector_catalog_digest, "connector_catalog_digest"),
            (self.parameters_hash, "parameters_hash"),
            (self.resource_binding_hash, "resource_binding_hash"),
            (self.input_hash, "input_hash"),
            (self.job_digest, "job_digest"),
        ):
            require_digest(value, field=field)
        if self.operation not in _OPERATIONS:
            raise RelayContractError("Relay operation is outside the closed catalog")
        if canonical_digest(self.typed_parameters) != self.parameters_hash:
            raise RelayContractError("typed parameters do not match parameters_hash")
        if any(
            value < 1
            for value in (
                self.enrollment_epoch,
                self.relay_connection_epoch,
                self.source_connection_epoch,
                self.placement_epoch,
                self.profile_ordinal,
            )
        ):
            raise RelayContractError("Relay epochs and ordinals must be positive")
        if not 1 <= self.maximum_pages <= 20:
            raise RelayContractError("maximum_pages is outside the closed bound")
        if not 1 <= self.maximum_items <= 1000:
            raise RelayContractError("maximum_items is outside the closed bound")
        if not 1 <= self.maximum_bytes <= 1_048_576:
            raise RelayContractError("maximum_bytes is outside the closed bound")
        if not 1 <= self.maximum_calls <= 20 or not 1 <= self.maximum_attempts <= 2:
            raise RelayContractError("Relay call or attempt budget is outside the closed bound")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise RelayContractError("Relay job times must be timezone-aware")
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if lifetime <= 0 or lifetime > 120:
            raise RelayContractError("Relay job lifetime must be within 120 seconds")
        if (self.window_start is None) != (self.window_end is None):
            raise RelayContractError("Relay evidence window must be complete or absent")
        if self.window_start is not None and self.window_end is not None:
            if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
                raise RelayContractError("Relay evidence window must be timezone-aware")
            if self.window_end < self.window_start:
                raise RelayContractError("Relay evidence window is reversed")

    def signed_projection(self, *, scope: Scope) -> dict[str, Any]:
        """Return the sole detached-signature payload for a collection job.

        Both the coordinator and poll path use this method.  It intentionally
        includes the scope binding and every persistence field that can affect
        a customer read; a compact downstream view is never substituted for
        the signed job.
        """

        return {
            "schema_version": 1,
            "canonicalization_version": 1,
            "scope_hash": canonical_digest(scope.canonical_dict()),
            "collection_job_id": self.collection_job_id,
            "enrollment_id": self.enrollment_id,
            "enrollment_epoch": self.enrollment_epoch,
            "relay_connection_id": self.relay_connection_id,
            "relay_connection_epoch": self.relay_connection_epoch,
            "source_binding_id": self.source_binding_id,
            "source_connection_id": self.source_connection_id,
            "source_connection_epoch": self.source_connection_epoch,
            "placement_epoch": self.placement_epoch,
            "cell_id": self.cell_id,
            "agent_run_id": self.agent_run_id,
            "tool_call_id": self.tool_call_id,
            "tool_arguments_hash": self.tool_arguments_hash,
            "incident_id": self.incident_id,
            "profile_key": self.profile_key,
            "profile_version": self.profile_version,
            "profile_material_hash": self.profile_material_hash,
            "profile_ordinal": self.profile_ordinal,
            "tool_key": self.tool_key,
            "tool_version": self.tool_version,
            "capability_receipt_id": self.capability_receipt_id,
            "capability_receipt_hash": self.capability_receipt_hash,
            "connector_catalog_key": "gcp-observe.v1",
            "connector_catalog_revision": 1,
            "connector_catalog_digest": self.connector_catalog_digest,
            "adapter_key": self.adapter_key.value,
            "adapter_revision": self.adapter_revision,
            "operation": self.operation,
            "typed_parameters": dict(self.typed_parameters),
            "parameters_hash": self.parameters_hash,
            "resource_binding_id": self.resource_binding_id,
            "graph_snapshot_id": self.graph_snapshot_id,
            "resource_binding_hash": self.resource_binding_hash,
            "window_start": None if self.window_start is None else self.window_start.isoformat(),
            "window_end": None if self.window_end is None else self.window_end.isoformat(),
            "maximum_pages": self.maximum_pages,
            "maximum_items": self.maximum_items,
            "maximum_bytes": self.maximum_bytes,
            "maximum_calls": self.maximum_calls,
            "maximum_attempts": self.maximum_attempts,
            "redaction_revision": self.redaction_revision,
            "classification_ceiling": self.classification_ceiling,
            "residency_region": self.residency_region,
            "input_hash": self.input_hash,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "job_nonce": self.job_nonce,
            "signing_key_id": self.signing_key_id,
        }

    def require_signed_digest(self, *, scope: Scope) -> None:
        if canonical_digest(self.signed_projection(scope=scope)) != self.job_digest:
            raise RelayContractError("job_digest does not bind the exact collection job")


@dataclass(frozen=True, slots=True)
class RelayJobClaim:
    collection_job_id: str
    job_digest: str
    claim_token: str
    attempt_id: str
    attempt_number: int
    lease_expires_at: datetime
    workflow_version: int


@dataclass(frozen=True, slots=True)
class RelayIdentityBinding:
    scope_organization_id: str
    scope_project_id: str
    scope_environment_id: str
    enrollment_id: str
    enrollment_epoch: int
    expected_audience: str
    lifecycle: RelayEnrollmentState


@dataclass(frozen=True, slots=True)
class RelayReadinessChallenge:
    """Identity-derived challenge material which a Relay runtime must echo exactly.

    The nonce itself is deliberately not persisted here.  The control plane keeps
    only its digest; the caller receives the nonce inside the separately signed
    challenge envelope.
    """

    challenge_id: str
    challenge_digest: str
    nonce_hash: str
    enrollment_id: str
    enrollment_epoch: int
    placement_epoch: int
    cell_id: str
    principal_claims_hash: str
    expected_audience: str
    process_boot_id: str
    image_digest: str
    local_policy_digest: str
    policy_key_id: str
    connector_catalog_digest: str
    redaction_revision: str
    runtime_proof_key_id: str
    runtime_proof_key_digest: str
    region: str
    classification_ceiling: str
    signing_key_id: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        validate_identifier(self.challenge_id, expected_prefix="rch")
        for value, field in (
            (self.challenge_digest, "challenge_digest"),
            (self.nonce_hash, "nonce_hash"),
            (self.principal_claims_hash, "principal_claims_hash"),
            (self.image_digest, "image_digest"),
            (self.local_policy_digest, "local_policy_digest"),
            (self.connector_catalog_digest, "connector_catalog_digest"),
            (self.runtime_proof_key_digest, "runtime_proof_key_digest"),
        ):
            require_digest(value, field=field)
        if self.enrollment_epoch < 1 or self.placement_epoch < 1:
            raise RelayContractError("readiness challenge epochs must be positive")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise RelayContractError("readiness challenge times must be timezone-aware")
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if lifetime <= 0 or lifetime > 60:
            raise RelayContractError("readiness challenge lifetime must be within 60 seconds")

    def unsigned_projection(self, *, nonce: str) -> dict[str, Any]:
        """Return the exact customer-visible signed challenge payload."""

        return {
            "schema_version": 1,
            "challenge_id": self.challenge_id,
            "challenge_digest": self.challenge_digest,
            "nonce": nonce,
            "nonce_hash": self.nonce_hash,
            "enrollment_id": self.enrollment_id,
            "enrollment_epoch": self.enrollment_epoch,
            "placement_epoch": self.placement_epoch,
            "cell_id": self.cell_id,
            "principal_claims_hash": self.principal_claims_hash,
            "expected_audience": self.expected_audience,
            "process_boot_id": self.process_boot_id,
            "image_digest": self.image_digest,
            "local_policy_digest": self.local_policy_digest,
            "policy_key_id": self.policy_key_id,
            "connector_catalog_digest": self.connector_catalog_digest,
            "redaction_revision": self.redaction_revision,
            "runtime_proof_key_id": self.runtime_proof_key_id,
            "runtime_proof_key_digest": self.runtime_proof_key_digest,
            "region": self.region,
            "classification_ceiling": self.classification_ceiling,
            "signing_key_id": self.signing_key_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class RelayRuntimePolicyProof:
    """The closed, customer-signed assertion used to issue one readiness receipt."""

    proof_id: str
    challenge_id: str
    challenge_digest: str
    enrollment_id: str
    enrollment_epoch: int
    placement_epoch: int
    principal_claims_hash: str
    expected_audience: str
    process_boot_id: str
    image_digest: str
    local_policy_digest: str
    local_policy_signature_digest: str
    policy_key_id: str
    connector_catalog_digest: str
    redaction_revision: str
    runtime_proof_key_id: str
    runtime_proof_key_digest: str
    region: str
    classification_ceiling: str
    local_policy_verified: bool
    proof_digest: str
    signature_base64: str
    verified_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        validate_identifier(self.proof_id, expected_prefix="rpf")
        validate_identifier(self.challenge_id, expected_prefix="rch")
        for value, field in (
            (self.challenge_digest, "challenge_digest"),
            (self.principal_claims_hash, "principal_claims_hash"),
            (self.image_digest, "image_digest"),
            (self.local_policy_digest, "local_policy_digest"),
            (self.local_policy_signature_digest, "local_policy_signature_digest"),
            (self.connector_catalog_digest, "connector_catalog_digest"),
            (self.runtime_proof_key_digest, "runtime_proof_key_digest"),
            (self.proof_digest, "proof_digest"),
        ):
            require_digest(value, field=field)
        if not self.local_policy_verified:
            raise RelayContractError("runtime policy proof must attest local policy verification")
        if self.verified_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise RelayContractError("runtime policy proof times must be timezone-aware")
        if self.expires_at <= self.verified_at:
            raise RelayContractError("runtime policy proof must expire after verification")

    def unsigned_projection(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "proof_id": self.proof_id,
            "challenge_id": self.challenge_id,
            "challenge_digest": self.challenge_digest,
            "enrollment_id": self.enrollment_id,
            "enrollment_epoch": self.enrollment_epoch,
            "placement_epoch": self.placement_epoch,
            "principal_claims_hash": self.principal_claims_hash,
            "expected_audience": self.expected_audience,
            "process_boot_id": self.process_boot_id,
            "image_digest": self.image_digest,
            "local_policy_digest": self.local_policy_digest,
            "local_policy_signature_digest": self.local_policy_signature_digest,
            "policy_key_id": self.policy_key_id,
            "connector_catalog_digest": self.connector_catalog_digest,
            "redaction_revision": self.redaction_revision,
            "runtime_proof_key_id": self.runtime_proof_key_id,
            "runtime_proof_key_digest": self.runtime_proof_key_digest,
            "region": self.region,
            "classification_ceiling": self.classification_ceiling,
            "local_policy_verified": self.local_policy_verified,
            "proof_digest": self.proof_digest,
            "verified_at": self.verified_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
