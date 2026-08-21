"""Deterministic contracts for independent release-health verification."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from math import isfinite
from typing import Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.release_authority import (
    ReleaseHealthSignalInput,
    ReleaseHealthSignalKind,
)
from solvan.application.workspace_hashing import canonical_json_bytes, canonical_sha256
from solvan.domain import Scope

_HASH = r"^sha256:[0-9a-f]{64}$"


class ReleaseVerificationError(ValueError):
    pass


class ReleaseVerificationEvidenceReader(Protocol):
    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int) -> bytes: ...


class ReleaseVerificationKmsReader(Protocol):
    def public_key_pem(self, key_version: str) -> bytes: ...


class ReleaseVerificationResult(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class HealthSignalMeasurement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_kind: ReleaseHealthSignalKind
    value: float
    point_count: int = Field(ge=0, le=100_000)
    request_ids: tuple[str, ...] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def validate_value(self) -> Self:
        if not isfinite(self.value):
            raise ReleaseVerificationError("release health measurement must be finite")
        return self


class ReleaseHealthSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    scope: Scope
    code_change_request_id: str
    release_candidate_id: str
    release_target_profile_id: str
    target_observation_hash: str = Field(pattern=_HASH)
    verification_profile_hash: str = Field(pattern=_HASH)
    target_version: str
    target_assignment_hash: str = Field(pattern=_HASH)
    external_project_id: str
    cloud_run_service_name: str
    window_start: datetime
    window_end: datetime
    measurements: tuple[HealthSignalMeasurement, ...] = Field(min_length=1, max_length=8)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if (
            self.window_start.tzinfo is None
            or self.window_end.tzinfo is None
            or self.observed_at.tzinfo is None
            or not self.window_start < self.window_end <= self.observed_at
            or len({item.signal_kind for item in self.measurements}) != len(self.measurements)
        ):
            raise ReleaseVerificationError("release health snapshot is malformed")
        return self

    @property
    def signal_results_hash(self) -> str:
        return canonical_sha256([item.model_dump(mode="json") for item in self.measurements])

    def signed_payload(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


class ReleaseHealthSnapshotExpected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    code_change_request_id: str
    release_candidate_id: str
    release_target_profile_id: str
    target_observation_hash: str = Field(pattern=_HASH)
    verification_profile_hash: str = Field(pattern=_HASH)
    target_version: str
    target_assignment_hash: str = Field(pattern=_HASH)
    verifier_identity: str = Field(pattern=r"^serviceAccount:")
    verifier_key_version: str = Field(pattern=r"^projects/.+/cryptoKeyVersions/[1-9][0-9]*$")


def verify_release_health_snapshot(
    snapshot: ReleaseHealthSnapshot,
    *,
    expected: ReleaseHealthSnapshotExpected,
    signature_ref: str,
    signature_hash: str,
    evidence: ReleaseVerificationEvidenceReader,
    kms: ReleaseVerificationKmsReader,
) -> None:
    if (
        snapshot.scope != expected.scope
        or snapshot.code_change_request_id != expected.code_change_request_id
        or snapshot.release_candidate_id != expected.release_candidate_id
        or snapshot.release_target_profile_id != expected.release_target_profile_id
        or snapshot.target_observation_hash != expected.target_observation_hash
        or snapshot.verification_profile_hash != expected.verification_profile_hash
        or snapshot.target_version != expected.target_version
        or snapshot.target_assignment_hash != expected.target_assignment_hash
    ):
        raise ReleaseVerificationError("release health snapshot authority differs")
    signature = evidence.get_bytes(uri=signature_ref, expected_hash=signature_hash, max_bytes=512)
    try:
        public_key = serialization.load_pem_public_key(
            kms.public_key_pem(expected.verifier_key_version)
        )
    except Exception as error:
        raise ReleaseVerificationError("release verifier public key is unavailable") from error
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ReleaseVerificationError("release verifier key is not P-256")
    try:
        public_key.verify(signature, snapshot.signed_payload(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise ReleaseVerificationError("release health signature is invalid") from error


class ReleaseVerificationEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    result: ReleaseVerificationResult
    rationale_codes: tuple[str, ...] = Field(min_length=1, max_length=16)


class ReleaseEffectReceiptEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    scope: Scope
    deployment_rollout_id: str
    stage_ordinal: int = Field(ge=1, le=32)
    observation_window_generation: int = Field(ge=1, le=1000)
    verification_profile_hash: str = Field(pattern=_HASH)
    release_health_baseline_ref: str = Field(pattern=r"^gs://")
    release_health_baseline_hash: str = Field(pattern=_HASH)
    predeploy_snapshot_ref: str = Field(pattern=r"^gs://")
    predeploy_snapshot_hash: str = Field(pattern=_HASH)
    postdeploy_observation_ref: str = Field(pattern=r"^gs://")
    postdeploy_observation_hash: str = Field(pattern=_HASH)
    intended_effect_hash: str = Field(pattern=_HASH)
    observed_target_version: str
    observed_assignment_hash: str = Field(pattern=_HASH)
    window_start: datetime
    window_end: datetime
    result: ReleaseVerificationResult
    rationale_codes: tuple[str, ...] = Field(min_length=1, max_length=16)
    verifier_identity: str = Field(pattern=r"^serviceAccount:")
    verifier_key_version: str = Field(pattern=r"^projects/.+/cryptoKeyVersions/[1-9][0-9]*$")
    observed_at: datetime

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if (
            self.window_start.tzinfo is None
            or self.window_end.tzinfo is None
            or self.observed_at.tzinfo is None
            or not self.window_start < self.window_end <= self.observed_at
        ):
            raise ReleaseVerificationError("release effect receipt time is malformed")
        return self

    def signed_payload(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


class ReleaseEffectReceiptExpected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    deployment_rollout_id: str
    stage_ordinal: int = Field(ge=1, le=32)
    observation_window_generation: int = Field(ge=1, le=1000)
    verification_profile_hash: str = Field(pattern=_HASH)
    release_health_baseline_hash: str = Field(pattern=_HASH)
    predeploy_snapshot_hash: str = Field(pattern=_HASH)
    intended_effect_hash: str = Field(pattern=_HASH)
    verifier_identity: str = Field(pattern=r"^serviceAccount:")
    verifier_key_version: str = Field(pattern=r"^projects/.+/cryptoKeyVersions/[1-9][0-9]*$")


def verify_release_effect_receipt(
    receipt: ReleaseEffectReceiptEnvelope,
    *,
    expected: ReleaseEffectReceiptExpected,
    signature_ref: str,
    signature_hash: str,
    evidence: ReleaseVerificationEvidenceReader,
    kms: ReleaseVerificationKmsReader,
) -> None:
    if (
        receipt.scope != expected.scope
        or receipt.deployment_rollout_id != expected.deployment_rollout_id
        or receipt.stage_ordinal != expected.stage_ordinal
        or receipt.observation_window_generation != expected.observation_window_generation
        or receipt.verification_profile_hash != expected.verification_profile_hash
        or receipt.release_health_baseline_hash != expected.release_health_baseline_hash
        or receipt.predeploy_snapshot_hash != expected.predeploy_snapshot_hash
        or receipt.intended_effect_hash != expected.intended_effect_hash
        or receipt.verifier_identity != expected.verifier_identity
        or receipt.verifier_key_version != expected.verifier_key_version
    ):
        raise ReleaseVerificationError("release effect receipt authority differs")
    signature = evidence.get_bytes(uri=signature_ref, expected_hash=signature_hash, max_bytes=512)
    try:
        public_key = serialization.load_pem_public_key(
            kms.public_key_pem(expected.verifier_key_version)
        )
    except Exception as error:
        raise ReleaseVerificationError("release verifier public key is unavailable") from error
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ReleaseVerificationError("release verifier key is not P-256")
    try:
        public_key.verify(signature, receipt.signed_payload(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise ReleaseVerificationError("release effect receipt signature is invalid") from error


class ReleaseRollbackReceiptEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    scope: Scope
    deployment_rollout_id: str
    expected_revision: str
    observed_target_version: str
    observed_assignment_hash: str = Field(pattern=_HASH)
    result: ReleaseVerificationResult
    verifier_identity: str = Field(pattern=r"^serviceAccount:")
    verifier_key_version: str = Field(pattern=r"^projects/.+/cryptoKeyVersions/[1-9][0-9]*$")
    observed_at: datetime

    @model_validator(mode="after")
    def rollback_result_is_closed(self) -> Self:
        if self.result is ReleaseVerificationResult.INCONCLUSIVE:
            raise ReleaseVerificationError("rollback verification cannot be inconclusive")
        if self.observed_at.tzinfo is None:
            raise ReleaseVerificationError("rollback verification time is malformed")
        return self

    def signed_payload(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


def verify_release_rollback_receipt(
    receipt: ReleaseRollbackReceiptEnvelope,
    *,
    scope: Scope,
    rollout_id: str,
    expected_revision: str,
    verifier_identity: str,
    verifier_key_version: str,
    signature_ref: str,
    signature_hash: str,
    evidence: ReleaseVerificationEvidenceReader,
    kms: ReleaseVerificationKmsReader,
) -> None:
    if (
        receipt.scope != scope
        or receipt.deployment_rollout_id != rollout_id
        or receipt.expected_revision != expected_revision
        or receipt.verifier_identity != verifier_identity
        or receipt.verifier_key_version != verifier_key_version
    ):
        raise ReleaseVerificationError("rollback receipt authority differs")
    signature = evidence.get_bytes(uri=signature_ref, expected_hash=signature_hash, max_bytes=512)
    try:
        key = serialization.load_pem_public_key(kms.public_key_pem(verifier_key_version))
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ReleaseVerificationError("rollback verifier key is not P-256")
        key.verify(signature, receipt.signed_payload(), ec.ECDSA(hashes.SHA256()))
    except ReleaseVerificationError:
        raise
    except Exception as error:
        raise ReleaseVerificationError("rollback receipt signature is invalid") from error


def evaluate_release_health(
    *,
    rules: tuple[ReleaseHealthSignalInput, ...],
    baseline: ReleaseHealthSnapshot,
    postdeploy: ReleaseHealthSnapshot,
) -> ReleaseVerificationEvaluation:
    baseline_by_kind = {item.signal_kind: item for item in baseline.measurements}
    post_by_kind = {item.signal_kind: item for item in postdeploy.measurements}
    expected = {item.signal_kind for item in rules}
    if set(baseline_by_kind) != expected or set(post_by_kind) != expected:
        return ReleaseVerificationEvaluation(
            result=ReleaseVerificationResult.INCONCLUSIVE,
            rationale_codes=("SIGNAL_SET_INCOMPLETE",),
        )
    failures: list[str] = []
    inconclusive: list[str] = []
    for rule in sorted(rules, key=lambda item: item.signal_kind):
        prior = baseline_by_kind[rule.signal_kind]
        current = post_by_kind[rule.signal_kind]
        if prior.point_count < rule.minimum_points or current.point_count < rule.minimum_points:
            inconclusive.append(f"{rule.signal_kind.value}_INSUFFICIENT_POINTS")
            continue
        if current.value > rule.maximum_value:
            failures.append(f"{rule.signal_kind.value}_ABSOLUTE_LIMIT")
        if current.value - prior.value > rule.maximum_regression:
            failures.append(f"{rule.signal_kind.value}_REGRESSION_LIMIT")
    if failures:
        return ReleaseVerificationEvaluation(
            result=ReleaseVerificationResult.FAILED,
            rationale_codes=tuple(sorted(set(failures))),
        )
    if inconclusive:
        return ReleaseVerificationEvaluation(
            result=ReleaseVerificationResult.INCONCLUSIVE,
            rationale_codes=tuple(sorted(set(inconclusive))),
        )
    return ReleaseVerificationEvaluation(
        result=ReleaseVerificationResult.VERIFIED,
        rationale_codes=("ALL_REGISTERED_SIGNALS_WITHIN_BOUNDS",),
    )
