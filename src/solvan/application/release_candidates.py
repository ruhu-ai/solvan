"""Strict signed release-candidate envelope and verification contract."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_hashing import canonical_json_bytes, sha256_bytes

_SHA256 = r"^sha256:[0-9a-f]{64}$"
_SHA = r"^[0-9a-f]{40}$"
_GCS = r"^gs://"
_IMAGE = r"^[a-z0-9.-]+/[a-z0-9_./-]+@sha256:[0-9a-f]{64}$"


class ReleaseCandidateError(ValueError):
    pass


class ReleaseEvidenceReader(Protocol):
    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int) -> bytes: ...


class ReleaseKmsReader(Protocol):
    def public_key_pem(self, key_version: str) -> bytes: ...


class ReleaseCandidateEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    code_change_request_id: str = Field(pattern=r"^ccr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    repository_binding_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    merged_commit_sha: str = Field(pattern=_SHA)
    source_tree_hash: str = Field(pattern=_SHA256)
    build_definition_ref: str = Field(pattern=_GCS)
    build_definition_hash: str = Field(pattern=_SHA256)
    builder_identity: str = Field(pattern=r"^serviceAccount:")
    build_invocation_ref: str = Field(pattern=_GCS)
    build_invocation_hash: str = Field(pattern=_SHA256)
    build_artifact_ref: str = Field(pattern=_IMAGE)
    build_artifact_hash: str = Field(pattern=_SHA256)
    sbom_ref: str = Field(pattern=_GCS)
    sbom_hash: str = Field(pattern=_SHA256)
    provenance_predicate_type: str = Field(min_length=3, max_length=255)
    provenance_predicate_version: str = Field(min_length=1, max_length=64)
    provenance_ref: str = Field(pattern=_GCS)
    provenance_hash: str = Field(pattern=_SHA256)
    signer_identity: str = Field(pattern=r"^serviceAccount:")
    signer_key_version: str = Field(pattern=r"^projects/.+/cryptoKeyVersions/[1-9][0-9]*$")
    deployment_manifest_ref: str = Field(pattern=_GCS)
    deployment_manifest_hash: str = Field(pattern=_SHA256)
    release_policy_hash: str = Field(pattern=_SHA256)
    release_signature_ref: str = Field(pattern=_GCS)
    release_signature_hash: str = Field(pattern=_SHA256)
    issued_at: datetime

    @model_validator(mode="after")
    def validate_subject(self) -> Self:
        if self.build_artifact_hash != "sha256:" + self.build_artifact_ref.rsplit("@sha256:", 1)[1]:
            raise ReleaseCandidateError("release artifact digest and subject differ")
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ReleaseCandidateError("release candidate time must include timezone")
        return self

    def signed_payload(self) -> bytes:
        material = self.model_dump(mode="json")
        material.pop("release_signature_ref")
        material.pop("release_signature_hash")
        return canonical_json_bytes(material)


class ReleaseCandidateExpected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code_change_request_id: str
    repository_binding_id: str
    merged_commit_sha: str
    source_tree_hash: str
    release_policy_hash: str
    signer_identity: str
    signer_key_version: str
    maximum_age_seconds: int = Field(ge=60, le=86400)
    now: datetime


def verify_release_candidate(
    envelope: ReleaseCandidateEnvelope,
    *,
    expected: ReleaseCandidateExpected,
    evidence: ReleaseEvidenceReader,
    kms: ReleaseKmsReader,
) -> None:
    if (
        envelope.code_change_request_id != expected.code_change_request_id
        or envelope.repository_binding_id != expected.repository_binding_id
        or envelope.merged_commit_sha != expected.merged_commit_sha
        or envelope.source_tree_hash != expected.source_tree_hash
        or envelope.release_policy_hash != expected.release_policy_hash
        or envelope.signer_identity != expected.signer_identity
        or envelope.signer_key_version != expected.signer_key_version
        or expected.now.tzinfo is None
        or envelope.issued_at > expected.now
        or (expected.now - envelope.issued_at).total_seconds() > expected.maximum_age_seconds
    ):
        raise ReleaseCandidateError("release candidate authority or lineage differs")
    for uri, digest, ceiling in (
        (envelope.build_definition_ref, envelope.build_definition_hash, 1_000_000),
        (envelope.build_invocation_ref, envelope.build_invocation_hash, 1_000_000),
        (envelope.sbom_ref, envelope.sbom_hash, 10_000_000),
        (envelope.provenance_ref, envelope.provenance_hash, 2_000_000),
        (envelope.deployment_manifest_ref, envelope.deployment_manifest_hash, 1_000_000),
    ):
        evidence.get_bytes(uri=uri, expected_hash=digest, max_bytes=ceiling)
    signature = evidence.get_bytes(
        uri=envelope.release_signature_ref,
        expected_hash=envelope.release_signature_hash,
        max_bytes=512,
    )
    try:
        public_key = serialization.load_pem_public_key(
            kms.public_key_pem(envelope.signer_key_version)
        )
    except Exception as error:
        raise ReleaseCandidateError("release signer public key is unavailable") from error
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ReleaseCandidateError("release signer key is not P-256")
    try:
        public_key.verify(signature, envelope.signed_payload(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise ReleaseCandidateError("release candidate signature is invalid") from error


def envelope_hash(envelope: ReleaseCandidateEnvelope) -> str:
    return sha256_bytes(canonical_json_bytes(envelope.model_dump(mode="json")))
