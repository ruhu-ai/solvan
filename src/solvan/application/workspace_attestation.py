"""Strict public-synthetic workspace attestation contract."""

from __future__ import annotations

from datetime import datetime
from typing import Self

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_hashing import sha256_bytes
from solvan.domain import validate_identifier

_SHA256 = r"^sha256:[0-9a-f]{64}$"
_KMS_VERSION = (
    r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/"
    r"cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+$"
)


class SyntheticDataAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    attestation_id: str = Field(min_length=1)
    organization_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    release_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    deployment_id: str = Field(min_length=1)
    fixture_id: str = Field(min_length=1)
    classification: str = Field(pattern=r"^PUBLIC$")
    synthetic: bool
    artifact_manifest_ref: str = Field(pattern=r"^gs://")
    artifact_manifest_hash: str = Field(pattern=_SHA256)
    issuer_principal: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    canonicalization: str = Field(pattern=r"^RFC8785$")
    signature_algorithm: str = Field(pattern=r"^EC_SIGN_P256_SHA256$")
    kms_key_version: str = Field(pattern=_KMS_VERSION)
    signed_payload_hash: str = Field(pattern=_SHA256)
    signature_ref: str = Field(pattern=r"^gs://")
    signature_hash: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_canonical_binding(self) -> Self:
        validate_identifier(self.attestation_id, expected_prefix="att")
        if self.synthetic is not True:
            raise ValueError("synthetic attestation must assert true")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("attestation timestamps must include timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expiry must follow issuance")
        if self.signed_payload_hash != sha256_bytes(self.signed_payload()):
            raise ValueError("attestation signed payload hash does not match RFC8785 bytes")
        return self

    def signed_payload(self) -> bytes:
        value = self.model_dump(
            mode="json",
            exclude={"signed_payload_hash", "signature_ref", "signature_hash"},
        )
        return rfc8785.dumps(value)


class SyntheticAttestationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    fixture_id: str = Field(min_length=1)
    artifact_manifest_ref: str = Field(pattern=r"^gs://")
    artifact_manifest_hash: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_workspace(self) -> Self:
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        return self


class SyntheticAttestationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attestation_ref: str = Field(pattern=r"^gs://")
    attestation_hash: str = Field(pattern=_SHA256)
    attestation: SyntheticDataAttestation
