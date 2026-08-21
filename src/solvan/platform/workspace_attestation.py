"""Cloud KMS verification for public-synthetic workspace attestations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from solvan.application import SyntheticDataAttestation
from solvan.domain import Scope
from solvan.platform.evidence_objects import GcsEvidenceReader
from solvan.platform.google_rest import GoogleRestSession


class AttestationVerificationError(ValueError):
    """The synthetic attestation cannot authorize provider use."""


class KmsPublicKeyReader(Protocol):
    def public_key_pem(self, key_version: str) -> bytes: ...


class GoogleKmsPublicKeyReader:
    def __init__(self, session: GoogleRestSession) -> None:
        self._session = session

    def public_key_pem(self, key_version: str) -> bytes:
        response = self._session.get(
            f"https://cloudkms.googleapis.com/v1/{key_version}/publicKey",
            timeout=30,
        )
        response.raise_for_status()
        value = response.json()
        pem = value.get("pem") if isinstance(value, dict) else None
        algorithm = value.get("algorithm") if isinstance(value, dict) else None
        if not isinstance(pem, str) or algorithm != "EC_SIGN_P256_SHA256":
            raise AttestationVerificationError("KMS key algorithm or public key is invalid")
        return pem.encode()


@dataclass(frozen=True, slots=True)
class AttestationPolicy:
    scope: Scope
    release_commit: str
    deployment_id: str
    allowed_issuer_principals: frozenset[str]
    allowed_kms_key_versions: frozenset[str]
    artifact_manifest_ref: str
    artifact_manifest_hash: str
    now: datetime


class SyntheticAttestationVerifier:
    def __init__(
        self,
        *,
        evidence_reader: GcsEvidenceReader,
        kms_reader: KmsPublicKeyReader,
    ) -> None:
        self._evidence_reader = evidence_reader
        self._kms_reader = kms_reader

    def verify(
        self, value: dict[str, object], *, policy: AttestationPolicy
    ) -> SyntheticDataAttestation:
        try:
            attestation = SyntheticDataAttestation.model_validate(value)
        except ValueError as error:
            raise AttestationVerificationError("synthetic attestation schema is invalid") from error
        expected_scope = policy.scope.canonical_dict()
        actual_scope = {
            "organization_id": attestation.organization_id,
            "project_id": attestation.project_id,
            "environment_id": attestation.environment_id,
        }
        if actual_scope != expected_scope:
            raise AttestationVerificationError("synthetic attestation scope is not exact")
        if (
            attestation.release_commit != policy.release_commit
            or attestation.deployment_id != policy.deployment_id
        ):
            raise AttestationVerificationError("attestation release or deployment binding changed")
        if (
            attestation.artifact_manifest_ref != policy.artifact_manifest_ref
            or attestation.artifact_manifest_hash != policy.artifact_manifest_hash
        ):
            raise AttestationVerificationError("attestation manifest binding changed")
        if attestation.issuer_principal not in policy.allowed_issuer_principals:
            raise AttestationVerificationError("attestation issuer is not allowed")
        if attestation.kms_key_version not in policy.allowed_kms_key_versions:
            raise AttestationVerificationError("attestation KMS key version is not allowed")
        if policy.now.tzinfo is None:
            raise ValueError("attestation policy clock must include timezone")
        if attestation.issued_at > policy.now or policy.now >= attestation.expires_at:
            raise AttestationVerificationError("synthetic attestation is not currently valid")
        try:
            signature = self._evidence_reader.get_bytes(
                uri=attestation.signature_ref,
                expected_hash=attestation.signature_hash,
                max_bytes=512,
            )
            public_key = serialization.load_pem_public_key(
                self._kms_reader.public_key_pem(attestation.kms_key_version)
            )
        except AttestationVerificationError:
            raise
        except Exception as error:
            raise AttestationVerificationError(
                "synthetic attestation verification dependency failed"
            ) from error
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise AttestationVerificationError("attestation key is not P-256")
        try:
            public_key.verify(signature, attestation.signed_payload(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as error:
            raise AttestationVerificationError(
                "synthetic attestation signature is invalid"
            ) from error
        return attestation
