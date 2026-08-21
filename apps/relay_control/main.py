"""Outbound-only Solvant Relay protocol control plane."""

from __future__ import annotations

import base64
import hashlib
import importlib
import os
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, cast
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi import FastAPI, Header, HTTPException, Response, status
from fastapi.responses import JSONResponse
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from psycopg import Connection
from pydantic import BaseModel, ConfigDict, Field

from solvan.domain import Scope, canonical_digest, require_digest
from solvan.domain.relay import RelayRuntimePolicyProof
from solvan.observability import instrument_fastapi
from solvan.persistence.relay_store import (
    PostgresRelayStore,
    RelayConflict,
    RuntimeProofVerificationKey,
)
from solvan.platform.database import connect_database
from solvan.platform.google_rest import authorized_session
from solvan.platform.relay_signing import GoogleKmsSigner, KmsSigner

storage: Any = importlib.import_module("google.cloud.storage")


class RelayControlSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    audience: str = Field(pattern=r"^https://")
    lease_seconds: int = Field(default=60, ge=1, le=90)
    signing_key_version: str | None = Field(
        default=None,
        pattern=(
            r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/"
            r"cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+$"
        ),
    )
    evidence_bucket: str | None = Field(default=None, min_length=3)
    evidence_cmek_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @classmethod
    def from_environment(cls) -> RelayControlSettings:
        audience = os.environ.get("SOLVAN_RELAY_CONTROL_AUDIENCE")
        if not audience:
            raise RuntimeError("SOLVAN_RELAY_CONTROL_AUDIENCE is required")
        return cls(
            audience=audience,
            signing_key_version=os.environ.get("SOLVAN_RELAY_CONTROL_SIGNING_KEY_VERSION"),
            evidence_bucket=os.environ.get("SOLVAN_RELAY_EVIDENCE_BUCKET"),
            evidence_cmek_digest=os.environ.get("SOLVAN_RELAY_EVIDENCE_CMEK_DIGEST"),
        )


class TokenVerifier(Protocol):
    def verify(self, token: str, *, audience: str) -> Mapping[str, Any]: ...


class GoogleTokenVerifier:
    def verify(self, token: str, *, audience: str) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
                token, GoogleAuthRequest(), audience=audience
            ),
        )


class RuntimeProofPublicKeyResolver(Protocol):
    def resolve(self, key: RuntimeProofVerificationKey) -> bytes: ...


class UploadUrlIssuer(Protocol):
    def issue(
        self,
        *,
        bucket: str,
        object_name: str,
        content_type: str,
        expires_at: datetime,
    ) -> tuple[str, dict[str, str]]: ...


class UploadedObjectVerifier(Protocol):
    def verify(
        self,
        *,
        object_ref: str,
        expected_content_hash: str,
        expected_generation: str | None,
        expected_metadata_hash: str | None,
        maximum_bytes: int,
    ) -> tuple[str, str]: ...


class GoogleStorageUploadedObjectVerifier:
    """Read one exact object and metadata independently of the Relay process."""

    def __init__(self, *, allowed_bucket: str) -> None:
        self._bucket = allowed_bucket

    def verify(
        self,
        *,
        object_ref: str,
        expected_content_hash: str,
        expected_generation: str | None,
        expected_metadata_hash: str | None,
        maximum_bytes: int,
    ) -> tuple[str, str]:
        prefix = f"gs://{self._bucket}/"
        if not object_ref.startswith(prefix):
            raise ValueError("evidence object is outside the approved Relay bucket")
        object_name = object_ref.removeprefix(prefix)
        if not object_name or ".." in object_name.split("/"):
            raise ValueError("evidence object reference is malformed")
        encoded = _path_component(object_name)
        session = authorized_session()
        metadata_response = session.get(
            f"https://storage.googleapis.com/storage/v1/b/{self._bucket}/o/{encoded}", timeout=30
        )
        metadata_response.raise_for_status()
        metadata = metadata_response.json()
        if not isinstance(metadata, dict):
            raise ValueError("Cloud Storage metadata is malformed")
        generation = metadata.get("generation")
        size = metadata.get("size")
        if not isinstance(generation, str) or not isinstance(size, str) or not size.isdigit():
            raise ValueError("Cloud Storage metadata is malformed")
        if expected_generation is not None and generation != expected_generation:
            raise ValueError("Cloud Storage generation does not match receipt")
        metadata_digest = canonical_digest(
            {
                "generation": generation,
                "size": size,
                "content_type": metadata.get("contentType"),
                "md5_hash": metadata.get("md5Hash"),
                "crc32c": metadata.get("crc32c"),
            }
        )
        if expected_metadata_hash is not None and metadata_digest != expected_metadata_hash:
            raise ValueError("Cloud Storage metadata digest does not match receipt")
        content_response = session.get(
            f"https://storage.googleapis.com/storage/v1/b/{self._bucket}/o/{encoded}?alt=media",
            timeout=30,
        )
        content_response.raise_for_status()
        content = bytes(content_response.content)
        if len(content) > maximum_bytes:
            raise ValueError("evidence object exceeds its Relay grant bound")
        if "sha256:" + hashlib.sha256(content).hexdigest() != expected_content_hash:
            raise ValueError("evidence object content hash does not match receipt")
        return generation, metadata_digest


class GoogleStorageUploadUrlIssuer:
    """Issue exactly one PUT URL for a control-plane-selected GCS object."""

    def issue(
        self,
        *,
        bucket: str,
        object_name: str,
        content_type: str,
        expires_at: datetime,
    ) -> tuple[str, dict[str, str]]:
        now = datetime.now(UTC)
        if expires_at <= now:
            raise ValueError("upload grant is already expired")
        headers = {"x-goog-if-generation-match": "0", "Content-Type": content_type}
        url = (
            storage.Client()
            .bucket(bucket)
            .blob(object_name)
            .generate_signed_url(
                version="v4",
                expiration=expires_at,
                method="PUT",
                content_type=content_type,
                headers=headers,
            )
        )
        return str(url), headers


class GoogleStorageRuntimeProofPublicKeyResolver:
    """Read only an enrolled public key from its exact customer-controlled GCS ref."""

    def resolve(self, key: RuntimeProofVerificationKey) -> bytes:
        if not key.public_key_ref.startswith("gs://"):
            raise ValueError("runtime proof public-key reference is not a GCS object")
        bucket_and_name = key.public_key_ref.removeprefix("gs://").split("/", 1)
        if len(bucket_and_name) != 2 or not all(bucket_and_name):
            raise ValueError("runtime proof public-key reference is malformed")
        bucket, name = bucket_and_name
        response = authorized_session().get(
            "https://storage.googleapis.com/storage/v1/b/"
            f"{bucket}/o/{_path_component(name)}?alt=media",
            timeout=15,
        )
        response.raise_for_status()
        value = bytes(response.content)
        digest = "sha256:" + hashlib.sha256(value).hexdigest()
        if digest != key.public_key_digest:
            raise ValueError("runtime proof public-key reference digest changed")
        return value


def _path_component(value: str) -> str:
    return quote(value, safe="")


class ReadinessChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    process_boot_id: str = Field(min_length=1, max_length=255)
    relay_version: str = Field(min_length=1, max_length=63)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_proof_key_id: str = Field(min_length=1, max_length=255)


class ReadinessChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge: dict[str, Any]
    signing_key_id: str
    signature_base64: str


class DeploymentProfileAssertionRequest(BaseModel):
    """Customer-side installation assertion; all identity comes from OIDC."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    relay_connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    host_kind: str = Field(pattern=r"^(CLOUD_RUN_WORKER_POOL|GKE|ONPREM_FEDERATED|ONPREM_KEYFILE)$")
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    image_attestation_id: str = Field(pattern=r"^ria_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    local_policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_key_id: str = Field(min_length=1, max_length=255)
    connector_catalog_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redaction_revision: str = Field(min_length=1, max_length=64)
    region: str = Field(min_length=2, max_length=63)
    classification_ceiling: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    relay_version: str = Field(min_length=1, max_length=63)
    runtime_proof_key_id: str = Field(min_length=1, max_length=255)
    runtime_proof_public_key_ref: str = Field(pattern=r"^gs://[^/]+/.+")
    runtime_proof_public_key_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    egress_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    local_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expires_at: datetime


class DeploymentProfileAssertionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deployment_profile_id: str
    review_state: str


class QualificationReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int
    enrollment_epoch: int = Field(ge=1)
    deployment_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    egress_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    ledger_configuration_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    qualified_adapter_keys: list[
        Literal[
            "cloud-monitoring.v1",
            "managed-prometheus.v1",
            "cloud-logging.v1",
            "cloud-trace.v1",
            "kubernetes-metadata.v1",
        ]
    ] = Field(min_length=1, max_length=5)
    kill_switch_state: str = Field(pattern=r"^ENABLED$")
    receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature_base64: str = Field(min_length=16, max_length=16384)
    runtime_proof_key_id: str = Field(min_length=1, max_length=255)
    issued_at: datetime
    expires_at: datetime


class QualificationReceiptResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    qualification_receipt_id: str


class RuntimeProofRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    proof_id: str = Field(pattern=r"^rpf_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    challenge_id: str = Field(pattern=r"^rch_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    challenge_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    enrollment_id: str = Field(pattern=r"^ren_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    enrollment_epoch: int = Field(ge=1)
    placement_epoch: int = Field(ge=1)
    principal_claims_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_audience: str = Field(pattern=r"^https://")
    process_boot_id: str = Field(min_length=1, max_length=255)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    local_policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    local_policy_signature_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_key_id: str = Field(min_length=1, max_length=255)
    connector_catalog_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redaction_revision: str = Field(min_length=1, max_length=64)
    runtime_proof_key_id: str = Field(min_length=1, max_length=255)
    runtime_proof_key_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    region: str = Field(min_length=2, max_length=63)
    classification_ceiling: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    local_policy_verified: bool
    proof_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature_base64: str = Field(min_length=1, max_length=512)
    verified_at: datetime
    expires_at: datetime


class RuntimeProofResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    proof_id: str
    proof_digest: str
    expires_at: datetime


class PollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    relay_version: str = Field(min_length=1, max_length=63)
    process_boot_id: str = Field(min_length=1, max_length=255)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    image_attestation_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    local_policy_id: str = Field(pattern=r"^rpol_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    local_policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_policy_proof_id: str = Field(pattern=r"^rpf_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    runtime_policy_proof_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    connector_catalog_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    relay_connection_epoch: int = Field(ge=1)
    enrollment_epoch: int = Field(ge=1)
    kill_switch_engaged: bool
    declared_adapter_revisions: tuple[str, ...] = Field(min_length=1, max_length=16)


class UploadGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    job_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    claim_token: str = Field(pattern=r"^[0-9a-f-]{36}$")
    attempt_id: str = Field(pattern=r"^rat_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    attempt_number: int = Field(ge=1, le=2)
    process_boot_id: str = Field(min_length=1, max_length=255)
    attempt_outcome_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    local_result_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    manifest_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redaction_manifest_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resource_binding_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    classification: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    residency_region: str = Field(min_length=2, max_length=63)
    content_type: str = Field(pattern=r"^application/json$")
    content_length: int = Field(ge=1, le=1_048_576)


class UploadGrantResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    upload_grant_id: str
    upload_grant_digest: str
    put_url: str
    object_ref: str
    required_headers: dict[str, str]
    maximum_byte_length: int
    cmek_digest: str
    expires_at: datetime


class ReceiptEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    object_ref: str = Field(pattern=r"^gs://")
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    manifest_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redaction_manifest_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resource_binding_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    classification: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    residency_region: str = Field(min_length=2, max_length=63)
    upload_grant_id: str = Field(pattern=r"^rug_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    upload_grant_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    # Signed XML upload responses do not reliably expose these values.  They
    # are optional Relay assertions; the control plane always reads and pins
    # the authoritative generation and metadata itself before acceptance.
    object_generation: str | None = Field(default=None, pattern=r"^[0-9]+$")
    object_metadata_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class ReceiptMeasurements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: int = Field(ge=0, le=1000)
    pages: int = Field(ge=0, le=20)
    bytes: int = Field(ge=0, le=1_048_576)
    calls: int = Field(ge=0, le=20)


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    job_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    claim_token: str = Field(pattern=r"^[0-9a-f-]{36}$")
    attempt_id: str = Field(pattern=r"^rat_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    attempt_number: int = Field(ge=1, le=2)
    process_boot_id: str = Field(min_length=1, max_length=255)
    input_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    attempt_outcome_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    local_result_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    result: str = Field(pattern=r"^SUCCEEDED$")
    error_class: None = None
    safe_measurements: ReceiptMeasurements
    evidence: ReceiptEvidence
    started_at: datetime
    completed_at: datetime
    receipt_nonce: str = Field(min_length=1, max_length=255)


class ReceiptResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt_id: str


class RetryableOutcomeMeasurements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: int = Field(ge=0, le=1000)
    pages: int = Field(ge=0, le=20)
    bytes: int = Field(ge=0, le=1_048_576)
    calls: int = Field(ge=0, le=20)


class RetryableOutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    job_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    claim_token: str = Field(pattern=r"^[0-9a-f-]{36}$")
    attempt_id: str = Field(pattern=r"^rat_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    attempt_number: int = Field(ge=1, le=2)
    process_boot_id: str = Field(min_length=1, max_length=255)
    input_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    attempt_outcome_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    error_class: str = Field(pattern=r"^(UPSTREAM_UNAVAILABLE|UPSTREAM_RATE_LIMITED)$")
    safe_measurements: RetryableOutcomeMeasurements
    started_at: datetime
    completed_at: datetime


class RetryableOutcomeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    collection_job_id: str
    attempt_id: str
    attempt_number: int
    state: str
    action: str
    workflow_version: int


class JobStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    collection_job_id: str
    job_digest: str
    state: str
    action: str
    attempt_id: str | None
    attempt_number: int | None
    local_result_hash: str | None
    cancel_requested: bool


class CancellationAcknowledgementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    process_boot_id: str = Field(min_length=1, max_length=255)


class ClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    job_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    claim_request_nonce: str = Field(min_length=1, max_length=255)
    process_boot_id: str = Field(min_length=1, max_length=255)
    accepted_at: datetime


class ClaimResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    collection_job_id: str
    job_digest: str
    claim_token: str
    attempt_id: str
    attempt_number: int
    lease_expires_at: datetime
    workflow_version: int


def _verified_claims(
    authorization: str | None,
    *,
    settings: RelayControlSettings,
    verifier: TokenVerifier,
) -> tuple[str, str]:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "IDENTITY_INVALID")
    try:
        claims = verifier.verify(authorization.removeprefix("Bearer "), audience=settings.audience)
    except Exception as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "IDENTITY_INVALID") from error
    issuer = claims.get("iss")
    subject = claims.get("sub")
    if not isinstance(issuer, str) or not issuer.startswith("https://"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "IDENTITY_INVALID")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "IDENTITY_INVALID")
    return issuer, subject


def _verify_runtime_proof_signature(
    *, public_key_bytes: bytes, proof: RelayRuntimePolicyProof, signature: bytes
) -> None:
    """Verify only P-256/SHA-256 over the exact RFC-8785 proof digest."""

    public_key = serialization.load_pem_public_key(public_key_bytes)
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("runtime proof key is not ECDSA P-256")
    require_digest(proof.proof_digest, field="proof_digest")
    public_key.verify(
        signature,
        bytes.fromhex(proof.proof_digest.removeprefix("sha256:")),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def _verify_digest_signature(*, public_key_bytes: bytes, digest: str, signature: bytes) -> None:
    public_key = serialization.load_pem_public_key(public_key_bytes)
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("qualification key is not ECDSA P-256")
    require_digest(digest, field="receipt_digest")
    public_key.verify(
        signature,
        bytes.fromhex(digest.removeprefix("sha256:")),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def create_app(
    *,
    settings: RelayControlSettings | None = None,
    verifier: TokenVerifier | None = None,
    signer: KmsSigner | None = None,
    runtime_proof_key_resolver: RuntimeProofPublicKeyResolver | None = None,
    upload_url_issuer: UploadUrlIssuer | None = None,
    uploaded_object_verifier: UploadedObjectVerifier | None = None,
    connection_factory: Callable[[], AbstractContextManager[Connection[Any]]] = connect_database,
    store_factory: Callable[[Connection[Any]], PostgresRelayStore] = PostgresRelayStore,
) -> FastAPI:
    resolved_verifier = verifier or GoogleTokenVerifier()
    resolved_signer = signer or GoogleKmsSigner()
    resolved_runtime_proof_key_resolver = (
        runtime_proof_key_resolver or GoogleStorageRuntimeProofPublicKeyResolver()
    )
    resolved_upload_url_issuer = upload_url_issuer or GoogleStorageUploadUrlIssuer()
    app = FastAPI(title="Solvan Relay Control Plane", version="1.0.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live", "authority": "cloud-sql"}

    @app.post(
        "/internal/v1/relay/deployment-profiles",
        response_model=DeploymentProfileAssertionResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def submit_deployment_profile(
        request: DeploymentProfileAssertionRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> DeploymentProfileAssertionResponse:
        """Accept a short-lived installation assertion from customer tooling.

        A profile is not enrollment authority: it is bound to verified workload
        OIDC, checked against the registered transport/attestation/policy key,
        then waits for a separately authenticated administrator review.
        """

        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        resolved = settings or RelayControlSettings.from_environment()
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        now = datetime.now(UTC)
        if request.expires_at.tzinfo is None or request.expires_at <= now:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "PROFILE_EXPIRY_INVALID")
        if request.expires_at > now + timedelta(hours=24):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "PROFILE_EXPIRY_TOO_LONG")
        try:
            with connection_factory() as connection:
                deployment_profile_id = store_factory(connection).submit_deployment_profile(
                    relay_connection_id=request.relay_connection_id,
                    host_kind=request.host_kind,
                    principal_issuer=issuer,
                    principal_subject=subject,
                    expected_audience=resolved.audience,
                    image_digest=request.image_digest,
                    image_attestation_id=request.image_attestation_id,
                    local_policy_digest=request.local_policy_digest,
                    policy_key_id=request.policy_key_id,
                    connector_catalog_digest=request.connector_catalog_digest,
                    redaction_revision=request.redaction_revision,
                    region=request.region,
                    classification_ceiling=request.classification_ceiling,
                    relay_version=request.relay_version,
                    runtime_proof_key_id=request.runtime_proof_key_id,
                    runtime_proof_public_key_ref=request.runtime_proof_public_key_ref,
                    runtime_proof_public_key_digest=request.runtime_proof_public_key_digest,
                    egress_manifest_digest=request.egress_manifest_digest,
                    local_binding_digest=request.local_binding_digest,
                    expires_at=request.expires_at,
                    asserted_at=now,
                )
                connection.commit()
        except (RelayConflict, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "PROFILE_INELIGIBLE") from error
        return DeploymentProfileAssertionResponse(
            deployment_profile_id=deployment_profile_id,
            review_state="PENDING_REVIEW",
        )

    @app.post(
        "/internal/v1/relay/qualification-receipts",
        response_model=QualificationReceiptResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def accept_qualification_receipt(
        request: QualificationReceiptRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> QualificationReceiptResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        if len(set(request.qualified_adapter_keys)) != len(request.qualified_adapter_keys):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "QUALIFICATION_ADAPTERS_INVALID"
            )
        resolved = settings or RelayControlSettings.from_environment()
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        now = datetime.now(UTC)
        if (
            request.issued_at.tzinfo is None
            or request.expires_at.tzinfo is None
            or not (
                request.issued_at
                <= now
                < request.expires_at
                <= request.issued_at + timedelta(days=30)
            )
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "QUALIFICATION_EXPIRY_INVALID"
            )
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None or identity.enrollment_epoch != request.enrollment_epoch:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                expected_digest = canonical_digest(
                    {
                        "schema_version": 1,
                        "enrollment_id": identity.enrollment_id,
                        "enrollment_epoch": identity.enrollment_epoch,
                        "deployment_manifest_digest": request.deployment_manifest_digest,
                        "egress_manifest_digest": request.egress_manifest_digest,
                        "ledger_configuration_digest": request.ledger_configuration_digest,
                        "qualified_adapter_keys": sorted(request.qualified_adapter_keys),
                        "kill_switch_state": request.kill_switch_state,
                        "runtime_proof_key_id": request.runtime_proof_key_id,
                        "issued_at": request.issued_at.isoformat(),
                        "expires_at": request.expires_at.isoformat(),
                    }
                )
                if request.receipt_digest != expected_digest:
                    raise HTTPException(status.HTTP_409_CONFLICT, "QUALIFICATION_DIGEST_MISMATCH")
                key = store.resolve_runtime_proof_key(
                    scope=Scope(
                        identity.scope_organization_id,
                        identity.scope_project_id,
                        identity.scope_environment_id,
                    ),
                    enrollment_id=identity.enrollment_id,
                    enrollment_epoch=identity.enrollment_epoch,
                    key_id=request.runtime_proof_key_id,
                    at=now,
                )
                if key is None:
                    raise HTTPException(status.HTTP_409_CONFLICT, "QUALIFICATION_KEY_INELIGIBLE")
                _verify_digest_signature(
                    public_key_bytes=resolved_runtime_proof_key_resolver.resolve(key),
                    digest=request.receipt_digest,
                    signature=base64.b64decode(request.signature_base64, validate=True),
                )
                receipt_id = store.record_qualification_receipt(
                    scope=Scope(
                        identity.scope_organization_id,
                        identity.scope_project_id,
                        identity.scope_environment_id,
                    ),
                    enrollment_id=identity.enrollment_id,
                    enrollment_epoch=identity.enrollment_epoch,
                    deployment_manifest_digest=request.deployment_manifest_digest,
                    egress_manifest_digest=request.egress_manifest_digest,
                    ledger_configuration_digest=request.ledger_configuration_digest,
                    qualified_adapter_keys=tuple(sorted(request.qualified_adapter_keys)),
                    kill_switch_state=request.kill_switch_state,
                    receipt_digest=request.receipt_digest,
                    signature_base64=request.signature_base64,
                    runtime_proof_key_id=request.runtime_proof_key_id,
                    issued_at=request.issued_at,
                    expires_at=request.expires_at,
                )
                connection.commit()
        except HTTPException:
            raise
        except (RelayConflict, ValueError, InvalidSignature) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "QUALIFICATION_REFUSED") from error
        return QualificationReceiptResponse(qualification_receipt_id=receipt_id)

    @app.post(
        "/internal/v1/relay/readiness-challenges",
        response_model=ReadinessChallengeResponse,
    )
    def issue_readiness_challenge(
        request: ReadinessChallengeRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> ReadinessChallengeResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        resolved = settings or RelayControlSettings.from_environment()
        if resolved.signing_key_version is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE")
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        now = datetime.now(UTC)
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                issued = store.issue_readiness_challenge(
                    scope=scope,
                    identity=identity,
                    issuer=issuer,
                    subject=subject,
                    process_boot_id=request.process_boot_id,
                    relay_version=request.relay_version,
                    image_digest=request.image_digest,
                    runtime_proof_key_id=request.runtime_proof_key_id,
                    issued_at=now,
                )
                payload = issued.challenge.unsigned_projection(nonce=issued.nonce)
                payload_digest = canonical_digest(payload)
                signature = resolved_signer.sign_sha256(
                    bytes.fromhex(payload_digest.removeprefix("sha256:")),
                    key_version=resolved.signing_key_version,
                )
                connection.commit()
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "ENROLLMENT_STALE") from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE") from error
        return ReadinessChallengeResponse(
            challenge=payload,
            signing_key_id=issued.challenge.signing_key_id,
            signature_base64=base64.b64encode(signature).decode("ascii"),
        )

    @app.post(
        "/internal/v1/relay/readiness-proofs",
        response_model=RuntimeProofResponse,
    )
    def accept_runtime_policy_proof(
        request: RuntimeProofRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> RuntimeProofResponse:
        if request.schema_version != 1 or request.verified_at.tzinfo is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        if request.expires_at.tzinfo is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "TIME_INVALID")
        resolved = settings or RelayControlSettings.from_environment()
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        proof = RelayRuntimePolicyProof(
            **request.model_dump(exclude={"schema_version"}),
        )
        unsigned = proof.unsigned_projection()
        unsigned.pop("proof_digest")
        if canonical_digest(unsigned) != proof.proof_digest:
            raise HTTPException(status.HTTP_409_CONFLICT, "POLICY_DIGEST_MISMATCH")
        try:
            signature = base64.b64decode(proof.signature_base64, validate=True)
        except ValueError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "SIGNATURE_INVALID") from error
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                if (
                    proof.enrollment_id != identity.enrollment_id
                    or proof.enrollment_epoch != identity.enrollment_epoch
                    or proof.expected_audience != identity.expected_audience
                ):
                    raise HTTPException(status.HTTP_409_CONFLICT, "ENROLLMENT_STALE")
                key = store.resolve_runtime_proof_key(
                    scope=scope,
                    enrollment_id=identity.enrollment_id,
                    enrollment_epoch=identity.enrollment_epoch,
                    key_id=proof.runtime_proof_key_id,
                    at=request.verified_at.astimezone(UTC),
                )
                if key is None or key.public_key_digest != proof.runtime_proof_key_digest:
                    raise HTTPException(status.HTTP_409_CONFLICT, "ENROLLMENT_STALE")
                _verify_runtime_proof_signature(
                    public_key_bytes=resolved_runtime_proof_key_resolver.resolve(key),
                    proof=proof,
                    signature=signature,
                )
                committed = store.record_runtime_policy_proof(
                    scope=scope,
                    identity=identity,
                    issuer=issuer,
                    subject=subject,
                    proof=proof,
                    verified_at=request.verified_at.astimezone(UTC),
                )
                connection.commit()
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "ENROLLMENT_STALE") from error
        except HTTPException:
            raise
        except (InvalidSignature, TypeError, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "SIGNATURE_INVALID") from error
        except Exception as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE") from error
        return RuntimeProofResponse(
            proof_id=committed.proof_id,
            proof_digest=committed.proof_digest,
            expires_at=committed.expires_at,
        )

    @app.post("/internal/v1/relay/poll")
    def poll(
        request: PollRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> Response:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        if request.kill_switch_engaged:
            raise HTTPException(status.HTTP_409_CONFLICT, "KILL_SWITCH_ENGAGED")
        resolved = settings or RelayControlSettings.from_environment()
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        now = datetime.now(UTC)
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                store.record_poll_readiness(
                    scope=scope,
                    identity=identity,
                    relay_version=request.relay_version,
                    process_boot_id=request.process_boot_id,
                    image_digest=request.image_digest,
                    image_attestation_digest=request.image_attestation_digest,
                    local_policy_id=request.local_policy_id,
                    local_policy_digest=request.local_policy_digest,
                    runtime_policy_proof_id=request.runtime_policy_proof_id,
                    runtime_policy_proof_digest=request.runtime_policy_proof_digest,
                    connector_catalog_digest=request.connector_catalog_digest,
                    relay_connection_epoch=request.relay_connection_epoch,
                    enrollment_epoch=request.enrollment_epoch,
                    declared_adapter_revisions=request.declared_adapter_revisions,
                    observed_at=now,
                )
                envelope = store.poll_signed_job(
                    scope=scope, enrollment_id=identity.enrollment_id, now=now
                )
                connection.commit()
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "ENROLLMENT_STALE") from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE") from error
        if envelope is None:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        return JSONResponse(content=envelope)

    @app.post(
        "/internal/v1/relay/jobs/{collection_job_id}/upload-grant",
        response_model=UploadGrantResponse,
    )
    def upload_grant(
        collection_job_id: str,
        request: UploadGrantRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> UploadGrantResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        resolved = settings or RelayControlSettings.from_environment()
        if resolved.evidence_bucket is None or resolved.evidence_cmek_digest is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE")
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        now = datetime.now(UTC)
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                object_name = (
                    f"relay/{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
                    f"{collection_job_id}/{request.attempt_id}/{request.local_result_hash.removeprefix('sha256:')}.json"
                )
                grant = store.create_upload_grant(
                    scope=scope,
                    enrollment_id=identity.enrollment_id,
                    collection_job_id=collection_job_id,
                    job_digest=request.job_digest,
                    claim_token=request.claim_token,
                    attempt_id=request.attempt_id,
                    attempt_number=request.attempt_number,
                    process_boot_id=request.process_boot_id,
                    attempt_outcome_hash=request.attempt_outcome_hash,
                    local_result_hash=request.local_result_hash,
                    content_hash=request.content_hash,
                    evidence_manifest_hash=request.manifest_hash,
                    redaction_manifest_hash=request.redaction_manifest_hash,
                    resource_binding_hash=request.resource_binding_hash,
                    classification=request.classification,
                    residency_region=request.residency_region,
                    content_type=request.content_type,
                    content_length=request.content_length,
                    object_ref=f"gs://{resolved.evidence_bucket}/{object_name}",
                    cmek_digest=resolved.evidence_cmek_digest,
                    requested_at=now,
                )
                connection.commit()
            put_url, required_headers = resolved_upload_url_issuer.issue(
                bucket=resolved.evidence_bucket,
                object_name=object_name,
                content_type=grant.content_type,
                expires_at=grant.expires_at,
            )
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "BINDING_CHANGED") from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE") from error
        return UploadGrantResponse(
            upload_grant_id=grant.upload_grant_id,
            upload_grant_digest=grant.upload_grant_digest,
            put_url=put_url,
            object_ref=grant.object_ref,
            required_headers=required_headers,
            maximum_byte_length=grant.content_length,
            cmek_digest=resolved.evidence_cmek_digest,
            expires_at=grant.expires_at,
        )

    @app.post(
        "/internal/v1/relay/jobs/{collection_job_id}/attempt-outcome",
        response_model=RetryableOutcomeResponse,
    )
    def retryable_attempt_outcome(
        collection_job_id: str,
        request: RetryableOutcomeRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> RetryableOutcomeResponse:
        if (
            request.schema_version != 1
            or request.started_at.tzinfo is None
            or request.completed_at.tzinfo is None
            or request.completed_at < request.started_at
        ):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        resolved = settings or RelayControlSettings.from_environment()
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                outcome = store.record_retryable_attempt_failure(
                    scope=scope,
                    enrollment_id=identity.enrollment_id,
                    collection_job_id=collection_job_id,
                    job_digest=request.job_digest,
                    claim_token=request.claim_token,
                    attempt_id=request.attempt_id,
                    attempt_number=request.attempt_number,
                    process_boot_id=request.process_boot_id,
                    input_hash=request.input_hash,
                    attempt_outcome_hash=request.attempt_outcome_hash,
                    error_class=request.error_class,
                    started_at=request.started_at.astimezone(UTC),
                    completed_at=request.completed_at.astimezone(UTC),
                )
                connection.commit()
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "IDEMPOTENCY_CONFLICT") from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE") from error
        return RetryableOutcomeResponse(
            collection_job_id=outcome.collection_job_id,
            attempt_id=outcome.attempt_id,
            attempt_number=outcome.attempt_number,
            state=outcome.job_state,
            action=outcome.action,
            workflow_version=outcome.workflow_version,
        )

    @app.get(
        "/internal/v1/relay/jobs/{collection_job_id}",
        response_model=JobStatusResponse,
    )
    def job_status(
        collection_job_id: str,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> JobStatusResponse:
        resolved = settings or RelayControlSettings.from_environment()
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                projection = store.get_job_status(
                    scope=scope,
                    enrollment_id=identity.enrollment_id,
                    collection_job_id=collection_job_id,
                )
        except RelayConflict as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "JOB_NOT_FOUND") from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE") from error
        return JobStatusResponse(
            collection_job_id=projection.collection_job_id,
            job_digest=projection.job_digest,
            state=projection.state,
            action=projection.action,
            attempt_id=projection.attempt_id,
            attempt_number=projection.attempt_number,
            local_result_hash=projection.local_result_hash,
            cancel_requested=projection.cancel_requested,
        )

    @app.post(
        "/internal/v1/relay/jobs/{collection_job_id}/cancel-ack",
        response_model=JobStatusResponse,
    )
    def acknowledge_cancellation(
        collection_job_id: str,
        request: CancellationAcknowledgementRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> JobStatusResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        resolved = settings or RelayControlSettings.from_environment()
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                projection = store.acknowledge_cancellation(
                    scope=scope,
                    enrollment_id=identity.enrollment_id,
                    collection_job_id=collection_job_id,
                    process_boot_id=request.process_boot_id,
                )
                connection.commit()
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "CANCEL_NOT_REQUESTED") from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE") from error
        return JobStatusResponse(
            collection_job_id=projection.collection_job_id,
            job_digest=projection.job_digest,
            state=projection.state,
            action=projection.action,
            attempt_id=projection.attempt_id,
            attempt_number=projection.attempt_number,
            local_result_hash=projection.local_result_hash,
            cancel_requested=projection.cancel_requested,
        )

    @app.post(
        "/internal/v1/relay/jobs/{collection_job_id}/receipt",
        response_model=ReceiptResponse,
    )
    def receipt(
        collection_job_id: str,
        request: ReceiptRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> ReceiptResponse:
        if (
            request.schema_version != 1
            or request.started_at.tzinfo is None
            or request.completed_at.tzinfo is None
            or request.completed_at < request.started_at
        ):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        resolved = settings or RelayControlSettings.from_environment()
        if resolved.evidence_bucket is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CELL_UNAVAILABLE")
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        verifier = uploaded_object_verifier or GoogleStorageUploadedObjectVerifier(
            allowed_bucket=resolved.evidence_bucket
        )
        evidence = request.evidence
        try:
            object_generation, object_metadata_hash = verifier.verify(
                object_ref=evidence.object_ref,
                expected_content_hash=evidence.content_hash,
                expected_generation=evidence.object_generation,
                expected_metadata_hash=evidence.object_metadata_hash,
                maximum_bytes=request.safe_measurements.bytes,
            )
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                receipt_id = store.commit_success_receipt(
                    scope=scope,
                    enrollment_id=identity.enrollment_id,
                    collection_job_id=collection_job_id,
                    job_digest=request.job_digest,
                    claim_token=request.claim_token,
                    attempt_id=request.attempt_id,
                    attempt_number=request.attempt_number,
                    process_boot_id=request.process_boot_id,
                    input_hash=request.input_hash,
                    attempt_outcome_hash=request.attempt_outcome_hash,
                    local_result_hash=request.local_result_hash,
                    content_hash=evidence.content_hash,
                    evidence_manifest_hash=evidence.manifest_hash,
                    redaction_manifest_hash=evidence.redaction_manifest_hash,
                    resource_binding_hash=evidence.resource_binding_hash,
                    classification=evidence.classification,
                    residency_region=evidence.residency_region,
                    upload_grant_id=evidence.upload_grant_id,
                    upload_grant_digest=evidence.upload_grant_digest,
                    object_ref=evidence.object_ref,
                    object_generation=object_generation,
                    object_metadata_hash=object_metadata_hash,
                    item_count=request.safe_measurements.items,
                    page_count=request.safe_measurements.pages,
                    byte_count=request.safe_measurements.bytes,
                    call_count=request.safe_measurements.calls,
                    started_at=request.started_at.astimezone(UTC),
                    completed_at=request.completed_at.astimezone(UTC),
                    receipt_nonce=request.receipt_nonce,
                )
                connection.commit()
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "IDEMPOTENCY_CONFLICT") from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "OBJECT_VERIFICATION_FAILED") from error
        return ReceiptResponse(receipt_id=receipt_id)

    @app.post(
        "/internal/v1/relay/jobs/{collection_job_id}/claim",
        response_model=ClaimResponse,
    )
    def claim_job(
        collection_job_id: str,
        request: ClaimRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> ClaimResponse:
        resolved = settings or RelayControlSettings.from_environment()
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "SCHEMA_UNSUPPORTED")
        if request.accepted_at.tzinfo is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "TIME_INVALID")
        issuer, subject = _verified_claims(
            authorization, settings=resolved, verifier=resolved_verifier
        )
        try:
            with connection_factory() as connection:
                store = store_factory(connection)
                identity = store.resolve_verified_identity(
                    issuer=issuer, subject=subject, audience=resolved.audience
                )
                if identity is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "ENROLLMENT_SCOPE_DENIED")
                scope = Scope(
                    identity.scope_organization_id,
                    identity.scope_project_id,
                    identity.scope_environment_id,
                )
                claim = store.claim_job(
                    scope=scope,
                    enrollment_id=identity.enrollment_id,
                    collection_job_id=collection_job_id,
                    job_digest=request.job_digest,
                    claim_request_nonce=request.claim_request_nonce,
                    process_boot_id=request.process_boot_id,
                    accepted_at=request.accepted_at.astimezone(UTC),
                    lease_seconds=resolved.lease_seconds,
                )
                connection.commit()
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "CLAIM_LOST") from error
        return ClaimResponse(**asdict(claim))

    return app


app = instrument_fastapi(create_app(), service_name="relay-control")
