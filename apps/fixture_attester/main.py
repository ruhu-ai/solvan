"""Private deterministic service signing eligible public-synthetic manifests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, Self, cast

import rfc8785
from fastapi import FastAPI, Header, HTTPException, status
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from solvan.application import (
    SyntheticAttestationReceipt,
    SyntheticAttestationRequest,
    SyntheticDataAttestation,
    WorkspaceArtifactManifest,
    WorkspaceClassification,
    sha256_bytes,
)
from solvan.domain import Scope, new_identifier
from solvan.observability import instrument_fastapi
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter, ObjectReceipt
from solvan.platform.google_rest import authorized_session


class AttesterSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    release_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    deployment_id: str = Field(min_length=1)
    coordinator_service_account: str = Field(pattern=r"^[^@\s]+@[^@\s]+$")
    attester_service_account: str = Field(pattern=r"^[^@\s]+@[^@\s]+$")
    audience: str = Field(pattern=r"^https://")
    runtime_bucket: str = Field(min_length=3)
    evidence_bucket: str = Field(min_length=3)
    fixture_prefix: str = Field(pattern=r"^gs://")
    fixture_ids: frozenset[str] = Field(min_length=1)
    kms_key_version: str = Field(
        pattern=(
            r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/"
            r"cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+$"
        )
    )

    @classmethod
    def from_environment(cls) -> Self:
        required = (
            "SOLVAN_ORGANIZATION_ID",
            "SOLVAN_SCOPE_PROJECT_ID",
            "SOLVAN_ENVIRONMENT_ID",
            "SOLVAN_RELEASE_COMMIT",
            "SOLVAN_DEPLOYMENT_ID",
            "SOLVAN_COORDINATOR_SERVICE_ACCOUNT",
            "SOLVAN_FIXTURE_ATTESTER_SERVICE_ACCOUNT",
            "SOLVAN_FIXTURE_ATTESTER_AUDIENCE",
            "SOLVAN_RUNTIME_BUCKET",
            "SOLVAN_EVIDENCE_BUCKET",
            "SOLVAN_SYNTHETIC_FIXTURE_PREFIX",
            "SOLVAN_SYNTHETIC_FIXTURE_IDS",
            "SOLVAN_SYNTHETIC_ATTESTER_KMS_KEY_VERSION",
        )
        values = {name: os.environ.get(name) for name in required}
        missing = sorted(name for name, value in values.items() if not value)
        if missing:
            raise RuntimeError(f"missing fixture-attester settings: {', '.join(missing)}")
        return cls(
            scope=Scope(
                cast(str, values["SOLVAN_ORGANIZATION_ID"]),
                cast(str, values["SOLVAN_SCOPE_PROJECT_ID"]),
                cast(str, values["SOLVAN_ENVIRONMENT_ID"]),
            ),
            release_commit=cast(str, values["SOLVAN_RELEASE_COMMIT"]),
            deployment_id=cast(str, values["SOLVAN_DEPLOYMENT_ID"]),
            coordinator_service_account=cast(str, values["SOLVAN_COORDINATOR_SERVICE_ACCOUNT"]),
            attester_service_account=cast(str, values["SOLVAN_FIXTURE_ATTESTER_SERVICE_ACCOUNT"]),
            audience=cast(str, values["SOLVAN_FIXTURE_ATTESTER_AUDIENCE"]),
            runtime_bucket=cast(str, values["SOLVAN_RUNTIME_BUCKET"]),
            evidence_bucket=cast(str, values["SOLVAN_EVIDENCE_BUCKET"]),
            fixture_prefix=cast(str, values["SOLVAN_SYNTHETIC_FIXTURE_PREFIX"]),
            fixture_ids=frozenset(
                item.strip()
                for item in cast(str, values["SOLVAN_SYNTHETIC_FIXTURE_IDS"]).split(",")
                if item.strip()
            ),
            kms_key_version=cast(str, values["SOLVAN_SYNTHETIC_ATTESTER_KMS_KEY_VERSION"]),
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


class ManifestReader(Protocol):
    def get_json(self, *, uri: str, expected_hash: str, max_bytes: int) -> dict[str, object]: ...


class EvidenceWriter(Protocol):
    def put_bytes(
        self, *, object_name: str, content: bytes, content_type: str
    ) -> ObjectReceipt: ...

    def put_json(self, *, object_name: str, value: dict[str, object]) -> ObjectReceipt: ...


class KmsSigner(Protocol):
    def sign_sha256(self, digest: bytes, *, key_version: str) -> bytes: ...


class GoogleKmsSigner:
    def sign_sha256(self, digest: bytes, *, key_version: str) -> bytes:
        response = authorized_session().post(
            f"https://cloudkms.googleapis.com/v1/{key_version}:asymmetricSign",
            json={"digest": {"sha256": base64.b64encode(digest).decode()}},
            timeout=30,
        )
        response.raise_for_status()
        value = response.json()
        signature = value.get("signature") if isinstance(value, dict) else None
        if not isinstance(signature, str):
            raise RuntimeError("Cloud KMS returned no asymmetric signature")
        return base64.b64decode(signature, validate=True)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def _authorize(
    authorization: str | None, *, settings: AttesterSettings, verifier: TokenVerifier
) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing caller identity")
    try:
        claims = verifier.verify(authorization.removeprefix("Bearer "), audience=settings.audience)
    except Exception as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid caller identity") from error
    if claims.get("email") != settings.coordinator_service_account:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not the coordinator")


def _validate_manifest(
    request: SyntheticAttestationRequest,
    value: dict[str, object],
    *,
    settings: AttesterSettings,
) -> WorkspaceArtifactManifest:
    manifest = WorkspaceArtifactManifest.model_validate(value)
    prefix = (
        f"gs://{settings.runtime_bucket}/{settings.scope.organization_id}/"
        f"{settings.scope.project_id}/{settings.scope.environment_id}/workspaces/"
        f"{request.workspace_id}/"
    )
    if not request.artifact_manifest_ref.startswith(prefix):
        raise ValueError("manifest is outside the exact workspace evidence prefix")
    if (
        manifest.workspace_id != request.workspace_id
        or manifest.workspace_generation != request.workspace_generation
        or manifest.manifest_kind != "INPUT"
        or manifest.classification is not WorkspaceClassification.PUBLIC
        or manifest.synthetic is not True
    ):
        raise ValueError("manifest is not an exact public-synthetic input generation")
    if request.fixture_id not in settings.fixture_ids:
        raise ValueError("fixture is not in the attester allowlist")
    if any(
        not entry.object_ref.split("#", maxsplit=1)[0].startswith(settings.fixture_prefix)
        for entry in manifest.entries
    ):
        raise ValueError("manifest entry is outside the isolated synthetic fixture prefix")
    return manifest


def create_app(
    *,
    settings: AttesterSettings | None = None,
    reader: ManifestReader | None = None,
    writer: EvidenceWriter | None = None,
    signer: KmsSigner | None = None,
    verifier: TokenVerifier | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    resolved_signer = signer or GoogleKmsSigner()
    resolved_verifier = verifier or GoogleTokenVerifier()
    resolved_clock = clock or SystemClock()
    app = FastAPI(title="Solvan Synthetic Fixture Attester", version="1.0.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live", "algorithm": "EC_SIGN_P256_SHA256"}

    @app.post("/internal/v1/synthetic-attestations", response_model=SyntheticAttestationReceipt)
    async def attest(
        request: SyntheticAttestationRequest,
        authorization: str | None = Header(default=None),
    ) -> SyntheticAttestationReceipt:
        resolved = settings or AttesterSettings.from_environment()
        session = authorized_session()
        resolved_reader = reader or GcsEvidenceReader(
            allowed_buckets=frozenset({resolved.runtime_bucket}), session=session
        )
        resolved_writer = writer or GcsEvidenceWriter(
            bucket=resolved.evidence_bucket, session=session
        )
        _authorize(authorization, settings=resolved, verifier=resolved_verifier)
        value = await asyncio.to_thread(
            resolved_reader.get_json,
            uri=request.artifact_manifest_ref,
            expected_hash=request.artifact_manifest_hash,
            max_bytes=2_000_000,
        )
        try:
            _validate_manifest(request, value, settings=resolved)
        except ValueError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
        attestation_id = new_identifier("att")
        issued_at = resolved_clock.now()
        signed = {
            "schema_version": 1,
            "attestation_id": attestation_id,
            **resolved.scope.canonical_dict(),
            "release_commit": resolved.release_commit,
            "deployment_id": resolved.deployment_id,
            "fixture_id": request.fixture_id,
            "classification": "PUBLIC",
            "synthetic": True,
            "artifact_manifest_ref": request.artifact_manifest_ref,
            "artifact_manifest_hash": request.artifact_manifest_hash,
            "issuer_principal": f"serviceAccount:{resolved.attester_service_account}",
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (issued_at + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "canonicalization": "RFC8785",
            "signature_algorithm": "EC_SIGN_P256_SHA256",
            "kms_key_version": resolved.kms_key_version,
        }
        payload = rfc8785.dumps(cast(Any, signed))
        signature = await asyncio.to_thread(
            resolved_signer.sign_sha256,
            hashlib.sha256(payload).digest(),
            key_version=resolved.kms_key_version,
        )
        prefix = (
            f"{resolved.scope.organization_id}/{resolved.scope.project_id}/"
            f"{resolved.scope.environment_id}/attestations/{attestation_id}"
        )
        signature_receipt = await asyncio.to_thread(
            resolved_writer.put_bytes,
            object_name=f"{prefix}/signature.der",
            content=signature,
            content_type="application/octet-stream",
        )
        attestation = SyntheticDataAttestation.model_validate(
            {
                **signed,
                "signed_payload_hash": sha256_bytes(payload),
                "signature_ref": signature_receipt.uri,
                "signature_hash": signature_receipt.content_hash,
            }
        )
        attestation_receipt = await asyncio.to_thread(
            resolved_writer.put_json,
            object_name=f"{prefix}/attestation.json",
            value=attestation.model_dump(mode="json"),
        )
        return SyntheticAttestationReceipt(
            attestation_ref=attestation_receipt.uri,
            attestation_hash=attestation_receipt.content_hash,
            attestation=attestation,
        )

    return app


app = instrument_fastapi(create_app(), service_name="fixture-attester")
