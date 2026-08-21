"""Authenticated administration of release signer and deployment-target authority."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from requests import RequestException

from solvan.application.release_authority import (
    CloudRunReleaseTargetInput,
    ReleaseSignerKeyInput,
    ReleaseVerifierKeyInput,
)
from solvan.domain import Scope
from solvan.persistence.release_authority_store import PostgresReleaseAuthorityStore
from solvan.platform.cloud_run_observer import (
    CloudRunObservationError,
    CloudRunServiceObserver,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.workspace_attestation import GoogleKmsPublicKeyReader


def release_authority_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any] = connect_database,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/release-authority")

    def administrator(token: str | None, scope: Scope) -> str:
        principal = principal_provider(token)
        with connect() as connection:
            row = connection.execute(
                """SELECT EXISTS (SELECT 1 FROM solvan.actor_role_bindings
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND principal=%(principal)s
                      AND role='ADMIN' AND (expires_at IS NULL OR expires_at>now()))""",
                {**scope.canonical_dict(), "principal": principal},
            ).fetchone()
        if row != (True,):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "RELEASE_ADMIN_REQUIRED")
        return principal

    @router.post("/signer-keys", status_code=status.HTTP_201_CREATED)
    def register_signer_key(
        request: ReleaseSignerKeyInput,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, str]:
        scope = scope_provider()
        administrator(human_token, scope)
        try:
            public_key = GoogleKmsPublicKeyReader(authorized_session()).public_key_pem(
                request.key_version
            )
            with connect() as connection, connection.transaction():
                signer_id, policy_hash = PostgresReleaseAuthorityStore(
                    connection, scope=scope
                ).register_signer(value=request, public_key_pem=public_key)
        except (RequestException, RuntimeError, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {"signer_key_id": signer_id, "signer_policy_hash": policy_hash}

    @router.get("/signer-keys")
    def list_signer_keys(
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[dict[str, Any]]:
        scope = scope_provider()
        administrator(human_token, scope)
        with connect() as connection:
            return PostgresReleaseAuthorityStore(connection, scope=scope).list_signers()

    @router.get("/targets")
    def list_targets(
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[dict[str, Any]]:
        scope = scope_provider()
        administrator(human_token, scope)
        with connect() as connection:
            return PostgresReleaseAuthorityStore(connection, scope=scope).list_targets()

    @router.get("/posture")
    def release_posture(
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, str]:
        scope = scope_provider()
        administrator(human_token, scope)
        names = {
            "api_service_account": "SOLVAN_API_SERVICE_ACCOUNT",
            "deployment_controller_service_account": (
                "SOLVAN_DEPLOYMENT_CONTROLLER_SERVICE_ACCOUNT"
            ),
            "release_verifier_service_account": "SOLVAN_RELEASE_VERIFIER_SERVICE_ACCOUNT",
            "release_verifier_key_version": ("SOLVAN_RELEASE_VERIFIER_SIGNING_KEY_VERSION"),
        }
        values = {key: os.environ.get(name, "").strip() for key, name in names.items()}
        if any(not value for value in values.values()):
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "RELEASE_AUTHORITY_POSTURE_NOT_CONFIGURED",
            )
        return values

    @router.post("/verifier-keys", status_code=status.HTTP_201_CREATED)
    def register_verifier_key(
        request: ReleaseVerifierKeyInput,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, str]:
        scope = scope_provider()
        administrator(human_token, scope)
        try:
            public_key = GoogleKmsPublicKeyReader(authorized_session()).public_key_pem(
                request.key_version
            )
            with connect() as connection, connection.transaction():
                key_id, policy_hash = PostgresReleaseAuthorityStore(
                    connection, scope=scope
                ).register_verifier(value=request, public_key_pem=public_key)
        except (RequestException, RuntimeError, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {
            "verifier_key_id": key_id,
            "verifier_policy_hash": policy_hash,
        }

    @router.get("/verifier-keys")
    def list_verifier_keys(
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[dict[str, Any]]:
        scope = scope_provider()
        administrator(human_token, scope)
        with connect() as connection:
            return PostgresReleaseAuthorityStore(connection, scope=scope).list_verifiers()

    @router.post("/targets", status_code=status.HTTP_201_CREATED)
    def register_target(
        request: CloudRunReleaseTargetInput,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, str]:
        scope = scope_provider()
        principal = administrator(human_token, scope)
        bucket = os.environ.get("SOLVAN_EVIDENCE_BUCKET", "").strip()
        if not bucket:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "RELEASE_EVIDENCE_NOT_CONFIGURED"
            )
        session = authorized_session()
        try:
            CloudRunServiceObserver(
                session=session,
                service_resource_name=request.service_resource_name,
                runtime_service_account=request.runtime_service_account,
                container_name=request.allowed_container_name,
            ).observe()
        except (CloudRunObservationError, RequestException, RuntimeError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "RELEASE_TARGET_PROBE_FAILED") from error
        writer = GcsEvidenceWriter(bucket=bucket, session=session)
        prefix = (
            f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
            f"release-target-profiles/{request.profile_hash}"
        )
        documents = request.documents
        manifest = writer.put_json(
            object_name=f"{prefix}/manifest-profile.json", value=documents["manifest"]
        )
        rollout = writer.put_json(
            object_name=f"{prefix}/rollout-policy.json", value=documents["rollout"]
        )
        verification = writer.put_json(
            object_name=f"{prefix}/verification-profile.json",
            value=documents["verification"],
        )
        try:
            with connect() as connection, connection.transaction():
                target_id = PostgresReleaseAuthorityStore(connection, scope=scope).register_target(
                    value=request,
                    manifest_ref=manifest.uri,
                    manifest_hash=manifest.content_hash,
                    rollout_ref=rollout.uri,
                    rollout_hash=rollout.content_hash,
                    verification_ref=verification.uri,
                    verification_hash=verification.content_hash,
                    principal=principal,
                )
        except ValueError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {"release_target_profile_id": target_id, "profile_hash": request.profile_hash}

    return router
