"""Administrator surface for immutable Code Change Request policy bundles."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status

from solvan.application.code_delivery_profiles import CodeDeliveryProfileInput
from solvan.domain import Scope
from solvan.persistence.code_delivery_profile_store import (
    DeliveryPolicyReceipts,
    PostgresCodeDeliveryProfileStore,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session


def code_delivery_profile_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any] = connect_database,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/code-delivery-profiles")

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
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CODE_DELIVERY_ADMIN_REQUIRED")
        return principal

    @router.get("")
    def list_profiles(
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[dict[str, Any]]:
        scope = scope_provider()
        administrator(human_token, scope)
        with connect() as connection:
            return PostgresCodeDeliveryProfileStore(connection, scope=scope).list()

    @router.post("", status_code=status.HTTP_201_CREATED)
    def register_profile(
        request: CodeDeliveryProfileInput,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, str]:
        scope = scope_provider()
        principal = administrator(human_token, scope)
        bucket = os.environ.get("SOLVAN_EVIDENCE_BUCKET", "").strip()
        if not bucket:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "CODE_DELIVERY_EVIDENCE_NOT_CONFIGURED"
            )
        writer = GcsEvidenceWriter(bucket=bucket, session=authorized_session())
        prefix = (
            f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
            f"code-delivery-profiles/{request.repository_binding_id}/{request.profile_hash}"
        )
        documents = request.documents
        receipts = DeliveryPolicyReceipts(
            required_checks=writer.put_json(
                object_name=f"{prefix}/required-checks.json",
                value=documents["required-checks"],
            ),
            reviewer=writer.put_json(
                object_name=f"{prefix}/reviewer.json", value=documents["reviewer"]
            ),
            pr_creation=writer.put_json(
                object_name=f"{prefix}/pr-creation.json", value=documents["pr-creation"]
            ),
            merge=writer.put_json(object_name=f"{prefix}/merge.json", value=documents["merge"]),
            deployment=writer.put_json(
                object_name=f"{prefix}/deployment.json", value=documents["deployment"]
            ),
            approval=writer.put_json(
                object_name=f"{prefix}/approval.json",
                value={
                    "schema_version": 1,
                    "event_kind": "CODE_DELIVERY_PROFILE_APPROVED",
                    "profile_hash": request.profile_hash,
                    "principal": principal,
                    "approved_at": datetime.now(UTC).isoformat(),
                },
            ),
        )
        try:
            with connect() as connection, connection.transaction():
                profile_id = PostgresCodeDeliveryProfileStore(connection, scope=scope).register(
                    value=request, receipts=receipts, principal=principal
                )
        except ValueError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {"profile_id": profile_id, "profile_hash": request.profile_hash}

    return router
