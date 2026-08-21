"""Authenticated exact patch-review HTTP routes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.domain import ActionPolicyError, Scope
from solvan.persistence import PostgresPatchReviewStore, WorkflowConflict
from solvan.platform.database import connect_database


class PatchDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    patch_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decision: Literal["APPROVE", "CHANGES_REQUESTED"]
    reason: str = Field(min_length=1, max_length=500)


class PatchDecisionResponse(BaseModel):
    review_id: str
    patch_artifact_id: str
    patch_digest: str
    decision: str
    created: bool


def patch_review_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/patches/{patch_artifact_id}/review-material")
    def review_material(
        patch_artifact_id: str,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        principal_provider(human_identity_token)
        try:
            with connect_database() as connection, connection.transaction():
                material = PostgresPatchReviewStore(connection).review(
                    scope=scope_provider(), patch_artifact_id=patch_artifact_id
                )
        except ActionPolicyError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
        return asdict(material)

    @router.post(
        "/api/v1/patches/{patch_artifact_id}:review",
        response_model=PatchDecisionResponse,
    )
    def decide_patch(
        patch_artifact_id: str,
        request: PatchDecisionRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None),
    ) -> PatchDecisionResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 128:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Idempotency-Key must contain 8 to 128 characters",
            )
        principal = principal_provider(human_identity_token)
        try:
            with connect_database() as connection, connection.transaction():
                result = PostgresPatchReviewStore(connection).decide(
                    scope=scope_provider(),
                    patch_artifact_id=patch_artifact_id,
                    reviewer_principal=principal,
                    expected_patch_digest=request.patch_digest,
                    decision=request.decision,
                    reason=request.reason,
                    decision_request_id=idempotency_key,
                )
        except ActionPolicyError as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
        except WorkflowConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return PatchDecisionResponse(**asdict(result))

    return router
