"""Administrative binding of approved detection rules to exact source epochs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence.detection_connection_store import (
    DetectionConnectionBindingError,
    PostgresDetectionConnectionStore,
)
from solvan.platform.database import connect_database


class DetectionConnectionBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    detection_rule_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    detection_rule_version: int = Field(ge=1)
    expected_connection_epoch: int = Field(ge=1)
    decision_ref: str = Field(min_length=1, max_length=1024)


class DetectionConnectionBindingResponse(BaseModel):
    detection_rule_id: str
    detection_rule_version: int
    connection_id: str
    connection_epoch: int


def detection_connection_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
) -> APIRouter:
    router = APIRouter()

    def admin(token: str | None, scope: Scope) -> str:
        principal = principal_provider(token)
        with connect_database() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM solvan.actor_role_bindings
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND principal = %(principal)s AND role = 'ADMIN'
                      AND (expires_at IS NULL OR expires_at > now())) AS active""",
                {**scope.canonical_dict(), "principal": principal},
            )
            row = cursor.fetchone()
        if row is None or not row[0]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "administrator role is required")
        return principal

    @router.post(
        "/api/v1/connections/{connection_id}/detection-rule-bindings",
        response_model=DetectionConnectionBindingResponse,
    )
    def bind_detection_rule(
        connection_id: str,
        request: DetectionConnectionBindingRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> DetectionConnectionBindingResponse:
        scope = scope_provider()
        actor = admin(human_identity_token, scope)
        if not idempotency_key or len(idempotency_key) > 128:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "an idempotency key is required"
            )
        request_hash = canonical_sha256(
            {"connection_id": connection_id, **request.model_dump(mode="json")}
        )
        try:
            with connect_database() as connection, connection.transaction():
                binding = PostgresDetectionConnectionStore(connection).bind(
                    scope=scope,
                    detection_rule_id=request.detection_rule_id,
                    detection_rule_version=request.detection_rule_version,
                    connection_id=connection_id,
                    expected_connection_epoch=request.expected_connection_epoch,
                    actor=actor,
                    decision_ref=request.decision_ref,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                )
        except DetectionConnectionBindingError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return DetectionConnectionBindingResponse(
            detection_rule_id=binding.detection_rule_id,
            detection_rule_version=binding.detection_rule_version,
            connection_id=binding.connection_id,
            connection_epoch=binding.connection_epoch,
        )

    return router
