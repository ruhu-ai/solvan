"""Authenticated console boundary for exact code-change stage decisions."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.code_change_decisions import (
    CodeChangeDecisionStage,
    CodeChangeDecisionValue,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence.code_change_decision_store import (
    CodeChangeDecisionConflict,
    PostgresCodeChangeDecisionStore,
)
from solvan.persistence.code_change_read_store import (
    CodeChangeReadConflict,
    PostgresCodeChangeReadStore,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session


@dataclass(frozen=True, slots=True)
class VerifiedHumanSession:
    principal: str
    session_hash: str
    authenticated_at: datetime


class DecisionChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: str
    stage: CodeChangeDecisionStage
    required_role: str
    decision_digest: str
    material: dict[str, Any]
    expires_at: datetime


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    challenge_id: str = Field(pattern=r"^dch_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    decision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decision: CodeChangeDecisionValue
    reason: str = Field(min_length=8, max_length=2_000)


class DecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: str
    decision_digest: str
    decision: CodeChangeDecisionValue
    expires_at: datetime
    created: bool


def code_change_decision_router(
    *,
    session_provider: Callable[[str | None], VerifiedHumanSession],
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any] = connect_database,
    writer_factory: Callable[[], GcsEvidenceWriter] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/code-change-requests")

    @router.get("/{request_id}")
    def read_request(
        request_id: str,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, object]:
        try:
            with connect() as connection:
                return PostgresCodeChangeReadStore(connection).by_id(
                    scope=scope_provider(),
                    request_id=request_id,
                    principal=principal_provider(human_token),
                    now=_now(),
                )
        except CodeChangeReadConflict as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error

    @router.get("/by-case/{case_id}/current")
    def current_for_case(
        case_id: str,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, object] | None:
        try:
            with connect() as connection:
                return PostgresCodeChangeReadStore(connection).current_for_case(
                    scope=scope_provider(),
                    case_id=case_id,
                    principal=principal_provider(human_token),
                    now=_now(),
                )
        except CodeChangeReadConflict as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error

    def evidence_writer() -> GcsEvidenceWriter:
        if writer_factory is not None:
            return writer_factory()
        bucket = os.environ.get("SOLVAN_EVIDENCE_BUCKET", "").strip()
        if not bucket:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "code-change decision evidence bucket is not configured",
            )
        return GcsEvidenceWriter(bucket=bucket, session=authorized_session())

    @router.post(
        "/{request_id}/decision-challenges/{stage}",
        response_model=DecisionChallengeResponse,
    )
    def create_challenge(
        request_id: str,
        stage: CodeChangeDecisionStage,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> DecisionChallengeResponse:
        session = session_provider(human_token)
        scope = scope_provider()
        now = _now()
        try:
            with connect() as connection:
                store = PostgresCodeChangeDecisionStore(connection)
                draft = store.draft_challenge(
                    scope=scope,
                    request_id=request_id,
                    stage=stage,
                    principal=session.principal,
                    authenticated_session_hash=session.session_hash,
                    authenticated_at=session.authenticated_at,
                    now=now,
                )
                writer = evidence_writer()
                prefix = (
                    f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
                    f"code-change-decisions/{request_id}/{stage.value.lower()}"
                )
                material_receipt = writer.put_json(
                    object_name=f"{prefix}/{draft.decision.digest.removeprefix('sha256:')}.json",
                    value=dict(draft.decision.material),
                )
                authorization_receipt = writer.put_json(
                    object_name=(
                        f"{prefix}/authorization-"
                        f"{draft.authorization_snapshot_hash.removeprefix('sha256:')}.json"
                    ),
                    value=dict(draft.authorization_snapshot),
                )
                with connection.transaction():
                    challenge = store.record_challenge(
                        scope=scope,
                        draft=draft,
                        material_receipt=material_receipt,
                        authorization_receipt=authorization_receipt,
                        now=now,
                    )
        except CodeChangeDecisionConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return DecisionChallengeResponse(
            challenge_id=challenge.challenge_id,
            stage=challenge.stage,
            required_role=challenge.required_role,
            decision_digest=challenge.decision_digest,
            material=dict(draft.decision.material),
            expires_at=challenge.expires_at,
        )

    @router.post("/{request_id}/decisions", response_model=DecisionResponse)
    def decide(
        request_id: str,
        request: DecisionRequest,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> DecisionResponse:
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 255:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Idempotency-Key must contain 8 to 255 characters",
            )
        session = session_provider(human_token)
        scope = scope_provider()
        now = _now()
        step_up_material = {
            "schema_version": 1,
            "event_kind": "CODE_CHANGE_DECISION_STEP_UP",
            "code_change_request_id": request_id,
            "challenge_id": request.challenge_id,
            "decision_digest": request.decision_digest,
            "decision": request.decision.value,
            "principal": session.principal,
            "authenticated_session_hash": session.session_hash,
            "authenticated_at": session.authenticated_at.isoformat(),
            "decided_at": now.isoformat(),
            "decision_request_id": idempotency_key,
        }
        writer = evidence_writer()
        receipt = writer.put_json(
            object_name=(
                f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
                f"code-change-decisions/{request_id}/step-up/"
                f"{canonical_sha256(step_up_material).removeprefix('sha256:')}.json"
            ),
            value=step_up_material,
        )
        try:
            with connect() as connection, connection.transaction():
                result = PostgresCodeChangeDecisionStore(connection).decide(
                    scope=scope,
                    challenge_id=request.challenge_id,
                    expected_request_id=request_id,
                    principal=session.principal,
                    decision_request_id=idempotency_key,
                    expected_digest=request.decision_digest,
                    decision=request.decision,
                    reason=request.reason,
                    step_up_receipt=receipt,
                    now=now,
                )
        except CodeChangeDecisionConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return DecisionResponse(
            decision_id=result.decision_id,
            decision_digest=result.decision_digest,
            decision=result.decision,
            expires_at=result.expires_at,
            created=result.created,
        )

    return router


def _now() -> datetime:
    return datetime.now(UTC)
