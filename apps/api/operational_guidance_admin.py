"""Typed, identity-derived Operational Guidance and trigger-policy commands."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.guidance_evaluation import GuidanceEvaluationVerifier
from solvan.application.operational_guidance import (
    BlockedBehavior,
    GuidanceError,
    GuidanceKind,
    GuidanceRevision,
    GuidanceSourceKind,
    GuidanceStepKind,
    GuidanceStepRevision,
    TriggerKind,
    TriggerPolicyRevision,
)
from solvan.domain import Scope
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore
from solvan.persistence.trigger_policy_store import PostgresTriggerPolicyStore


@dataclass(frozen=True, slots=True)
class GuidanceContentInspection:
    accepted: bool
    reason_codes: tuple[str, ...]
    armor_verdict_ref: str | None = None


class _StrictCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class GuidanceStepDraft(_StrictCommand):
    step_key: str
    ordinal: int
    title: str
    objective: str
    step_kind: GuidanceStepKind
    allowed_tool_revisions: tuple[str, ...]
    prerequisite_step_keys: tuple[str, ...]
    completion_predicate_key: str
    completion_predicate_version: str
    required_evidence_kinds: tuple[str, ...]
    maximum_tool_requests: int
    on_blocked: BlockedBehavior


class GuidanceDraftCommand(_StrictCommand):
    schema_version: Literal[1]
    guidance_key: str
    version: str
    display_name: str
    description: str
    owner_department: str
    discoverable_departments: tuple[str, ...]
    guidance_kind: GuidanceKind
    applicable_service_kinds: tuple[str, ...]
    applicable_incident_classes: tuple[str, ...]
    symptom_tags: tuple[str, ...]
    purpose: str
    classification: str
    eligible_regions: tuple[str, ...]
    allowed_agent_keys: tuple[str, ...]
    required_profile_revisions: tuple[str, ...]
    steps: tuple[GuidanceStepDraft, ...]
    content_ref: str
    content_hash: str
    source_kind: GuidanceSourceKind
    source_ref: str
    source_license: str | None = None
    supersedes: str | None = None

    def revision(self, *, principal: str) -> GuidanceRevision:
        material = self.model_dump(mode="python")
        material["steps"] = tuple(
            GuidanceStepRevision.model_validate(step) for step in material["steps"]
        )
        return GuidanceRevision.model_validate(
            {
                **material,
                "author_principal": principal,
                "lifecycle": "DRAFT",
            }
        )


class TriggerPolicyDraftCommand(_StrictCommand):
    schema_version: Literal[1]
    policy_key: str
    version: str
    owner_department: str
    trigger_kind: TriggerKind
    source_connection_id: str
    source_connection_epoch: int
    source_capability_tool_ref: str
    source_capability_agent_key: str
    source_capability_identity_ref: str
    source_capability_class: str
    target_selector_ref: str
    incident_class: str
    severity: str
    deduplication_dimension: str
    action_budget: int
    repeated_action_limit: int
    guidance_revision: str | None = None
    investigation_profile_ref: str
    delay_ms: int
    cooldown_ms: int
    maximum_pending_per_target: int
    supersession: str
    region: str
    classification_ceiling: str

    def policy(self, *, principal: str) -> TriggerPolicyRevision:
        return TriggerPolicyRevision.model_validate(
            {
                **self.model_dump(mode="python"),
                "author_principal": principal,
                "lifecycle": "DRAFT",
            }
        )


class DigestCommand(_StrictCommand):
    schema_version: Literal[1]
    expected_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class TriggerHeadCommand(DigestCommand):
    current_version: str = Field(min_length=1)
    expected_head_epoch: int = Field(ge=1)
    expected_activation_id: str = Field(min_length=1)


class TriggerActivationCommand(DigestCommand):
    candidate_version: str = Field(min_length=1)
    expected_prior_head_epoch: int = Field(ge=0)
    expected_activation_id: str | None = None
    placement_epoch: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_prior_head_fence(self) -> TriggerActivationCommand:
        if (self.expected_prior_head_epoch == 0) != (self.expected_activation_id is None):
            raise ValueError(
                "an initial activation has no activation ID; a replacement activation requires one"
            )
        return self


class TriggerRetirementCommand(DigestCommand):
    expected_lifecycle_epoch: int = Field(ge=1)
    expected_head_epoch: int | None = Field(default=None, ge=1)
    expected_activation_id: str | None = None


class TriggerReplacementCommand(_StrictCommand):
    schema_version: Literal[1]
    retiring_version: str = Field(min_length=1)
    retiring_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    successor_version: str = Field(min_length=1)
    successor_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_head_epoch: int = Field(ge=1)
    expected_activation_id: str = Field(min_length=1)
    expected_lifecycle_epoch: int = Field(ge=1)
    placement_epoch: int = Field(ge=1)


class TriggerReplacementConsumptionCommand(_StrictCommand):
    schema_version: Literal[1]
    replacement_intent_id: str = Field(min_length=1)
    expected_compound_request_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ApprovalCommand(DigestCommand):
    reason: str = Field(min_length=1, max_length=500)


class GuidanceApprovalCommand(ApprovalCommand):
    evaluation_ref: str = Field(pattern=r"^gev_[0-7][0-9A-HJKMNP-TV-Z]{25}$")


class EvaluationCommand(DigestCommand):
    receipt_ref: str = Field(min_length=1, max_length=2_000)


class TriggerEvaluationCommand(DigestCommand):
    suite_version: str = Field(min_length=1, max_length=120)
    passed_cases: int = Field(ge=0)
    failed_cases: int = Field(ge=0)
    receipt_ref: str = Field(min_length=1, max_length=2_000)
    receipt_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason_codes: tuple[str, ...] = Field(min_length=1, max_length=40)


def _decision_id(value: str, suffix: str) -> str:
    return f"op-{suffix}-{hashlib.sha256(value.encode()).hexdigest()[:48]}"


def _idempotency(value: str | None) -> str:
    if value is None or not 8 <= len(value) <= 128:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Idempotency-Key must contain 8 to 128 characters",
        )
    return value


def _safe_error(error: Exception) -> HTTPException:
    message = str(error)
    code = (
        status.HTTP_403_FORBIDDEN
        if "role is inactive" in message or "cannot approve" in message
        else status.HTTP_409_CONFLICT
    )
    return HTTPException(code, message)


def operational_guidance_router(
    *,
    principal_provider: Callable[[str | None], str],
    reader_principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    content_inspector: Callable[[GuidanceRevision], GuidanceContentInspection],
    known_predicates: frozenset[str],
    evaluation_verifier: GuidanceEvaluationVerifier,
) -> APIRouter:
    """Build the read/admin surface without accepting identity or scope in a body."""

    router = APIRouter()

    def _principal(token: str | None) -> str:
        return principal_provider(token)

    def _reader(token: str | None) -> str:
        return reader_principal_provider(token)

    @router.post("/api/admin/guidance/drafts")
    def create_guidance_draft(
        request: GuidanceDraftCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        principal = _principal(human_identity_token)
        command_id = _idempotency(idempotency_key)
        revision = request.revision(principal=principal)
        try:
            inspection = content_inspector(revision)
            with connect() as connection, connection.transaction():
                store = PostgresOperationalGuidanceStore(connection)
                result = store.create_draft(
                    scope=scope_provider(),
                    revision=revision,
                    decision_request_id=_decision_id(command_id, "guidance-draft"),
                )
                ingestion_id = store.record_ingestion(
                    scope=scope_provider(),
                    guidance_key=revision.guidance_key,
                    version=revision.version,
                    content_hash=revision.content_hash,
                    accepted=inspection.accepted,
                    reason_codes=inspection.reason_codes,
                    armor_verdict_ref=inspection.armor_verdict_ref,
                    principal=principal,
                    decision_request_id=_decision_id(command_id, "guidance-ingestion"),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        payload = {**asdict(result), "ingestion_id": ingestion_id}
        if not inspection.accepted:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                {
                    "message": "guidance content was rejected",
                    "reason_codes": inspection.reason_codes,
                },
            )
        return payload

    @router.post("/api/admin/guidance/{key}/revisions/{version}/submit")
    def submit_guidance(
        key: str,
        version: str,
        request: DigestCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresOperationalGuidanceStore(connection).submit(
                    scope=scope_provider(),
                    guidance_key=key,
                    version=version,
                    principal=_principal(human_identity_token),
                    expected_digest=request.expected_digest,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post("/api/admin/guidance/{key}/revisions/{version}/evaluations")
    def evaluate_guidance(
        key: str,
        version: str,
        request: EvaluationCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, str]:
        try:
            scope = scope_provider()
            verified = evaluation_verifier.verify(
                scope=scope,
                guidance_key=key,
                version=version,
                expected_digest=request.expected_digest,
                receipt_ref=request.receipt_ref,
            )
            with connect() as connection, connection.transaction():
                evaluation_id = PostgresOperationalGuidanceStore(connection).record_evaluation(
                    scope=scope,
                    guidance_key=key,
                    version=version,
                    expected_digest=request.expected_digest,
                    principal=_principal(human_identity_token),
                    suite_version=verified.suite_version,
                    passed_cases=verified.passed_cases,
                    failed_cases=verified.failed_cases,
                    receipt_ref=verified.receipt_ref,
                    receipt_hash=verified.receipt_hash,
                    receipt_generation=verified.object_generation,
                    corpus_digest=verified.corpus_digest,
                    case_set_digest=verified.case_set_digest,
                    scorer_name=verified.scorer_name,
                    scorer_version=verified.scorer_version,
                    model_config_pins=verified.model_config_pins,
                    repetitions=verified.repetitions,
                    pass_thresholds=verified.pass_thresholds,
                    reason_codes=verified.reason_codes,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except (GuidanceError, RuntimeError, ValueError) as error:
            raise _safe_error(error) from error
        return {"evaluation_id": evaluation_id}

    @router.post("/api/admin/guidance/{key}/revisions/{version}/approve")
    def approve_guidance(
        key: str,
        version: str,
        request: GuidanceApprovalCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresOperationalGuidanceStore(connection).approve(
                    scope=scope_provider(),
                    guidance_key=key,
                    version=version,
                    principal=_principal(human_identity_token),
                    expected_digest=request.expected_digest,
                    evaluation_ref=request.evaluation_ref,
                    decision_request_id=_idempotency(idempotency_key),
                    reason=request.reason,
                    known_predicates=known_predicates,
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    def _guidance_transition(
        *,
        operation: Literal["deprecate", "retire"],
        key: str,
        version: str,
        request: DigestCommand,
        token: str | None,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                store = PostgresOperationalGuidanceStore(connection)
                method = store.deprecate if operation == "deprecate" else store.retire
                result = method(
                    scope=scope_provider(),
                    guidance_key=key,
                    version=version,
                    principal=_principal(token),
                    expected_digest=request.expected_digest,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post("/api/admin/guidance/{key}/revisions/{version}/deprecate")
    def deprecate_guidance(
        key: str,
        version: str,
        request: DigestCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        return _guidance_transition(
            operation="deprecate",
            key=key,
            version=version,
            request=request,
            token=human_identity_token,
            idempotency_key=idempotency_key,
        )

    @router.post("/api/admin/guidance/{key}/revisions/{version}/retire")
    def retire_guidance(
        key: str,
        version: str,
        request: DigestCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        return _guidance_transition(
            operation="retire",
            key=key,
            version=version,
            request=request,
            token=human_identity_token,
            idempotency_key=idempotency_key,
        )

    # Deferred: the split module imports this module's command models, so a
    # top-level import here would close the cycle.
    from apps.api.operational_trigger_policy_admin import register_trigger_policy_commands

    register_trigger_policy_commands(
        router,
        scope_provider=scope_provider,
        connect=connect,
        principal=_principal,
        idempotency=_idempotency,
        safe_error=_safe_error,
    )

    @router.get("/api/fleet/guidance/{key}/revisions/{version}/evaluations")
    def guidance_evaluations(
        key: str,
        version: str,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _reader(authorization)
        response.headers["Cache-Control"] = "private, no-store"
        with connect() as connection:
            values = PostgresOperationalGuidanceStore(connection).evaluations_projection(
                scope=scope_provider(), guidance_key=key, version=version
            )
        return {"evaluations": values}

    @router.get("/api/fleet/trigger-policies/{key}/revisions/{version}")
    def trigger_policy_detail(
        key: str,
        version: str,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _reader(authorization)
        response.headers["Cache-Control"] = "private, no-store"
        with connect() as connection:
            value = PostgresTriggerPolicyStore(connection).policy_projection(
                scope=scope_provider(), policy_key=key, version=version
            )
        if value is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Trigger policy was not found")
        return value

    @router.get("/api/incidents/{incident_id}/guidance-runs")
    def incident_guidance_runs(
        incident_id: str,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _reader(authorization)
        response.headers["Cache-Control"] = "private, no-store"
        with connect() as connection:
            values = PostgresOperationalGuidanceStore(connection).guidance_runs_projection(
                scope=scope_provider(), incident_id=incident_id
            )
        return {"incident_id": incident_id, "guidance_runs": values}

    return router
