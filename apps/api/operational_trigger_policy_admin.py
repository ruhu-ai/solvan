"""Trigger-policy administration commands.

Split out of `operational_guidance_admin` under the size ceiling's removal
condition. Routes and verified-principal derivation are unchanged: the caller
still supplies `_principal` and `_safe_error` from the guidance router, so the
identity path is identical to before the split.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status

from apps.api.operational_guidance_admin import (
    ApprovalCommand,
    DigestCommand,
    TriggerActivationCommand,
    TriggerEvaluationCommand,
    TriggerHeadCommand,
    TriggerPolicyDraftCommand,
    TriggerReplacementCommand,
    TriggerReplacementConsumptionCommand,
    TriggerRetirementCommand,
)
from solvan.application.alert_triage import AlertPolicyError, AlertPolicyRevisionV1
from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope
from solvan.persistence.alert_triage import AlertTriageRepository
from solvan.persistence.trigger_policy_store import PostgresTriggerPolicyStore


def register_trigger_policy_commands(
    router: APIRouter,
    *,
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    principal: Callable[[str | None], str],
    idempotency: Callable[[str | None], str],
    safe_error: Callable[[Exception], HTTPException],
) -> None:
    """Attach the closed trigger-policy lifecycle commands to `router`."""

    _principal = principal
    _idempotency = idempotency
    _safe_error = safe_error

    @router.post("/api/admin/trigger-policies/drafts")
    def create_trigger_policy(
        request: TriggerPolicyDraftCommand | AlertPolicyRevisionV1,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        principal = _principal(human_identity_token)
        policy = (
            request.trigger_policy(principal=principal)
            if isinstance(request, AlertPolicyRevisionV1)
            else request.policy(principal=principal)
        )
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).create_draft(
                    scope=scope_provider(),
                    policy=policy,
                    decision_request_id=_idempotency(idempotency_key),
                )
                subtype = (
                    AlertTriageRepository(connection).record_alert_policy_subtype(
                        scope=scope_provider(),
                        policy=request,
                        generic_policy_hash=policy.policy_hash,
                        retention_policy_revision="retention/alert-policy-v1",
                    )
                    if isinstance(request, AlertPolicyRevisionV1)
                    else None
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        except AlertPolicyError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if subtype is None:
            return asdict(result)
        return {"generic_policy": asdict(result), "alert_policy": asdict(subtype)}

    @router.post("/api/admin/trigger-policies/{key}/revisions/{version}/evaluations")
    def evaluate_trigger_policy(
        key: str,
        version: str,
        request: TriggerEvaluationCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, str]:
        try:
            with connect() as connection, connection.transaction():
                evaluation_id = PostgresTriggerPolicyStore(connection).record_evaluation(
                    scope=scope_provider(),
                    policy_key=key,
                    version=version,
                    expected_digest=request.expected_digest,
                    principal=_principal(human_identity_token),
                    suite_version=request.suite_version,
                    passed_cases=request.passed_cases,
                    failed_cases=request.failed_cases,
                    receipt_ref=request.receipt_ref,
                    receipt_hash=request.receipt_hash,
                    reason_codes=request.reason_codes,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return {"evaluation_id": evaluation_id}

    @router.post("/api/admin/trigger-policies/{key}/revisions/{version}/approve")
    def approve_trigger_policy(
        key: str,
        version: str,
        request: ApprovalCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).approve(
                    scope=scope_provider(),
                    policy_key=key,
                    version=version,
                    principal=_principal(human_identity_token),
                    expected_digest=request.expected_digest,
                    reason=request.reason,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post("/api/admin/trigger-policies/{key}/revisions/{version}/mark-eligible")
    def mark_trigger_policy_eligible(
        key: str,
        version: str,
        request: DigestCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).mark_eligible(
                    scope=scope_provider(),
                    policy_key=key,
                    version=version,
                    principal=_principal(human_identity_token),
                    expected_digest=request.expected_digest,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post("/api/admin/trigger-policies/{key}/heads/activate")
    def activate_trigger_policy(
        key: str,
        request: TriggerActivationCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).activate(
                    scope=scope_provider(),
                    policy_key=key,
                    version=request.candidate_version,
                    principal=_principal(human_identity_token),
                    expected_digest=request.expected_digest,
                    expected_prior_head_epoch=request.expected_prior_head_epoch,
                    expected_activation_id=request.expected_activation_id,
                    placement_epoch=request.placement_epoch,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post("/api/admin/trigger-policies/{key}/heads/deactivate")
    def disable_trigger_policy(
        key: str,
        request: TriggerHeadCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).disable(
                    scope=scope_provider(),
                    policy_key=key,
                    version=request.current_version,
                    principal=_principal(human_identity_token),
                    expected_digest=request.expected_digest,
                    expected_head_epoch=request.expected_head_epoch,
                    expected_activation_id=request.expected_activation_id,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post("/api/admin/trigger-policies/{key}/heads/prepare-replacement")
    def prepare_trigger_policy_replacement(
        key: str,
        request: TriggerReplacementCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).prepare_replacement(
                    scope=scope_provider(),
                    retiring_policy_key=key,
                    retiring_version=request.retiring_version,
                    retiring_digest=request.retiring_digest,
                    successor_policy_key=key,
                    successor_version=request.successor_version,
                    successor_digest=request.successor_digest,
                    principal=_principal(human_identity_token),
                    expected_head_epoch=request.expected_head_epoch,
                    expected_activation_id=request.expected_activation_id,
                    expected_lifecycle_epoch=request.expected_lifecycle_epoch,
                    placement_epoch=request.placement_epoch,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post("/api/admin/trigger-policies/{key}/revisions/{version}/retire")
    def retire_trigger_policy(
        key: str,
        version: str,
        request: TriggerRetirementCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).retire(
                    scope=scope_provider(),
                    policy_key=key,
                    version=version,
                    principal=_principal(human_identity_token),
                    expected_digest=request.expected_digest,
                    expected_lifecycle_epoch=request.expected_lifecycle_epoch,
                    expected_head_epoch=request.expected_head_epoch,
                    expected_activation_id=request.expected_activation_id,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)

    @router.post(
        "/api/admin/trigger-policies/{key}/revisions/{version}/retire-with-prepared-replacement"
    )
    def retire_trigger_policy_with_replacement(
        key: str,
        version: str,
        request: TriggerReplacementConsumptionCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                result = PostgresTriggerPolicyStore(connection).retire_with_prepared_replacement(
                    scope=scope_provider(),
                    replacement_intent_id=request.replacement_intent_id,
                    expected_retiring_policy_key=key,
                    expected_retiring_version=version,
                    principal=_principal(human_identity_token),
                    expected_compound_request_hash=request.expected_compound_request_hash,
                    decision_request_id=_idempotency(idempotency_key),
                )
        except GuidanceError as error:
            raise _safe_error(error) from error
        return asdict(result)
