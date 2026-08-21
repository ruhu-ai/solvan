"""Fenced GitHub draft-to-ready transition for one governed pull request."""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from solvan.application.delivery_commands import (
    DeliveryOutcome,
    DeliveryReasonCode,
)
from solvan.domain import Scope
from solvan.persistence.code_change_operation_store import (
    CodeChangeOperationConflict,
    PostgresCodeChangeOperationStore,
    PullRequestProviderMaterial,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.github import GitHubApiError
from solvan.platform.github_code_change import GitHubCodeChangeClient


def ensure_ready_for_review(
    *,
    code: GitHubCodeChangeClient,
    scope: Scope,
    material: PullRequestProviderMaterial,
    head_sha: str,
    writer: GcsEvidenceWriter,
    command_id: str,
) -> tuple[DeliveryOutcome, DeliveryReasonCode, dict[str, Any]] | None:
    with connect_database() as connection:
        store = PostgresCodeChangeOperationStore(connection)
        operation_status = store.operation_statuses(
            scope=scope, request_id=material.request_id
        ).get("MARK_PR_READY")
        observed = code.find_pull_request(
            owner=material.owner,
            name=material.name,
            branch=material.branch_name,
            base=material.default_branch,
        )
        if observed is None or observed.head_sha != head_sha:
            return _failure(
                store=store,
                connection=connection,
                scope=scope,
                material=material,
                writer=writer,
                command_id=command_id,
                reason="PULL_REQUEST_STATE_MISMATCH",
                ambiguous=operation_status != "PREPARED",
            )
        if operation_status == "PREPARED":
            if not observed.draft:
                return _failure(
                    store=store,
                    connection=connection,
                    scope=scope,
                    material=material,
                    writer=writer,
                    command_id=command_id,
                    reason="EXTERNAL_STATE_CHANGED",
                    ambiguous=False,
                )
            with connection.transaction():
                if not store.claim_operation(
                    scope=scope,
                    request_id=material.request_id,
                    kind="MARK_PR_READY",
                ):
                    raise CodeChangeOperationConflict("ready-for-review issue fence was claimed")
            with suppress(GitHubApiError):
                code.mark_pull_request_ready(pull_request_node_id=observed.node_id)
            observed = code.find_pull_request(
                owner=material.owner,
                name=material.name,
                branch=material.branch_name,
                base=material.default_branch,
            )
        if observed is None or observed.draft or observed.head_sha != head_sha:
            return _failure(
                store=store,
                connection=connection,
                scope=scope,
                material=material,
                writer=writer,
                command_id=command_id,
                reason="READY_FOR_REVIEW_NOT_RECONCILED",
                ambiguous=operation_status != "PREPARED",
            )
        if operation_status != "SUCCEEDED":
            receipt = writer.put_json(
                object_name=_result_name(scope, command_id, "ready-for-review.json"),
                value={
                    "pull_request_number": observed.number,
                    "head_commit_sha": observed.head_sha,
                    "draft": observed.draft,
                },
            )
            with connection.transaction():
                store.complete_operation(
                    scope=scope,
                    request_id=material.request_id,
                    kind="MARK_PR_READY",
                    response_ref=receipt.uri,
                    response_hash=receipt.content_hash,
                    status="SUCCEEDED",
                )
    return None


def _failure(
    *,
    store: PostgresCodeChangeOperationStore,
    connection: Any,
    scope: Scope,
    material: PullRequestProviderMaterial,
    writer: GcsEvidenceWriter,
    command_id: str,
    reason: str,
    ambiguous: bool,
) -> tuple[DeliveryOutcome, DeliveryReasonCode, dict[str, Any]]:
    result = {
        "schema_version": 1,
        "outcome": "AMBIGUOUS" if ambiguous else "REFUSED",
        "reason": reason,
    }
    receipt = writer.put_json(
        object_name=_result_name(scope, command_id, "mark-pr-ready-failure.json"),
        value=result,
    )
    with connection.transaction():
        current = store.operation_statuses(scope=scope, request_id=material.request_id).get(
            "MARK_PR_READY"
        )
        if current not in {"SUCCEEDED", "REFUSED", "AMBIGUOUS"}:
            store.complete_operation(
                scope=scope,
                request_id=material.request_id,
                kind="MARK_PR_READY",
                response_ref=receipt.uri,
                response_hash=receipt.content_hash,
                status="AMBIGUOUS" if ambiguous else "REFUSED",
                error_class=reason,
            )
    return (
        DeliveryOutcome.AMBIGUOUS if ambiguous else DeliveryOutcome.REFUSED,
        DeliveryReasonCode.EXTERNAL_STATE_AMBIGUOUS
        if ambiguous
        else DeliveryReasonCode.PRECONDITION_FAILED,
        result,
    )


def _result_name(scope: Scope, command_id: str, suffix: str) -> str:
    return (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        f"github-code-change/{command_id}/{suffix}"
    )
