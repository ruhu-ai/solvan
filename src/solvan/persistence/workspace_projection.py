"""Pure projections and equality fences for durable workspace rows."""

from __future__ import annotations

from typing import Any, cast

from solvan.application import (
    WorkspaceCheckpoint,
    WorkspaceClassification,
    WorkspaceKind,
    WorkspaceProviderKind,
    WorkspaceRef,
    WorkspaceSpec,
    WorkspaceStatus,
    WorkspaceTaskInvocation,
)
from solvan.domain import Scope


def select_workspace_row(
    cursor: Any,
    scope: Scope,
    workspace_id: str,
    *,
    for_update: bool,
) -> dict[str, Any] | None:
    lock = " FOR UPDATE" if for_update else ""
    cursor.execute(
        """SELECT * FROM solvan.workspaces
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND id = %(workspace_id)s"""
        + lock,
        {**scope.canonical_dict(), "workspace_id": workspace_id},
    )
    return cast(dict[str, Any] | None, cursor.fetchone())


def project_workspace_ref(row: dict[str, Any], scope: Scope) -> WorkspaceRef:
    return WorkspaceRef(
        scope=scope,
        workspace_id=str(row["id"]),
        generation=int(row["generation"]),
        kind=WorkspaceKind(str(row["kind"])),
        provider=WorkspaceProviderKind(str(row["provider"])),
        implementation_sdk=str(row["implementation_sdk"]),
        implementation_sdk_version=str(row["implementation_sdk_version"]),
        implementation_sdk_distribution_hash=str(row["implementation_sdk_distribution_hash"]),
        provider_artifact_digest=str(row["provider_artifact_digest"]),
        provider_revision=str(row["provider_revision"]),
        status=WorkspaceStatus(str(row["status"])),
        classification=WorkspaceClassification(str(row["classification"])),
        synthetic=bool(row["synthetic"]),
        artifact_prefix=str(row["artifact_prefix"]),
        input_manifest_ref=str(row["input_manifest_ref"]),
        input_manifest_hash=str(row["input_manifest_hash"]),
    )


def project_workspace_checkpoint(row: dict[str, Any], scope: Scope) -> WorkspaceCheckpoint:
    return WorkspaceCheckpoint(
        scope=scope,
        checkpoint_id=str(row["id"]),
        workspace_id=str(row["workspace_id"]),
        workspace_generation=int(row["workspace_generation"]),
        sequence_no=int(row["sequence_no"]),
        event_kind=str(row["event_kind"]),
        parent_checkpoint_id=(
            None if row["parent_checkpoint_id"] is None else str(row["parent_checkpoint_id"])
        ),
        provider=WorkspaceProviderKind(str(row["provider"])),
        implementation_sdk=str(row["implementation_sdk"]),
        implementation_sdk_version=str(row["implementation_sdk_version"]),
        implementation_sdk_distribution_hash=str(row["implementation_sdk_distribution_hash"]),
        provider_artifact_digest=str(row["provider_artifact_digest"]),
        provider_revision=str(row["provider_revision"]),
        provider_request_hash=str(row["provider_request_hash"]),
        provider_receipt_ref=str(row["provider_receipt_ref"]),
        provider_receipt_hash=str(row["provider_receipt_hash"]),
        provider_boot_hash=str(row["provider_boot_hash"]),
        provider_service_revision=str(row["provider_service_revision"]),
        input_manifest_ref=str(row["input_manifest_ref"]),
        input_manifest_hash=str(row["input_manifest_hash"]),
        artifact_manifest_ref=str(row["artifact_manifest_ref"]),
        artifact_manifest_hash=str(row["artifact_manifest_hash"]),
        effective_tool_set_hash=str(row["effective_tool_set_hash"]),
        effective_network_policy_hash=str(row["effective_network_policy_hash"]),
        created_by_principal=str(row["created_by_principal"]),
    )


def matches_workspace_spec(row: dict[str, Any], spec: WorkspaceSpec) -> bool:
    pairs = (
        (row["kind"], spec.kind.value),
        (row["service_id"], spec.service_id),
        (row["reliability_case_id"], spec.reliability_case_id),
        (row["provider"], spec.provider.value),
        (row["implementation_sdk"], spec.implementation_sdk),
        (row["implementation_sdk_version"], spec.implementation_sdk_version),
        (row["provider_revision"], spec.provider_revision),
        (
            row["implementation_sdk_distribution_hash"],
            spec.implementation_sdk_distribution_hash,
        ),
        (row["provider_artifact_digest"], spec.provider_artifact_digest),
        (row["provider_agent_resource"], spec.provider_agent_resource),
        (row["provider_service_identity"], spec.provider_service_identity),
        (row["input_manifest_hash"], spec.input_manifest_hash),
        (row["provider_eligibility_decision_id"], spec.provider_eligibility_decision_id),
    )
    return all(str(actual) == str(expected) for actual, expected in pairs)


def matches_workspace_ref(row: dict[str, Any], ref: WorkspaceRef) -> bool:
    return (
        str(row["id"]) == ref.workspace_id
        and int(row["generation"]) == ref.generation
        and str(row["provider"]) == ref.provider.value
        and str(row["provider_revision"]) == ref.provider_revision
        and str(row["implementation_sdk_distribution_hash"])
        == ref.implementation_sdk_distribution_hash
        and str(row["provider_artifact_digest"]) == ref.provider_artifact_digest
        and str(row["input_manifest_hash"]) == ref.input_manifest_hash
    )


def matches_workspace_invocation(row: dict[str, Any], invocation: WorkspaceTaskInvocation) -> bool:
    return (
        str(row["id"]) == invocation.run_id
        and str(row["invocation_id"]) == invocation.invocation_id
        and str(row["provider_request_id"]) == invocation.request_id
        and str(row["provider_request_hash"]) == invocation.request_hash
        and str(row["implementation_sdk_distribution_hash"])
        == invocation.implementation_sdk_distribution_hash
        and str(row["provider_artifact_digest"]) == invocation.provider_artifact_digest
        and str(row["workspace_id"]) == invocation.workspace_id
        and int(row["workspace_generation"]) == invocation.workspace_generation
        and int(row["workflow_version"]) == invocation.workflow_version
        and int(row["attempt"]) == invocation.attempt
        and str(row["status"]) in {"CREATED", "DISPATCHED", "RUNNING", "SUCCEEDED", "FAILED"}
    )
