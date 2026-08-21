"""Coordinator-owned Antigravity checkpoint rehydration after provider replacement."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from typing import Any

import httpx
from psycopg import Connection
from psycopg.rows import dict_row

from apps.coordinator.antigravity_tasks import SDK_DISTRIBUTION_HASH
from apps.coordinator.contracts import CoordinatorSettings, WorkspaceRehydrationCandidate
from solvan.application import (
    WorkspaceArtifactManifest,
    WorkspaceCheckpoint,
    WorkspaceCheckpointMaterial,
    WorkspaceProviderKind,
    WorkspaceRef,
    WorkspaceRehydrationReceipt,
    WorkspaceRehydrationRequest,
    WorkspaceStatus,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence import PostgresWorkspaceStore, WorkspaceConflict
from solvan.platform import (
    AntigravityProviderConfiguration,
    AntigravityWorkspaceProvider,
    GoogleIdentityTokenProvider,
)
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter


def select_rehydration_candidate(
    *, scope: Scope, connection: Connection[Any]
) -> WorkspaceRehydrationCandidate:
    """Select one exact hibernated public-synthetic checkpoint for qualification."""

    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT w.id AS workspace_id,
                CASE WHEN latest.event_kind = 'REHYDRATION'
                  THEN latest.parent_checkpoint_id ELSE latest.id END AS checkpoint_id,
                CASE WHEN latest.event_kind = 'REHYDRATION'
                  THEN parent.provider_service_revision
                  ELSE latest.provider_service_revision END AS provider_service_revision,
                (latest.event_kind = 'REHYDRATION') AS reconciliation_pending
              FROM solvan.workspaces w
              JOIN LATERAL (
                SELECT id, event_kind, parent_checkpoint_id, provider_service_revision
                FROM solvan.workspace_checkpoints c
                WHERE c.organization_id = w.organization_id
                  AND c.project_id = w.project_id
                  AND c.environment_id = w.environment_id
                  AND c.workspace_id = w.id
                  AND c.workspace_generation = w.generation
                ORDER BY c.sequence_no DESC LIMIT 1
              ) latest ON true
              LEFT JOIN solvan.workspace_checkpoints parent
                ON (parent.organization_id, parent.project_id, parent.environment_id,
                    parent.id)
                 = (w.organization_id, w.project_id, w.environment_id,
                    latest.parent_checkpoint_id)
              WHERE w.organization_id = %(organization_id)s
                AND w.project_id = %(project_id)s
                AND w.environment_id = %(environment_id)s
                AND w.provider = 'ANTIGRAVITY_SDK_CLOUD_RUN'
                AND w.classification = 'PUBLIC' AND w.synthetic = true
                AND ((w.status = 'HIBERNATED' AND latest.event_kind = 'CHECKPOINT')
                  OR (w.status = 'OPEN' AND latest.event_kind = 'REHYDRATION'
                    AND parent.id IS NOT NULL))
              ORDER BY w.updated_at, w.id LIMIT 2""",
            scope.canonical_dict(),
        )
        rows = cursor.fetchall()
    if len(rows) != 1:
        raise WorkspaceConflict("qualification requires exactly one hibernated candidate")
    return WorkspaceRehydrationCandidate.model_validate(rows[0])


def rehydrate_antigravity_workspace(
    *,
    settings: CoordinatorSettings,
    connection: Connection[Any],
    workspace_id: str,
    expected_checkpoint_id: str,
    reader: GcsEvidenceReader,
    writer: GcsEvidenceWriter,
    evidence_writer: GcsEvidenceWriter | None = None,
    provider_call: (
        Callable[[WorkspaceRehydrationRequest], WorkspaceRehydrationReceipt] | None
    ) = None,
) -> WorkspaceRehydrationReceipt:
    """Rehydrate one hibernated workspace through a fresh private provider process."""

    config = settings.antigravity
    if config is None:
        raise WorkspaceConflict("Antigravity provider is disabled")
    store = PostgresWorkspaceStore(connection)
    ref = store.load(scope=settings.scope, workspace_id=workspace_id)
    if ref.provider is not WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN:
        raise WorkspaceConflict("workspace is not an Antigravity workspace")
    if ref.status is WorkspaceStatus.OPEN:
        return _reconcile_completed_rehydration(
            settings=settings,
            store=store,
            connection=connection,
            ref=ref,
            expected_checkpoint_id=expected_checkpoint_id,
            reader=reader,
            evidence_writer=evidence_writer,
        )
    if ref.status is not WorkspaceStatus.HIBERNATED:
        raise WorkspaceConflict("workspace is not hibernated")
    checkpoint = store.latest_checkpoint(ref)
    if checkpoint.checkpoint_id != expected_checkpoint_id:
        raise WorkspaceConflict("workspace checkpoint changed before rehydration")
    manifest_value = reader.get_json(
        uri=checkpoint.artifact_manifest_ref,
        expected_hash=checkpoint.artifact_manifest_hash,
        max_bytes=1_048_576,
    )
    manifest = WorkspaceArtifactManifest.model_validate(manifest_value)
    request = WorkspaceRehydrationRequest.build(
        schema_version=1,
        request_id=new_identifier("req"),
        workspace_id=ref.workspace_id,
        workspace_generation=ref.generation,
        checkpoint_id=checkpoint.checkpoint_id,
        provider_revision=ref.provider_revision,
        implementation_sdk_distribution_hash=(checkpoint.implementation_sdk_distribution_hash),
        provider_artifact_digest=checkpoint.provider_artifact_digest,
        previous_provider_service_revision=checkpoint.provider_service_revision,
        previous_provider_boot_hash=checkpoint.provider_boot_hash,
        input_manifest_ref=checkpoint.input_manifest_ref,
        input_manifest_hash=checkpoint.input_manifest_hash,
        artifact_manifest_ref=checkpoint.artifact_manifest_ref,
        artifact_manifest_hash=checkpoint.artifact_manifest_hash,
        artifact_manifest=manifest,
        effective_tool_set_hash=checkpoint.effective_tool_set_hash,
        effective_network_policy_hash=checkpoint.effective_network_policy_hash,
        trace_id=secrets.token_hex(16),
        span_id=secrets.token_hex(8),
    )

    async def execute() -> WorkspaceRehydrationReceipt:
        async with httpx.AsyncClient() as client:
            provider = AntigravityWorkspaceProvider(
                config=AntigravityProviderConfiguration(
                    base_url=config.base_url,
                    audience=config.audience,
                    provider_revision=config.provider_revision,
                    implementation_sdk_distribution_hash=SDK_DISTRIBUTION_HASH,
                    provider_artifact_digest=config.provider_artifact_digest,
                    effective_tool_set_hash=config.effective_tool_set_hash,
                    effective_network_policy_hash=config.effective_network_policy_hash,
                    artifact_bucket=settings.runtime_bucket,
                ),
                client=client,
                token_provider=GoogleIdentityTokenProvider(),
                object_writer=writer,
            )
            return await provider.rehydrate(request)

    receipt = provider_call(request) if provider_call is not None else asyncio.run(execute())
    receipt.assert_matches(request)
    rehydration_object = writer.put_json(
        object_name=_rehydration_receipt_object(
            settings, ref.workspace_id, receipt.provider_service_revision
        ),
        value=receipt.model_dump(mode="json"),
    )
    store.resume(
        checkpoint,
        WorkspaceCheckpointMaterial(
            provider_request_hash=request.request_hash,
            provider_receipt_ref=rehydration_object.uri,
            provider_receipt_hash=rehydration_object.content_hash,
            provider_boot_hash=receipt.provider_boot_hash,
            provider_service_revision=receipt.provider_service_revision,
            artifact_manifest_ref=receipt.artifact_manifest_ref,
            artifact_manifest_hash=receipt.artifact_manifest_hash,
            effective_tool_set_hash=receipt.effective_tool_set_hash,
            effective_network_policy_hash=receipt.effective_network_policy_hash,
            created_by_principal=settings.coordinator_principal,
        ),
    )
    if evidence_writer is not None:
        _write_qualification_receipt(
            settings=settings,
            connection=connection,
            checkpoint=checkpoint,
            receipt=receipt,
            rehydration_receipt_ref=rehydration_object.uri,
            writer=evidence_writer,
        )
    return receipt


def _reconcile_completed_rehydration(
    *,
    settings: CoordinatorSettings,
    store: PostgresWorkspaceStore,
    connection: Connection[Any],
    ref: WorkspaceRef,
    expected_checkpoint_id: str,
    reader: GcsEvidenceReader,
    evidence_writer: GcsEvidenceWriter | None,
) -> WorkspaceRehydrationReceipt:
    latest = store.latest_checkpoint(ref)
    if latest.event_kind != "REHYDRATION" or latest.parent_checkpoint_id != expected_checkpoint_id:
        raise WorkspaceConflict("open workspace has no matching rehydration to reconcile")
    checkpoint = store.checkpoint_by_id(ref, expected_checkpoint_id)
    value = reader.get_json(
        uri=latest.provider_receipt_ref,
        expected_hash=latest.provider_receipt_hash,
        max_bytes=262_144,
    )
    receipt = WorkspaceRehydrationReceipt.model_validate(value)
    if (
        receipt.workspace_id != latest.workspace_id
        or receipt.workspace_generation != latest.workspace_generation
        or receipt.checkpoint_id != checkpoint.checkpoint_id
        or receipt.request_hash != latest.provider_request_hash
        or receipt.provider_service_revision != latest.provider_service_revision
        or receipt.provider_boot_hash != latest.provider_boot_hash
        or receipt.implementation_sdk_distribution_hash
        != latest.implementation_sdk_distribution_hash
        or receipt.provider_artifact_digest != latest.provider_artifact_digest
        or receipt.input_manifest_hash != latest.input_manifest_hash
        or receipt.artifact_manifest_hash != latest.artifact_manifest_hash
        or receipt.effective_tool_set_hash != latest.effective_tool_set_hash
        or receipt.effective_network_policy_hash != latest.effective_network_policy_hash
    ):
        raise WorkspaceConflict("persisted rehydration receipt does not match lineage")
    if evidence_writer is not None:
        _write_qualification_receipt(
            settings=settings,
            connection=connection,
            checkpoint=checkpoint,
            receipt=receipt,
            rehydration_receipt_ref=latest.provider_receipt_ref,
            writer=evidence_writer,
        )
    return receipt


def _write_qualification_receipt(
    *,
    settings: CoordinatorSettings,
    connection: Connection[Any],
    checkpoint: WorkspaceCheckpoint,
    receipt: WorkspaceRehydrationReceipt,
    rehydration_receipt_ref: str,
    writer: GcsEvidenceWriter,
) -> None:
    config = settings.antigravity
    assert config is not None
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT w.synthetic_attestation_ref, w.synthetic_attestation_hash,
                allow_decision.reason_code AS allow_reason,
                allow_decision.receipt_ref AS allow_receipt_ref,
                deny_decision.reason_code AS deny_reason,
                deny_decision.receipt_ref AS deny_receipt_ref
              FROM solvan.workspaces w
              JOIN solvan.policy_decisions allow_decision
                ON (allow_decision.organization_id, allow_decision.project_id,
                    allow_decision.environment_id, allow_decision.id)
                 = (w.organization_id, w.project_id, w.environment_id,
                    w.provider_eligibility_decision_id)
              LEFT JOIN LATERAL (
                SELECT reason_code, receipt_ref FROM solvan.policy_decisions p
                WHERE p.organization_id = w.organization_id
                  AND p.project_id = w.project_id
                  AND p.environment_id = w.environment_id
                  AND p.policy_kind = 'PROVIDER_ELIGIBILITY'
                  AND p.decision = 'DENY'
                  AND p.input_ref = allow_decision.input_ref
                  AND p.reason_code LIKE '%%CLASSIFICATION_NOT_PUBLIC%%'
                ORDER BY p.decided_at DESC LIMIT 1
              ) deny_decision ON true
              WHERE w.organization_id = %(organization_id)s
                AND w.project_id = %(project_id)s
                AND w.environment_id = %(environment_id)s
                AND w.id = %(workspace_id)s""",
            {
                **settings.scope.canonical_dict(),
                "workspace_id": checkpoint.workspace_id,
            },
        )
        evidence = cursor.fetchone()
    if evidence is None:
        raise WorkspaceConflict("workspace qualification evidence disappeared")
    attested = (
        evidence["synthetic_attestation_ref"] is not None
        and evidence["synthetic_attestation_hash"] is not None
        and "PUBLIC_SYNTHETIC_ATTESTED_POLICY_MATCH" in str(evidence["allow_reason"])
    )
    nonpublic_denied = evidence[
        "deny_receipt_ref"
    ] is not None and "CLASSIFICATION_NOT_PUBLIC" in str(evidence["deny_reason"])
    continuity = (
        checkpoint.provider_service_revision != receipt.provider_service_revision
        and checkpoint.provider_boot_hash != receipt.provider_boot_hash
        and checkpoint.implementation_sdk_distribution_hash
        == receipt.implementation_sdk_distribution_hash
        and checkpoint.provider_artifact_digest == receipt.provider_artifact_digest
        and checkpoint.input_manifest_hash == receipt.input_manifest_hash
        and checkpoint.artifact_manifest_hash == receipt.artifact_manifest_hash
        and checkpoint.effective_tool_set_hash == receipt.effective_tool_set_hash
        and checkpoint.effective_network_policy_hash == receipt.effective_network_policy_hash
    )
    evidence_refs = [
        str(evidence["allow_receipt_ref"]),
        str(evidence["deny_receipt_ref"]),
        str(evidence["synthetic_attestation_ref"]),
        checkpoint.artifact_manifest_ref,
        rehydration_receipt_ref,
    ]
    writer.put_json(
        object_name=(f"preflight/{config.deployment_id}/antigravity-qualification.json"),
        value={
            "schema_version": 1,
            "kind": "ANTIGRAVITY_QUALIFICATION",
            "project_id": settings.gcp_project_id,
            "release_commit": config.release_commit,
            "deployment_id": config.deployment_id,
            "provider_revision": config.provider_revision,
            "provider_service_revision_before": checkpoint.provider_service_revision,
            "provider_service_revision_after": receipt.provider_service_revision,
            "provider_boot_hash_before": checkpoint.provider_boot_hash,
            "provider_boot_hash_after": receipt.provider_boot_hash,
            "implementation_sdk_distribution_hash_before": (
                checkpoint.implementation_sdk_distribution_hash
            ),
            "implementation_sdk_distribution_hash_after": (
                receipt.implementation_sdk_distribution_hash
            ),
            "provider_artifact_digest_before": checkpoint.provider_artifact_digest,
            "provider_artifact_digest_after": receipt.provider_artifact_digest,
            "input_manifest_hash_before": checkpoint.input_manifest_hash,
            "input_manifest_hash_after": receipt.input_manifest_hash,
            "artifact_manifest_hash_before": checkpoint.artifact_manifest_hash,
            "artifact_manifest_hash_after": receipt.artifact_manifest_hash,
            "effective_tool_set_hash_before": checkpoint.effective_tool_set_hash,
            "effective_tool_set_hash_after": receipt.effective_tool_set_hash,
            "effective_network_policy_hash_before": (checkpoint.effective_network_policy_hash),
            "effective_network_policy_hash_after": (receipt.effective_network_policy_hash),
            "proofs": {
                "antigravity_fixture_attestation_verified": attested,
                "antigravity_public_synthetic_allowed": attested,
                "antigravity_nonpublic_denied": nonpublic_denied,
                "antigravity_checkpoint_rehydrated_new_boot": continuity,
                "antigravity_revision_continuity_preserved": continuity,
            },
            "evidence_refs": evidence_refs,
        },
    )


def _rehydration_receipt_object(
    settings: CoordinatorSettings, workspace_id: str, service_revision: str
) -> str:
    if not service_revision or "/" in service_revision or ".." in service_revision:
        raise ValueError("provider service revision is unsafe for an evidence path")
    return (
        f"{settings.scope.organization_id}/{settings.scope.project_id}/"
        f"{settings.scope.environment_id}/workspaces/{workspace_id}/rehydrations/"
        f"{service_revision}/receipt.json"
    )
