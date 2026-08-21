"""Provider-neutral isolated adjudication of Workspace Agent repair proposals."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from solvan.application import (
    CaseSchedule,
    WorkspaceArtifactManifest,
    WorkspaceCheckpointMaterial,
    WorkspaceCognitionArtifact,
    WorkspaceManifestEntry,
    WorkspaceModelProposal,
    WorkspaceProviderKind,
    WorkspaceTaskKind,
    WorkspaceTaskResult,
)
from solvan.application.workspace_candidate import (
    CandidateFile,
    CandidateTree,
    candidate_tree_from_manifest,
    derive_unified_diff,
)
from solvan.persistence import (
    AggregateType,
    PostgresReliabilityCaseStore,
    PostgresRepairStore,
    PostgresWorkflowStore,
    PostgresWorkspaceStore,
    TransitionWrite,
)
from solvan.persistence.code_change_qualification_store import (
    PatchAdjudicationMaterial,
    PostgresCodeChangeQualificationStore,
)
from solvan.persistence.workspace_repair_store import PostgresWorkspaceRepairStore
from solvan.platform.antigravity_workspace import GoogleIdentityTokenProvider
from solvan.platform.cloud_run_sandbox import (
    CloudRunSandboxConfiguration,
    CloudRunSandboxExecutor,
)
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.repository_snapshot import parse_repository_snapshot
from solvan.platform.workspace_validation import WorkspacePatchValidator


@dataclass(frozen=True, slots=True)
class WorkspaceAdjudicationRun:
    run_id: str
    reliability_case_id: str
    workflow_version: int
    provider_output_hash: str
    provider_boot_hash: str
    provider_service_revision: str


def poll_antigravity_workspace_results(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
) -> None:
    store = PostgresWorkspaceStore(connection)
    with workflow.transaction():
        pending_results = store.pending_antigravity_results(scope=settings.scope)
    for pending in pending_results:
        run = WorkspaceAdjudicationRun(
            run_id=pending.run_id,
            reliability_case_id=pending.reliability_case_id,
            workflow_version=pending.workflow_version,
            provider_output_hash=pending.output_hash,
            provider_boot_hash=pending.provider_boot_hash,
            provider_service_revision=pending.provider_service_revision,
        )
        try:
            value = reader.get_json(
                uri=pending.output_ref,
                expected_hash=pending.output_hash,
                max_bytes=2_000_000,
            )
            result = WorkspaceTaskResult.model_validate(
                {**value, "output_hash": pending.output_hash}
            )
            store.assert_pending_result_matches(pending, result)
            if (
                result.provider is not WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN
                or result.task_kind is not WorkspaceTaskKind.REPAIR
            ):
                raise ValueError("pending provider result has the wrong task boundary")
            proposal = WorkspaceModelProposal(
                terminal_status=result.terminal_status,
                summary=result.summary,
                mechanism=result.mechanism,
                base_commit_sha=result.base_commit_sha,
                unified_diff=result.unified_diff,
                reproduction_command=result.reproduction_command,
                test_command=result.test_command,
                hypotheses=result.hypotheses,
                candidate_artifact_paths=tuple(item.path for item in result.artifacts),
                citations=result.citations,
                residual_risks=result.residual_risks,
            )
        except Exception as error:
            store.record_pending_result_security_event(
                scope=settings.scope,
                pending=pending,
                event_type="WORKSPACE_PERSISTED_RESULT_REJECTED",
                safe_summary=f"Persisted provider result failed validation: {type(error).__name__}",
            )
            block_workspace_failure(
                settings=settings,
                owner=owner,
                workflow=workflow,
                connection=connection,
                run=run,
                error_class=type(error).__name__,
            )
            continue
        adjudicate_workspace_proposal(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
            reader=reader,
            run=run,
            output=proposal,
        )


def block_workspace_failure(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
    run: WorkspaceAdjudicationRun,
    error_class: str,
) -> None:
    with workflow.transaction():
        lease = workflow.acquire_lease(
            scope=settings.scope,
            aggregate_type=AggregateType.RELIABILITY_CASE,
            entity_id=run.reliability_case_id,
            owner=owner,
            lease_ttl_ms=60_000,
        )
    if lease is None:
        return
    try:
        if lease.workflow_version != run.workflow_version:
            return
        _block_workspace_attempt(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
            run=run,
            cases=PostgresReliabilityCaseStore(connection),
            lease=lease,
            error_class=error_class,
        )
    finally:
        with workflow.transaction():
            workflow.release_lease(scope=settings.scope, lease=lease)


def adjudicate_workspace_proposal(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
    run: WorkspaceAdjudicationRun,
    output: WorkspaceModelProposal,
) -> None:
    with workflow.transaction():
        lease = workflow.acquire_lease(
            scope=settings.scope,
            aggregate_type=AggregateType.RELIABILITY_CASE,
            entity_id=run.reliability_case_id,
            owner=owner,
            lease_ttl_ms=360_000,
        )
    if lease is None:
        return
    if lease.workflow_version != run.workflow_version:
        with workflow.transaction():
            workflow.release_lease(scope=settings.scope, lease=lease)
        return
    cases = PostgresReliabilityCaseStore(connection)
    repairs = PostgresRepairStore(connection)
    try:
        try:
            with workflow.transaction():
                material = repairs.workspace_attempt(
                    scope=settings.scope, lease=lease, run_id=run.run_id
                )
            plan = material.repair_plan
            if output.terminal_status.value != "SUCCEEDED":
                raise ValueError("Workspace Agent reported insufficient evidence")
            if output.base_commit_sha != plan.base_commit_sha:
                raise ValueError("Workspace Agent changed the repair plan base commit")
            if output.test_command != plan.test_command:
                raise ValueError("Workspace Agent changed the exact test command")
            snapshot_value = reader.get_json(
                uri=plan.repository_snapshot_uri,
                expected_hash=plan.repository_snapshot_hash,
                max_bytes=800_000,
            )
            snapshot = parse_repository_snapshot(
                snapshot_value,
                expected_commit_sha=plan.base_commit_sha,
                allowed_file_globs=plan.allowed_file_globs,
            )
            generation = None
            command_definitions_hash = None
            if plan.provider == WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE.value:
                if (
                    output.unified_diff is not None
                    or output.candidate_generation_id is None
                    or output.candidate_tree_hash is None
                ):
                    raise ValueError(
                        "production Workspace output must name only its candidate generation"
                    )
                generation = PostgresWorkspaceRepairStore(connection).load_candidate_generation(
                    scope=settings.scope,
                    agent_run_id=run.run_id,
                    generation_id=output.candidate_generation_id,
                    candidate_tree_hash=output.candidate_tree_hash,
                )
                candidate_value = reader.get_json(
                    uri=generation.manifest_ref,
                    expected_hash=generation.manifest_hash,
                    max_bytes=1_200_000,
                )
                candidate_tree = candidate_tree_from_manifest(
                    candidate_value, allowed_file_globs=plan.allowed_file_globs
                )
                base_tree = CandidateTree(
                    tuple(CandidateFile(item.path, item.content) for item in snapshot.files),
                    plan.allowed_file_globs,
                )
                if (
                    base_tree.tree_hash != generation.base_tree_hash
                    or candidate_tree.tree_hash != generation.candidate_tree_hash
                ):
                    raise ValueError("candidate generation does not derive from the frozen base")
                command_definitions_hash = PostgresWorkspaceRepairStore(
                    connection
                ).load_command_definitions_hash(
                    scope=settings.scope,
                    repair_plan_id=plan.repair_plan_id,
                    repair_plan_version=plan.plan_version,
                )
                adjudication_diff = derive_unified_diff(base=base_tree, candidate=candidate_tree)
            else:
                if output.unified_diff is None or output.candidate_generation_id is not None:
                    raise ValueError("synthetic Workspace output has the wrong patch material")
                adjudication_diff = output.unified_diff
            with httpx.Client() as sandbox_client:
                sandbox = CloudRunSandboxExecutor(
                    config=CloudRunSandboxConfiguration(
                        base_url=settings.workspace_sandbox.base_url,
                        audience=settings.workspace_sandbox.audience,
                        region=settings.gcp_region,
                        max_request_bytes=2_000_000,
                        max_response_bytes=2_000_000,
                        execution_timeout_seconds=300,
                    ),
                    client=sandbox_client,
                    token_provider=GoogleIdentityTokenProvider(),
                )
                receipt = WorkspacePatchValidator(sandbox).execute(
                    case_id=run.reliability_case_id,
                    snapshot=snapshot,
                    unified_diff=adjudication_diff,
                    reproduction_command=plan.reproduction_command,
                    test_command=plan.test_command,
                    allowed_file_globs=plan.allowed_file_globs,
                )
            writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=authorized_session())
            prefix = (
                f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                f"{settings.scope.environment_id}/repairs/{run.reliability_case_id}/"
                f"{run.run_id}"
            )
            patch_receipt = writer.put_bytes(
                object_name=f"{prefix}/repair.patch",
                content=receipt.unified_diff,
                content_type="text/x-diff",
            )
            cognition = WorkspaceCognitionArtifact(
                trust_class="PROPOSED",
                workspace_id=material.workspace_id,
                workspace_generation=material.workspace_generation,
                agent_run_id=run.run_id,
                confirmed_fast_lane_cause_id=plan.confirmed_root_cause_id,
                mechanism=output.mechanism or "",
                hypotheses=output.hypotheses,
                reproduction_command=plan.reproduction_command,
                citations=tuple(
                    dict.fromkeys(
                        (
                            *output.citations,
                            *(
                                citation
                                for hypothesis in output.hypotheses
                                for citation in (
                                    *hypothesis.supporting_citations,
                                    *hypothesis.contradicting_citations,
                                )
                            ),
                        )
                    )
                ),
            )
            cognition_value = cognition.model_dump(mode="json")
            cognition_bytes = json.dumps(
                cognition_value, sort_keys=True, separators=(",", ":")
            ).encode()
            cognition_receipt = writer.put_json(
                object_name=f"{prefix}/cognition.json",
                value=cognition_value,
            )
            reproduction_output = receipt.reproduction_output or b"(no reproduction output)\n"
            reproduction_receipt = writer.put_bytes(
                object_name=f"{prefix}/reproduction-output.txt",
                content=reproduction_output,
                content_type="text/plain; charset=utf-8",
            )
            test_output = receipt.test_output or b"(no test output)\n"
            test_receipt = writer.put_bytes(
                object_name=f"{prefix}/test-output.txt",
                content=test_output,
                content_type="text/plain; charset=utf-8",
            )
            adjudication_receipt = None
            if (
                generation is not None
                and command_definitions_hash is not None
                and receipt.reproduction_exit_code != 0
                and receipt.test_exit_code == 0
            ):
                adjudication_value = {
                    "schema_version": 1,
                    "run_kind": "ADJUDICATION",
                    "agent_run_id": run.run_id,
                    "candidate_generation_id": generation.generation_id,
                    "base_tree_hash": generation.base_tree_hash,
                    "candidate_tree_hash": generation.candidate_tree_hash,
                    "command_definitions_hash": command_definitions_hash,
                    "sandbox_resource": receipt.sandbox_resource,
                    "sandbox_image_hash": settings.workspace_sandbox.image_hash,
                    "sandbox_service_revision": settings.workspace_sandbox.service_revision,
                    "reproduction_exit_code": receipt.reproduction_exit_code,
                    "test_exit_code": receipt.test_exit_code,
                    "patch_hash": patch_receipt.content_hash,
                    "reproduction_output_hash": reproduction_receipt.content_hash,
                    "test_output_hash": test_receipt.content_hash,
                }
                adjudication_receipt = writer.put_json(
                    object_name=f"{prefix}/adjudication-receipt.json",
                    value=adjudication_value,
                )
            workspace_store = PostgresWorkspaceStore(connection)
            workspace_ref = workspace_store.load(
                scope=settings.scope, workspace_id=material.workspace_id
            )
            lineage = workspace_store.next_manifest_lineage(workspace_ref)
            principal = settings.coordinator_principal
            checkpoint_manifest = WorkspaceArtifactManifest(
                manifest_kind="CHECKPOINT",
                workspace_id=workspace_ref.workspace_id,
                workspace_generation=workspace_ref.generation,
                checkpoint_sequence=lineage.sequence_no,
                parent_manifest_ref=lineage.parent_manifest_ref,
                parent_manifest_hash=lineage.parent_manifest_hash,
                classification=workspace_ref.classification,
                synthetic=workspace_ref.synthetic,
                entries=(
                    WorkspaceManifestEntry(
                        path="repair/cognition.json",
                        object_ref=cognition_receipt.uri,
                        content_hash=cognition_receipt.content_hash,
                        size_bytes=len(cognition_bytes),
                        media_type="application/json",
                        provenance_refs=(material.provider_output_ref, plan.content_hash),
                    ),
                    WorkspaceManifestEntry(
                        path="repair/repair.patch",
                        object_ref=patch_receipt.uri,
                        content_hash=patch_receipt.content_hash,
                        size_bytes=len(receipt.unified_diff),
                        media_type="text/x-diff",
                        provenance_refs=(material.provider_output_ref, plan.content_hash),
                    ),
                    WorkspaceManifestEntry(
                        path="repair/reproduction-output.txt",
                        object_ref=reproduction_receipt.uri,
                        content_hash=reproduction_receipt.content_hash,
                        size_bytes=len(reproduction_output),
                        media_type="text/plain; charset=utf-8",
                        provenance_refs=(
                            cognition_receipt.uri,
                            plan.repository_snapshot_hash,
                        ),
                    ),
                    WorkspaceManifestEntry(
                        path="repair/test-output.txt",
                        object_ref=test_receipt.uri,
                        content_hash=test_receipt.content_hash,
                        size_bytes=len(test_output),
                        media_type="text/plain; charset=utf-8",
                        provenance_refs=(patch_receipt.uri, plan.content_hash),
                    ),
                ),
                created_by=principal,
                created_at=datetime.now(UTC),
            )
            manifest_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/workspaces/"
                    f"{workspace_ref.workspace_id}/checkpoints/"
                    f"{lineage.sequence_no}/manifest.json"
                ),
                value=checkpoint_manifest.model_dump(mode="json"),
            )
            with workflow.transaction():
                artifact_id = repairs.persist_patch_artifact(
                    scope=settings.scope,
                    lease=lease,
                    material=material,
                    sandbox_resource=receipt.sandbox_resource,
                    unified_diff_ref=patch_receipt.uri,
                    unified_diff_hash=patch_receipt.content_hash,
                    changed_paths=receipt.changed_paths,
                    cognition_ref=cognition_receipt.uri,
                    cognition_hash=cognition_receipt.content_hash,
                    mechanism=cognition.mechanism,
                    hypotheses=tuple(item.model_dump(mode="json") for item in output.hypotheses),
                    reproduction_exit_code=receipt.reproduction_exit_code,
                    reproduction_output_ref=reproduction_receipt.uri,
                    reproduction_output_hash=reproduction_receipt.content_hash,
                    test_exit_code=receipt.test_exit_code,
                    test_output_ref=test_receipt.uri,
                    test_output_hash=test_receipt.content_hash,
                    residual_risks=output.residual_risks,
                    provider_output_hash=run.provider_output_hash,
                    provider_boot_hash=run.provider_boot_hash,
                    provider_service_revision=run.provider_service_revision,
                )
                if adjudication_receipt is not None and generation is not None:
                    if command_definitions_hash is None:
                        raise RuntimeError("adjudication command definitions were not frozen")
                    PostgresCodeChangeQualificationStore(connection).record_patch_adjudication(
                        scope=settings.scope,
                        patch_artifact_id=artifact_id,
                        material=PatchAdjudicationMaterial(
                            candidate_generation_id=generation.generation_id,
                            base_tree_hash=generation.base_tree_hash,
                            candidate_tree_hash=generation.candidate_tree_hash,
                            command_definitions_hash=command_definitions_hash,
                            sandbox_resource=receipt.sandbox_resource,
                            sandbox_image_hash=settings.workspace_sandbox.image_hash,
                            reproduction_exit_code=receipt.reproduction_exit_code,
                            test_exit_code=receipt.test_exit_code,
                            coordinator_service_revision=(settings.coordinator_service_revision),
                        ),
                        receipt=adjudication_receipt,
                    )
                workspace_store.checkpoint(
                    workspace_ref,
                    WorkspaceCheckpointMaterial(
                        provider_request_hash=material.provider_request_hash,
                        provider_receipt_ref=material.provider_output_ref,
                        provider_receipt_hash=run.provider_output_hash,
                        provider_boot_hash=run.provider_boot_hash,
                        provider_service_revision=run.provider_service_revision,
                        artifact_manifest_ref=manifest_receipt.uri,
                        artifact_manifest_hash=manifest_receipt.content_hash,
                        effective_tool_set_hash=material.effective_tool_set_hash,
                        effective_network_policy_hash=(material.effective_network_policy_hash),
                        created_by_principal=principal,
                    ),
                    hibernate=True,
                )
                cases.complete_active_wakeup_for_transition(scope=settings.scope, lease=lease)
                _commit_patch_outcome(
                    settings=settings,
                    owner=owner,
                    cases=cases,
                    lease=lease,
                    case_id=run.reliability_case_id,
                    artifact_id=artifact_id,
                    reproduction_exit_code=receipt.reproduction_exit_code,
                    test_exit_code=receipt.test_exit_code,
                    cognition_ref=cognition_receipt.uri,
                    reproduction_ref=reproduction_receipt.uri,
                    patch_ref=patch_receipt.uri,
                    test_ref=test_receipt.uri,
                )
        except Exception as error:
            _block_workspace_attempt(
                settings=settings,
                owner=owner,
                workflow=workflow,
                connection=connection,
                run=run,
                cases=cases,
                lease=lease,
                error_class=type(error).__name__,
            )
    finally:
        with workflow.transaction():
            workflow.release_lease(scope=settings.scope, lease=lease)


def _commit_patch_outcome(
    *,
    settings: CoordinatorSettings,
    owner: str,
    cases: PostgresReliabilityCaseStore,
    lease: Any,
    case_id: str,
    artifact_id: str,
    reproduction_exit_code: int,
    test_exit_code: int,
    cognition_ref: str,
    reproduction_ref: str,
    patch_ref: str,
    test_ref: str,
) -> None:
    if reproduction_exit_code != 0 and test_exit_code == 0:
        cases.commit_progress_transition(
            scope=settings.scope,
            lease=lease,
            transition=TransitionWrite(
                from_state="REPAIR_IN_PROGRESS",
                to_state="AWAITING_REVIEW",
                transition_key=f"PATCH_READY:{artifact_id}",
                actor_type="COORDINATOR",
                actor_id=owner,
                reason_code="REPRODUCTION_PATCH_AND_TEST_RECEIPTS_PRESENT",
                rationale_summary=(
                    "The baseline reproduced the failure and the exact regression test "
                    "passed after the patch inside the regional Cloud Run Sandbox."
                ),
                evidence_refs=(cognition_ref, reproduction_ref, patch_ref, test_ref),
            ),
            schedule=CaseSchedule(
                logical_step_key=f"case:{case_id}:review-patch:5",
                next_action_kind="REVIEW_PATCH",
                wake_at=datetime.now(UTC),
                reason="An authenticated human must review the exact patch.",
            ),
        )
        return
    review_at = datetime.now(UTC) + timedelta(hours=1)
    cases.commit_progress_transition(
        scope=settings.scope,
        lease=lease,
        transition=TransitionWrite(
            from_state="REPAIR_IN_PROGRESS",
            to_state="BLOCKED",
            transition_key=f"PROVIDER_BLOCKED:{artifact_id}",
            actor_type="COORDINATOR",
            actor_id=owner,
            reason_code=(
                "BASELINE_REPRODUCTION_FAILED"
                if reproduction_exit_code == 0
                else "PATCH_TEST_FAILED"
            ),
            rationale_summary=(
                "The baseline did not prove the failure or the exact patched test failed; "
                "no review, merge, or deployment authority was granted."
            ),
            evidence_refs=(reproduction_ref, test_ref),
        ),
        schedule=CaseSchedule(
            logical_step_key=f"case:{case_id}:failed-test-review",
            next_action_kind="REVIEW_FAILED_PATCH",
            wake_at=review_at,
            reason="Application Engineering must review the failed test.",
        ),
        blocked_owner="application-engineering",
        next_review_at=review_at,
        recovery_plan=(
            "Review the sandbox test receipt and explicitly create a new bounded repair-plan "
            "version before retrying."
        ),
    )


def _block_workspace_attempt(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
    run: WorkspaceAdjudicationRun,
    cases: PostgresReliabilityCaseStore,
    lease: Any,
    error_class: str,
) -> None:
    review_at = datetime.now(UTC) + timedelta(hours=1)
    with workflow.transaction():
        PostgresWorkspaceStore(connection).fail_run_result(
            scope=settings.scope,
            run_id=run.run_id,
            workflow_version=run.workflow_version,
            error_class=error_class,
        )
        cases.complete_active_wakeup_for_transition(scope=settings.scope, lease=lease)
        cases.commit_progress_transition(
            scope=settings.scope,
            lease=lease,
            transition=TransitionWrite(
                from_state="REPAIR_IN_PROGRESS",
                to_state="BLOCKED",
                transition_key=f"PROVIDER_BLOCKED:{run.run_id}",
                actor_type="COORDINATOR",
                actor_id=owner,
                reason_code=error_class[:128],
                rationale_summary=(
                    "Workspace or isolated test authority failed closed; untrusted "
                    "repository code was not executed in Cloud Run."
                ),
            ),
            schedule=CaseSchedule(
                logical_step_key=f"case:{run.reliability_case_id}:workspace-provider-review",
                next_action_kind="RECHECK_WORKSPACE_PROVIDER",
                wake_at=review_at,
                reason="Recheck workspace provider and Agent Engine sandbox availability.",
            ),
            blocked_owner="application-engineering",
            next_review_at=review_at,
            recovery_plan=(
                "Restore the exact Workspace Agent provider or europe-west1 Agent Engine "
                "Cloud Run Sandbox preflight, then create a new bounded attempt."
            ),
        )
