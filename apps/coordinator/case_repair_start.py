"""Start one exact repair plan as a reserved, fenced Workspace Agent attempt."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from psycopg import Connection

from apps.coordinator.antigravity_tasks import (
    dispatch_antigravity_repair,
    ensure_antigravity_incident_workspace,
)
from apps.coordinator.contracts import CoordinatorSettings, _runtime
from apps.coordinator.tool_binding import PostgresAgentRunBinder
from apps.coordinator.workspace_tasks import ensure_adk_incident_workspace
from solvan.application import (
    CaseSchedule,
    ClaimedWakeup,
    RepairPlanningError,
    WorkspaceProviderKind,
    sha256_bytes,
)
from solvan.application.workspace_candidate import CandidateFile, CandidateTree
from solvan.persistence import (
    LeaseHandle,
    PostgresReliabilityCaseStore,
    PostgresRepairStore,
    PostgresRuntimeRunStore,
    PostgresWorkspaceRepairStore,
    PostgresWorkspaceStore,
    TransitionWrite,
    WorkspaceConflict,
)
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.repository_snapshot import parse_repository_snapshot

ROOT = Path(__file__).resolve().parents[2]

# Starting a repair reads an 800 KB repository snapshot, writes a workspace
# input manifest, calls the provider attester, and reserves the Workspace Agent
# attempt. A one-minute lease expires mid-step and the durable commit at the
# end is then refused by the lease predicate, stranding everything the step
# already did. The Antigravity adjudication path already sizes its lease this
# way for a comparable run.
START_REPAIR_LEASE_MS = 360_000

# Faults that cannot be cured by retrying the same claim: the pinned repository
# snapshot does not match its recorded digest or policy, the exact repair plan
# or its provenance is absent, or the workspace provider refuses this case.
# These become one owned BLOCKED review, exactly like the RCA and replan steps,
# instead of re-aborting the coordinator tick on every wakeup.
PERMANENT_REPAIR_FAILURES = (RepairPlanningError, WorkspaceConflict, ValueError)


def start_planned_repair(
    *,
    settings: CoordinatorSettings,
    owner: str,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
    store: PostgresReliabilityCaseStore,
    claim: ClaimedWakeup,
    lease: LeaseHandle,
) -> None:
    """Turn one exact repair plan into one reserved Workspace Agent attempt.

    Every fault this raises is classified by the caller: a permanent one
    becomes an owned BLOCKED review, and anything else leaves the claim to its
    bounded budget. Nothing here is allowed to abort the surrounding tick.
    """

    repair_store = PostgresRepairStore(connection)
    with store.transaction():
        plan = repair_store.load_active_plan(
            scope=settings.scope,
            lease=lease,
            required_state="REPAIR_PLANNED",
        )
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
    writer = GcsEvidenceWriter(
        bucket=settings.runtime_bucket,
        session=authorized_session(),
    )
    use_antigravity = plan.provider == WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN.value
    guidance_files: list[dict[str, str]] = []
    guidance_selection = None
    command_catalog = None
    if not use_antigravity:
        guidance_store = PostgresWorkspaceRepairStore(connection)
        base_tree = CandidateTree(
            tuple(CandidateFile(item.path, item.content) for item in snapshot.files),
            plan.allowed_file_globs,
        )
        command_catalog = guidance_store.materialize_command_catalog(
            scope=settings.scope,
            repair_plan_id=plan.repair_plan_id,
            repair_plan_version=plan.plan_version,
            repository_node_id=plan.repository_node_id,
            base_tree=base_tree,
        )
        guidance_selection = guidance_store.prepare_base_guidance(
            scope=settings.scope,
            repair_plan_id=plan.repair_plan_id,
            repair_plan_version=plan.plan_version,
            runtime_region=settings.gcp_region,
            selected_by_identity=settings.coordinator_principal,
        )
        guidance_path = (ROOT / guidance_selection.content_ref).resolve()
        guidance_root = (ROOT / "guidance").resolve()
        if guidance_root not in guidance_path.parents or not guidance_path.is_file():
            raise WorkspaceConflict("selected first-party guidance path is unavailable")
        guidance_content = guidance_path.read_text(encoding="utf-8")
        if sha256_bytes(guidance_content.encode("utf-8")) != guidance_selection.content_hash:
            raise WorkspaceConflict("selected first-party guidance content drifted")
        guidance_receipt = writer.put_bytes(
            object_name=(
                f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                f"{settings.scope.environment_id}/repair-plans/{plan.repair_plan_id}/"
                f"guidance/{guidance_selection.guidance_key}@"
                f"{guidance_selection.guidance_version}.md"
            ),
            content=guidance_content.encode("utf-8"),
            content_type="text/markdown; charset=utf-8",
        )
        guidance_files.append(
            {
                "path": "guidance/reliability.code-repair/SKILL.md",
                "content": guidance_content,
                "content_hash": guidance_receipt.content_hash,
                "object_ref": guidance_receipt.uri,
                "provenance_ref": guidance_selection.selection_set_hash,
            }
        )
    prepared = (
        ensure_antigravity_incident_workspace(
            settings=settings,
            connection=connection,
            plan=plan,
            repository_files=snapshot.prompt_payload(),
            writer=writer,
        )
        if use_antigravity
        else ensure_adk_incident_workspace(
            settings=settings,
            connection=connection,
            plan=plan,
            repository_files=snapshot.prompt_payload(),
            guidance_files=guidance_files,
            writer=writer,
        )
    )
    provider_resource = (
        settings.antigravity.base_url
        if use_antigravity and settings.antigravity is not None
        else settings.workspace_agent_resource
    )
    provider_revision = (
        settings.antigravity.provider_revision
        if use_antigravity and settings.antigravity is not None
        else settings.workspace_agent_revision
    )
    with store.transaction():
        dispatch = PostgresRuntimeRunStore(connection).reserve_workspace_repair(
            scope=settings.scope,
            lease=lease,
            plan=plan,
            workspace=prepared.ref,
            repository_files=snapshot.prompt_payload(),
            guidance_files=guidance_files,
            agent_resource=provider_resource,
            agent_revision=provider_revision,
            effective_tool_set_hash=prepared.effective_tool_set_hash,
            effective_tool_set=prepared.effective_tool_set,
            effective_network_policy_hash=(prepared.effective_network_policy_hash),
            command_catalog_ids=(
                None
                if command_catalog is None
                else (
                    command_catalog.reproduction_command_id,
                    command_catalog.regression_command_id,
                )
            ),
            command_catalog_hash=(
                None if command_catalog is None else command_catalog.catalog_hash
            ),
        )
        if dispatch is None:
            raise RepairPlanningError("the exact repair plan already has an active Workspace Agent")
        if guidance_selection is not None:
            PostgresWorkspaceRepairStore(connection).bind_guidance_selection(
                scope=settings.scope,
                selection_set_id=guidance_selection.selection_set_id,
                agent_run_id=dispatch.run_id,
            )
        store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
        store.commit_progress_transition(
            scope=settings.scope,
            lease=lease,
            transition=TransitionWrite(
                from_state="REPAIR_PLANNED",
                to_state="REPAIR_IN_PROGRESS",
                transition_key=f"REPAIR_STARTED:{claim.wakeup_id}",
                actor_type="COORDINATOR",
                actor_id=owner,
                reason_code="REPAIR_STARTED",
                rationale_summary=(
                    "The exact Workspace Agent attempt was created before "
                    "the case entered repair-in-progress."
                ),
            ),
            schedule=CaseSchedule(
                logical_step_key=f"case:{claim.case_id}:check-patch:4",
                next_action_kind="CHECK_PATCH_RESULT",
                wake_at=datetime.now(UTC) + timedelta(seconds=30),
                reason="Check the durable Workspace Agent and sandbox result.",
            ),
        )
    try:
        with store.transaction():
            PostgresAgentRunBinder(
                region=settings.gcp_region,
                bindings=settings.governed_agent_bindings,
                connection=connection,
            ).bind_run(
                scope=settings.scope,
                run_id=dispatch.run_id,
                agent_key="workspace-agent",
            )
    except Exception as error:
        with store.transaction():
            PostgresWorkspaceStore(connection).fail_task(dispatch, error_class=type(error).__name__)
        return
    if use_antigravity:
        dispatch_antigravity_repair(
            settings=settings,
            connection=connection,
            invocation=dispatch,
            writer=writer,
        )
        return
    runtime = _runtime(settings)
    try:
        receipt = runtime.invoke_workspace(dispatch)
        with store.transaction():
            PostgresWorkspaceStore(connection).record_runtime_dispatch(dispatch, receipt)
    except Exception as error:
        with store.transaction():
            PostgresWorkspaceStore(connection).fail_task(dispatch, error_class=type(error).__name__)
