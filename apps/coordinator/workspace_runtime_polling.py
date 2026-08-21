"""Provider-neutral completion path for durable Workspace Agent runs."""

from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from apps.coordinator.workspace_adjudication import (
    WorkspaceAdjudicationRun,
    adjudicate_workspace_proposal,
    block_workspace_failure,
)
from solvan.agents.result_adapter import AgentResultParseError, parse_workspace_model_proposal
from solvan.persistence import PendingRuntimeRun, PostgresRuntimeRunStore, PostgresWorkflowStore
from solvan.platform.agent_runtime import GeminiAgentRuntime, structured_query_output
from solvan.platform.evidence_objects import GcsEvidenceReader


def poll_workspace_run(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    runtime: GeminiAgentRuntime,
    run: PendingRuntimeRun,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
) -> None:
    """Poll ADK and hand every proposal to the provider-neutral adjudicator."""

    del runs  # completion is owned by the provider-neutral workspace store
    if run.reliability_case_id is None or run.repair_plan_id is None:
        return
    terminal_error: str | None = None
    provider_output = b""
    raw: bytes | None = None
    if run.deadline <= datetime.now(UTC):
        with suppress(Exception):
            runtime.cancel(
                agent_resource=run.agent_resource,
                operation_name=run.runtime_operation_name,
            )
        terminal_error = "RUNTIME_DEADLINE_EXCEEDED"
    else:
        try:
            check = runtime.check(run.runtime_operation_name)
        except Exception:
            return
        if check.status == "RUNNING":
            return
        if check.status == "FAILED" or check.result is None:
            terminal_error = "AGENT_RUNTIME_QUERY_FAILED"
        else:
            provider_output = check.result.encode()
            try:
                raw = structured_query_output(check.result)
            except ValueError:
                terminal_error = "INVALID_AGENT_OUTPUT"

    adjudication_run = WorkspaceAdjudicationRun(
        run_id=run.run_id,
        reliability_case_id=run.reliability_case_id,
        workflow_version=run.workflow_version,
        provider_output_hash="sha256:" + hashlib.sha256(provider_output).hexdigest(),
        provider_boot_hash=(
            "sha256:"
            + hashlib.sha256(
                ("agent-runtime-operation:" + run.runtime_operation_name).encode()
            ).hexdigest()
        ),
        provider_service_revision=settings.workspace_agent_revision,
    )
    if terminal_error is not None or raw is None:
        block_workspace_failure(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
            run=adjudication_run,
            error_class=terminal_error or "WORKSPACE_OUTPUT_MISSING",
        )
        return
    try:
        output = parse_workspace_model_proposal(raw)
    except (ValueError, AgentResultParseError):
        block_workspace_failure(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
            run=adjudication_run,
            error_class="INVALID_AGENT_OUTPUT",
        )
        return
    adjudicate_workspace_proposal(
        settings=settings,
        owner=owner,
        workflow=workflow,
        connection=connection,
        reader=reader,
        run=adjudication_run,
        output=output,
    )
