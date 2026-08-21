"""Convert strict authenticated callback JSON into an application commit."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import ValidationError

from solvan.agents.contracts import (
    AgentOutput,
    AgentResultEnvelope,
    SupervisorPlanOutput,
)
from solvan.application import (
    AgentCompletion,
    AgentRunMaterial,
    AgentSemanticStatus,
    FindingCommit,
    FindingKind,
    WorkspaceModelProposal,
)
from solvan.domain import (
    InvestigationPlanProposal,
    InvestigationStepKind,
    PlanValidationPolicy,
    ProposedStep,
    StepBudget,
)


class AgentResultParseError(ValueError):
    """Runtime output is malformed or exceeds its pre-parse boundary."""


def parse_workspace_model_proposal(raw: bytes) -> WorkspaceModelProposal:
    if not raw or len(raw) > 600_000:
        raise AgentResultParseError("Workspace Agent output is empty or exceeds its ceiling")
    try:
        return WorkspaceModelProposal.model_validate_json(raw)
    except ValidationError as error:
        raise AgentResultParseError("Runtime output failed the Workspace Agent schema") from error


def parse_supervisor_plan(raw: bytes, *, policy: PlanValidationPolicy) -> InvestigationPlanProposal:
    if not raw or len(raw) > 64_000:
        raise AgentResultParseError("supervisor output is empty or exceeds its ceiling")
    try:
        output = SupervisorPlanOutput.model_validate_json(raw)
    except ValidationError as error:
        raise AgentResultParseError("Runtime output failed the supervisor schema") from error
    steps: list[ProposedStep] = []
    for step in output.steps:
        kind = (
            InvestigationStepKind.INVOKE_AGENT
            if step.kind == "invoke_agent"
            else InvestigationStepKind.COORDINATOR_CHECK
        )
        if step.agent is None:
            budget = StepBudget(
                deadline_ms=1_000,
                max_tool_calls=0,
                max_output_bytes=1,
                max_model_calls=0,
                max_replans=0,
            )
        else:
            limit = policy.agent_limits.get(step.agent)
            if limit is None:
                raise AgentResultParseError("supervisor selected an unregistered agent")
            budget = limit.maximum
        steps.append(
            ProposedStep(
                step_key=step.step_key,
                kind=kind,
                agent_key=step.agent,
                scope_ref=step.scope_ref,
                purpose=step.purpose,
                required=step.required,
                depends_on=step.depends_on,
                budget=budget,
                fallback_ref=step.fallback_ref,
            )
        )
    return InvestigationPlanProposal(
        objective=output.objective,
        completion_condition=output.completion_condition,
        uncertainties=output.uncertainties,
        steps=tuple(steps),
    )


def parse_runtime_agent_output(
    raw: bytes,
    *,
    material: AgentRunMaterial,
    completed_at: datetime | None = None,
    provider_output: bytes | None = None,
) -> AgentCompletion:
    if not raw or len(raw) > 1_000_000:
        raise AgentResultParseError("Runtime output is empty or exceeds the parse ceiling")
    try:
        output = AgentOutput.model_validate_json(raw)
    except ValidationError as error:
        raise AgentResultParseError("Runtime output failed the strict agent schema") from error
    authoritative_output = provider_output or raw
    output_hash = f"sha256:{hashlib.sha256(authoritative_output).hexdigest()}"
    return AgentCompletion(
        agent_resource=material.agent_resource,
        agent_revision=material.agent_revision,
        invocation_id=material.invocation_id,
        incident_id=material.incident_id,
        workflow_version=material.workflow_version,
        input_scope_hash=material.input_hash,
        output_ref=material.output_ref,
        output_hash=output_hash,
        output_size_bytes=len(authoritative_output),
        semantic_status=AgentSemanticStatus(output.status),
        summary=output.summary,
        evidence_refs=output.evidence_refs,
        findings=tuple(
            FindingCommit(
                finding_key=finding.finding_key,
                kind=FindingKind(finding.kind),
                statement=finding.statement,
                evidence_refs=finding.evidence_refs,
                confidence=finding.confidence,
                contradiction_refs=finding.contradiction_refs,
            )
            for finding in output.findings
        ),
        completed_at=completed_at or datetime.now(UTC),
        trace_id=material.trace_id,
    )


def parse_agent_result(
    raw: bytes,
    *,
    output_ref: str,
    absolute_maximum_bytes: int = 1_000_000,
) -> AgentCompletion:
    if not raw or len(raw) > absolute_maximum_bytes:
        raise AgentResultParseError("Runtime output is empty or exceeds the parse ceiling")
    try:
        envelope = AgentResultEnvelope.model_validate_json(raw)
    except ValidationError as error:
        raise AgentResultParseError("Runtime output failed the strict agent schema") from error
    output_hash = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    return AgentCompletion(
        agent_resource=envelope.agent_resource,
        agent_revision=envelope.agent_revision,
        invocation_id=envelope.invocation_id,
        incident_id=_incident_id(envelope),
        workflow_version=envelope.workflow_version,
        input_scope_hash=envelope.input_scope_hash,
        output_ref=output_ref,
        output_hash=output_hash,
        output_size_bytes=len(raw),
        semantic_status=AgentSemanticStatus(envelope.output.status),
        summary=envelope.output.summary,
        evidence_refs=envelope.output.evidence_refs,
        findings=tuple(
            FindingCommit(
                finding_key=finding.finding_key,
                kind=FindingKind(finding.kind),
                statement=finding.statement,
                evidence_refs=finding.evidence_refs,
                confidence=finding.confidence,
                contradiction_refs=finding.contradiction_refs,
            )
            for finding in envelope.output.findings
        ),
        completed_at=envelope.completed_at,
        trace_id=envelope.trace_id,
    )


def _incident_id(envelope: AgentResultEnvelope) -> str:
    if envelope.incident_id is None:
        raise AgentResultParseError("this callback path requires an incident owner")
    return envelope.incident_id
