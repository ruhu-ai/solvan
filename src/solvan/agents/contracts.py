"""Strict provider-boundary schemas shared by Solvan's ADK agents."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    model_validator,
)

from solvan.domain import Scope

type Identifier = Annotated[str, Field(min_length=1, max_length=256)]


class InvocationBudget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_runtime_seconds: int = Field(ge=1, le=4_200)
    max_model_calls: int = Field(ge=0, le=32)
    max_tool_calls: int = Field(ge=0, le=64)
    max_output_bytes: int = Field(ge=1, le=1_000_000)
    max_replans: int = Field(ge=0, le=4)


class TraceContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    span_id: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")]
    trace_flags: Literal["00", "01"]


class AgentInvocation(BaseModel):
    """The complete authority ceiling for one bounded agent attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    invocation_id: Identifier
    logical_step_key: Identifier
    organization_id: Identifier
    project_id: Identifier
    environment_id: Identifier
    incident_id: Identifier | None
    reliability_case_id: Identifier | None
    workflow_version: int = Field(ge=1)
    deadline: AwareDatetime
    budget: InvocationBudget
    evidence_refs: tuple[Identifier, ...] = ()
    allowed_tool_names: tuple[Identifier, ...] = ()
    input_payload: dict[str, JsonValue]
    trace_context: TraceContext

    @model_validator(mode="after")
    def validate_authority(self) -> AgentInvocation:
        if (self.incident_id is None) == (self.reliability_case_id is None):
            raise ValueError("exactly one incident or Reliability Case owner is required")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("evidence references must be unique")
        if len(set(self.allowed_tool_names)) != len(self.allowed_tool_names):
            raise ValueError("allowed tool names must be unique")
        Scope(self.organization_id, self.project_id, self.environment_id)
        return self


class SupervisorStepOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
    kind: Literal["invoke_agent", "coordinator_check"]
    agent: Identifier | None
    scope_ref: Identifier
    purpose: Annotated[str, Field(min_length=1, max_length=1_000)]
    depends_on: tuple[Identifier, ...] = ()
    required: bool = True
    fallback_ref: Identifier | None = None

    @model_validator(mode="after")
    def validate_kind(self) -> SupervisorStepOutput:
        if (self.kind == "invoke_agent") != (self.agent is not None):
            raise ValueError("invoke_agent requires an agent and coordinator_check forbids one")
        return self


class SupervisorPlanOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    objective: Annotated[str, Field(min_length=1, max_length=2_000)]
    steps: Annotated[tuple[SupervisorStepOutput, ...], Field(min_length=1, max_length=16)]
    completion_condition: Annotated[str, Field(min_length=1, max_length=2_000)]
    uncertainties: Annotated[tuple[str, ...], Field(max_length=16)] = ()


class FindingOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
    kind: Literal["OBSERVATION", "INFERENCE"]
    statement: Annotated[str, Field(min_length=1, max_length=4_000)]
    evidence_refs: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=32)]
    confidence: float | None = Field(default=None, ge=0, le=1)
    contradiction_refs: Annotated[tuple[Identifier, ...], Field(max_length=32)] = ()


class AgentOutput(BaseModel):
    """Bounded evidence output; it deliberately has no action or authority fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    status: Literal["SUCCEEDED", "INSUFFICIENT_EVIDENCE"]
    summary: Annotated[str, Field(min_length=1, max_length=4_000)]
    evidence_refs: Annotated[tuple[Identifier, ...], Field(max_length=64)] = ()
    findings: Annotated[tuple[FindingOutput, ...], Field(max_length=64)] = ()
    unresolved_questions: Annotated[tuple[str, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def validate_citations(self) -> AgentOutput:
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("agent evidence references must be unique")
        keys = [finding.finding_key for finding in self.findings]
        if len(keys) != len(set(keys)):
            raise ValueError("agent finding keys must be unique")
        cited = {
            evidence_ref
            for finding in self.findings
            for evidence_ref in (*finding.evidence_refs, *finding.contradiction_refs)
        }
        if not cited.issubset(set(self.evidence_refs)):
            raise ValueError("all finding citations must appear in the output evidence list")
        return self


class ExecutionAgentOutput(BaseModel):
    """A non-authoritative report; the execution receipt remains authoritative."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    action_id: Identifier
    status: Literal["TOOL_COMPLETED", "TOOL_REJECTED"]
    summary: Annotated[str, Field(min_length=1, max_length=1_000)]


class VerificationAgentOutput(BaseModel):
    """A narrative projection; the verifier's durable row owns the verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    action_id: Identifier
    verification_id: Identifier | None = None
    status: Literal["TOOL_COMPLETED", "TOOL_REJECTED"]
    summary: Annotated[str, Field(min_length=1, max_length=1_000)]


class AgentResultEnvelope(BaseModel):
    """Authenticated callback shape compared against the stored agent attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    agent_resource: Identifier
    agent_revision: Identifier
    invocation_id: Identifier
    incident_id: Identifier | None
    reliability_case_id: Identifier | None
    workflow_version: int = Field(ge=1)
    input_scope_hash: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    output: AgentOutput
    completed_at: AwareDatetime
    trace_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]

    @model_validator(mode="after")
    def validate_owner(self) -> AgentResultEnvelope:
        if (self.incident_id is None) == (self.reliability_case_id is None):
            raise ValueError("exactly one callback owner is required")
        return self


def utc_timestamp(value: datetime) -> str:
    """Serialize one aware timestamp consistently for provider input hashes."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.isoformat()
