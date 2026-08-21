"""Typed investigation-plan validation and deterministic DAG ordering."""

from __future__ import annotations

import heapq
import re
from dataclasses import dataclass
from enum import StrEnum


class InvestigationPlanError(ValueError):
    """A proposed plan exceeds coordinator-owned structural or policy bounds."""


class InvestigationStepKind(StrEnum):
    INVOKE_AGENT = "INVOKE_AGENT"
    COORDINATOR_CHECK = "COORDINATOR_CHECK"


@dataclass(frozen=True, slots=True)
class StepBudget:
    deadline_ms: int
    max_tool_calls: int
    max_output_bytes: int
    max_model_calls: int = 1
    max_replans: int = 0

    def __post_init__(self) -> None:
        if (
            self.deadline_ms < 1
            or self.max_tool_calls < 0
            or self.max_output_bytes < 1
            or self.max_model_calls < 0
            or self.max_replans < 0
        ):
            raise InvestigationPlanError("step budget values are invalid")


@dataclass(frozen=True, slots=True)
class AgentLimit:
    agent_resource: str
    agent_revision: str
    maximum: StepBudget
    allowed_scope_refs: frozenset[str]
    allowed_tool_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.agent_resource.strip() or not self.agent_revision.strip():
            raise InvestigationPlanError("agent resource and revision are required")
        if not self.allowed_scope_refs:
            raise InvestigationPlanError("agent must have at least one allowed scope")
        if len(set(self.allowed_tool_names)) != len(self.allowed_tool_names):
            raise InvestigationPlanError("agent tool names must be unique")
        if any(not tool.strip() for tool in self.allowed_tool_names):
            raise InvestigationPlanError("agent tool names cannot be empty")


@dataclass(frozen=True, slots=True)
class ProposedStep:
    step_key: str
    kind: InvestigationStepKind
    agent_key: str | None
    scope_ref: str
    purpose: str
    required: bool
    depends_on: tuple[str, ...]
    budget: StepBudget
    fallback_ref: str | None = None


@dataclass(frozen=True, slots=True)
class InvestigationPlanProposal:
    objective: str
    completion_condition: str
    uncertainties: tuple[str, ...]
    steps: tuple[ProposedStep, ...]


@dataclass(frozen=True, slots=True)
class PlanValidationPolicy:
    agent_limits: dict[str, AgentLimit]
    allowed_scope_refs: frozenset[str]
    maximum_steps: int
    required_agent_keys: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class AcceptedStep:
    ordinal: int
    proposal: ProposedStep
    agent_resource: str | None
    agent_revision: str | None
    allowed_tool_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AcceptedInvestigationPlan:
    objective: str
    completion_condition: str
    uncertainties: tuple[str, ...]
    steps: tuple[AcceptedStep, ...]


_STEP_KEY = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def validate_investigation_plan(
    proposal: InvestigationPlanProposal, policy: PlanValidationPolicy
) -> AcceptedInvestigationPlan:
    """Reject authority widening and return one stable lexical topological order."""

    if not proposal.objective.strip() or not proposal.completion_condition.strip():
        raise InvestigationPlanError("plan objective and completion condition are required")
    if not proposal.steps or len(proposal.steps) > policy.maximum_steps:
        raise InvestigationPlanError("plan step count exceeds policy")
    by_key: dict[str, ProposedStep] = {}
    for step in proposal.steps:
        if not _STEP_KEY.fullmatch(step.step_key):
            raise InvestigationPlanError(f"invalid step key {step.step_key}")
        if step.step_key in by_key:
            raise InvestigationPlanError(f"duplicate step key {step.step_key}")
        if step.scope_ref not in policy.allowed_scope_refs:
            raise InvestigationPlanError(f"scope widening rejected for {step.step_key}")
        if not step.purpose.strip():
            raise InvestigationPlanError(f"step purpose is required for {step.step_key}")
        if len(set(step.depends_on)) != len(step.depends_on):
            raise InvestigationPlanError(f"duplicate dependency in {step.step_key}")
        _validate_agent_and_budget(step, policy)
        by_key[step.step_key] = step

    selected_agents = {
        step.agent_key
        for step in proposal.steps
        if step.kind is InvestigationStepKind.INVOKE_AGENT and step.agent_key is not None
    }
    unknown_required = policy.required_agent_keys - policy.agent_limits.keys()
    if unknown_required:
        raise InvestigationPlanError(
            f"plan policy requires unregistered agents: {sorted(unknown_required)}"
        )
    missing_required = policy.required_agent_keys - selected_agents
    if missing_required:
        raise InvestigationPlanError(f"plan omits required agents: {sorted(missing_required)}")

    for step in proposal.steps:
        unknown = set(step.depends_on) - by_key.keys()
        if unknown:
            raise InvestigationPlanError(
                f"unknown dependencies for {step.step_key}: {sorted(unknown)}"
            )
        if step.step_key in step.depends_on:
            raise InvestigationPlanError(f"step {step.step_key} depends on itself")

    indegree = {key: 0 for key in by_key}
    dependents: dict[str, list[str]] = {key: [] for key in by_key}
    for step in proposal.steps:
        indegree[step.step_key] = len(step.depends_on)
        for dependency in step.depends_on:
            dependents[dependency].append(step.step_key)
    ready = [key for key, count in indegree.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[str] = []
    while ready:
        key = heapq.heappop(ready)
        ordered.append(key)
        for dependent in sorted(dependents[key]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(ordered) != len(by_key):
        raise InvestigationPlanError("investigation plan contains a dependency cycle")
    return AcceptedInvestigationPlan(
        objective=proposal.objective,
        completion_condition=proposal.completion_condition,
        uncertainties=proposal.uncertainties,
        steps=tuple(
            _accepted_step(index, by_key[key], policy) for index, key in enumerate(ordered)
        ),
    )


def _validate_agent_and_budget(step: ProposedStep, policy: PlanValidationPolicy) -> None:
    if step.kind is InvestigationStepKind.COORDINATOR_CHECK:
        if (
            step.agent_key is not None
            or step.budget.max_tool_calls != 0
            or step.budget.max_model_calls != 0
            or step.budget.max_replans != 0
        ):
            raise InvestigationPlanError(
                f"coordinator check {step.step_key} cannot invoke an agent or tool"
            )
        return
    if step.agent_key is None or step.agent_key not in policy.agent_limits:
        raise InvestigationPlanError(f"unknown agent for {step.step_key}")
    agent = policy.agent_limits[step.agent_key]
    if step.scope_ref not in agent.allowed_scope_refs:
        raise InvestigationPlanError(f"agent scope widening rejected for {step.step_key}")
    maximum = agent.maximum
    if (
        step.budget.deadline_ms > maximum.deadline_ms
        or step.budget.max_tool_calls > maximum.max_tool_calls
        or step.budget.max_output_bytes > maximum.max_output_bytes
        or step.budget.max_model_calls > maximum.max_model_calls
        or step.budget.max_replans > maximum.max_replans
    ):
        raise InvestigationPlanError(f"agent budget exceeds policy for {step.step_key}")


def _accepted_step(ordinal: int, step: ProposedStep, policy: PlanValidationPolicy) -> AcceptedStep:
    if step.agent_key is None:
        return AcceptedStep(ordinal, step, None, None, ())
    agent = policy.agent_limits[step.agent_key]
    return AcceptedStep(
        ordinal,
        step,
        agent.agent_resource,
        agent.agent_revision,
        agent.allowed_tool_names,
    )
