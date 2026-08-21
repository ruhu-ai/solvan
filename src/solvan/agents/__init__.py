"""Bounded Google ADK agents and strict provider-facing contracts."""

from solvan.agents.adk_agents import (
    AgentBuildConfig,
    build_evidence_agent,
    build_execution_agent,
    build_incident_supervisor,
    build_infrastructure_agent,
    build_verification_agent,
    build_workspace_agent,
)
from solvan.agents.contracts import (
    AgentInvocation,
    AgentOutput,
    AgentResultEnvelope,
    ExecutionAgentOutput,
    FindingOutput,
    InvocationBudget,
    SupervisorPlanOutput,
    SupervisorStepOutput,
    TraceContext,
    VerificationAgentOutput,
)
from solvan.agents.result_adapter import (
    AgentResultParseError,
    parse_agent_result,
    parse_runtime_agent_output,
    parse_supervisor_plan,
    parse_workspace_model_proposal,
)

__all__ = [
    "AgentBuildConfig",
    "AgentInvocation",
    "AgentOutput",
    "AgentResultEnvelope",
    "AgentResultParseError",
    "ExecutionAgentOutput",
    "FindingOutput",
    "InvocationBudget",
    "SupervisorPlanOutput",
    "SupervisorStepOutput",
    "TraceContext",
    "VerificationAgentOutput",
    "build_evidence_agent",
    "build_execution_agent",
    "build_incident_supervisor",
    "build_infrastructure_agent",
    "build_verification_agent",
    "build_workspace_agent",
    "parse_agent_result",
    "parse_runtime_agent_output",
    "parse_supervisor_plan",
    "parse_workspace_model_proposal",
]
