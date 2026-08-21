"""Durable Agent Runtime polling record types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PendingRuntimeRun:
    run_id: str
    incident_id: str | None
    alert_episode_id: str | None
    reliability_case_id: str | None
    agent_key: str
    agent_resource: str
    runtime_operation_name: str
    runtime_output_ref: str
    deadline: datetime
    workflow_version: int
    investigation_step_id: str | None
    action_id: str | None
    repair_plan_id: str | None


@dataclass(frozen=True, slots=True)
class ExpiredCreatedRuntimeRun:
    run_id: str
    invocation_id: str
    incident_id: str | None
    alert_episode_id: str | None
    action_id: str | None
    agent_key: str
    agent_resource: str
    workflow_version: int
    runtime_operation_name: str | None
    runtime_input_ref: str | None
    runtime_output_ref: str | None
    input_hash: str
    deadline: datetime


@dataclass(frozen=True, slots=True)
class ExecutionReceiptOutcome:
    action_id: str
    action_status: str
    receipt_id: str | None
    receipt_result: str | None


class RuntimeRunConflict(RuntimeError):
    """The Runtime operation no longer owns the live durable attempt."""


class RuntimeRunBudgetExhausted(RuntimeError):
    """The durable attempt count reached the step's immutable retry budget."""
