"""Immutable workflow aggregates with version fencing and guard enforcement."""

from __future__ import annotations

from dataclasses import dataclass

from solvan.domain.transitions import Transition, TransitionMachine


class WorkflowError(ValueError):
    """Base class for deterministic workflow commit rejection."""


class StaleWorkflowVersion(WorkflowError):
    """Raised when a caller attempts to commit from an old snapshot."""


class GuardRejected(WorkflowError):
    """Raised when application policy did not satisfy the transition guard."""


@dataclass(frozen=True, slots=True)
class WorkflowSnapshot:
    entity_id: str
    state: str
    workflow_version: int
    state_machine_version: int

    def __post_init__(self) -> None:
        if self.workflow_version < 1:
            raise WorkflowError("workflow_version must be positive")
        if self.state_machine_version < 1:
            raise WorkflowError("state_machine_version must be positive")


@dataclass(frozen=True, slots=True)
class TransitionCommit:
    before: WorkflowSnapshot
    after: WorkflowSnapshot
    transition: Transition
    reason_code: str


def apply_transition(
    *,
    machine: TransitionMachine,
    snapshot: WorkflowSnapshot,
    event: str,
    expected_workflow_version: int,
    guard_passed: bool,
    reason_code: str,
) -> TransitionCommit:
    """Resolve and apply one transition without mutating the prior snapshot."""

    if snapshot.state_machine_version != machine.version:
        raise WorkflowError("snapshot state-machine version does not match loaded machine")
    if snapshot.workflow_version != expected_workflow_version:
        raise StaleWorkflowVersion(
            f"expected workflow version {expected_workflow_version}; "
            f"current is {snapshot.workflow_version}"
        )
    transition = machine.resolve(current_state=snapshot.state, event=event)
    if not guard_passed:
        raise GuardRejected(f"guard rejected: {transition.guard}")
    if not reason_code:
        raise WorkflowError("reason_code must not be empty")
    after = WorkflowSnapshot(
        entity_id=snapshot.entity_id,
        state=transition.to_state,
        workflow_version=snapshot.workflow_version + 1,
        state_machine_version=snapshot.state_machine_version,
    )
    return TransitionCommit(
        before=snapshot,
        after=after,
        transition=transition,
        reason_code=reason_code,
    )
