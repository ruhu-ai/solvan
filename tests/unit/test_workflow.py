from pathlib import Path

import pytest
import yaml

from solvan.domain import (
    GuardRejected,
    StaleWorkflowVersion,
    TransitionMachine,
    WorkflowError,
    WorkflowSnapshot,
    apply_transition,
)

ROOT = Path(__file__).resolve().parents[2]


def incident_machine() -> TransitionMachine:
    value = yaml.safe_load(
        (ROOT / "specs/artifacts/incident-transitions.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(value, dict)
    return TransitionMachine.from_mapping(value)


def test_transition_commit_is_immutable_and_increments_once() -> None:
    before = WorkflowSnapshot("inc_01TEST", "DETECTED", 7, 1)

    commit = apply_transition(
        machine=incident_machine(),
        snapshot=before,
        event="TRIAGE_STARTED",
        expected_workflow_version=7,
        guard_passed=True,
        reason_code="DETECTOR_THRESHOLD_PASSED",
    )

    assert before.state == "DETECTED"
    assert commit.after == WorkflowSnapshot("inc_01TEST", "TRIAGING", 8, 1)
    assert commit.before is before
    assert commit.reason_code == "DETECTOR_THRESHOLD_PASSED"


def test_stale_version_is_rejected_before_transition_resolution() -> None:
    snapshot = WorkflowSnapshot("inc_01TEST", "DETECTED", 7, 1)

    with pytest.raises(StaleWorkflowVersion, match="current is 7"):
        apply_transition(
            machine=incident_machine(),
            snapshot=snapshot,
            event="TRIAGE_STARTED",
            expected_workflow_version=6,
            guard_passed=True,
            reason_code="TEST",
        )


def test_failed_guard_does_not_create_a_commit() -> None:
    snapshot = WorkflowSnapshot("inc_01TEST", "DETECTED", 1, 1)

    with pytest.raises(GuardRejected, match="detector_false_positive_rule_passed"):
        apply_transition(
            machine=incident_machine(),
            snapshot=snapshot,
            event="FALSE_POSITIVE_CONFIRMED",
            expected_workflow_version=1,
            guard_passed=False,
            reason_code="TEST",
        )


def test_snapshot_versions_must_be_positive() -> None:
    with pytest.raises(WorkflowError, match="workflow_version must be positive"):
        WorkflowSnapshot("inc_01TEST", "DETECTED", 0, 1)
    with pytest.raises(WorkflowError, match="state_machine_version must be positive"):
        WorkflowSnapshot("inc_01TEST", "DETECTED", 1, 0)


def test_machine_version_and_reason_are_enforced() -> None:
    machine = incident_machine()
    wrong_machine = WorkflowSnapshot("inc_01TEST", "DETECTED", 1, 2)
    with pytest.raises(WorkflowError, match="state-machine version"):
        apply_transition(
            machine=machine,
            snapshot=wrong_machine,
            event="TRIAGE_STARTED",
            expected_workflow_version=1,
            guard_passed=True,
            reason_code="TEST",
        )

    snapshot = WorkflowSnapshot("inc_01TEST", "DETECTED", 1, 1)
    with pytest.raises(WorkflowError, match="reason_code"):
        apply_transition(
            machine=machine,
            snapshot=snapshot,
            event="TRIAGE_STARTED",
            expected_workflow_version=1,
            guard_passed=True,
            reason_code="",
        )
