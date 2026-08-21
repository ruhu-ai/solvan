from pathlib import Path

import pytest
import yaml

from solvan.domain import (
    IllegalTransition,
    TerminalState,
    TransitionMachine,
    TransitionMachineError,
    UnknownState,
)

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "specs" / "artifacts"


def load_machine(name: str) -> tuple[TransitionMachine, dict[str, object]]:
    value = yaml.safe_load((ARTIFACTS / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return TransitionMachine.from_mapping(value), value


def test_incident_machine_resolves_case_termination_and_absorbs_terminal_states() -> None:
    machine, artifact = load_machine("incident-transitions.yaml")

    transition = machine.resolve(current_state="MITIGATED", event="CASE_TERMINATED_WITHOUT_REPAIR")

    assert transition.to_state == "ESCALATED"
    stale_policy = artifact["stale_policy"]
    assert isinstance(stale_policy, dict)
    assert "MITIGATED" not in stale_policy["applies_to_states"]
    with pytest.raises(TerminalState):
        machine.resolve(current_state="ESCALATED", event="TRIAGE_STARTED")


def test_case_machine_declares_atomic_cross_aggregate_cancellation() -> None:
    machine, artifact = load_machine("reliability-case-transitions.yaml")

    cancellation = artifact["cancellation_policy"]
    assert isinstance(cancellation, dict)
    linked = cancellation["when_linked_incident_is_mitigated"]
    assert isinstance(linked, dict)
    assert linked == {
        "emit_incident_event": "CASE_TERMINATED_WITHOUT_REPAIR",
        "atomic_with_case_transition": True,
    }
    assert machine.resolve(current_state="OBSERVING", event="OPERATOR_CANCELLED").to_state == (
        "CANCELLED"
    )


@pytest.mark.parametrize(
    "artifact",
    ["incident-transitions.yaml", "reliability-case-transitions.yaml"],
)
def test_every_declared_state_is_reachable_from_initial_or_is_a_terminal_target(
    artifact: str,
) -> None:
    machine, _ = load_machine(artifact)
    reachable = {machine.initial_state}
    changed = True
    while changed:
        changed = False
        for transition in machine.transitions:
            if transition.from_state in reachable and transition.to_state not in reachable:
                reachable.add(transition.to_state)
                changed = True

    assert reachable == machine.states


def test_transition_resolver_rejects_unknown_and_illegal_inputs() -> None:
    machine, _ = load_machine("incident-transitions.yaml")

    with pytest.raises(UnknownState):
        machine.resolve(current_state="QUEUED", event="TRIAGE_STARTED")
    with pytest.raises(IllegalTransition):
        machine.resolve(current_state="DETECTED", event="VERIFICATION_PASSED")


def valid_definition() -> dict[str, object]:
    return {
        "machine": "test",
        "machine_version": 1,
        "initial_state": "OPEN",
        "terminal_states": ["CLOSED"],
        "transition_defaults": {"guard": "always", "side_effects": ["audit"]},
        "transitions": [{"from": "OPEN", "event": "CLOSE", "to": "CLOSED"}],
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("machine"),
        lambda value: value.__setitem__("machine_version", True),
        lambda value: value.__setitem__("machine_version", 0),
        lambda value: value.__setitem__("terminal_states", []),
        lambda value: value.__setitem__("initial_state", "CLOSED"),
        lambda value: value.__setitem__("transition_defaults", "invalid"),
        lambda value: value.__setitem__("terminal_states", "CLOSED"),
        lambda value: value.__setitem__("terminal_states", [""]),
        lambda value: value.__setitem__("transitions", "invalid"),
        lambda value: value.__setitem__("transitions", ["invalid"]),
        lambda value: value.__setitem__(
            "transitions",
            [
                {"from": "OPEN", "event": "CLOSE", "to": "CLOSED"},
                {"from": "OPEN", "event": "CLOSE", "to": "CLOSED"},
            ],
        ),
        lambda value: value.__setitem__(
            "transitions", [{"from": "CLOSED", "event": "REOPEN", "to": "OPEN"}]
        ),
        lambda value: value.__setitem__(
            "transitions", [{"from": "OTHER", "event": "CLOSE", "to": "CLOSED"}]
        ),
    ],
)
def test_invalid_machine_definitions_fail_closed(mutate: object) -> None:
    value = valid_definition()
    assert callable(mutate)
    mutate(value)

    with pytest.raises(TransitionMachineError):
        TransitionMachine.from_mapping(value)
