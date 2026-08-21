"""Strict loader and resolver for the authoritative transition artifacts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class TransitionMachineError(ValueError):
    """Base class for invalid machine definitions and transition requests."""


class UnknownState(TransitionMachineError):
    """Raised when a caller supplies a state outside the machine vocabulary."""


class IllegalTransition(TransitionMachineError):
    """Raised when no transition exists for the state/event pair."""


class TerminalState(IllegalTransition):
    """Raised when any transition is requested from an absorbing state."""


@dataclass(frozen=True, slots=True)
class Transition:
    from_state: str
    event: str
    to_state: str
    guard: str
    side_effects: tuple[str, ...]
    atomic: bool


@dataclass(frozen=True, slots=True)
class TransitionMachine:
    name: str
    version: int
    initial_state: str
    terminal_states: frozenset[str]
    transitions: tuple[Transition, ...]

    @property
    def states(self) -> frozenset[str]:
        values = {self.initial_state, *self.terminal_states}
        values.update(transition.from_state for transition in self.transitions)
        values.update(transition.to_state for transition in self.transitions)
        return frozenset(values)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> TransitionMachine:
        name = _required_string(value, "machine")
        version = _required_int(value, "machine_version")
        initial_state = _required_string(value, "initial_state")
        terminal_states = frozenset(_string_sequence(value, "terminal_states"))
        defaults = _required_mapping(value, "transition_defaults")
        default_guard = _required_string(defaults, "guard")
        default_side_effects = tuple(_string_sequence(defaults, "side_effects"))
        raw_transitions = value.get("transitions")
        if not isinstance(raw_transitions, Sequence) or isinstance(raw_transitions, str):
            raise TransitionMachineError("transitions must be a sequence")

        transitions: list[Transition] = []
        keys: set[tuple[str, str]] = set()
        for index, raw_transition in enumerate(raw_transitions):
            if not isinstance(raw_transition, Mapping):
                raise TransitionMachineError(f"transitions[{index}] must be a mapping")
            from_state = _required_string(raw_transition, "from")
            event = _required_string(raw_transition, "event")
            key = (from_state, event)
            if key in keys:
                raise TransitionMachineError(
                    f"duplicate transition for state={from_state} event={event}"
                )
            keys.add(key)
            raw_side_effects = raw_transition.get("side_effects")
            side_effects = (
                default_side_effects
                if raw_side_effects is None
                else tuple(_string_sequence(raw_transition, "side_effects"))
            )
            transitions.append(
                Transition(
                    from_state=from_state,
                    event=event,
                    to_state=_required_string(raw_transition, "to"),
                    guard=str(raw_transition.get("guard", default_guard)),
                    side_effects=side_effects,
                    atomic=bool(raw_transition.get("atomic", False)),
                )
            )

        machine = cls(
            name=name,
            version=version,
            initial_state=initial_state,
            terminal_states=terminal_states,
            transitions=tuple(transitions),
        )
        machine.validate()
        return machine

    def validate(self) -> None:
        if self.version < 1:
            raise TransitionMachineError("machine_version must be positive")
        if not self.terminal_states:
            raise TransitionMachineError("terminal_states must not be empty")
        if self.initial_state in self.terminal_states:
            raise TransitionMachineError("initial_state cannot be terminal")
        outgoing = {transition.from_state for transition in self.transitions}
        terminal_outgoing = self.terminal_states.intersection(outgoing)
        if terminal_outgoing:
            raise TransitionMachineError(
                f"terminal states have outgoing transitions: {sorted(terminal_outgoing)}"
            )
        missing_outgoing = self.states.difference(self.terminal_states).difference(outgoing)
        if missing_outgoing:
            raise TransitionMachineError(
                f"non-terminal states have no outgoing transition: {sorted(missing_outgoing)}"
            )

    def resolve(self, *, current_state: str, event: str) -> Transition:
        if current_state not in self.states:
            raise UnknownState(f"unknown {self.name} state: {current_state}")
        if current_state in self.terminal_states:
            raise TerminalState(f"terminal {self.name} state is absorbing: {current_state}")
        for transition in self.transitions:
            if transition.from_state == current_state and transition.event == event:
                return transition
        raise IllegalTransition(f"illegal {self.name} event {event} from {current_state}")


def _required_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    result = value.get(key)
    if not isinstance(result, Mapping):
        raise TransitionMachineError(f"{key} must be a mapping")
    return result


def _required_string(value: Mapping[str, Any], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise TransitionMachineError(f"{key} must be a non-empty string")
    return result


def _required_int(value: Mapping[str, Any], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise TransitionMachineError(f"{key} must be an integer")
    return result


def _string_sequence(value: Mapping[str, Any], key: str) -> tuple[str, ...]:
    result = value.get(key)
    if not isinstance(result, Sequence) or isinstance(result, str):
        raise TransitionMachineError(f"{key} must be a sequence")
    if not all(isinstance(item, str) and item for item in result):
        raise TransitionMachineError(f"{key} must contain only non-empty strings")
    return tuple(result)
