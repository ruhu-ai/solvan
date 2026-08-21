"""Application-owned pre-mutation gate contracts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from solvan.application.actions import ExecutionAuthorization, StandingAuthority
from solvan.domain import ActionPolicyError, Scope


class ActionPreMutationGate(Protocol):
    """A deterministic check performed before dispatch is persisted."""

    def check(self, *, scope: Scope, authority: ExecutionAuthorization) -> None: ...


@dataclass(frozen=True, slots=True)
class GraphActionBinding:
    """The graph identity captured when the action was authored."""

    snapshot_id: str
    cell_id: str
    placement_epoch: int

    def __post_init__(self) -> None:
        if not self.snapshot_id or not self.cell_id or self.placement_epoch < 1:
            raise ValueError("graph action binding is incomplete")


class CompositeActionPreMutationGate:
    """Run every target gate in a stable order; no gate may weaken another."""

    def __init__(self, gates: Iterable[ActionPreMutationGate]) -> None:
        self._gates = tuple(gates)

    def check(self, *, scope: Scope, authority: ExecutionAuthorization) -> None:
        for gate in self._gates:
            gate.check(scope=scope, authority=authority)


class HumanApprovalOnlyActionGate:
    """Safe degradation for runtimes without the target autonomy schemas."""

    def check(self, *, scope: Scope, authority: ExecutionAuthorization) -> None:
        if authority.material.scope != scope:
            raise ActionPolicyError("execution_scope_drift")
        if isinstance(authority, StandingAuthority):
            raise ActionPolicyError("earned_autonomy_gate_unavailable")
