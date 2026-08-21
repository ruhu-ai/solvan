"""Immutable result values for durable trigger policy persistence."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class TriggerFiringResult:
    firing_id: str
    status: str
    created: bool


@dataclass(frozen=True, slots=True)
class TriggerWakeClaim:
    wakeup_id: str
    firing_id: str
    claim_token: UUID
    policy_key: str
    policy_version: str
    activation_id: str
    head_epoch: int
    lifecycle_epoch: int
    connection_id: str
    connection_epoch: int
    target_key: str
    target_snapshot_hash: str
    region: str
    classification: str


@dataclass(frozen=True, slots=True)
class TriggerEnqueueResult:
    firing_id: str
    status: str
    inbox_event_id: str | None
    decision_reason: str | None = None


@dataclass(frozen=True, slots=True)
class TriggerPolicyLifecycleCommit:
    policy_key: str
    version: str
    lifecycle: str
    digest: str
    decision_id: str | None
    created: bool


@dataclass(frozen=True, slots=True)
class TriggerPolicyReplacementIntentCommit:
    intent_id: str
    retiring_policy_key: str
    retiring_version: str
    successor_policy_key: str
    successor_version: str
    compound_request_hash: str
    created: bool
