"""Durable, fenced trigger-policy firings and coordinator enqueue."""

from solvan.persistence.trigger_policy_authoring import TriggerPolicyAuthoringMixin
from solvan.persistence.trigger_policy_runtime import TriggerPolicyRuntimeMixin
from solvan.persistence.trigger_policy_types import (
    TriggerEnqueueResult,
    TriggerFiringResult,
    TriggerPolicyLifecycleCommit,
    TriggerWakeClaim,
)

__all__ = [
    "PostgresTriggerPolicyStore",
    "TriggerEnqueueResult",
    "TriggerFiringResult",
    "TriggerPolicyLifecycleCommit",
    "TriggerWakeClaim",
]


class PostgresTriggerPolicyStore(TriggerPolicyAuthoringMixin, TriggerPolicyRuntimeMixin):
    """Cohesive facade over one caller-owned PostgreSQL transaction."""
