"""What one Tool capability probe observed, as a typed application value.

The observation lives here rather than beside the transport that produced it so
that persistence can commit it without importing the platform layer, exactly as
`CapabilityObservation` sits beside its connection probe. Platform performs the
bounded provider read; this module owns what the result is allowed to mean.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from solvan.application.tenant_integration import ConnectionPolicyError

#: How long an observation is treated as current. Short enough that a revoked
#: grant stops binding new work quickly, long enough that an investigation does
#: not re-probe every step. The bind query enforces it as `expires_at > now()`.
PROBE_FRESHNESS = timedelta(minutes=30)

ToolProbeOutcome = Literal["GRANTED", "DENIED", "MISCONFIGURED", "UNREACHABLE", "NOT_PROBED"]


@dataclass(frozen=True, slots=True)
class ToolProbeTarget:
    """Everything a Tool probe may know. Deliberately excludes any credential."""

    tool_key: str
    tool_version: str
    capability: str
    provider: str
    gcp_project_id: str

    @property
    def tool_revision(self) -> str:
        return f"{self.tool_key}@{self.tool_version}"


@dataclass(frozen=True, slots=True)
class ToolCapabilityObservation:
    """One probed Tool capability and, when unavailable, the missing grant."""

    tool_revision: str
    capability: str
    available: bool
    outcome: ToolProbeOutcome
    missing_grant: str | None
    reason_code: str | None
    receipt_ref: str
    receipt_hash: str
    observed_at: datetime
    expires_at: datetime

    def validated(self) -> ToolCapabilityObservation:
        if self.available != (self.outcome == "GRANTED"):
            raise ConnectionPolicyError("Tool capability availability and probe outcome disagree")
        if not self.available and not (self.missing_grant and self.reason_code):
            raise ConnectionPolicyError(
                "an unavailable Tool capability must name its reason and missing grant"
            )
        if self.available and (self.missing_grant or self.reason_code):
            raise ConnectionPolicyError(
                "an observed Tool capability cannot also report a missing grant"
            )
        if self.expires_at <= self.observed_at:
            raise ConnectionPolicyError("a Tool probe must expire after observation")
        return self

    @property
    def probe_outcome(self) -> Literal["PASSED", "FAILED"]:
        """The two-valued outcome `tool_probe_receipts` stores.

        Every non-GRANTED observation collapses to FAILED. The richer reason
        survives in `reason_code`, so a denial and an unreachable provider stay
        distinguishable to an operator without either one being storable as a
        pass.
        """

        return "PASSED" if self.available else "FAILED"
