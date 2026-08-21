"""The checked-in shape of one catalog Tool seed.

Its own module so the provider-specific seed lists can each import it without
importing one another. Capability metadata only: a seed grants no connection,
identity, Gateway route, or Runtime authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from solvan.application.tool_catalog import (
    EvidenceKind,
    ImplementationKind,
    ModelArmorCoverage,
    NoDataSemantics,
    PermissionClass,
)


@dataclass(frozen=True, slots=True)
class ToolSeed:
    key: str
    agent_key: str
    permission: PermissionClass
    implementation: ImplementationKind
    provider: str
    capability: str
    destination: str
    evidence_kind: EvidenceKind
    use_case: str
    retrieval_control: str
    no_data: NoDataSemantics = NoDataSemantics.UNKNOWN
    model_armor: ModelArmorCoverage = ModelArmorCoverage.NOT_SUPPORTED
    timeout_ms: int = 30_000
    max_input_bytes: int = 65_536
    max_output_bytes: int = 262_144
    default_call_budget: int = 3
