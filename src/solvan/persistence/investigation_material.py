"""Canonical hashes for immutable investigation control material."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from solvan.application.investigation import CoordinatorAuthority
from solvan.domain import AcceptedInvestigationPlan, Scope


def plan_content_hash(plan: AcceptedInvestigationPlan) -> str:
    return _sha256(
        {
            "objective": plan.objective,
            "completion_condition": plan.completion_condition,
            "uncertainties": plan.uncertainties,
            "steps": [
                {
                    "ordinal": item.ordinal,
                    **asdict(item.proposal),
                    "agent_resource": item.agent_resource,
                    "agent_revision": item.agent_revision,
                    "allowed_tool_names": item.allowed_tool_names,
                }
                for item in plan.steps
            ],
        }
    )


def input_hash(
    scope: Scope,
    incident_id: str,
    authority: CoordinatorAuthority,
    step: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> str:
    return _sha256(
        {
            "scope": scope.canonical_dict(),
            "incident_id": incident_id,
            "workflow_version": authority.workflow_version,
            "plan_id": step["plan_id"],
            "step_id": step["id"],
            "step_key": step["step_key"],
            "scope_ref": step["scope_ref"],
            "purpose": step["purpose"],
            "agent_resource": step["agent_resource"],
            "agent_revision": step["agent_revision"],
            "allowed_tool_names": step["allowed_tool_names_json"],
            "budget": step["budget_json"],
            "context": context or {},
        }
    )


def _sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
