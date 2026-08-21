"""Precommit the production code-repair Tool set before Workspace dispatch."""

from __future__ import annotations

from apps.coordinator.contracts import GovernedAgentBinding
from solvan.application.default_tool_catalog import catalog_profile
from solvan.application.effective_tool_set import (
    EffectiveToolBindingV1,
    EffectiveToolSetV1,
    ToolConnectionBindingKind,
    ToolRevisionRefV1,
    accepted_step_budget_hash,
)
from solvan.application.workspaces import WorkspaceTaskBudget
from solvan.domain import Scope

WORKSPACE_PROFILE_REF = "workspace.code-repair.v1@1"
WORKSPACE_GATEWAY_DESTINATION = "solvan-workspace-adapter.internal"
WORKSPACE_TOOL_ORDINALS = (1, 2, 3)


def production_workspace_tool_set(
    *,
    scope: Scope,
    agent_revision: str,
    runtime_region: str,
    binding: GovernedAgentBinding,
    budget: WorkspaceTaskBudget,
) -> EffectiveToolSetV1:
    """Build the exact preimage later reconstructed from published catalog rows."""

    if f"{binding.profile_key}@{binding.profile_version}" != WORKSPACE_PROFILE_REF:
        raise ValueError("Workspace Agent is not bound to the production code-repair profile")
    if binding.accepted_tool_ordinals != WORKSPACE_TOOL_ORDINALS:
        raise ValueError("Workspace Agent must accept the exact ordered code-repair Tool set")
    if binding.connection_epochs:
        raise ValueError("Workspace code-repair Tools cannot carry source connections")
    if binding.gateway_destinations != frozenset({WORKSPACE_GATEWAY_DESTINATION}):
        raise ValueError("Workspace Agent Gateway destination is not exact")
    ranks = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
    if binding.data_classification not in ranks or ranks[binding.data_classification] > 2:
        raise ValueError("Workspace code-repair classification exceeds its profile ceiling")

    profile = catalog_profile(
        agent_key="workspace-agent",
        approval_ref="preimage://catalog-approval-excluded-from-material",
        evaluation_ref="preimage://catalog-evaluation-excluded-from-material",
    )
    tools = tuple(
        ToolRevisionRefV1(tool_key=tool_key, version=version)
        for tool_key, version in (revision.rsplit("@", 1) for revision in profile.tool_revisions)
    )
    return EffectiveToolSetV1(
        profile_material_hash=profile.profile_material_hash,
        accepted_tools=tools,
        agent_key="workspace-agent",
        agent_revision=agent_revision,
        scope=scope.canonical_dict(),
        connection_bindings=tuple(
            EffectiveToolBindingV1(
                tool=tool,
                binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
            )
            for tool in tools
        ),
        runtime_region=runtime_region,
        accepted_data_classification=binding.data_classification,
        classification_ceiling=profile.data_classification_ceiling,
        policy_head_activation_id=None,
        policy_head_epoch=0,
        placement_epoch=1,
        accepted_step_budget_hash=accepted_step_budget_hash(budget),
    )
