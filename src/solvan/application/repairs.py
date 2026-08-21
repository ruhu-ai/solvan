"""Immutable permanent-repair planning contracts."""

from __future__ import annotations

from dataclasses import dataclass


class RepairPlanningError(RuntimeError):
    """The case or approved repository policy cannot define an exact repair."""


@dataclass(frozen=True, slots=True)
class RepairPlanRecord:
    repair_plan_id: str
    reliability_case_id: str
    plan_version: int
    repository_node_id: str
    repository_snapshot_uri: str
    repository_snapshot_hash: str
    base_commit_sha: str
    reproduction_command: str
    allowed_file_globs: tuple[str, ...]
    test_command: str
    artifact_output_uri: str
    confirmed_root_cause_id: str
    evidence_refs: tuple[str, ...]
    provider: str
    content_hash: str
    created: bool


@dataclass(frozen=True, slots=True)
class WorkspaceAttemptMaterial:
    run_id: str
    workspace_id: str
    workspace_generation: int
    reliability_case_id: str
    repair_plan: RepairPlanRecord
    provider_output_ref: str
    provider_operation_name: str
    provider_revision: str
    provider_request_hash: str
    implementation_sdk_distribution_hash: str
    provider_artifact_digest: str
    effective_tool_set_hash: str
    effective_network_policy_hash: str
