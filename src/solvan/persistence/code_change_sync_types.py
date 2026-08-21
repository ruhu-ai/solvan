"""Typed coordinator/provider material for governed GitHub PR synchronization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PullRequestSyncCandidate:
    request_id: str
    material_hash: str
    generation: int
    sequence_no: int
    deadline: datetime


@dataclass(frozen=True, slots=True)
class PullRequestSyncMaterial:
    request_id: str
    repository_binding_id: str
    repository_policy_hash: str
    installation_id: int
    owner: str
    name: str
    default_branch: str
    base_commit_sha: str
    proposed_tree_hash: str
    patch_transform_ref: str
    patch_transform_hash: str
    required_checks_policy_ref: str
    required_checks_policy_hash: str
    reviewer_policy_ref: str
    reviewer_policy_hash: str
    required_check_definition_paths: tuple[str, ...]
    base_required_check_definitions_hash: str
    branch_name: str
    pull_request_number: int
    pull_request_url: str
    expected_head_commit_sha: str
    previous_observation_hash: str
    request_state: str
    request_sequence_no: int
    expires_at: datetime
