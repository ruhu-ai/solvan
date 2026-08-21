"""Validation helpers for permanent-repair repository policy and evidence."""

from __future__ import annotations

from typing import Any, cast

from solvan.application import RepairPlanningError
from solvan.domain import Scope

REPOSITORY_KEYS = {
    "repository_binding_id",
    "repository_snapshot_uri",
    "repository_snapshot_hash",
    "base_commit_sha",
    "reproduction_command_definition_id",
    "regression_command_definition_id",
    "allowed_file_globs",
    "artifact_output_uri",
    "provider",
}
_PROVIDERS = {"GEMINI_ADK_AGENT_ENGINE", "ANTIGRAVITY_SDK_CLOUD_RUN"}


def confirmed_evidence_refs(
    cursor: Any, scope: Scope, *, confirmed_root_cause_id: str
) -> tuple[str, ...]:
    cursor.execute(
        """SELECT supporting_evidence_refs
          FROM solvan.hypotheses
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND id = %(hypothesis_id)s AND status = 'CONFIRMED'""",
        {**scope.canonical_dict(), "hypothesis_id": confirmed_root_cause_id},
    )
    row = cursor.fetchone()
    refs = None if row is None else row["supporting_evidence_refs"]
    if not isinstance(refs, list) or not refs:
        raise RepairPlanningError("confirmed root cause has no durable supporting evidence")
    values = tuple(str(item) for item in refs)
    if any(not value for value in values) or len(values) != len(set(values)):
        raise RepairPlanningError("confirmed root-cause evidence references are malformed")
    return values


def validate_repository_policy(policy: dict[str, Any]) -> None:
    string_keys = REPOSITORY_KEYS - {"allowed_file_globs"}
    if any(not isinstance(policy[key], str) or not policy[key].strip() for key in string_keys):
        raise RepairPlanningError("repository policy string fields must be non-empty")
    snapshot_hash = cast(str, policy["repository_snapshot_hash"])
    if len(snapshot_hash) != 71 or not snapshot_hash.startswith("sha256:"):
        raise RepairPlanningError("repository snapshot hash must be sha256")
    try:
        int(snapshot_hash.removeprefix("sha256:"), 16)
    except ValueError as error:
        raise RepairPlanningError("repository snapshot hash must be sha256") from error
    commit = cast(str, policy["base_commit_sha"])
    if len(commit) != 40:
        raise RepairPlanningError("repository base commit must be a full SHA")
    try:
        int(commit, 16)
    except ValueError as error:
        raise RepairPlanningError("repository base commit must be a full SHA") from error
    globs = policy["allowed_file_globs"]
    if (
        not isinstance(globs, list)
        or not globs
        or not all(isinstance(item, str) and item and not item.startswith("/") for item in globs)
        or len(globs) != len(set(globs))
    ):
        raise RepairPlanningError("repository allowed file globs are malformed")
    if policy["provider"] not in _PROVIDERS:
        raise RepairPlanningError("repository workspace provider is unsupported")
    if not cast(str, policy["repository_snapshot_uri"]).startswith("gs://"):
        raise RepairPlanningError("repository snapshot must be a GCS URI")
    if not cast(str, policy["artifact_output_uri"]).startswith("gs://"):
        raise RepairPlanningError("repair artifact output must be a GCS URI")
    identifiers = {
        "repository_binding_id": "ghr_",
        "reproduction_command_definition_id": "rcd_",
        "regression_command_definition_id": "rcd_",
    }
    for key, prefix in identifiers.items():
        value = cast(str, policy[key])
        if not value.startswith(prefix) or len(value) != 30:
            raise RepairPlanningError(f"repository policy {key} is invalid")
    if policy["reproduction_command_definition_id"] == policy["regression_command_definition_id"]:
        raise RepairPlanningError("reproduction and regression commands must be distinct")
