"""Exact, stage-specific human decision material for governed code delivery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from solvan.application.workspace_hashing import canonical_sha256


class CodeChangeDecisionError(ValueError):
    """Decision material is incomplete, stale, or not reviewable."""


class CodeChangeDecisionStage(StrEnum):
    PR_CREATION = "PR_CREATION"
    MERGE = "MERGE"
    DEPLOYMENT = "DEPLOYMENT"
    ROLLBACK = "ROLLBACK"


class CodeChangeDecisionValue(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


_EXPECTED_STATE = {
    CodeChangeDecisionStage.PR_CREATION: "PR_CREATION_APPROVAL_PENDING",
    CodeChangeDecisionStage.MERGE: "MERGE_APPROVAL_PENDING",
    CodeChangeDecisionStage.DEPLOYMENT: "DEPLOYMENT_APPROVAL_PENDING",
    CodeChangeDecisionStage.ROLLBACK: "ROLLBACK_APPROVAL_PENDING",
}

_REQUIRED_ROLE = {
    CodeChangeDecisionStage.PR_CREATION: "CODE_CHANGE_APPROVER",
    CodeChangeDecisionStage.MERGE: "CODE_CHANGE_APPROVER",
    CodeChangeDecisionStage.DEPLOYMENT: "RELEASE_APPROVER",
    CodeChangeDecisionStage.ROLLBACK: "RELEASE_APPROVER",
}


@dataclass(frozen=True, slots=True)
class DecisionMaterial:
    code_change_request_id: str
    stage: CodeChangeDecisionStage
    required_role: str
    material: Mapping[str, object]
    digest: str
    expires_at: datetime
    github_reviewer_binding_id: str | None = None
    github_review_state_hash: str | None = None
    release_candidate_id: str | None = None
    release_target_profile_id: str | None = None
    release_target_observation_hash: str | None = None
    release_health_baseline_id: str | None = None
    release_health_baseline_hash: str | None = None
    deployment_rollout_id: str | None = None
    release_verification_receipt_hash: str | None = None


def reserved_branch_name(code_change_request_id: str) -> str:
    if not code_change_request_id.startswith("ccr_"):
        raise CodeChangeDecisionError("code-change request identifier is invalid")
    return f"solvan/ccr/{code_change_request_id}"


def pr_creation_decision_material(
    *, request: Mapping[str, object], expires_at: datetime
) -> DecisionMaterial:
    """Bind approval to the exact qualified request and derived reserved ref."""

    if request.get("state") != _EXPECTED_STATE[CodeChangeDecisionStage.PR_CREATION]:
        raise CodeChangeDecisionError("PR creation is not awaiting a decision")
    request_id = _required_text(request, "id")
    request_expiry = request.get("expires_at")
    if not isinstance(request_expiry, datetime) or expires_at > request_expiry:
        raise CodeChangeDecisionError("decision expiry exceeds the request lifetime")
    material: dict[str, object] = {
        "schema_version": 1,
        "stage": CodeChangeDecisionStage.PR_CREATION.value,
        "code_change_request_id": request_id,
        "immutable_request_hash": _required_text(request, "immutable_request_hash"),
        "repository_binding_id": _required_text(request, "repository_binding_id"),
        "repository_policy_hash": _required_text(request, "repository_policy_hash"),
        "base_commit_sha": _required_text(request, "base_commit_sha"),
        "base_tree_hash": _required_text(request, "base_tree_hash"),
        "proposed_tree_hash": _required_text(request, "proposed_tree_hash"),
        "patch_transform_hash": _required_text(request, "patch_transform_hash"),
        "allowed_paths_hash": _required_text(request, "allowed_paths_hash"),
        "required_check_definition_paths_hash": _required_text(
            request, "required_check_definition_paths_hash"
        ),
        "base_required_check_definitions_hash": _required_text(
            request, "base_required_check_definitions_hash"
        ),
        "pr_creation_policy_hash": _required_text(request, "pr_creation_policy_hash"),
        "reserved_branch": reserved_branch_name(request_id),
        "request_sequence_no": _required_integer(request, "sequence_no"),
        "expires_at": expires_at.isoformat(),
    }
    return DecisionMaterial(
        code_change_request_id=request_id,
        stage=CodeChangeDecisionStage.PR_CREATION,
        required_role=_REQUIRED_ROLE[CodeChangeDecisionStage.PR_CREATION],
        material=material,
        digest=canonical_sha256(material),
        expires_at=expires_at,
    )


def merge_decision_material(
    *, request: Mapping[str, object], github: Mapping[str, object], expires_at: datetime
) -> DecisionMaterial:
    """Bind merge approval to one exact provider observation and reviewer link."""

    if request.get("state") != _EXPECTED_STATE[CodeChangeDecisionStage.MERGE]:
        raise CodeChangeDecisionError("merge is not awaiting a decision")
    if github.get("required_check_state") != "PASSING" or github.get("review_state") != "APPROVED":
        raise CodeChangeDecisionError("GitHub checks and required review are not current")
    request_id = _required_text(request, "id")
    request_expiry = request.get("expires_at")
    binding_expiry = github.get("binding_expires_at")
    observed_at = github.get("observed_at")
    if (
        not isinstance(request_expiry, datetime)
        or not isinstance(binding_expiry, datetime)
        or not isinstance(observed_at, datetime)
        or expires_at > request_expiry
        or expires_at > binding_expiry
    ):
        raise CodeChangeDecisionError("merge material lifetime is invalid")
    binding_id = _required_text(github, "github_reviewer_binding_id")
    review_hash = _required_text(github, "review_state_hash")
    material: dict[str, object] = {
        "schema_version": 1,
        "stage": CodeChangeDecisionStage.MERGE.value,
        "code_change_request_id": request_id,
        "immutable_request_hash": _required_text(request, "immutable_request_hash"),
        "repository_binding_id": _required_text(request, "repository_binding_id"),
        "repository_policy_hash": _required_text(request, "repository_policy_hash"),
        "pull_request_number": _required_integer(github, "pull_request_number"),
        "pull_request_url": _required_text(github, "pull_request_url"),
        "base_commit_sha": _required_text(github, "base_commit_sha"),
        "head_commit_sha": _required_text(github, "head_commit_sha"),
        "head_tree_hash": _required_text(github, "head_tree_hash"),
        "diff_hash": _required_text(github, "diff_hash"),
        "required_checks_hash": _required_text(github, "required_checks_hash"),
        "branch_rule_hash": _required_text(github, "branch_rule_hash"),
        "review_state_hash": review_hash,
        "required_check_definitions_hash": _required_text(
            github, "required_check_definitions_hash"
        ),
        "github_observation_hash": _required_text(github, "observation_hash"),
        "github_observation_sequence_no": _required_integer(github, "observation_sequence_no"),
        "github_reviewer_binding_id": binding_id,
        "github_account_node_id": _required_text(github, "github_account_node_id"),
        "github_binding_proof_hash": _required_text(github, "binding_proof_hash"),
        "reviewer_policy_hash": _required_text(request, "reviewer_policy_hash"),
        "merge_policy_hash": _required_text(request, "merge_policy_hash"),
        "request_sequence_no": _required_integer(request, "sequence_no"),
        "observed_at": observed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    return DecisionMaterial(
        code_change_request_id=request_id,
        stage=CodeChangeDecisionStage.MERGE,
        required_role=_REQUIRED_ROLE[CodeChangeDecisionStage.MERGE],
        material=material,
        digest=canonical_sha256(material),
        expires_at=expires_at,
        github_reviewer_binding_id=binding_id,
        github_review_state_hash=review_hash,
    )


def deployment_decision_material(
    *, request: Mapping[str, object], release: Mapping[str, object], expires_at: datetime
) -> DecisionMaterial:
    """Bind deployment approval to one signed candidate and fresh target state."""

    if request.get("state") != _EXPECTED_STATE[CodeChangeDecisionStage.DEPLOYMENT]:
        raise CodeChangeDecisionError("deployment is not awaiting a decision")
    request_expiry = request.get("expires_at")
    observed_at = release.get("observed_at")
    if (
        not isinstance(request_expiry, datetime)
        or not isinstance(observed_at, datetime)
        or expires_at > request_expiry
    ):
        raise CodeChangeDecisionError("deployment material lifetime is invalid")
    request_id = _required_text(request, "id")
    candidate_id = _required_text(release, "release_candidate_id")
    target_profile_id = _required_text(release, "release_target_profile_id")
    observation_hash = _required_text(release, "observation_hash")
    baseline_id = _required_text(release, "release_health_baseline_id")
    baseline_hash = _required_text(release, "release_health_baseline_hash")
    effect_inputs = {
        "release_candidate_id": candidate_id,
        "build_artifact_hash": _required_text(release, "build_artifact_hash"),
        "target_key": _required_text(release, "target_key"),
        "verification_profile_hash": _required_text(release, "verification_profile_hash"),
        "release_health_baseline_hash": baseline_hash,
    }
    effect_inputs_hash = canonical_sha256(effect_inputs)
    intended_effect_hash = canonical_sha256(
        {
            "schema_version": 1,
            "template_id": "cloud-run-release-health",
            "template_version": "1",
            "input_refs_hash": effect_inputs_hash,
            "predicate": (
                "candidate revision serves traffic without degrading registered health signals"
            ),
        }
    )
    material: dict[str, object] = {
        "schema_version": 1,
        "stage": CodeChangeDecisionStage.DEPLOYMENT.value,
        "code_change_request_id": request_id,
        "immutable_request_hash": _required_text(request, "immutable_request_hash"),
        "request_sequence_no": _required_integer(request, "sequence_no"),
        "deployment_policy_hash": _required_text(request, "deployment_policy_hash"),
        "release_candidate_id": candidate_id,
        "merged_commit_sha": _required_text(release, "merged_commit_sha"),
        "source_tree_hash": _required_text(release, "source_tree_hash"),
        "build_artifact_ref": _required_text(release, "build_artifact_ref"),
        "build_artifact_hash": _required_text(release, "build_artifact_hash"),
        "provenance_hash": _required_text(release, "provenance_hash"),
        "release_signature_hash": _required_text(release, "release_signature_hash"),
        "signer_identity": _required_text(release, "signer_identity"),
        "signer_key_version": _required_text(release, "signer_key_version"),
        "deployment_manifest_hash": _required_text(release, "deployment_manifest_hash"),
        "release_target_profile_id": target_profile_id,
        "release_target_profile_hash": _required_text(release, "release_target_profile_hash"),
        "target_key": _required_text(release, "target_key"),
        "service_resource_name": _required_text(release, "service_resource_name"),
        "target_version": _required_text(release, "target_version"),
        "target_epoch": _required_integer(release, "target_epoch"),
        "service_generation": _required_integer(release, "service_generation"),
        "service_etag_hash": _required_text(release, "service_etag_hash"),
        "predeploy_release_candidate_id": _required_text(release, "current_release_candidate_id"),
        "predeploy_revision": _required_text(release, "current_revision"),
        "predeploy_assignment_hash": _required_text(release, "assignment_hash"),
        "target_observation_hash": observation_hash,
        "release_health_baseline_id": baseline_id,
        "release_health_baseline_ref": _required_text(release, "release_health_baseline_ref"),
        "release_health_baseline_hash": baseline_hash,
        "rollout_policy_hash": _required_text(release, "rollout_policy_hash"),
        "verification_profile_id": _required_text(release, "verification_profile_id"),
        "verification_profile_version": _required_text(release, "verification_profile_version"),
        "verification_profile_hash": _required_text(release, "verification_profile_hash"),
        "release_effect_template_id": "cloud-run-release-health",
        "release_effect_template_version": "1",
        "release_effect_input_refs_hash": effect_inputs_hash,
        "intended_effect_hash": intended_effect_hash,
        "observed_at": observed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    return DecisionMaterial(
        code_change_request_id=request_id,
        stage=CodeChangeDecisionStage.DEPLOYMENT,
        required_role=_REQUIRED_ROLE[CodeChangeDecisionStage.DEPLOYMENT],
        material=material,
        digest=canonical_sha256(material),
        expires_at=expires_at,
        release_candidate_id=candidate_id,
        release_target_profile_id=target_profile_id,
        release_target_observation_hash=observation_hash,
        release_health_baseline_id=baseline_id,
        release_health_baseline_hash=baseline_hash,
    )


def rollback_decision_material(
    *, request: Mapping[str, object], rollback: Mapping[str, object], expires_at: datetime
) -> DecisionMaterial:
    """Bind rollback approval to the frozen prior release and latest failed receipt."""

    if request.get("state") != _EXPECTED_STATE[CodeChangeDecisionStage.ROLLBACK]:
        raise CodeChangeDecisionError("rollback is not awaiting a decision")
    request_expiry = request.get("expires_at")
    observed_at = rollback.get("observed_at")
    if (
        not isinstance(request_expiry, datetime)
        or not isinstance(observed_at, datetime)
        or expires_at > request_expiry
    ):
        raise CodeChangeDecisionError("rollback material lifetime is invalid")
    request_id = _required_text(request, "id")
    rollout_id = _required_text(rollback, "deployment_rollout_id")
    receipt_hash = _required_text(rollback, "receipt_envelope_hash")
    material: dict[str, object] = {
        "schema_version": 1,
        "stage": CodeChangeDecisionStage.ROLLBACK.value,
        "code_change_request_id": request_id,
        "immutable_request_hash": _required_text(request, "immutable_request_hash"),
        "request_sequence_no": _required_integer(request, "sequence_no"),
        "rollback_policy_hash": _required_text(request, "rollback_policy_hash"),
        "deployment_rollout_id": rollout_id,
        "release_candidate_id": _required_text(rollback, "release_candidate_id"),
        "target_key": _required_text(rollback, "target_key"),
        "release_target_profile_id": _required_text(rollback, "release_target_profile_id"),
        "release_target_profile_hash": _required_text(rollback, "release_target_profile_hash"),
        "target_reservation_id": _required_text(rollback, "target_reservation_id"),
        "rollback_release_candidate_id": _required_text(rollback, "rollback_release_candidate_id"),
        "rollback_revision": _required_text(rollback, "rollback_revision"),
        "rollback_assignment_hash": _required_text(rollback, "rollback_assignment_hash"),
        "failed_verification_result": _required_text(rollback, "result"),
        "failed_verification_stage_ordinal": _required_integer(rollback, "stage_ordinal"),
        "failed_verification_receipt_hash": receipt_hash,
        "observed_target_version": _required_text(rollback, "observed_target_version"),
        "observed_assignment_hash": _required_text(rollback, "observed_assignment_hash"),
        "observed_at": observed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    return DecisionMaterial(
        code_change_request_id=request_id,
        stage=CodeChangeDecisionStage.ROLLBACK,
        required_role=_REQUIRED_ROLE[CodeChangeDecisionStage.ROLLBACK],
        material=material,
        digest=canonical_sha256(material),
        expires_at=expires_at,
        deployment_rollout_id=rollout_id,
        release_verification_receipt_hash=receipt_hash,
    )


def expected_state(stage: CodeChangeDecisionStage) -> str:
    return _EXPECTED_STATE[stage]


def required_role(stage: CodeChangeDecisionStage) -> str:
    return _REQUIRED_ROLE[stage]


def _required_text(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise CodeChangeDecisionError(f"decision source lacks {key}")
    return item


def _required_integer(value: Mapping[str, object], key: str) -> int:
    item = value.get(key)
    if type(item) is not int or item < 0:
        raise CodeChangeDecisionError(f"decision source lacks {key}")
    return item
