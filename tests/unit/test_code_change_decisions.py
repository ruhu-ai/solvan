from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.code_change_decisions import (
    CodeChangeDecisionError,
    deployment_decision_material,
    merge_decision_material,
    pr_creation_decision_material,
    reserved_branch_name,
)


def _request(now: datetime) -> dict[str, object]:
    return {
        "id": "ccr_00000000000000000000000001",
        "state": "PR_CREATION_APPROVAL_PENDING",
        "sequence_no": 1,
        "immutable_request_hash": "sha256:" + "1" * 64,
        "repository_binding_id": "ghr_00000000000000000000000001",
        "repository_policy_hash": "sha256:" + "2" * 64,
        "base_commit_sha": "3" * 40,
        "base_tree_hash": "sha256:" + "4" * 64,
        "proposed_tree_hash": "sha256:" + "5" * 64,
        "patch_transform_hash": "sha256:" + "6" * 64,
        "allowed_paths_hash": "sha256:" + "7" * 64,
        "required_check_definition_paths_hash": "sha256:" + "8" * 64,
        "base_required_check_definitions_hash": "sha256:" + "9" * 64,
        "pr_creation_policy_hash": "sha256:" + "a" * 64,
        "expires_at": now + timedelta(hours=1),
    }


def test_pr_creation_material_derives_reserved_branch_and_binds_expiry() -> None:
    now = datetime(2026, 8, 17, tzinfo=UTC)
    result = pr_creation_decision_material(
        request=_request(now), expires_at=now + timedelta(minutes=5)
    )
    assert result.material["reserved_branch"] == ("solvan/ccr/ccr_00000000000000000000000001")
    assert result.required_role == "CODE_CHANGE_APPROVER"
    assert result.digest.startswith("sha256:")


def test_pr_creation_material_refuses_wrong_state_and_lifetime() -> None:
    now = datetime(2026, 8, 17, tzinfo=UTC)
    source = _request(now)
    source["state"] = "PATCH_VALIDATED"
    with pytest.raises(CodeChangeDecisionError, match="not awaiting"):
        pr_creation_decision_material(request=source, expires_at=now + timedelta(minutes=5))
    source["state"] = "PR_CREATION_APPROVAL_PENDING"
    with pytest.raises(CodeChangeDecisionError, match="exceeds"):
        pr_creation_decision_material(request=source, expires_at=now + timedelta(hours=2))


def test_reserved_branch_cannot_be_caller_selected() -> None:
    assert reserved_branch_name("ccr_00000000000000000000000001").startswith("solvan/ccr/")
    with pytest.raises(CodeChangeDecisionError):
        reserved_branch_name("attacker/main")


def test_merge_material_binds_exact_github_observation_and_reviewer_identity() -> None:
    now = datetime(2026, 8, 17, tzinfo=UTC)
    request = _request(now) | {
        "state": "MERGE_APPROVAL_PENDING",
        "reviewer_policy_hash": "sha256:" + "b" * 64,
        "merge_policy_hash": "sha256:" + "c" * 64,
    }
    github: dict[str, object] = {
        "pull_request_number": 42,
        "pull_request_url": "https://github.com/acme/service/pull/42",
        "base_commit_sha": "3" * 40,
        "head_commit_sha": "d" * 40,
        "head_tree_hash": "sha256:" + "5" * 64,
        "diff_hash": "sha256:" + "6" * 64,
        "required_check_state": "PASSING",
        "required_checks_hash": "sha256:" + "7" * 64,
        "branch_rule_hash": "sha256:" + "8" * 64,
        "review_state": "APPROVED",
        "review_state_hash": "sha256:" + "9" * 64,
        "required_check_definitions_hash": "sha256:" + "a" * 64,
        "observation_hash": "sha256:" + "d" * 64,
        "observation_sequence_no": 3,
        "github_reviewer_binding_id": "grb_00000000000000000000000001",
        "github_account_node_id": "MDQ6VXNlcjE=",
        "binding_proof_hash": "sha256:" + "e" * 64,
        "binding_expires_at": now + timedelta(hours=1),
        "observed_at": now,
    }

    result = merge_decision_material(
        request=request, github=github, expires_at=now + timedelta(minutes=5)
    )

    assert result.github_reviewer_binding_id == github["github_reviewer_binding_id"]
    assert result.material["github_observation_hash"] == github["observation_hash"]
    assert result.material["github_account_node_id"] == github["github_account_node_id"]


def test_merge_material_refuses_nonpassing_or_unreviewed_github_state() -> None:
    now = datetime(2026, 8, 17, tzinfo=UTC)
    request = _request(now) | {
        "state": "MERGE_APPROVAL_PENDING",
        "reviewer_policy_hash": "sha256:" + "b" * 64,
        "merge_policy_hash": "sha256:" + "c" * 64,
    }
    with pytest.raises(CodeChangeDecisionError, match="checks and required review"):
        merge_decision_material(
            request=request,
            github={"required_check_state": "PENDING", "review_state": "APPROVED"},
            expires_at=now + timedelta(minutes=5),
        )


def test_deployment_material_binds_candidate_target_prestate_and_effect() -> None:
    now = datetime(2026, 8, 17, tzinfo=UTC)
    request = _request(now) | {
        "state": "DEPLOYMENT_APPROVAL_PENDING",
        "deployment_policy_hash": "sha256:" + "b" * 64,
    }
    release: dict[str, object] = {
        "release_candidate_id": "rlc_00000000000000000000000001",
        "merged_commit_sha": "c" * 40,
        "source_tree_hash": "sha256:" + "d" * 64,
        "build_artifact_ref": "registry.example/app@sha256:" + "e" * 64,
        "build_artifact_hash": "sha256:" + "e" * 64,
        "provenance_hash": "sha256:" + "f" * 64,
        "release_signature_hash": "sha256:" + "1" * 64,
        "signer_identity": "serviceAccount:builder@example.iam.gserviceaccount.com",
        "signer_key_version": "projects/example/cryptoKeyVersions/1",
        "deployment_manifest_hash": "sha256:" + "2" * 64,
        "release_target_profile_id": "rtp_00000000000000000000000001",
        "release_target_profile_hash": "sha256:" + "3" * 64,
        "target_key": "cloud-run:production:payments",
        "service_resource_name": "projects/p/locations/r/services/s",
        "target_version": "7",
        "target_epoch": 2,
        "service_generation": 7,
        "service_etag_hash": "sha256:" + "4" * 64,
        "current_release_candidate_id": "rlc_00000000000000000000000000",
        "current_revision": "payments-old",
        "assignment_hash": "sha256:" + "5" * 64,
        "observation_hash": "sha256:" + "6" * 64,
        "rollout_policy_hash": "sha256:" + "7" * 64,
        "verification_profile_id": "payments-health",
        "verification_profile_version": "1",
        "verification_profile_hash": "sha256:" + "8" * 64,
        "release_health_baseline_id": "rhb_00000000000000000000000001",
        "release_health_baseline_ref": "gs://evidence/baseline.json",
        "release_health_baseline_hash": "sha256:" + "9" * 64,
        "observed_at": now,
    }
    result = deployment_decision_material(
        request=request, release=release, expires_at=now + timedelta(minutes=5)
    )
    assert result.release_candidate_id == release["release_candidate_id"]
    assert result.release_target_observation_hash == release["observation_hash"]
    assert result.release_health_baseline_id == release["release_health_baseline_id"]
    assert (
        result.material["predeploy_release_candidate_id"] == release["current_release_candidate_id"]
    )
    assert str(result.material["intended_effect_hash"]).startswith("sha256:")
