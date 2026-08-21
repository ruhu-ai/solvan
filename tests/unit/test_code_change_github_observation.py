from __future__ import annotations

import base64

import pytest

from solvan.application.code_change_github_observation import (
    GitHubObservationError,
    required_check_projection,
    review_projection,
    validate_branch_rule,
    validate_changed_files,
)
from solvan.application.code_change_transform import CanonicalPatchTransform, TransformOperation
from solvan.application.workspace_hashing import sha256_bytes
from solvan.platform.github_contracts import (
    GitHubCheckRunResponse,
    GitHubPullRequestFileResponse,
    GitHubReviewResponse,
)


def _transform() -> CanonicalPatchTransform:
    return CanonicalPatchTransform(
        "solvan-regular-tree-transform/v1",
        "a" * 40,
        "sha256:" + "1" * 64,
        "sha256:" + "2" * 64,
        (
            TransformOperation(
                "REPLACE",
                "src/app.py",
                "sha256:" + "3" * 64,
                "100644",
                sha256_bytes(b"new\n"),
                "100644",
                base64.b64encode(b"new\n").decode(),
            ),
        ),
    )


def test_diff_must_equal_the_frozen_transform() -> None:
    assert validate_changed_files(
        transform=_transform(),
        files=(GitHubPullRequestFileResponse("src/app.py", "modified", "b" * 40),),
    ).startswith("sha256:")
    with pytest.raises(GitHubObservationError, match="diff differs"):
        validate_changed_files(
            transform=_transform(),
            files=(GitHubPullRequestFileResponse("src/other.py", "modified", "b" * 40),),
        )


def test_required_checks_are_head_bound_and_fail_closed() -> None:
    head = "b" * 40
    passing = GitHubCheckRunResponse(2, "unit", "COMPLETED", "SUCCESS", head, None)
    state, document = required_check_projection(
        required_names=("unit",), runs=(passing,), head_sha=head
    )
    assert state == "PASSING"
    assert document["state"] == "PASSING"
    state, _ = required_check_projection(
        required_names=("security",), runs=(passing,), head_sha=head
    )
    assert state == "PENDING"
    with pytest.raises(GitHubObservationError, match="another head"):
        required_check_projection(
            required_names=("unit",),
            runs=(GitHubCheckRunResponse(2, "unit", "COMPLETED", "SUCCESS", "c" * 40, None),),
            head_sha=head,
        )


def test_review_requires_githubs_authoritative_decision_and_exact_head() -> None:
    head = "b" * 40
    review = GitHubReviewResponse(4, "U_node", "APPROVED", head, "2026-08-17T00:00:00Z")
    state, _ = review_projection(
        reviews=(review,),
        head_sha=head,
        github_review_decision="APPROVED",
        reviewer_policy={"minimum_approvals": 1, "require_code_owner_review": True},
    )
    assert state == "APPROVED"
    stale = GitHubReviewResponse(4, "U_node", "APPROVED", "c" * 40, "2026-08-17T00:00:00Z")
    state, _ = review_projection(
        reviews=(stale,),
        head_sha=head,
        github_review_decision="APPROVED",
        reviewer_policy={"minimum_approvals": 1, "require_code_owner_review": True},
    )
    assert state == "PENDING"


def test_branch_protection_cannot_be_weaker_than_frozen_policy() -> None:
    rule = {
        "schema_version": 1,
        "required_status_check_contexts": ["security", "unit"],
        "strict_status_checks": True,
        "required_approving_review_count": 1,
        "require_code_owner_reviews": True,
        "enforce_admins": True,
        "restrictions_present": False,
    }
    assert (
        validate_branch_rule(
            observed=rule,
            required_checks=("unit",),
            reviewer_policy={"minimum_approvals": 1, "require_code_owner_review": True},
        )
        == rule
    )
    with pytest.raises(GitHubObservationError, match="weaker"):
        validate_branch_rule(
            observed=rule | {"enforce_admins": False},
            required_checks=("unit",),
            reviewer_policy={"minimum_approvals": 1, "require_code_owner_review": True},
        )
