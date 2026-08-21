"""Deterministic validation and projection of governed GitHub PR state."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from solvan.application.code_change_transform import CanonicalPatchTransform
from solvan.application.workspace_hashing import canonical_sha256


class PullRequestFile(Protocol):
    @property
    def path(self) -> str: ...

    @property
    def status(self) -> str: ...


class CheckRun(Protocol):
    @property
    def external_id(self) -> int: ...

    @property
    def name(self) -> str: ...

    @property
    def status(self) -> str: ...

    @property
    def conclusion(self) -> str | None: ...

    @property
    def head_sha(self) -> str: ...

    @property
    def details_url(self) -> str | None: ...


class PullRequestReview(Protocol):
    @property
    def external_id(self) -> int: ...

    @property
    def account_node_id(self) -> str: ...

    @property
    def state(self) -> str: ...

    @property
    def commit_sha(self) -> str: ...

    @property
    def submitted_at(self) -> str: ...


class GitHubObservationError(ValueError):
    """Observed GitHub material is ambiguous or outside frozen policy."""


def validate_changed_files(
    *, transform: CanonicalPatchTransform, files: Sequence[PullRequestFile]
) -> str:
    expected = [
        {
            "path": item.path,
            "status": {"CREATE": "added", "REPLACE": "modified", "DELETE": "removed"}[item.kind],
        }
        for item in transform.operations
    ]
    observed = [{"path": item.path, "status": item.status} for item in files]
    if observed != expected:
        raise GitHubObservationError("GitHub pull-request diff differs from frozen transform")
    return canonical_sha256(observed)


def required_check_projection(
    *, required_names: Sequence[str], runs: Sequence[CheckRun], head_sha: str
) -> tuple[str, dict[str, object]]:
    if not required_names or len(required_names) != len(set(required_names)):
        raise GitHubObservationError("required-check policy is malformed")
    current: dict[str, CheckRun] = {}
    for run in runs:
        if run.head_sha != head_sha:
            raise GitHubObservationError("GitHub check run is bound to another head")
        if run.name in current and current[run.name].external_id == run.external_id:
            raise GitHubObservationError("GitHub check run identity is duplicated")
        if run.name not in current or run.external_id > current[run.name].external_id:
            current[run.name] = run
    selected = [current.get(name) for name in required_names]
    if any(item is None or item.status != "COMPLETED" for item in selected):
        state = "PENDING"
    elif any(item is not None and item.conclusion != "SUCCESS" for item in selected):
        state = "FAILING"
    else:
        state = "PASSING"
    document = {
        "schema_version": 1,
        "head_commit_sha": head_sha,
        "required_checks": list(required_names),
        "state": state,
        "check_runs": [
            {
                "external_id": item.external_id,
                "name": item.name,
                "status": item.status,
                "conclusion": item.conclusion,
                "details_url": item.details_url,
            }
            for item in selected
            if item is not None
        ],
    }
    return state, document


def review_projection(
    *,
    reviews: Sequence[PullRequestReview],
    head_sha: str,
    github_review_decision: str,
    reviewer_policy: Mapping[str, object],
) -> tuple[str, dict[str, object]]:
    minimum = reviewer_policy.get("minimum_approvals")
    require_code_owner = reviewer_policy.get("require_code_owner_review")
    if (
        not isinstance(minimum, int)
        or not 1 <= minimum <= 10
        or not isinstance(require_code_owner, bool)
    ):
        raise GitHubObservationError("reviewer policy is malformed")
    latest: dict[str, PullRequestReview] = {}
    for review in reviews:
        previous = latest.get(review.account_node_id)
        if previous is None or (review.submitted_at, review.external_id) > (
            previous.submitted_at,
            previous.external_id,
        ):
            latest[review.account_node_id] = review
    approvals = sorted(
        item.account_node_id
        for item in latest.values()
        if item.state == "APPROVED" and item.commit_sha == head_sha
    )
    if github_review_decision == "CHANGES_REQUESTED":
        state = "CHANGES_REQUESTED"
    elif github_review_decision == "APPROVED" and len(approvals) >= minimum:
        state = "APPROVED"
    else:
        state = "PENDING"
    document = {
        "schema_version": 1,
        "head_commit_sha": head_sha,
        "github_review_decision": github_review_decision,
        "minimum_approvals": minimum,
        "require_code_owner_review": require_code_owner,
        "state": state,
        "reviews": [
            {
                "external_id": item.external_id,
                "account_node_id": item.account_node_id,
                "state": item.state,
                "commit_sha": item.commit_sha,
                "submitted_at": item.submitted_at,
            }
            for item in sorted(latest.values(), key=lambda value: value.account_node_id)
        ],
    }
    return state, document


def validate_branch_rule(
    *,
    observed: Mapping[str, object],
    required_checks: Sequence[str],
    reviewer_policy: Mapping[str, object],
) -> dict[str, object]:
    contexts = observed.get("required_status_check_contexts")
    minimum = reviewer_policy.get("minimum_approvals")
    code_owner = reviewer_policy.get("require_code_owner_review")
    observed_approvals = observed.get("required_approving_review_count")
    if (
        not isinstance(contexts, list)
        or any(not isinstance(item, str) for item in contexts)
        or not set(required_checks).issubset(contexts)
        or observed.get("strict_status_checks") is not True
        or observed.get("enforce_admins") is not True
        or not isinstance(observed_approvals, int)
        or not isinstance(minimum, int)
        or observed_approvals < minimum
        or (code_owner is True and observed.get("require_code_owner_reviews") is not True)
    ):
        raise GitHubObservationError("GitHub branch protection is weaker than frozen policy")
    return dict(observed)
