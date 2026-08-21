"""Immutable, bounded projections returned by the GitHub REST boundary."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GitHubPullRequestResponse:
    number: int
    node_id: str
    html_url: str
    head_sha: str
    base_sha: str
    state: str
    merged: bool
    mergeable_state: str | None
    title: str
    draft: bool
    merge_commit_sha: str | None


@dataclass(frozen=True, slots=True)
class GitHubCheckRunResponse:
    external_id: int
    name: str
    status: str
    conclusion: str | None
    head_sha: str
    details_url: str | None


@dataclass(frozen=True, slots=True)
class GitHubReviewResponse:
    external_id: int
    account_node_id: str
    state: str
    commit_sha: str
    submitted_at: str


@dataclass(frozen=True, slots=True)
class GitHubPullRequestFileResponse:
    path: str
    status: str
    blob_sha: str


@dataclass(frozen=True, slots=True)
class GitHubMergeResponse:
    merged: bool
    merge_commit_sha: str | None
    message: str
