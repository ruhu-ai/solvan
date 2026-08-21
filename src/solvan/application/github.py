"""Typed contracts for the policy-bound GitHub release provider.

GitHub is a release-system integration, never an agent authority.  These
contracts deliberately carry immutable patch and commit digests so a provider
cannot turn a stale workspace result into a current repository mutation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.domain import Scope

GitHubOperationKind = Literal[
    "CREATE_PULL_REQUEST",
    "SYNC_PULL_REQUEST",
    "MERGE_PULL_REQUEST",
    "CLOSE_PULL_REQUEST",
    "CREATE_ISSUE",
    "POST_ISSUE_COMMENT",
    "SUBMIT_PULL_REQUEST_REVIEW",
]

#: The operations that publish text into a repository's conversation.  They are
#: granted independently of code-delivery authority: a binding that may comment
#: cannot thereby open a branch, and a binding that may merge has no voice in a
#: thread (specification 24 §1).
GITHUB_CONVERSATION_OPERATIONS: frozenset[str] = frozenset(
    {"CREATE_ISSUE", "POST_ISSUE_COMMENT", "SUBMIT_PULL_REQUEST_REVIEW"}
)
GitHubOperationStatus = Literal[
    "CREATED",
    "DISPATCHED",
    "SUCCEEDED",
    "FAILED",
    "REJECTED",
    "STALE",
]
GitHubPullRequestStatus = Literal[
    "PROPOSED",
    "OPEN",
    "CHANGES_REQUESTED",
    "APPROVED",
    "MERGED",
    "CLOSED",
    "DEPLOYED",
    "FAILED",
]

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_REF = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")


class GitHubContractError(ValueError):
    """A GitHub integration payload violates a fail-closed contract."""


class GitHubRepositoryBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    installation_id: int = Field(gt=0)
    owner: str = Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
    name: str = Field(pattern=r"^[A-Za-z0-9._-]{1,100}$")
    default_branch: str = Field(pattern=r"^[A-Za-z0-9._/-]{1,255}$")
    api_base_url: str = Field(pattern=r"^https://")
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    policy_hash: str = Field(pattern=_SHA.pattern)
    allowed_operations: tuple[GitHubOperationKind, ...] = ()
    status: Literal["PENDING", "ACTIVE", "DEGRADED", "REVOKED"] = "PENDING"

    @model_validator(mode="after")
    def validate_operations(self) -> GitHubRepositoryBinding:
        if len(set(self.allowed_operations)) != len(self.allowed_operations):
            raise GitHubContractError("GitHub operation allowlist contains duplicates")
        if "MERGE_PULL_REQUEST" in self.allowed_operations and self.classification == "RESTRICTED":
            raise GitHubContractError("restricted repositories cannot receive merge authority")
        return self


class GitHubWebhookEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    delivery_id: str = Field(pattern=r"^[A-Za-z0-9-]{8,128}$")
    event_name: str = Field(pattern=r"^[a-z_]{1,64}$")
    action: str | None = Field(default=None, pattern=r"^[a-z_]{1,64}$")
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    owner: str = Field(min_length=1, max_length=39)
    name: str = Field(min_length=1, max_length=100)
    sender_login: str | None = Field(default=None, max_length=100)
    installation_id: int | None = Field(default=None, gt=0)
    payload_hash: str = Field(pattern=_SHA.pattern)
    signature_verified: bool
    pull_request_number: int | None = Field(default=None, gt=0)
    pull_request_head_sha: str | None = Field(default=None, pattern=_GIT_SHA.pattern)
    pull_request_base_sha: str | None = Field(default=None, pattern=_GIT_SHA.pattern)
    pull_request_merged: bool | None = None
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def require_verified_signature(self) -> GitHubWebhookEnvelope:
        if not self.signature_verified:
            raise GitHubContractError("unverified GitHub webhook cannot enter the workflow")
        return self


class CreatePullRequestCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    patch_artifact_id: str = Field(pattern=r"^pat_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    patch_digest: str = Field(pattern=_SHA.pattern)
    base_commit_sha: str = Field(pattern=_GIT_SHA.pattern)
    head_commit_sha: str = Field(pattern=_GIT_SHA.pattern)
    branch_name: str = Field(pattern=r"^solvan/[a-z0-9][a-z0-9._/-]{1,100}$")
    title: str = Field(min_length=1, max_length=256)
    body: str = Field(min_length=1, max_length=16_000)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,128}$")
    actor_principal: str = Field(min_length=3, max_length=255)


class MergePullRequestCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    pull_request_id: str = Field(pattern=r"^ghp_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    expected_head_commit_sha: str = Field(pattern=_GIT_SHA.pattern)
    patch_review_id: str = Field(pattern=r"^prv_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    merge_method: Literal["merge", "squash", "rebase"] = "squash"
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,128}$")
    actor_principal: str = Field(min_length=3, max_length=255)


@dataclass(frozen=True, slots=True)
class GitHubOperationReceipt:
    operation_id: str
    status: GitHubOperationStatus
    operation: GitHubOperationKind
    pull_request_id: str | None
    external_number: int | None
    head_commit_sha: str | None
    response_hash: str | None
    receipt_ref: str | None
    error_class: str | None


def validate_ref(value: str) -> str:
    """Validate a branch/ref before it reaches a GitHub API path or body."""

    if _REF.fullmatch(value) is None or value.startswith(("/", "-")) or ".." in value:
        raise GitHubContractError("GitHub ref is unsafe")
    return value


def ensure_scope(scope: Scope, candidate: Scope) -> None:
    if scope != candidate:
        raise GitHubContractError("GitHub object belongs to another tenant scope")


def operation_hash(value: dict[str, Any]) -> str:
    """Return a stable operation hash without serialising secrets."""

    import hashlib
    import json

    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )
