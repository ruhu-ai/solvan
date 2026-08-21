"""Request shapes for the provider's code-delivery evidence reads.

Separated from the routes so the module that wires GitHub credentials stays
small enough to read in full. Each names the binding it reads: absent falls
back to this deployment's configured repository, which is the single-repository
behaviour being retired.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CommitRangeReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    #: The binding to read. Absent falls back to this deployment's configured
    #: repository, which is the single-repository behaviour being retired.
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    base_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class PullRequestDiffReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    #: The binding to read. Absent falls back to this deployment's configured
    #: repository, which is the single-repository behaviour being retired.
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    pull_request_number: int = Field(gt=0)
    maximum_patch_bytes: int = Field(ge=1_000, le=500_000)


class WorkflowRunReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    #: The binding to read. Absent falls back to this deployment's configured
    #: repository, which is the single-repository behaviour being retired.
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    check_run_id: int = Field(gt=0)
    expected_head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
