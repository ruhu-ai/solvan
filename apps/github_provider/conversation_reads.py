"""Bounded conversational reads over one bound repository.

These are the reads that let an agent understand a thread before anything is
proposed: search, one issue with its comments, and commit history. They are
separated from the provider's command surface because they are the only GitHub
routes that answer with attacker-authored text, and because the risk they carry
is a scoping risk rather than a mutation one.

That risk is concrete. GitHub's search syntax lets a query name its own
repository, so a search endpoint that passed caller text through unchanged
would let a caller holding one binding read issues from any repository the
installation can reach. The query is therefore refused rather than sanitised
when it carries a scope qualifier, and the binding's own qualifier is prepended
by this module.

Specification 24 §2 governs.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.platform.github_conversation import GitHubConversationClient

#: Qualifiers that would move a search off the binding it was invoked for.
_SCOPE_QUALIFIERS = ("repo:", "org:", "user:", "is:private")


class SearchReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    #: Free text only. The repository qualifier is appended by this service, so
    #: a caller cannot search outside the binding it was invoked for — GitHub's
    #: search syntax would otherwise let `repo:` in the query text do exactly
    #: that.
    query: str = Field(min_length=1, max_length=200)
    search_kind: str = Field(default="issues", pattern=r"^(issues|repositories)$")
    limit: int = Field(default=10, ge=1, le=50)


class IssueReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    number: int = Field(gt=0)
    include_comments: bool = True
    comment_limit: int = Field(default=30, ge=1, le=100)


class CommitHistoryReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    author: str | None = Field(default=None, min_length=1, max_length=100)
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=30, ge=1, le=100)


class RepositoryTreeReadRequest(BaseModel):
    """Read the repository's files at one pinned commit.

    This is what a clone is actually for, minus the clone. `github_clone` in the
    comparison connector hands an agent a working copy and a token-bearing git
    remote; this returns the same file content with neither. The commit must be
    exact, because "read the repository" without a pin is a read of whatever
    happened to be at HEAD when the request landed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    path_prefix: str = Field(default="", max_length=500)
    maximum_files: int = Field(default=128, ge=1, le=512)
    maximum_bytes: int = Field(default=1_000_000, ge=1_000, le=8_000_000)


class WorkflowRunsReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    limit: int = Field(default=30, ge=1, le=100)


class DeploymentsReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    environment: str | None = Field(default=None, min_length=1, max_length=255)
    sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    limit: int = Field(default=20, ge=1, le=50)


class DiscussionsReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    limit: int = Field(default=20, ge=1, le=50)


class MergeQueueReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    repository_id: str | None = Field(default=None, pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    branch: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/-]+$")
    limit: int = Field(default=20, ge=1, le=50)


def register_conversation_reads(
    app: FastAPI,
    *,
    settings_factory: Callable[[], Any],
    principal: Callable[[str | None, Any], str],
    evidence_binding: Callable[..., tuple[str, str, int, str]],
    client_factory: Callable[[Any, int, str], GitHubConversationClient],
    tree_reader_factory: Callable[[Any, int], Any] | None = None,
    delivery_reader_factory: Callable[[Any, int, str], Any] | None = None,
) -> None:
    """Attach the conversational read routes to the provider application.

    Dependencies are injected rather than imported so this module never reaches
    back into the provider's settings or token wiring; it can be exercised with
    a fake client and no GitHub credential anywhere in the test.
    """

    @app.post("/internal/github/evidence/search")
    def read_search(
        request: SearchReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        # A caller-supplied qualifier would let one binding read another's
        # issues, so the query is rejected rather than sanitised: silently
        # stripping `repo:` would leave the caller believing it searched
        # somewhere it did not.
        if any(token in request.query.lower() for token in _SCOPE_QUALIFIERS):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "search query may not carry its own scope qualifier",
            )
        scoped = (
            request.query
            if request.search_kind == "repositories"
            else f"repo:{owner}/{name} {request.query}"
        )
        hits = client_factory(settings, installation_id, api_base_url).search(
            query=scoped, search_kind=request.search_kind, limit=request.limit
        )
        return {
            "schema_version": 1,
            "search_kind": request.search_kind,
            "results": [
                {
                    "kind": hit.kind,
                    "identifier": hit.identifier,
                    "title": hit.title,
                    "html_url": hit.html_url,
                    "state": hit.state,
                }
                for hit in hits
            ],
        }

    @app.post("/internal/github/evidence/issue")
    def read_issue(
        request: IssueReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        client = client_factory(settings, installation_id, api_base_url)
        issue = client.issue(owner=owner, name=name, number=request.number)
        comments = (
            client.issue_comments(
                owner=owner, name=name, number=request.number, limit=request.comment_limit
            )
            if request.include_comments
            else ()
        )
        return {
            "schema_version": 1,
            "number": issue.number,
            "title": issue.title,
            "body": issue.body,
            "state": issue.state,
            "locked": issue.locked,
            "author_login": issue.author_login,
            "html_url": issue.html_url,
            "labels": list(issue.labels),
            "is_pull_request": issue.is_pull_request,
            "comment_count": issue.comment_count,
            "created_at": issue.created_at,
            "updated_at": issue.updated_at,
            "comments": [
                {
                    "comment_id": comment.comment_id,
                    "author_login": comment.author_login,
                    "author_association": comment.author_association,
                    "body": comment.body,
                    "created_at": comment.created_at,
                }
                for comment in comments
            ],
        }

    @app.post("/internal/github/evidence/commit-history")
    def read_commit_history(
        request: CommitHistoryReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        commits = client_factory(settings, installation_id, api_base_url).commit_history(
            owner=owner,
            name=name,
            author=request.author,
            since=request.since,
            until=request.until,
            limit=request.limit,
        )
        return {
            "schema_version": 1,
            "commits": [
                {
                    "sha": commit.sha,
                    "author_login": commit.author_login,
                    "author_name": commit.author_name,
                    "authored_at": commit.authored_at,
                    "message": commit.message,
                }
                for commit in commits
            ],
        }

    @app.post("/internal/github/evidence/repository-tree")
    def read_repository_tree(
        request: RepositoryTreeReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        if tree_reader_factory is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "repository tree reads are not configured on this deployment",
            )
        prefix = request.path_prefix.strip("/")
        if prefix and any(part in {"", ".", ".."} for part in prefix.split("/")):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "path prefix is unsafe")
        owner, name, installation_id, _ = evidence_binding(settings, request.repository_id)
        # The reader verifies every blob's bytes reproduce its Git object ID, so
        # a file here is the file that commit actually contains — a guarantee a
        # clone gives by construction and an unchecked API read does not.
        files = tree_reader_factory(settings, installation_id).regular_file_tree(
            owner=owner,
            name=name,
            commit_sha=request.commit_sha,
            maximum_files=request.maximum_files,
            maximum_bytes=request.maximum_bytes,
        )
        selected = [
            item
            for item in files
            if not prefix or item.path == prefix or item.path.startswith(prefix + "/")
        ]
        return {
            "schema_version": 1,
            "commit_sha": request.commit_sha,
            "path_prefix": prefix,
            "files": [
                {
                    "path": item.path,
                    "mode": item.mode,
                    "blob_sha": item.blob_sha,
                    "content_hash": item.content_hash,
                    # Decoded lossily on purpose: this read serves source
                    # inspection, and a binary blob that cannot be read as text
                    # is not something an agent should be handed as if it were.
                    "content_utf8": item.content.decode("utf-8", errors="replace"),
                }
                for item in selected
            ],
            "truncated_by_prefix": len(selected) != len(files),
        }

    @app.post("/internal/github/evidence/workflow-runs")
    def read_workflow_runs(
        request: WorkflowRunsReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        runs = client_factory(settings, installation_id, api_base_url).workflow_runs(
            owner=owner, name=name, head_sha=request.head_sha, limit=request.limit
        )
        return {
            "schema_version": 1,
            "head_sha": request.head_sha,
            "workflow_runs": [
                {
                    "run_id": run.run_id,
                    "name": run.name,
                    "workflow_path": run.workflow_path,
                    "status": run.status,
                    "conclusion": run.conclusion,
                    "event": run.event,
                    "run_number": run.run_number,
                    "html_url": run.html_url,
                    "created_at": run.created_at,
                }
                for run in runs
            ],
        }

    def _delivery(settings: Any, installation_id: int, api_base_url: str) -> Any:
        if delivery_reader_factory is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "delivery reads are not configured on this deployment",
            )
        return delivery_reader_factory(settings, installation_id, api_base_url)

    @app.post("/internal/github/evidence/deployments")
    def read_deployments(
        request: DeploymentsReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        deployments = _delivery(settings, installation_id, api_base_url).deployments(
            owner=owner,
            name=name,
            environment=request.environment,
            sha=request.sha,
            limit=request.limit,
        )
        return {
            "schema_version": 1,
            "deployments": [
                {
                    "deployment_id": item.deployment_id,
                    "sha": item.sha,
                    "ref": item.ref,
                    "task": item.task,
                    "environment": item.environment,
                    "production_environment": item.production_environment,
                    "transient_environment": item.transient_environment,
                    "creator_login": item.creator_login,
                    "created_at": item.created_at,
                    "state": item.state,
                    "state_description": item.state_description,
                    "target_url": item.target_url,
                }
                for item in deployments
            ],
        }

    @app.post("/internal/github/evidence/discussions")
    def read_discussions(
        request: DiscussionsReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        discussions = _delivery(settings, installation_id, api_base_url).discussions(
            owner=owner, name=name, limit=request.limit
        )
        return {
            "schema_version": 1,
            "discussions": [
                {
                    "number": item.number,
                    "title": item.title,
                    "category": item.category,
                    "author_login": item.author_login,
                    "url": item.url,
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                    "answered": item.answered,
                }
                for item in discussions
            ],
        }

    @app.post("/internal/github/evidence/merge-queue")
    def read_merge_queue(
        request: MergeQueueReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = settings_factory()
        principal(authorization, settings)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        entries = _delivery(settings, installation_id, api_base_url).merge_queue(
            owner=owner, name=name, branch=request.branch, limit=request.limit
        )
        return {
            "schema_version": 1,
            "branch": request.branch,
            "entries": [
                {
                    "pull_request_number": item.pull_request_number,
                    "title": item.title,
                    "position": item.position,
                    "state": item.state,
                    "enqueued_at": item.enqueued_at,
                }
                for item in entries
            ],
        }
