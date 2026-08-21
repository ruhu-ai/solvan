"""Evidence-broker client for private, credential-owning GitHub provider reads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from solvan.platform.github_release import IdentityTokenProvider


@dataclass(frozen=True, slots=True)
class GitHubEvidenceProviderConfiguration:
    base_url: str
    audience: str
    repository_id: str

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://") or self.base_url.endswith("/"):
            raise ValueError("GitHub evidence provider URL must be one HTTPS origin")
        if not self.audience.startswith("https://"):
            raise ValueError("GitHub evidence provider audience must be HTTPS")
        if not self.repository_id.startswith("ghr_"):
            raise ValueError("GitHub evidence repository binding is invalid")


class GitHubEvidenceProviderClient:
    """Deterministic broker-only read client; no Agent receives its identity."""

    def __init__(
        self,
        *,
        config: GitHubEvidenceProviderConfiguration,
        client: httpx.Client,
        token_provider: IdentityTokenProvider,
        repository_id: str | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._tokens = token_provider
        #: The binding this reader addresses. The provider resolves it and
        #: reads with that binding's own installation, so one deployment serves
        #: every repository an operator connected rather than only the one it
        #: was configured with.
        self._repository_id = repository_id or config.repository_id

    def commit_range(self, *, base_sha: str, head_sha: str) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/commit-range",
            {"schema_version": 1, "base_sha": base_sha, "head_sha": head_sha},
        )

    def pull_request_diff(
        self, *, pull_request_number: int, maximum_patch_bytes: int
    ) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/pull-request-diff",
            {
                "schema_version": 1,
                "pull_request_number": pull_request_number,
                "maximum_patch_bytes": maximum_patch_bytes,
            },
        )

    def workflow_run(self, *, check_run_id: int, expected_head_sha: str) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/workflow-run",
            {
                "schema_version": 1,
                "check_run_id": check_run_id,
                "expected_head_sha": expected_head_sha,
            },
        )

    def search(self, *, query: str, search_kind: str, limit: int) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/search",
            {
                "schema_version": 1,
                "query": query,
                "search_kind": search_kind,
                "limit": limit,
            },
        )

    def issue(self, *, number: int, include_comments: bool, comment_limit: int) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/issue",
            {
                "schema_version": 1,
                "number": number,
                "include_comments": include_comments,
                "comment_limit": comment_limit,
            },
        )

    def commit_history(
        self,
        *,
        author: str | None,
        since: str | None,
        until: str | None,
        limit: int,
    ) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/commit-history",
            {
                "schema_version": 1,
                "author": author,
                "since": since,
                "until": until,
                "limit": limit,
            },
        )

    def repository_tree(
        self,
        *,
        commit_sha: str,
        path_prefix: str,
        maximum_files: int,
        maximum_bytes: int,
    ) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/repository-tree",
            {
                "schema_version": 1,
                "commit_sha": commit_sha,
                "path_prefix": path_prefix,
                "maximum_files": maximum_files,
                "maximum_bytes": maximum_bytes,
            },
        )

    def workflow_runs(self, *, head_sha: str, limit: int) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/workflow-runs",
            {"schema_version": 1, "head_sha": head_sha, "limit": limit},
        )

    def deployments(
        self, *, environment: str | None, sha: str | None, limit: int
    ) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/deployments",
            {"schema_version": 1, "environment": environment, "sha": sha, "limit": limit},
        )

    def discussions(self, *, limit: int) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/discussions", {"schema_version": 1, "limit": limit}
        )

    def merge_queue(self, *, branch: str, limit: int) -> dict[str, Any]:
        return self._post(
            "/internal/github/evidence/merge-queue",
            {"schema_version": 1, "branch": branch, "limit": limit},
        )

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        payload = {**payload, "repository_id": self._repository_id}
        response = self._client.post(
            f"{self._config.base_url}{path}",
            headers={
                "Authorization": (f"Bearer {self._tokens.token(audience=self._config.audience)}"),
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=60,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"GitHub evidence provider returned HTTP {response.status_code}")
        value = response.json()
        if not isinstance(value, dict):
            raise RuntimeError("GitHub evidence provider returned a non-object response")
        return value
