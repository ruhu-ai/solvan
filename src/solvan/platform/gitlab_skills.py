"""Bounded GitLab repository connector for Agent Skills ingestion.

The connector accepts only an explicitly registered ``gitlab://group/project``
reference and an exact commit SHA.  Tree refreshes read metadata only; import
reads only the allowlisted subtree files and repackages them into the same
deterministic ZIP shape used by the GitHub connector.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import Any
from urllib.parse import quote
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from solvan.application.skills_governance import RepositoryObservation
from solvan.application.workspace_hashing import canonical_sha256
from solvan.platform.github import GitHubApiError

#: A registered skills repository is a bounded package source, not an arbitrary
#: monorepo mirror; twenty 100-entry pages is far past any legitimate package.
_MAX_TREE_PAGES = 20


@dataclass(frozen=True, slots=True)
class ConfiguredGitLabTokenProvider:
    value: str

    def token(self) -> str:
        if not self.value or len(self.value) > 4096:
            raise GitHubApiError("GitLab token is missing or oversized")
        return self.value


@dataclass(frozen=True, slots=True)
class GitLabMetadataConnector:
    """Allowlisted, pinned GitLab tree and raw-file connector."""

    transport: Any
    token_provider: ConfiguredGitLabTokenProvider
    allowed_repositories: frozenset[str]
    api_base_url: str = "https://gitlab.com/api/v4"

    def __post_init__(self) -> None:
        if not self.api_base_url.startswith("https://") or self.api_base_url.endswith("/"):
            raise ValueError("GitLab API base URL must be an HTTPS origin")

    def _repository(self, repository_ref: str) -> str:
        if not repository_ref.startswith("gitlab://"):
            raise GitHubApiError("repository reference must use the registered gitlab:// scheme")
        path = repository_ref.removeprefix("gitlab://")
        if not path or path not in self.allowed_repositories:
            raise GitHubApiError("repository is not registered for this tenant")
        if any(part in {"", ".", ".."} for part in path.split("/")):
            raise GitHubApiError("GitLab repository path is unsafe")
        return path

    @staticmethod
    def _commit(commit_sha: str) -> str:
        if len(commit_sha) != 40 or any(c not in "0123456789abcdef" for c in commit_sha):
            raise GitHubApiError("GitLab read requires an exact lowercase commit SHA")
        return commit_sha

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "PRIVATE-TOKEN": self.token_provider.token()}

    def _get(self, url: str, *, expected: tuple[int, ...] = (200,)) -> Any:
        response = self.transport.get(
            url,
            headers=self._headers(),
            timeout=30,
            allow_redirects=False,
        )
        if response.status_code not in expected or 300 <= response.status_code < 400:
            raise GitHubApiError(f"GitLab API returned HTTP {response.status_code}")
        if len(response.content) > 2_000_000:
            raise GitHubApiError("GitLab API response exceeds the bounded response size")
        return response

    def _tree(self, *, repository: str, commit_sha: str, subdirectory: str) -> list[dict[str, Any]]:
        prefix = subdirectory.strip("/")
        if prefix and any(part in {"", ".", ".."} for part in prefix.split("/")):
            raise GitHubApiError("GitLab subtree path is unsafe")
        base_url = (
            f"{self.api_base_url}/projects/{quote(repository, safe='')}"
            f"/repository/tree?ref={quote(commit_sha, safe='')}&recursive=true&per_page=100"
        )
        entries: list[Any] = []
        page = 1
        while True:
            response = self._get(f"{base_url}&page={page}")
            value = response.json()
            if not isinstance(value, list) or len(value) > 100:
                raise GitHubApiError("GitLab tree response is malformed or oversized")
            entries.extend(value)
            # GitLab signals truncation only through pagination headers; a
            # transport that cannot surface them cannot prove the tree is
            # complete, and a partial tree would defeat moving-origin
            # detection, so both cases refuse instead of proceeding partial.
            headers = getattr(response, "headers", None)
            if headers is None:
                raise GitHubApiError("GitLab tree response carries no pagination headers")
            next_page = str(headers.get("x-next-page") or "").strip()
            if not next_page:
                break
            if not next_page.isdigit() or int(next_page) != page + 1:
                raise GitHubApiError("GitLab tree pagination headers are inconsistent")
            if int(next_page) > _MAX_TREE_PAGES:
                raise GitHubApiError("GitLab tree exceeds the bounded page count")
            page = int(next_page)
        selected: list[dict[str, Any]] = []
        for item in entries:
            if not isinstance(item, dict) or item.get("type") != "blob":
                continue
            path = item.get("path")
            blob_id = item.get("id")
            if not isinstance(path, str) or not isinstance(blob_id, str):
                continue
            if prefix and not (path == prefix or path.startswith(prefix + "/")):
                continue
            relative = path[len(prefix) + 1 :] if prefix else path
            if not relative or any(part in {"", ".", ".."} for part in relative.split("/")):
                raise GitHubApiError("GitLab subtree contains an unsafe path")
            selected.append({"path": relative, "blob_id": blob_id})
        if (
            len(selected) == 0
            or len(selected) > 100
            or "SKILL.md" not in {str(item["path"]) for item in selected}
        ):
            raise GitHubApiError("GitLab subtree has no bounded SKILL.md package")
        return sorted(selected, key=lambda item: str(item["path"]))

    def observe_tree(
        self, *, repository_ref: str, commit_sha: str, subdirectory: str
    ) -> RepositoryObservation:
        repository = self._repository(repository_ref)
        commit = self._commit(commit_sha)
        tree = self._tree(repository=repository, commit_sha=commit, subdirectory=subdirectory)
        tree_hash = canonical_sha256(
            {
                "provider": "gitlab",
                "repository": repository,
                "commit_sha": commit,
                "subdirectory": subdirectory.strip("/"),
                "tree": tree,
            }
        )
        return RepositoryObservation(commit_sha=commit, subtree_hash=tree_hash)

    def observe_ref(
        self, *, repository_ref: str, upstream_ref: str, subdirectory: str
    ) -> RepositoryObservation:
        if not (upstream_ref.startswith("refs/heads/") or upstream_ref.startswith("refs/tags/")):
            raise GitHubApiError("GitLab upstream ref must name refs/heads or refs/tags")
        repository = self._repository(repository_ref)
        ref_name = upstream_ref.split("/", 2)[2]
        url = (
            f"{self.api_base_url}/projects/{quote(repository, safe='')}"
            f"/repository/commits/{quote(ref_name, safe='')}"
        )
        value = self._get(url).json()
        commit = value.get("id") if isinstance(value, dict) else None
        resolved = self._commit(commit) if isinstance(commit, str) else self._commit("")
        return self.observe_tree(
            repository_ref=repository_ref,
            commit_sha=resolved,
            subdirectory=subdirectory,
        )

    def fetch_archive(self, *, repository_ref: str, commit_sha: str, subdirectory: str) -> bytes:
        repository = self._repository(repository_ref)
        commit = self._commit(commit_sha)
        tree = self._tree(repository=repository, commit_sha=commit, subdirectory=subdirectory)
        output = BytesIO()
        total = 0
        archive_root = subdirectory.strip("/").rsplit("/", 1)[-1] or repository.rsplit("/", 1)[-1]
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            for item in tree:
                path = str(item["path"])
                # `path` is relative to the requested subdirectory, so a path-based
                # raw read resolves against the repository root and returns a
                # different file — or 404s. The blob id addresses the exact pinned
                # content, matching how the GitHub connector fetches blobs.
                raw_url = (
                    f"{self.api_base_url}/projects/{quote(repository, safe='')}"
                    f"/repository/blobs/{quote(str(item['blob_id']), safe='')}/raw"
                )
                response = self._get(raw_url)
                content = bytes(response.content)
                total += len(content)
                if total > 1_000_000:
                    raise GitHubApiError("GitLab subtree exceeds the package bound")
                info = ZipInfo(f"{archive_root}/{path}", date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content)
        return output.getvalue()
