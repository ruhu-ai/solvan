"""Minimal, typed GitHub App boundary used by the release provider.

The client deliberately accepts an injected installation token provider.  The
provider service may obtain short-lived tokens from a Secret Manager-backed
broker, while tests use a deterministic token.  No GitHub credential is ever
stored in Cloud SQL or returned to the console.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Protocol, cast
from urllib.parse import quote
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from solvan.application.workspace_hashing import canonical_sha256

# Re-exported while callers move through the stable GitHub provider boundary.
from solvan.platform.github_contracts import (
    GitHubCheckRunResponse as _GitHubCheckRunResponse,
)
from solvan.platform.github_contracts import (
    GitHubPullRequestResponse as _GitHubPullRequestResponse,
)
from solvan.platform.github_webhook import (
    parse_webhook as _parse_webhook,
)
from solvan.platform.github_webhook import (
    project_webhook as _project_webhook,
)
from solvan.platform.github_webhook import (
    verified_webhook_payload as _verified_webhook_payload,
)
from solvan.platform.github_webhook import (
    verify_webhook_signature as _verify_webhook_signature,
)
from solvan.platform.github_webhook import (
    webhook_repository_identity as _webhook_repository_identity,
)

parse_webhook = _parse_webhook
project_webhook = _project_webhook
verified_webhook_payload = _verified_webhook_payload
webhook_repository_identity = _webhook_repository_identity
verify_webhook_signature = _verify_webhook_signature
GitHubPullRequestResponse = _GitHubPullRequestResponse
GitHubCheckRunResponse = _GitHubCheckRunResponse


class GitHubApiError(RuntimeError):
    """A GitHub API call failed or returned an unsafe response."""


class GitHubTokenProvider(Protocol):
    def token(self, *, installation_id: int) -> str: ...


class GitHubApiResponse(Protocol):
    status_code: int
    content: bytes

    def json(self) -> Any: ...


class GitHubApiTransport(Protocol):
    def get(self, url: str, **kwargs: Any) -> GitHubApiResponse: ...

    def post(self, url: str, **kwargs: Any) -> GitHubApiResponse: ...

    def put(self, url: str, **kwargs: Any) -> GitHubApiResponse: ...


#: The identity shapes a binding is allowed to carry, applied where GitHub is
#: read rather than where a binding is written. A listing entry that cannot
#: become a legal binding is dropped here, so an operator is never offered a
#: repository the store would refuse and onboarding never depends on the
#: database to reject a malformed name.
_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_ACCOUNT_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$")


@dataclass(frozen=True, slots=True)
class GitHubInstallation:
    """One installation of this App, as GitHub reports it."""

    installation_id: int
    account_login: str
    account_type: str
    target_type: str
    repository_selection: str
    html_url: str
    suspended: bool


@dataclass(frozen=True, slots=True)
class GitHubInstallationRepository:
    """One repository an installation can actually reach."""

    owner: str
    name: str
    default_branch: str
    private: bool
    archived: bool
    html_url: str


def _bounded_body(response: GitHubApiResponse, *, expected: tuple[int, ...]) -> Any:
    """Decode one bounded GitHub response without trusting its shape."""

    if response.status_code not in expected:
        raise GitHubApiError(f"GitHub API returned HTTP {response.status_code}")
    if len(response.content) > 2_000_000:
        raise GitHubApiError("GitHub API response exceeds the bounded response size")
    return response.json()


def _installation(value: Mapping[str, Any]) -> GitHubInstallation | None:
    """Project one installation entry, or nothing when it cannot be trusted."""

    identifier = value.get("id")
    account = value.get("account")
    login = account.get("login") if isinstance(account, dict) else None
    account_type = account.get("type") if isinstance(account, dict) else None
    if not isinstance(identifier, int) or identifier <= 0:
        return None
    if not isinstance(login, str) or _ACCOUNT_LOGIN.fullmatch(login) is None:
        return None
    html_url = value.get("html_url")
    return GitHubInstallation(
        installation_id=identifier,
        account_login=login,
        account_type=str(account_type or "Unknown")[:32],
        target_type=str(value.get("target_type", "Unknown"))[:32],
        repository_selection=str(value.get("repository_selection", "unknown"))[:32],
        html_url=str(html_url)[:500] if isinstance(html_url, str) else "",
        suspended=value.get("suspended_at") is not None,
    )


def _installation_repository(value: Mapping[str, Any]) -> GitHubInstallationRepository | None:
    """Project one repository entry, or nothing when it cannot be trusted."""

    owner_value = value.get("owner")
    owner = owner_value.get("login") if isinstance(owner_value, dict) else None
    name = value.get("name")
    branch = value.get("default_branch")
    if not isinstance(owner, str) or _OWNER.fullmatch(owner) is None:
        return None
    if not isinstance(name, str) or _REPOSITORY_NAME.fullmatch(name) is None:
        return None
    if not isinstance(branch, str) or _BRANCH.fullmatch(branch) is None:
        return None
    html_url = value.get("html_url")
    return GitHubInstallationRepository(
        owner=owner,
        name=name,
        default_branch=branch,
        private=bool(value.get("private", True)),
        archived=bool(value.get("archived", False)),
        html_url=str(html_url)[:500] if isinstance(html_url, str) else "",
    )


class GitHubAppClient:
    """App-JWT reads only: which installations exist for this App.

    `GET /app/installations` is the one GitHub read authenticated as the App
    itself rather than as an installation, so it cannot share `GitHubClient`'s
    installation token. The class holds no mutation method and no path a caller
    can steer: the App JWT reaches exactly one endpoint from here.
    """

    def __init__(
        self,
        *,
        transport: GitHubApiTransport,
        app_jwt_provider: Callable[[], str],
        api_base_url: str = "https://api.github.com",
    ) -> None:
        if not api_base_url.startswith("https://") or api_base_url.endswith("/"):
            raise ValueError("GitHub API base URL must be an HTTPS origin")
        self._transport = transport
        self._app_jwt_provider = app_jwt_provider
        self._base = api_base_url

    def _headers(self) -> dict[str, str]:
        assertion = self._app_jwt_provider()
        if not assertion or len(assertion) > 8_192:
            raise GitHubApiError("GitHub App assertion is missing or oversized")
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {assertion}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def installations(
        self, *, maximum_pages: int = 5, per_page: int = 100
    ) -> tuple[GitHubInstallation, ...]:
        """List this App's installations so an operator picks a real one."""

        if not 1 <= maximum_pages <= 20 or not 1 <= per_page <= 100:
            raise GitHubApiError("GitHub installation listing bounds are invalid")
        collected: list[GitHubInstallation] = []
        for page in range(1, maximum_pages + 1):
            url = f"{self._base}/app/installations?per_page={per_page}&page={page}"
            value = _bounded_body(
                self._transport.get(
                    url, headers=self._headers(), timeout=30, allow_redirects=False
                ),
                expected=(200,),
            )
            if not isinstance(value, list) or len(value) > per_page:
                raise GitHubApiError("GitHub installation page is malformed or oversized")
            for item in value:
                if isinstance(item, dict) and (projected := _installation(item)) is not None:
                    collected.append(projected)
            if len(value) < per_page:
                break
        return tuple(collected)


class GitHubClient:
    """GitHub REST client with path/response bounds and no generic requests."""

    def __init__(
        self,
        *,
        transport: GitHubApiTransport,
        token_provider: GitHubTokenProvider,
        installation_id: int,
        api_base_url: str = "https://api.github.com",
    ) -> None:
        if not api_base_url.startswith("https://") or api_base_url.endswith("/"):
            raise ValueError("GitHub API base URL must be an HTTPS origin")
        self._transport = transport
        self._tokens = token_provider
        self._installation_id = installation_id
        self._base = api_base_url

    def _headers(self) -> dict[str, str]:
        token = self._tokens.token(installation_id=self._installation_id)
        if not token or len(token) > 4096:
            raise GitHubApiError("GitHub installation token is missing or oversized")
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _decode(self, response: GitHubApiResponse, *, expected: tuple[int, ...]) -> dict[str, Any]:
        if response.status_code not in expected:
            raise GitHubApiError(f"GitHub API returned HTTP {response.status_code}")
        if len(response.content) > 2_000_000:
            raise GitHubApiError("GitHub API response exceeds the bounded response size")
        value = response.json()
        if not isinstance(value, dict):
            raise GitHubApiError("GitHub API response is not an object")
        return cast(dict[str, Any], value)

    def _decode_list(
        self, response: GitHubApiResponse, *, expected: tuple[int, ...]
    ) -> list[dict[str, Any]]:
        if response.status_code not in expected:
            raise GitHubApiError(f"GitHub API returned HTTP {response.status_code}")
        if len(response.content) > 2_000_000:
            raise GitHubApiError("GitHub API response exceeds the bounded response size")
        value = response.json()
        if not isinstance(value, list) or len(value) > 100:
            raise GitHubApiError("GitHub API list response is malformed or oversized")
        return [cast(dict[str, Any], item) for item in value if isinstance(item, dict)]

    @staticmethod
    def _require_sha(value: str) -> str:
        if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
            raise GitHubApiError("GitHub read requires an exact lowercase commit SHA")
        return value

    def repository(self, *, owner: str, name: str) -> dict[str, Any]:
        url = f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
        return self._decode(
            self._transport.get(url, headers=self._headers(), timeout=30, allow_redirects=False),
            expected=(200,),
        )

    def installation_repositories(
        self, *, maximum_pages: int = 5, per_page: int = 100
    ) -> tuple[GitHubInstallationRepository, ...]:
        """List exactly what this installation can reach.

        Onboarding resolves a binding's owner, name, and default branch from
        this listing rather than from anything an operator typed, so a binding
        can never name a repository the installation cannot actually open.
        """

        if not 1 <= maximum_pages <= 20 or not 1 <= per_page <= 100:
            raise GitHubApiError("GitHub installation repository bounds are invalid")
        collected: list[GitHubInstallationRepository] = []
        for page in range(1, maximum_pages + 1):
            url = f"{self._base}/installation/repositories?per_page={per_page}&page={page}"
            value = self._decode(
                self._transport.get(
                    url, headers=self._headers(), timeout=30, allow_redirects=False
                ),
                expected=(200,),
            )
            raw = value.get("repositories")
            if not isinstance(raw, list) or len(raw) > per_page:
                raise GitHubApiError("GitHub installation repository page is malformed")
            for item in raw:
                if (
                    isinstance(item, dict)
                    and (projected := _installation_repository(item)) is not None
                ):
                    collected.append(projected)
            if len(raw) < per_page:
                break
        return tuple(collected)

    def branch_head(self, *, owner: str, name: str, branch: str) -> str:
        """Read the signed CI-published branch before opening a pull request."""

        url = (
            f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
            f"/git/ref/heads/{quote(branch, safe='')}"
        )
        value = self._decode(
            self._transport.get(url, headers=self._headers(), timeout=30, allow_redirects=False),
            expected=(200,),
        )
        obj = value.get("object")
        sha = obj.get("sha") if isinstance(obj, dict) else None
        if (
            not isinstance(sha, str)
            or len(sha) != 40
            or any(c not in "0123456789abcdef" for c in sha)
        ):
            raise GitHubApiError("GitHub branch ref returned an invalid commit SHA")
        return sha

    def resolve_commit(self, *, owner: str, name: str, ref: str) -> str:
        """Resolve one explicit branch/tag ref to the provider's commit SHA."""

        if not (ref.startswith("refs/heads/") or ref.startswith("refs/tags/")):
            raise GitHubApiError("GitHub upstream ref must name refs/heads or refs/tags")
        url = (
            f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
            f"/commits/{quote(ref, safe='')}"
        )
        value = self._decode(
            self._transport.get(url, headers=self._headers(), timeout=30, allow_redirects=False),
            expected=(200,),
        )
        sha = value.get("sha")
        return self._require_sha(sha) if isinstance(sha, str) else self._require_sha("")

    def subtree_tree_hash(
        self, *, owner: str, name: str, commit_sha: str, subdirectory: str = ""
    ) -> str:
        """Observe a pinned tree without fetching file contents.

        The returned digest is a canonical hash of path/type/mode/blob SHA
        metadata. A truncated tree is refused because it cannot support a
        trustworthy refresh decision.
        """
        sha = self._require_sha(commit_sha)
        prefix = subdirectory.strip("/")
        if prefix and any(part in {"", ".", ".."} for part in prefix.split("/")):
            raise GitHubApiError("GitHub subtree path is unsafe")
        url = (
            f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
            f"/git/trees/{sha}?recursive=1"
        )
        value = self._decode(
            self._transport.get(url, headers=self._headers(), timeout=30, allow_redirects=False),
            expected=(200,),
        )
        if value.get("truncated") is True:
            raise GitHubApiError("GitHub tree is truncated")
        raw = value.get("tree")
        if not isinstance(raw, list) or len(raw) > 10_000:
            raise GitHubApiError("GitHub tree response is malformed or oversized")
        selected = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            if not isinstance(path, str) or not (
                not prefix or path == prefix or path.startswith(prefix + "/")
            ):
                continue
            selected.append(
                {
                    "path": path,
                    "type": str(item.get("type", "")),
                    "mode": str(item.get("mode", "")),
                    "sha": str(item.get("sha", "")),
                }
            )
        if not selected:
            raise GitHubApiError("GitHub subtree is empty or not found")
        return canonical_sha256(sorted(selected, key=lambda item: item["path"].encode("utf-8")))

    def subtree_archive(
        self,
        *,
        owner: str,
        name: str,
        commit_sha: str,
        subdirectory: str = "",
        archive_root: str = "",
        maximum_files: int = 100,
        maximum_bytes: int = 1_000_000,
    ) -> bytes:
        """Fetch one pinned subtree through Git blobs without following redirects."""
        sha = self._require_sha(commit_sha)
        prefix = subdirectory.strip("/")
        root = archive_root.strip("/")
        if root and any(part in {"", ".", ".."} for part in root.split("/")):
            raise GitHubApiError("GitHub archive root is unsafe")
        if prefix and any(part in {"", ".", ".."} for part in prefix.split("/")):
            raise GitHubApiError("GitHub subtree path is unsafe")
        tree_url = (
            f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
            f"/git/trees/{sha}?recursive=1"
        )
        tree = self._decode(
            self._transport.get(
                tree_url, headers=self._headers(), timeout=30, allow_redirects=False
            ),
            expected=(200,),
        )
        if tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
            raise GitHubApiError("GitHub tree is unavailable or truncated")
        selected: list[tuple[str, str]] = []
        for item in tree["tree"]:
            if not isinstance(item, dict) or item.get("type") != "blob":
                continue
            path = item.get("path")
            blob_sha = item.get("sha")
            if not isinstance(path, str) or not isinstance(blob_sha, str):
                continue
            if prefix and not (path == prefix or path.startswith(prefix + "/")):
                continue
            relative = path[len(prefix) + 1 :] if prefix else path
            if not relative or any(part in {"", ".", ".."} for part in relative.split("/")):
                raise GitHubApiError("GitHub subtree contains an unsafe path")
            selected.append((relative, blob_sha))
        if (
            len(selected) == 0
            or len(selected) > maximum_files
            or "SKILL.md" not in {path for path, _ in selected}
        ):
            raise GitHubApiError("GitHub subtree has no bounded SKILL.md package")
        output = BytesIO()
        total = 0
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            for path, blob_sha in sorted(selected):
                blob_url = (
                    f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
                    f"/git/blobs/{quote(blob_sha, safe='')}"
                )
                blob = self._decode(
                    self._transport.get(
                        blob_url, headers=self._headers(), timeout=30, allow_redirects=False
                    ),
                    expected=(200,),
                )
                if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
                    raise GitHubApiError("GitHub blob encoding is unsupported")
                try:
                    content = base64.b64decode(blob["content"], validate=False)
                except (ValueError, TypeError) as error:
                    raise GitHubApiError("GitHub blob content is invalid") from error
                total += len(content)
                if total > maximum_bytes:
                    raise GitHubApiError("GitHub subtree exceeds the package bound")
                archived_path = f"{root}/{path}" if root else path
                info = ZipInfo(archived_path, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content)
        return output.getvalue()

    def pull_request(self, *, owner: str, name: str, number: int) -> GitHubPullRequestResponse:
        url = f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}/pulls/{number}"
        return self._pull_request(
            self._decode(
                self._transport.get(url, headers=self._headers(), timeout=30), expected=(200,)
            )
        )

    def check_runs(self, *, owner: str, name: str, ref: str) -> tuple[GitHubCheckRunResponse, ...]:
        url = (
            f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
            f"/commits/{quote(ref, safe='')}/check-runs"
        )
        value = self._decode(
            self._transport.get(url, headers=self._headers(), timeout=30), expected=(200,)
        )
        raw = value.get("check_runs")
        if not isinstance(raw, list) or len(raw) > 200:
            raise GitHubApiError("GitHub check-run response is malformed or oversized")
        result: list[GitHubCheckRunResponse] = []
        for item in raw:
            if not isinstance(item, dict) or not isinstance(item.get("id"), int):
                continue
            result.append(
                GitHubCheckRunResponse(
                    external_id=int(item["id"]),
                    name=str(item.get("name", "unknown"))[:128],
                    status=str(item.get("status", "unknown")).upper()[:32],
                    conclusion=(
                        str(item["conclusion"]).upper()
                        if item.get("conclusion") is not None
                        else None
                    ),
                    head_sha=str(item.get("head_sha", "")),
                    details_url=(str(item["details_url"]) if item.get("details_url") else None),
                )
            )
        return tuple(result)

    def compare_commits(
        self, *, owner: str, name: str, base_sha: str, head_sha: str
    ) -> dict[str, Any]:
        """Return bounded metadata and paths between two exact commits."""

        base = self._require_sha(base_sha)
        head = self._require_sha(head_sha)
        url = (
            f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
            f"/compare/{base}...{head}"
        )
        value = self._decode(
            self._transport.get(url, headers=self._headers(), timeout=30), expected=(200,)
        )
        files = value.get("files", [])
        commits = value.get("commits", [])
        if not isinstance(files, list) or len(files) > 300 or not isinstance(commits, list):
            raise GitHubApiError("GitHub comparison is malformed or oversized")
        return {
            "base_sha": base,
            "head_sha": head,
            "status": str(value.get("status", "unknown"))[:32],
            "ahead_by": int(value.get("ahead_by", 0)),
            "behind_by": int(value.get("behind_by", 0)),
            "total_commits": int(value.get("total_commits", len(commits))),
            "changed_paths": [
                {
                    "path": str(item.get("filename", ""))[:1_000],
                    "status": str(item.get("status", "unknown"))[:32],
                    "additions": int(item.get("additions", 0)),
                    "deletions": int(item.get("deletions", 0)),
                }
                for item in files[:100]
                if isinstance(item, dict)
            ],
            "paths_truncated": len(files) > 100,
        }

    def pull_request_diff(
        self, *, owner: str, name: str, number: int, maximum_patch_bytes: int = 200_000
    ) -> dict[str, Any]:
        """Return one PR's bounded changed paths and patch fragments."""

        if number <= 0 or not 1_000 <= maximum_patch_bytes <= 500_000:
            raise GitHubApiError("GitHub pull-request diff bounds are invalid")
        url = (
            f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
            f"/pulls/{number}/files?per_page=100"
        )
        files = self._decode_list(
            self._transport.get(url, headers=self._headers(), timeout=30), expected=(200,)
        )
        remaining = maximum_patch_bytes
        projected = []
        truncated = False
        for item in files:
            patch = str(item.get("patch", ""))
            encoded = patch.encode()
            if len(encoded) > remaining:
                patch = encoded[:remaining].decode(errors="ignore")
                truncated = True
            remaining -= len(patch.encode())
            projected.append(
                {
                    "path": str(item.get("filename", ""))[:1_000],
                    "status": str(item.get("status", "unknown"))[:32],
                    "additions": int(item.get("additions", 0)),
                    "deletions": int(item.get("deletions", 0)),
                    "patch": patch,
                }
            )
            if remaining <= 0:
                truncated = True
                break
        return {"pull_request_number": number, "files": projected, "patch_truncated": truncated}

    def check_run_detail(
        self, *, owner: str, name: str, check_run_id: int, expected_head_sha: str
    ) -> dict[str, Any]:
        """Return one exact check run and bounded failure annotations."""

        if check_run_id <= 0:
            raise GitHubApiError("GitHub check-run identifier is invalid")
        expected_sha = self._require_sha(expected_head_sha)
        base = f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
        value = self._decode(
            self._transport.get(
                f"{base}/check-runs/{check_run_id}", headers=self._headers(), timeout=30
            ),
            expected=(200,),
        )
        if value.get("head_sha") != expected_sha or value.get("id") != check_run_id:
            raise GitHubApiError("GitHub check run does not match the bound commit")
        annotations = self._decode_list(
            self._transport.get(
                f"{base}/check-runs/{check_run_id}/annotations?per_page=50",
                headers=self._headers(),
                timeout=30,
            ),
            expected=(200,),
        )
        return {
            "check_run_id": check_run_id,
            "head_sha": expected_sha,
            "name": str(value.get("name", "unknown"))[:128],
            "status": str(value.get("status", "unknown"))[:32],
            "conclusion": str(value.get("conclusion", "unknown"))[:32],
            "annotations": [
                {
                    "path": str(item.get("path", ""))[:1_000],
                    "start_line": int(item.get("start_line", 0)),
                    "end_line": int(item.get("end_line", 0)),
                    "level": str(item.get("annotation_level", "unknown"))[:32],
                    "message": str(item.get("message", ""))[:2_000],
                }
                for item in annotations[:50]
            ],
        }

    @staticmethod
    def _pull_request(value: Mapping[str, Any]) -> GitHubPullRequestResponse:
        head = value.get("head")
        base = value.get("base")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        base_sha = base.get("sha") if isinstance(base, dict) else None
        number = value.get("number")
        node_id = value.get("node_id")
        draft = value.get("draft")
        merge_commit_sha = value.get("merge_commit_sha")
        if (
            not isinstance(number, int)
            or not isinstance(node_id, str)
            or not node_id
            or not isinstance(head_sha, str)
            or not isinstance(base_sha, str)
            or not isinstance(draft, bool)
            or (merge_commit_sha is not None and not isinstance(merge_commit_sha, str))
        ):
            raise GitHubApiError("GitHub pull-request response is missing immutable refs")
        return GitHubPullRequestResponse(
            number=number,
            node_id=node_id,
            html_url=str(value.get("html_url", "")),
            head_sha=head_sha,
            base_sha=base_sha,
            state=str(value.get("state", "unknown")),
            merged=bool(value.get("merged", False)),
            mergeable_state=(
                str(value["mergeable_state"]) if value.get("mergeable_state") else None
            ),
            title=str(value.get("title", ""))[:256],
            draft=draft,
            merge_commit_sha=merge_commit_sha,
        )
