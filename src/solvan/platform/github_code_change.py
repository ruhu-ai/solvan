"""Closed GitHub Git-data boundary for one canonical Solvan code change."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from urllib.parse import quote

from solvan.application.code_change_transform import CanonicalPatchTransform
from solvan.platform.github import (
    GitHubApiError,
    GitHubApiResponse,
    GitHubApiTransport,
    GitHubTokenProvider,
)
from solvan.platform.github_contracts import (
    GitHubCheckRunResponse,
    GitHubMergeResponse,
    GitHubPullRequestFileResponse,
    GitHubPullRequestResponse,
    GitHubReviewResponse,
)


@dataclass(frozen=True, slots=True)
class PreparedGitCommit:
    tree_sha: str
    commit_sha: str


class GitHubCodeChangeClient:
    """No generic request method and no caller-selected endpoint or ref namespace."""

    def __init__(
        self,
        *,
        transport: GitHubApiTransport,
        token_provider: GitHubTokenProvider,
        installation_id: int,
        api_base_url: str = "https://api.github.com",
    ) -> None:
        if not api_base_url.startswith("https://") or api_base_url.endswith("/"):
            raise ValueError("GitHub API base URL must be one HTTPS origin")
        self._transport = transport
        self._tokens = token_provider
        self._installation_id = installation_id
        self._base = api_base_url

    def prepare_commit(
        self,
        *,
        owner: str,
        name: str,
        base_commit_sha: str,
        transform: CanonicalPatchTransform,
        committed_at: datetime,
        message: str,
    ) -> PreparedGitCommit:
        """Create only content-addressed blobs/tree/commit before ref mutation."""

        commit = self._object(
            self._transport.get(
                f"{self._repo(owner, name)}/git/commits/{_sha(base_commit_sha)}",
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            expected=(200,),
        )
        tree_value = commit.get("tree")
        base_tree_sha = tree_value.get("sha") if isinstance(tree_value, dict) else None
        if not isinstance(base_tree_sha, str):
            raise GitHubApiError("base commit omitted its tree")
        entries: list[dict[str, object]] = []
        for operation in transform.operations:
            if operation.kind == "DELETE":
                if operation.expected_base_mode is None:
                    raise GitHubApiError("delete transform lacks its base mode")
                entries.append(
                    {
                        "path": operation.path,
                        "mode": operation.expected_base_mode,
                        "type": "blob",
                        "sha": None,
                    }
                )
                continue
            if operation.content_base64 is None or operation.result_mode is None:
                raise GitHubApiError("canonical transform lacks result content")
            content = base64.b64decode(operation.content_base64, validate=True)
            blob = self._object(
                self._transport.post(
                    f"{self._repo(owner, name)}/git/blobs",
                    headers=self._headers(),
                    json={
                        "content": base64.b64encode(content).decode("ascii"),
                        "encoding": "base64",
                    },
                    timeout=30,
                ),
                expected=(201,),
            )
            blob_sha = blob.get("sha")
            if not isinstance(blob_sha, str):
                raise GitHubApiError("created Git blob omitted its SHA")
            entries.append(
                {
                    "path": operation.path,
                    "mode": operation.result_mode,
                    "type": "blob",
                    "sha": _sha(blob_sha),
                }
            )
        tree = self._object(
            self._transport.post(
                f"{self._repo(owner, name)}/git/trees",
                headers=self._headers(),
                json={"base_tree": _sha(base_tree_sha), "tree": entries},
                timeout=30,
            ),
            expected=(201,),
        )
        tree_sha = tree.get("sha")
        if not isinstance(tree_sha, str):
            raise GitHubApiError("created Git tree omitted its SHA")
        identity = {
            "name": "Solvan",
            "email": "noreply@solvan.invalid",
            "date": committed_at.isoformat(),
        }
        created = self._object(
            self._transport.post(
                f"{self._repo(owner, name)}/git/commits",
                headers=self._headers(),
                json={
                    "message": message,
                    "tree": _sha(tree_sha),
                    "parents": [_sha(base_commit_sha)],
                    "author": identity,
                    "committer": identity,
                },
                timeout=30,
            ),
            expected=(201,),
        )
        commit_sha = created.get("sha")
        if not isinstance(commit_sha, str):
            raise GitHubApiError("created Git commit omitted its SHA")
        return PreparedGitCommit(_sha(tree_sha), _sha(commit_sha))

    def read_branch(self, *, owner: str, name: str, branch: str) -> str | None:
        response = self._transport.get(
            f"{self._repo(owner, name)}/git/ref/heads/{quote(branch, safe='')}",
            headers=self._headers(),
            timeout=30,
            allow_redirects=False,
        )
        if response.status_code == 404:
            return None
        value = self._object(response, expected=(200,))
        target = value.get("object")
        sha = target.get("sha") if isinstance(target, dict) else None
        if not isinstance(sha, str):
            raise GitHubApiError("GitHub branch ref omitted its commit")
        return _sha(sha)

    def create_branch(self, *, owner: str, name: str, branch: str, commit_sha: str) -> None:
        self._object(
            self._transport.post(
                f"{self._repo(owner, name)}/git/refs",
                headers=self._headers(),
                json={"ref": f"refs/heads/{branch}", "sha": _sha(commit_sha)},
                timeout=30,
            ),
            expected=(201,),
        )

    def find_pull_request(
        self, *, owner: str, name: str, branch: str, base: str
    ) -> GitHubPullRequestResponse | None:
        url = (
            f"{self._repo(owner, name)}/pulls?state=all&base={quote(base, safe='')}"
            f"&head={quote(owner + ':' + branch, safe='')}&per_page=2"
        )
        value = self._list(
            self._transport.get(url, headers=self._headers(), timeout=30, allow_redirects=False),
            expected=(200,),
        )
        if len(value) > 1:
            raise GitHubApiError("reserved branch maps to multiple pull requests")
        return _pull_request(value[0]) if value else None

    def create_pull_request(
        self, *, owner: str, name: str, branch: str, base: str, title: str, body: str
    ) -> GitHubPullRequestResponse:
        value = self._object(
            self._transport.post(
                f"{self._repo(owner, name)}/pulls",
                headers=self._headers(),
                json={
                    "title": title,
                    "body": body,
                    "head": branch,
                    "base": base,
                    "draft": True,
                },
                timeout=30,
            ),
            expected=(201,),
        )
        return _pull_request(value)

    def mark_pull_request_ready(self, *, pull_request_node_id: str) -> GitHubPullRequestResponse:
        if not pull_request_node_id or len(pull_request_node_id) > 255:
            raise GitHubApiError("GitHub pull-request node ID is invalid")
        value = self._object(
            self._transport.post(
                f"{self._base}/graphql",
                headers=self._headers(),
                json={
                    "query": (
                        "mutation MarkReady($id:ID!){markPullRequestReadyForReview("
                        "input:{pullRequestId:$id}){pullRequest{number node_id:id url "
                        "headRefOid baseRefOid state merged mergeable title isDraft}}}"
                    ),
                    "variables": {"id": pull_request_node_id},
                },
                timeout=30,
            ),
            expected=(200,),
        )
        if value.get("errors"):
            raise GitHubApiError("GitHub refused ready-for-review mutation")
        data = value.get("data")
        mutation = data.get("markPullRequestReadyForReview") if isinstance(data, dict) else None
        pull = mutation.get("pullRequest") if isinstance(mutation, dict) else None
        if not isinstance(pull, dict):
            raise GitHubApiError("GitHub ready-for-review response is malformed")
        normalized = {
            "number": pull.get("number"),
            "node_id": pull.get("node_id"),
            "html_url": pull.get("url"),
            "head": {"sha": pull.get("headRefOid")},
            "base": {"sha": pull.get("baseRefOid")},
            "state": str(pull.get("state", "")).lower(),
            "merged": pull.get("merged"),
            "mergeable_state": str(pull.get("mergeable", "")).lower(),
            "title": pull.get("title"),
            "draft": pull.get("isDraft"),
        }
        return _pull_request(normalized)

    def merge_pull_request(
        self,
        *,
        owner: str,
        name: str,
        number: int,
        expected_head_sha: str,
        merge_method: str,
    ) -> GitHubMergeResponse:
        if number <= 0 or merge_method not in {"merge", "squash", "rebase"}:
            raise GitHubApiError("GitHub merge parameters are invalid")
        value = self._object(
            self._transport.put(
                f"{self._repo(owner, name)}/pulls/{number}/merge",
                headers=self._headers(),
                json={"sha": _sha(expected_head_sha), "merge_method": merge_method},
                timeout=30,
            ),
            expected=(200, 405, 409),
        )
        merged = value.get("merged")
        commit_sha = value.get("sha")
        message = value.get("message")
        if (
            not isinstance(merged, bool)
            or (commit_sha is not None and not isinstance(commit_sha, str))
            or not isinstance(message, str)
        ):
            raise GitHubApiError("GitHub merge response is malformed")
        return GitHubMergeResponse(
            merged=merged,
            merge_commit_sha=_sha(commit_sha) if commit_sha else None,
            message=message[:500],
        )

    def pull_request(self, *, owner: str, name: str, number: int) -> GitHubPullRequestResponse:
        if number <= 0:
            raise GitHubApiError("GitHub pull-request number is invalid")
        return _pull_request(
            self._object(
                self._transport.get(
                    f"{self._repo(owner, name)}/pulls/{number}",
                    headers=self._headers(),
                    timeout=30,
                    allow_redirects=False,
                ),
                expected=(200,),
            )
        )

    def pull_request_files(
        self, *, owner: str, name: str, number: int
    ) -> tuple[GitHubPullRequestFileResponse, ...]:
        values = self._bounded_list(
            self._transport.get(
                f"{self._repo(owner, name)}/pulls/{number}/files?per_page=100&page=1",
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            maximum=128,
        )
        result: list[GitHubPullRequestFileResponse] = []
        for value in values:
            path, state, sha = value.get("filename"), value.get("status"), value.get("sha")
            if (
                not isinstance(path, str)
                or state not in {"added", "modified", "removed"}
                or not isinstance(sha, str)
            ):
                raise GitHubApiError("GitHub pull-request file projection is malformed")
            result.append(GitHubPullRequestFileResponse(path, str(state), _sha(sha)))
        return tuple(sorted(result, key=lambda item: item.path.encode("utf-8")))

    def commit_statuses(
        self, *, owner: str, name: str, head_sha: str
    ) -> tuple[GitHubCheckRunResponse, ...]:
        """Read legacy commit statuses as if they were check runs.

        Branch protection's required contexts may name either a check run or a
        Statuses-API context, and plenty of CI still reports the latter. Reading
        only check runs left such a context permanently unobserved, so the
        required-check state never left PENDING and the merge blocked forever —
        safe, but indistinguishable from CI that never finished.

        Projecting both into one shape lets the required-check policy match by
        name without caring which API produced the answer.
        """

        value = self._object(
            self._transport.get(
                f"{self._repo(owner, name)}/commits/{_sha(head_sha)}/status?per_page=100",
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            expected=(200,),
        )
        raw = value.get("statuses")
        if not isinstance(raw, list) or len(raw) > 100:
            raise GitHubApiError("GitHub commit-status projection is malformed or truncated")
        observed = value.get("sha")
        if not isinstance(observed, str) or _sha(observed) != _sha(head_sha):
            raise GitHubApiError("GitHub commit status is bound to another head")
        result: list[GitHubCheckRunResponse] = []
        for item in raw:
            if not isinstance(item, dict):
                raise GitHubApiError("GitHub commit-status response is malformed")
            external_id = item.get("id")
            context = item.get("context")
            state = item.get("state")
            target_url = item.get("target_url")
            if (
                not isinstance(external_id, int)
                or not isinstance(context, str)
                or state not in {"success", "pending", "failure", "error"}
                or (target_url is not None and not isinstance(target_url, str))
            ):
                raise GitHubApiError("GitHub commit-status response is malformed")
            # `pending` is the only non-terminal state the Statuses API has, so
            # everything else is a completed run whose conclusion is success or
            # not. `error` is a failure that never produced a verdict, which is
            # a failure for a required check either way.
            completed = state != "pending"
            result.append(
                GitHubCheckRunResponse(
                    external_id,
                    context[:128],
                    "COMPLETED" if completed else "IN_PROGRESS",
                    ("SUCCESS" if state == "success" else "FAILURE") if completed else None,
                    _sha(head_sha),
                    target_url[:500] if target_url else None,
                )
            )
        return tuple(result)

    def check_runs(
        self, *, owner: str, name: str, head_sha: str
    ) -> tuple[GitHubCheckRunResponse, ...]:
        value = self._object(
            self._transport.get(
                f"{self._repo(owner, name)}/commits/{_sha(head_sha)}/check-runs?per_page=100",
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            expected=(200,),
        )
        raw = value.get("check_runs")
        if not isinstance(raw, list) or len(raw) > 100:
            raise GitHubApiError("GitHub check-run projection is malformed or truncated")
        result: list[GitHubCheckRunResponse] = []
        for item in raw:
            app = item.get("app") if isinstance(item, dict) else None
            external_id = item.get("id") if isinstance(item, dict) else None
            check_name = item.get("name") if isinstance(item, dict) else None
            status = item.get("status") if isinstance(item, dict) else None
            conclusion = item.get("conclusion") if isinstance(item, dict) else None
            observed_sha = item.get("head_sha") if isinstance(item, dict) else None
            details_url = item.get("details_url") if isinstance(item, dict) else None
            app_slug = app.get("slug") if isinstance(app, dict) else None
            if (
                not isinstance(external_id, int)
                or not isinstance(check_name, str)
                or status not in {"queued", "in_progress", "completed"}
                or (conclusion is not None and not isinstance(conclusion, str))
                or not isinstance(observed_sha, str)
                or (app_slug is not None and not isinstance(app_slug, str))
                or (details_url is not None and not isinstance(details_url, str))
            ):
                raise GitHubApiError("GitHub check-run response is malformed")
            result.append(
                GitHubCheckRunResponse(
                    external_id,
                    check_name[:128],
                    str(status).upper(),
                    str(conclusion).upper() if conclusion else None,
                    _sha(observed_sha),
                    details_url[:500] if details_url else None,
                )
            )
        return tuple(sorted(result, key=lambda item: (item.name, item.external_id)))

    def reviews(self, *, owner: str, name: str, number: int) -> tuple[GitHubReviewResponse, ...]:
        values = self._bounded_list(
            self._transport.get(
                f"{self._repo(owner, name)}/pulls/{number}/reviews?per_page=100&page=1",
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            maximum=100,
        )
        result: list[GitHubReviewResponse] = []
        for value in values:
            user = value.get("user")
            external_id, state = value.get("id"), value.get("state")
            account_node_id = user.get("node_id") if isinstance(user, dict) else None
            commit_sha, submitted_at = value.get("commit_id"), value.get("submitted_at")
            if (
                not isinstance(external_id, int)
                or not isinstance(account_node_id, str)
                or state not in {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"}
                or not isinstance(commit_sha, str)
                or not isinstance(submitted_at, str)
            ):
                raise GitHubApiError("GitHub review response is malformed")
            result.append(
                GitHubReviewResponse(
                    external_id, account_node_id, str(state), _sha(commit_sha), submitted_at
                )
            )
        return tuple(sorted(result, key=lambda item: (item.submitted_at, item.external_id)))

    def pull_request_review_decision(self, *, pull_request_node_id: str) -> str:
        if not pull_request_node_id or len(pull_request_node_id) > 255:
            raise GitHubApiError("GitHub pull-request node ID is invalid")
        value = self._object(
            self._transport.post(
                f"{self._base}/graphql",
                headers=self._headers(),
                json={
                    "query": (
                        "query ReviewDecision($id:ID!){node(id:$id){... on PullRequest{"
                        "reviewDecision}}}"
                    ),
                    "variables": {"id": pull_request_node_id},
                },
                timeout=30,
            ),
            expected=(200,),
        )
        if value.get("errors"):
            raise GitHubApiError("GitHub review-decision query failed")
        data = value.get("data")
        node = data.get("node") if isinstance(data, dict) else None
        decision = node.get("reviewDecision") if isinstance(node, dict) else None
        if decision not in {"APPROVED", "CHANGES_REQUESTED", "REVIEW_REQUIRED"}:
            raise GitHubApiError("GitHub review decision is absent or malformed")
        return str(decision)

    def branch_protection(self, *, owner: str, name: str, branch: str) -> dict[str, object]:
        value = self._object(
            self._transport.get(
                f"{self._repo(owner, name)}/branches/{quote(branch, safe='')}/protection",
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            expected=(200,),
        )
        checks = value.get("required_status_checks")
        reviews = value.get("required_pull_request_reviews")
        enforce_admins = value.get("enforce_admins")
        restrictions = value.get("restrictions")
        if not isinstance(checks, dict) or not isinstance(reviews, dict):
            raise GitHubApiError("required GitHub branch protection is absent")
        contexts = checks.get("contexts")
        required_approvals = reviews.get("required_approving_review_count")
        require_code_owner = reviews.get("require_code_owner_reviews")
        if (
            not isinstance(contexts, list)
            or len(contexts) > 100
            or any(not isinstance(item, str) for item in contexts)
            or not isinstance(required_approvals, int)
            or not isinstance(require_code_owner, bool)
            or not isinstance(enforce_admins, dict)
            or not isinstance(enforce_admins.get("enabled"), bool)
        ):
            raise GitHubApiError("GitHub branch-protection projection is malformed")
        return {
            "schema_version": 1,
            "required_status_check_contexts": sorted(contexts),
            "strict_status_checks": checks.get("strict") is True,
            "required_approving_review_count": required_approvals,
            "require_code_owner_reviews": require_code_owner,
            "enforce_admins": enforce_admins["enabled"],
            "restrictions_present": restrictions is not None,
        }

    def _headers(self) -> dict[str, str]:
        token = self._tokens.token(installation_id=self._installation_id)
        if not token or len(token) > 4_096:
            raise GitHubApiError("GitHub installation token is missing or oversized")
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _repo(self, owner: str, name: str) -> str:
        return f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"

    @staticmethod
    def _object(response: GitHubApiResponse, *, expected: tuple[int, ...]) -> dict[str, Any]:
        value = _decode(response, expected=expected)
        if not isinstance(value, dict):
            raise GitHubApiError("GitHub API response is not an object")
        return cast("dict[str, Any]", value)

    @staticmethod
    def _list(response: GitHubApiResponse, *, expected: tuple[int, ...]) -> list[Mapping[str, Any]]:
        value = _decode(response, expected=expected)
        if (
            not isinstance(value, list)
            or len(value) > 2
            or any(not isinstance(item, dict) for item in value)
        ):
            raise GitHubApiError("GitHub pull-request search response is malformed")
        return cast("list[Mapping[str, Any]]", value)

    @staticmethod
    def _bounded_list(response: GitHubApiResponse, *, maximum: int) -> list[Mapping[str, Any]]:
        value = _decode(response, expected=(200,))
        if (
            not isinstance(value, list)
            or len(value) > maximum
            or any(not isinstance(item, dict) for item in value)
        ):
            raise GitHubApiError("GitHub bounded list response is malformed or truncated")
        return cast("list[Mapping[str, Any]]", value)


def _decode(response: GitHubApiResponse, *, expected: tuple[int, ...]) -> object:
    if response.status_code not in expected:
        raise GitHubApiError(f"GitHub API returned HTTP {response.status_code}")
    if len(response.content) > 2_000_000:
        raise GitHubApiError("GitHub API response exceeds the bounded response size")
    return response.json()


def _sha(value: str) -> str:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise GitHubApiError("GitHub object SHA is invalid")
    return value


def _pull_request(value: Mapping[str, Any]) -> GitHubPullRequestResponse:
    head = value.get("head")
    base = value.get("base")
    number = value.get("number")
    node_id = value.get("node_id")
    head_sha = head.get("sha") if isinstance(head, dict) else None
    base_sha = base.get("sha") if isinstance(base, dict) else None
    html_url = value.get("html_url")
    draft = value.get("draft")
    merge_commit_sha = value.get("merge_commit_sha")
    if (
        not isinstance(number, int)
        or not isinstance(node_id, str)
        or not node_id
        or not isinstance(head_sha, str)
        or not isinstance(base_sha, str)
        or not isinstance(html_url, str)
        or not html_url.startswith("https://")
        or not isinstance(draft, bool)
        or (merge_commit_sha is not None and not isinstance(merge_commit_sha, str))
    ):
        raise GitHubApiError("GitHub pull-request response omitted immutable refs")
    return GitHubPullRequestResponse(
        number=number,
        node_id=node_id,
        html_url=html_url[:500],
        head_sha=_sha(head_sha),
        base_sha=_sha(base_sha),
        state=str(value.get("state", "unknown"))[:32],
        merged=bool(value.get("merged", False)),
        mergeable_state=(str(value["mergeable_state"]) if value.get("mergeable_state") else None),
        title=str(value.get("title", ""))[:256],
        draft=draft,
        merge_commit_sha=_sha(merge_commit_sha) if merge_commit_sha else None,
    )
