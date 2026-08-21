"""Closed GitHub boundary for the conversational surface.

Like every other GitHub client here, this one has no generic `request` method
and no caller-steerable endpoint: each capability is a named method that builds
one path from validated components.  What differs is the threat model.  The
code-delivery client reads material Solvan itself produced; this one reads text
written by whoever can open an issue on the repository, and publishes text back
into that same public space.

So two things are stricter.  Every projected string is length-clipped at the
boundary and carries no HTML, because it flows onward into prompts and console
views.  And every publication takes an already-rendered body — this module
cannot compose one, so there is no path by which model prose reaches GitHub
without passing the claim registry first.

Specification 24 governs.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast
from urllib.parse import quote

from solvan.application.github_conversation import (
    ConversationOperation,
    GitHubConversationError,
    ReviewEvent,
)
from solvan.platform.github import (
    GitHubApiError,
    GitHubApiResponse,
    GitHubApiTransport,
    GitHubTokenProvider,
)

#: GitHub's search API is capped at 100 per page and is rate-limited far more
#: tightly than the REST endpoints; the default stays well under both.
_MAXIMUM_SEARCH_RESULTS = 50
_MAXIMUM_COMMENTS = 100
_MAXIMUM_COMMITS = 100
_MAXIMUM_RESPONSE_BYTES = 2_000_000
_MAXIMUM_QUERY_LENGTH = 256


class GitHubRateLimited(GitHubApiError):
    """GitHub refused the call for rate reasons; the work is retryable.

    Carried as its own class because the delivery contract distinguishes a
    pre-issue availability refusal, which may be retried, from a state refusal,
    which may not.  Collapsing the two would either retry a real conflict or
    fail a call that merely arrived too fast.
    """

    def __init__(self, message: str, *, retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class GitHubHeaderedResponse(Protocol):
    """A response whose headers are readable, so rate limits can be observed."""

    status_code: int
    content: bytes
    headers: Mapping[str, str]

    def json(self) -> Any: ...


@dataclass(frozen=True, slots=True)
class ConversationComment:
    """One projected comment.  Untrusted text, bounded and attributed."""

    comment_id: int
    author_login: str
    body: str
    created_at: str
    author_association: str


@dataclass(frozen=True, slots=True)
class ConversationIssue:
    """One issue or pull-request thread as GitHub reports it."""

    number: int
    node_id: str
    title: str
    body: str
    state: str
    locked: bool
    author_login: str
    html_url: str
    labels: tuple[str, ...]
    is_pull_request: bool
    comment_count: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class PullRequestHead:
    """The head a pull request currently points at.

    Read from `GET /pulls/{n}` rather than `GET /issues/{n}`, which serves
    pull requests but carries no head. A review is bound to the commit its
    approver read, so the publication path needs the current head to tell
    whether that commit is still what the pull request proposes.
    """

    number: int
    head_sha: str
    base_sha: str
    state: str
    merged: bool
    draft: bool


@dataclass(frozen=True, slots=True)
class SearchHit:
    """One bounded search result.  Deliberately thin: identity, not content."""

    kind: str
    identifier: str
    title: str
    html_url: str
    state: str


@dataclass(frozen=True, slots=True)
class CommitSummary:
    """One commit's metadata, without its diff."""

    sha: str
    author_login: str
    author_name: str
    authored_at: str
    message: str


@dataclass(frozen=True, slots=True)
class WorkflowRun:
    """One Actions run, projected without its logs."""

    run_id: int
    name: str
    workflow_path: str
    head_sha: str
    status: str
    conclusion: str
    event: str
    run_number: int
    html_url: str
    created_at: str


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    """What a publication produced, so it reconciles exactly once."""

    operation: ConversationOperation
    external_id: int
    external_url: str
    external_number: int | None


def _clip(value: Any, limit: int) -> str:
    """Project one untrusted string, bounded and stripped of control bytes.

    GitHub text reaches prompts, console views, and audit records.  A control
    character in any of those is at best a rendering defect and at worst a way
    to make two different strings look identical to a reviewer.
    """

    if not isinstance(value, str):
        return ""
    cleaned = "".join(character for character in value if character == "\n" or character >= " ")
    return cleaned[:limit]


def _is_commit_sha(value: Any) -> bool:
    """Whether GitHub reported a full 40-character commit SHA."""

    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _login(value: Any) -> str:
    """Project an actor login, or empty when GitHub reports something else."""

    if not isinstance(value, dict):
        return ""
    login = value.get("login")
    if not isinstance(login, str) or not 1 <= len(login) <= 39:
        return ""
    return login if all(c.isalnum() or c == "-" for c in login) else ""


class GitHubConversationClient:
    """Bounded reads over a repository's conversation, and the three writes."""

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

    # -- transport -----------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        token = self._tokens.token(installation_id=self._installation_id)
        if not token or len(token) > 4096:
            raise GitHubApiError("GitHub installation token is missing or oversized")
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _repo(self, owner: str, name: str) -> str:
        return f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"

    @staticmethod
    def _check_rate_limit(response: GitHubApiResponse) -> None:
        """Raise the retryable class when GitHub says we are over a limit.

        Both limits are checked because they behave differently: the primary
        limit reports a remaining count and a reset time, while the secondary
        limit returns 403 with `Retry-After` and no remaining count at all.
        Treating only the first would turn abuse-detection throttling into a
        permanent-looking failure.
        """

        headers = getattr(response, "headers", None)
        if not isinstance(headers, Mapping):
            return
        lowered = {str(key).lower(): str(value) for key, value in headers.items()}
        retry_after = lowered.get("retry-after")
        seconds: int | None = None
        if retry_after is not None and retry_after.strip().isdigit():
            seconds = min(int(retry_after.strip()), 3_600)
        if response.status_code in (403, 429):
            remaining = lowered.get("x-ratelimit-remaining")
            if seconds is not None or remaining == "0":
                raise GitHubRateLimited("GitHub rate limit reached", retry_after_seconds=seconds)

    def _get_object(self, url: str, *, expected: tuple[int, ...] = (200,)) -> dict[str, Any]:
        response = self._transport.get(
            url, headers=self._headers(), timeout=30, allow_redirects=False
        )
        self._check_rate_limit(response)
        return self._object(response, expected=expected)

    def _get_list(self, url: str, *, limit: int) -> list[dict[str, Any]]:
        response = self._transport.get(
            url, headers=self._headers(), timeout=30, allow_redirects=False
        )
        self._check_rate_limit(response)
        if response.status_code != 200:
            raise GitHubApiError(f"GitHub API returned HTTP {response.status_code}")
        if len(response.content) > _MAXIMUM_RESPONSE_BYTES:
            raise GitHubApiError("GitHub API response exceeds the bounded response size")
        value = response.json()
        if not isinstance(value, list) or len(value) > limit:
            raise GitHubApiError("GitHub API list response is malformed or oversized")
        return [cast(dict[str, Any], item) for item in value if isinstance(item, dict)]

    @staticmethod
    def _object(response: GitHubApiResponse, *, expected: tuple[int, ...]) -> dict[str, Any]:
        if response.status_code not in expected:
            raise GitHubApiError(f"GitHub API returned HTTP {response.status_code}")
        if len(response.content) > _MAXIMUM_RESPONSE_BYTES:
            raise GitHubApiError("GitHub API response exceeds the bounded response size")
        value = response.json()
        if not isinstance(value, dict):
            raise GitHubApiError("GitHub API response is not an object")
        return cast(dict[str, Any], value)

    def _post(self, url: str, body: dict[str, Any], *, expected: tuple[int, ...]) -> dict[str, Any]:
        response = self._transport.post(url, headers=self._headers(), json=body, timeout=30)
        self._check_rate_limit(response)
        return self._object(response, expected=expected)

    # -- reads ---------------------------------------------------------------

    def search(
        self, *, query: str, search_kind: str = "issues", limit: int = 10
    ) -> tuple[SearchHit, ...]:
        """Search issues/pull requests or repositories, bounded.

        The query is scoped by the caller, not here — the provider appends the
        repository qualifier before calling, so an agent cannot broaden a search
        beyond the binding it was invoked for.
        """

        if search_kind not in {"issues", "repositories"}:
            raise GitHubApiError("GitHub search kind is not available")
        if not query.strip() or len(query) > _MAXIMUM_QUERY_LENGTH:
            raise GitHubApiError("GitHub search query is empty or oversized")
        if not 1 <= limit <= _MAXIMUM_SEARCH_RESULTS:
            raise GitHubApiError("GitHub search bounds are invalid")
        url = f"{self._base}/search/{search_kind}?q={quote(query, safe='')}&per_page={limit}&page=1"
        value = self._get_object(url)
        items = value.get("items")
        if not isinstance(items, list) or len(items) > limit:
            raise GitHubApiError("GitHub search response is malformed or oversized")
        hits: list[SearchHit] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if search_kind == "repositories":
                identifier = _clip(item.get("full_name"), 140)
                title = identifier
                state = "ARCHIVED" if item.get("archived") else "ACTIVE"
            else:
                number = item.get("number")
                if not isinstance(number, int):
                    continue
                identifier = str(number)
                title = _clip(item.get("title"), 256)
                state = _clip(item.get("state"), 32).upper()
            html_url = _clip(item.get("html_url"), 500)
            if not identifier or not html_url.startswith("https://"):
                continue
            hits.append(
                SearchHit(
                    kind="REPOSITORY" if search_kind == "repositories" else "ISSUE",
                    identifier=identifier,
                    title=title,
                    html_url=html_url,
                    state=state,
                )
            )
        return tuple(hits)

    def issue(self, *, owner: str, name: str, number: int) -> ConversationIssue:
        """Read one issue or pull request.  GitHub serves both from this path."""

        if number <= 0:
            raise GitHubApiError("GitHub issue number is invalid")
        value = self._get_object(f"{self._repo(owner, name)}/issues/{number}")
        observed = value.get("number")
        node_id = value.get("node_id")
        if observed != number or not isinstance(node_id, str) or not node_id:
            raise GitHubApiError("GitHub issue response does not identify the requested thread")
        labels = value.get("labels")
        label_names: list[str] = []
        if isinstance(labels, list):
            for label in labels[:50]:
                if isinstance(label, dict) and (text := _clip(label.get("name"), 100)):
                    label_names.append(text)
        return ConversationIssue(
            number=number,
            node_id=node_id[:128],
            title=_clip(value.get("title"), 256),
            body=_clip(value.get("body"), 16_000),
            state=_clip(value.get("state"), 32).upper() or "UNKNOWN",
            locked=bool(value.get("locked", False)),
            author_login=_login(value.get("user")),
            html_url=_clip(value.get("html_url"), 500),
            labels=tuple(label_names),
            is_pull_request=isinstance(value.get("pull_request"), dict),
            comment_count=int(value.get("comments", 0))
            if isinstance(value.get("comments"), int)
            else 0,
            created_at=_clip(value.get("created_at"), 32),
            updated_at=_clip(value.get("updated_at"), 32),
        )

    def pull_request_head(self, *, owner: str, name: str, number: int) -> PullRequestHead:
        """Read one pull request's current head, base, and state.

        Deliberately thin: the publication path needs to know whether the code
        under review moved, not what it says. Nothing here is projected into a
        prompt, so nothing here needs clipping beyond the SHA shape check.
        """

        if number <= 0:
            raise GitHubApiError("GitHub pull request number is invalid")
        value = self._get_object(f"{self._repo(owner, name)}/pulls/{number}")
        if value.get("number") != number:
            raise GitHubApiError(
                "GitHub pull request response does not identify the requested thread"
            )
        head = value.get("head")
        base = value.get("base")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        base_sha = base.get("sha") if isinstance(base, dict) else None
        if not _is_commit_sha(head_sha):
            raise GitHubApiError("GitHub pull request response carries no head commit")
        return PullRequestHead(
            number=number,
            head_sha=cast(str, head_sha),
            base_sha=cast(str, base_sha) if _is_commit_sha(base_sha) else "",
            state=_clip(value.get("state"), 32).upper() or "UNKNOWN",
            merged=value.get("merged") is True,
            draft=value.get("draft") is True,
        )

    def issue_comments(
        self, *, owner: str, name: str, number: int, limit: int = 30
    ) -> tuple[ConversationComment, ...]:
        """Read one thread's comments, newest page only and bounded."""

        if number <= 0 or not 1 <= limit <= _MAXIMUM_COMMENTS:
            raise GitHubApiError("GitHub comment bounds are invalid")
        items = self._get_list(
            f"{self._repo(owner, name)}/issues/{number}/comments?per_page={limit}&page=1",
            limit=limit,
        )
        comments: list[ConversationComment] = []
        for item in items:
            identifier = item.get("id")
            if not isinstance(identifier, int) or identifier <= 0:
                continue
            comments.append(
                ConversationComment(
                    comment_id=identifier,
                    author_login=_login(item.get("user")),
                    body=_clip(item.get("body"), 8_000),
                    created_at=_clip(item.get("created_at"), 32),
                    author_association=_clip(item.get("author_association"), 32).upper(),
                )
            )
        return tuple(comments)

    def commit_history(
        self,
        *,
        owner: str,
        name: str,
        author: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 30,
    ) -> tuple[CommitSummary, ...]:
        """List commits newest-first, optionally filtered by author and window.

        This is the read the existing `compare_commits` cannot serve: that one
        needs two exact SHAs, which is precisely what a caller asking "what
        changed here lately" does not have.
        """

        if not 1 <= limit <= _MAXIMUM_COMMITS:
            raise GitHubApiError("GitHub commit history bounds are invalid")
        if since is not None and until is not None and since > until:
            raise GitHubApiError("GitHub commit window ends before it begins")
        query = [f"per_page={limit}", "page=1"]
        if author is not None:
            if not 1 <= len(author) <= 100:
                raise GitHubApiError("GitHub commit author filter is invalid")
            query.append(f"author={quote(author, safe='')}")
        for label, moment in (("since", since), ("until", until)):
            if moment is None:
                continue
            if moment.tzinfo is None or moment.utcoffset() is None:
                raise GitHubApiError("GitHub commit window bounds must include a timezone")
            query.append(f"{label}={quote(moment.isoformat(), safe='')}")
        url = f"{self._repo(owner, name)}/commits?" + "&".join(query)
        items = self._get_list(url, limit=limit)
        commits: list[CommitSummary] = []
        for item in items:
            sha = item.get("sha")
            if not isinstance(sha, str) or len(sha) != 40:
                continue
            commit = item.get("commit")
            author_block = commit.get("author") if isinstance(commit, dict) else None
            message = commit.get("message") if isinstance(commit, dict) else ""
            commits.append(
                CommitSummary(
                    sha=sha,
                    author_login=_login(item.get("author")),
                    author_name=_clip(
                        author_block.get("name") if isinstance(author_block, dict) else "", 128
                    ),
                    authored_at=_clip(
                        author_block.get("date") if isinstance(author_block, dict) else "", 32
                    ),
                    message=_clip(message, 2_000),
                )
            )
        return tuple(commits)

    def workflow_runs(
        self, *, owner: str, name: str, head_sha: str, limit: int = 30
    ) -> tuple[WorkflowRun, ...]:
        """List Actions runs for one exact commit.

        Distinct from `check_runs`, which reports the *result* another system
        published against a commit. This reports the workflow that ran, which
        file defined it, and what triggered it — the difference between "a check
        called deploy failed" and "the deploy workflow ran from this file on a
        push and failed", which is usually the question during an incident.
        """

        if len(head_sha) != 40 or any(c not in "0123456789abcdef" for c in head_sha):
            raise GitHubApiError("GitHub workflow-run read requires an exact commit SHA")
        if not 1 <= limit <= 100:
            raise GitHubApiError("GitHub workflow-run bounds are invalid")
        value = self._get_object(
            f"{self._repo(owner, name)}/actions/runs?head_sha={head_sha}&per_page={limit}&page=1"
        )
        raw = value.get("workflow_runs")
        if not isinstance(raw, list) or len(raw) > limit:
            raise GitHubApiError("GitHub workflow-run response is malformed or oversized")
        runs: list[WorkflowRun] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            run_id = item.get("id")
            observed = item.get("head_sha")
            if not isinstance(run_id, int) or observed != head_sha:
                continue
            runs.append(
                WorkflowRun(
                    run_id=run_id,
                    name=_clip(item.get("name"), 128) or "unknown",
                    workflow_path=_clip(item.get("path"), 500),
                    head_sha=head_sha,
                    status=_clip(item.get("status"), 32).upper() or "UNKNOWN",
                    conclusion=_clip(item.get("conclusion"), 32).upper() or "PENDING",
                    event=_clip(item.get("event"), 32),
                    run_number=int(item.get("run_number", 0))
                    if isinstance(item.get("run_number"), int)
                    else 0,
                    html_url=_clip(item.get("html_url"), 500),
                    created_at=_clip(item.get("created_at"), 32),
                )
            )
        return tuple(runs)

    # -- publications --------------------------------------------------------

    def create_issue(self, *, owner: str, name: str, title: str, body: str) -> PublicationReceipt:
        """Open one issue from an already-rendered body."""

        if not 1 <= len(title) <= 256 or not body:
            raise GitHubConversationError("issue title or body is out of bounds")
        value = self._post(
            f"{self._repo(owner, name)}/issues",
            {"title": title, "body": body},
            expected=(201,),
        )
        return self._receipt(value, ConversationOperation.CREATE_ISSUE, numbered=True)

    def create_issue_comment(
        self, *, owner: str, name: str, number: int, body: str
    ) -> PublicationReceipt:
        """Comment on one issue or pull-request thread."""

        if number <= 0 or not body:
            raise GitHubConversationError("comment target or body is out of bounds")
        value = self._post(
            f"{self._repo(owner, name)}/issues/{number}/comments",
            {"body": body},
            expected=(201,),
        )
        return self._receipt(
            value, ConversationOperation.POST_ISSUE_COMMENT, external_number=number
        )

    def submit_pull_request_review(
        self,
        *,
        owner: str,
        name: str,
        number: int,
        event: ReviewEvent,
        body: str,
        commit_id: str,
    ) -> PublicationReceipt:
        """Submit one review bound to the exact commit it reviewed.

        `commit_id` is not optional here even though GitHub allows omitting it.
        Without it GitHub attaches the review to whatever the head happens to be
        at delivery, which is how a review of reviewed code silently becomes a
        review of code nobody read.
        """

        if event not in (ReviewEvent.COMMENT, ReviewEvent.REQUEST_CHANGES):
            raise GitHubConversationError("Solvan does not emit approving reviews")
        if number <= 0 or not body:
            raise GitHubConversationError("review target or body is out of bounds")
        if len(commit_id) != 40 or any(c not in "0123456789abcdef" for c in commit_id):
            raise GitHubConversationError("a review requires an exact lowercase head commit")
        value = self._post(
            f"{self._repo(owner, name)}/pulls/{number}/reviews",
            {"body": body, "event": event.value, "commit_id": commit_id},
            expected=(200,),
        )
        return self._receipt(
            value,
            ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW,
            external_number=number,
        )

    @staticmethod
    def _receipt(
        value: Mapping[str, Any],
        operation: ConversationOperation,
        *,
        external_number: int | None = None,
        numbered: bool = False,
    ) -> PublicationReceipt:
        identifier = value.get("id")
        html_url = value.get("html_url")
        if not isinstance(identifier, int) or identifier <= 0:
            raise GitHubApiError("GitHub publication response omitted its identifier")
        if not isinstance(html_url, str) or not html_url.startswith("https://"):
            raise GitHubApiError("GitHub publication response omitted its URL")
        number = external_number
        if numbered:
            observed = value.get("number")
            if not isinstance(observed, int) or observed <= 0:
                raise GitHubApiError("GitHub issue creation omitted its number")
            number = observed
        return PublicationReceipt(
            operation=operation,
            external_id=identifier,
            external_url=html_url[:500],
            external_number=number,
        )
