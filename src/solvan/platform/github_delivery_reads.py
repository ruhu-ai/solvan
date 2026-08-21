"""Bounded reads over what a repository has shipped and what it is discussing.

Three surfaces that sit beside the pull request rather than inside it:
deployments (what actually reached an environment), discussions (the long-form
context a thread rarely carries), and the merge queue (why a merge that passed
every check still has not landed).

Two of the three are GraphQL-only on GitHub, which is why they live here rather
than beside the REST reads. The query text is a module constant in every case:
there is no path by which a caller composes a query, so the fields this client
can reach are the fields written below and nothing else.

Like every read client here, this one has no mutation method, caps every
response, and length-clips every projected string — the text comes from anyone
who can open a discussion, and it flows onward into prompts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import quote

from solvan.platform.github import (
    GitHubApiError,
    GitHubApiResponse,
    GitHubApiTransport,
    GitHubTokenProvider,
)

_MAXIMUM_RESPONSE_BYTES = 2_000_000
_GIT_SHA = "0123456789abcdef"

#: Repository discussions, newest first. Bodies are deliberately absent: a
#: discussion body is unbounded prose from an arbitrary author, and the title,
#: category, and URL are enough to decide whether one is worth opening.
_DISCUSSIONS_QUERY = """
query($owner:String!,$name:String!,$first:Int!){
  repository(owner:$owner,name:$name){
    discussions(first:$first, orderBy:{field:UPDATED_AT,direction:DESC}){
      nodes{
        number title url createdAt updatedAt isAnswered
        category{ name }
        author{ login }
      }
    }
  }
}
"""

#: One branch's merge queue. `state` is why an entry has not merged, which is
#: the question the REST check-run view cannot answer.
_MERGE_QUEUE_QUERY = """
query($owner:String!,$name:String!,$branch:String!,$first:Int!){
  repository(owner:$owner,name:$name){
    mergeQueue(branch:$branch){
      entries(first:$first){
        nodes{
          position state enqueuedAt
          pullRequest{ number title }
        }
      }
    }
  }
}
"""


@dataclass(frozen=True, slots=True)
class Deployment:
    """One deployment and the state it most recently reported."""

    deployment_id: int
    sha: str
    ref: str
    task: str
    environment: str
    production_environment: bool
    transient_environment: bool
    creator_login: str
    created_at: str
    state: str
    state_description: str
    target_url: str


@dataclass(frozen=True, slots=True)
class Discussion:
    """One repository discussion, without its body."""

    number: int
    title: str
    category: str
    author_login: str
    url: str
    created_at: str
    updated_at: str
    answered: bool


@dataclass(frozen=True, slots=True)
class MergeQueueEntry:
    """One pull request waiting in a branch's merge queue."""

    pull_request_number: int
    title: str
    position: int
    state: str
    enqueued_at: str


def _clip(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(character for character in value if character == "\n" or character >= " ")
    return cleaned[:limit]


class GitHubDeliveryReadClient:
    """Deployments, discussions, and merge-queue reads for one installation."""

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
    def _decode(response: GitHubApiResponse, *, expected: tuple[int, ...]) -> Any:
        if response.status_code not in expected:
            raise GitHubApiError(f"GitHub API returned HTTP {response.status_code}")
        if len(response.content) > _MAXIMUM_RESPONSE_BYTES:
            raise GitHubApiError("GitHub API response exceeds the bounded response size")
        return response.json()

    def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Run one module-constant query.

        `query` is never caller-supplied; the parameter exists so the two
        constants above can share this transport, not so a query can be passed
        in. GraphQL errors are surfaced as one refusal without their text,
        which can quote repository content.
        """

        value = self._decode(
            self._transport.post(
                f"{self._base}/graphql",
                headers=self._headers(),
                json={"query": query, "variables": variables},
                timeout=30,
            ),
            expected=(200,),
        )
        if not isinstance(value, dict):
            raise GitHubApiError("GitHub GraphQL response is not an object")
        if value.get("errors"):
            raise GitHubApiError("GitHub GraphQL query was refused")
        data = value.get("data")
        if not isinstance(data, dict):
            raise GitHubApiError("GitHub GraphQL response carries no data")
        return cast(dict[str, Any], data)

    def deployments(
        self,
        *,
        owner: str,
        name: str,
        environment: str | None = None,
        sha: str | None = None,
        limit: int = 20,
    ) -> tuple[Deployment, ...]:
        """List recent deployments and each one's latest reported state.

        The state is fetched per deployment because GitHub reports it on a
        separate resource, and a deployment without its state answers nothing
        useful — "we created a deployment" is not "it succeeded".
        """

        if not 1 <= limit <= 50:
            raise GitHubApiError("GitHub deployment bounds are invalid")
        if sha is not None and (len(sha) != 40 or any(c not in _GIT_SHA for c in sha)):
            raise GitHubApiError("GitHub deployment filter requires an exact commit SHA")
        query = [f"per_page={limit}", "page=1"]
        if environment is not None:
            if not 1 <= len(environment) <= 255:
                raise GitHubApiError("GitHub deployment environment filter is invalid")
            query.append(f"environment={quote(environment, safe='')}")
        if sha is not None:
            query.append(f"sha={sha}")
        raw = self._decode(
            self._transport.get(
                f"{self._repo(owner, name)}/deployments?" + "&".join(query),
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            expected=(200,),
        )
        if not isinstance(raw, list) or len(raw) > limit:
            raise GitHubApiError("GitHub deployment response is malformed or oversized")
        results: list[Deployment] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            identifier = item.get("id")
            if not isinstance(identifier, int) or identifier <= 0:
                continue
            state, description, target = self._latest_deployment_state(
                owner=owner, name=name, deployment_id=identifier
            )
            creator = item.get("creator")
            results.append(
                Deployment(
                    deployment_id=identifier,
                    sha=_clip(item.get("sha"), 40),
                    ref=_clip(item.get("ref"), 255),
                    task=_clip(item.get("task"), 64),
                    environment=_clip(item.get("environment"), 255),
                    production_environment=bool(item.get("production_environment", False)),
                    transient_environment=bool(item.get("transient_environment", False)),
                    creator_login=_clip(
                        creator.get("login") if isinstance(creator, dict) else "", 39
                    ),
                    created_at=_clip(item.get("created_at"), 32),
                    state=state,
                    state_description=description,
                    target_url=target,
                )
            )
        return tuple(results)

    def _latest_deployment_state(
        self, *, owner: str, name: str, deployment_id: int
    ) -> tuple[str, str, str]:
        raw = self._decode(
            self._transport.get(
                f"{self._repo(owner, name)}/deployments/{deployment_id}/statuses?per_page=1",
                headers=self._headers(),
                timeout=30,
                allow_redirects=False,
            ),
            expected=(200,),
        )
        if not isinstance(raw, list) or not raw or not isinstance(raw[0], dict):
            return "UNKNOWN", "", ""
        latest = raw[0]
        return (
            _clip(latest.get("state"), 32).upper() or "UNKNOWN",
            _clip(latest.get("description"), 500),
            _clip(latest.get("target_url"), 500),
        )

    def discussions(self, *, owner: str, name: str, limit: int = 20) -> tuple[Discussion, ...]:
        """List recent repository discussions, newest first."""

        if not 1 <= limit <= 50:
            raise GitHubApiError("GitHub discussion bounds are invalid")
        data = self._graphql(_DISCUSSIONS_QUERY, {"owner": owner, "name": name, "first": limit})
        repository = data.get("repository")
        container = repository.get("discussions") if isinstance(repository, dict) else None
        nodes = container.get("nodes") if isinstance(container, dict) else None
        if nodes is None:
            # Discussions can be disabled on a repository, which is an answer
            # rather than a failure.
            return ()
        if not isinstance(nodes, list) or len(nodes) > limit:
            raise GitHubApiError("GitHub discussion response is malformed or oversized")
        results: list[Discussion] = []
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get("number"), int):
                continue
            category = node.get("category")
            author = node.get("author")
            results.append(
                Discussion(
                    number=int(node["number"]),
                    title=_clip(node.get("title"), 256),
                    category=_clip(category.get("name") if isinstance(category, dict) else "", 100),
                    author_login=_clip(author.get("login") if isinstance(author, dict) else "", 39),
                    url=_clip(node.get("url"), 500),
                    created_at=_clip(node.get("createdAt"), 32),
                    updated_at=_clip(node.get("updatedAt"), 32),
                    answered=bool(node.get("isAnswered", False)),
                )
            )
        return tuple(results)

    def merge_queue(
        self, *, owner: str, name: str, branch: str, limit: int = 20
    ) -> tuple[MergeQueueEntry, ...]:
        """List what is waiting to merge into one branch, and why.

        A pull request that passed every check and still has not landed is
        usually queued behind something, which no check-run read explains.
        """

        if not 1 <= limit <= 50:
            raise GitHubApiError("GitHub merge-queue bounds are invalid")
        if not 1 <= len(branch) <= 255:
            raise GitHubApiError("GitHub merge-queue branch is invalid")
        data = self._graphql(
            _MERGE_QUEUE_QUERY,
            {"owner": owner, "name": name, "branch": branch, "first": limit},
        )
        repository = data.get("repository")
        queue = repository.get("mergeQueue") if isinstance(repository, dict) else None
        entries = queue.get("entries") if isinstance(queue, dict) else None
        nodes = entries.get("nodes") if isinstance(entries, dict) else None
        if nodes is None:
            # No merge queue configured on this branch, which is an answer.
            return ()
        if not isinstance(nodes, list) or len(nodes) > limit:
            raise GitHubApiError("GitHub merge-queue response is malformed or oversized")
        results: list[MergeQueueEntry] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            pull = node.get("pullRequest")
            number = pull.get("number") if isinstance(pull, dict) else None
            if not isinstance(number, int):
                continue
            position = node.get("position")
            results.append(
                MergeQueueEntry(
                    pull_request_number=number,
                    title=_clip(pull.get("title") if isinstance(pull, dict) else "", 256),
                    position=position if isinstance(position, int) and position >= 0 else -1,
                    state=_clip(node.get("state"), 32).upper() or "UNKNOWN",
                    enqueued_at=_clip(node.get("enqueuedAt"), 32),
                )
            )
        return tuple(results)
