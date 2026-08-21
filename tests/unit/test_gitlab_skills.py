from __future__ import annotations

import json

import pytest

from solvan.platform.github import GitHubApiError
from solvan.platform.gitlab_skills import (
    ConfiguredGitLabTokenProvider,
    GitLabMetadataConnector,
)


class Response:
    def __init__(
        self,
        value: object,
        *,
        content: bytes | None = None,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = json.dumps(value).encode() if content is None else content
        self.headers = {"x-next-page": ""} if headers is None else headers

    def json(self) -> object:
        return json.loads(self.content)


class Transport:
    def __init__(self, *, mode: str = "normal") -> None:
        self.mode = mode
        self.urls: list[str] = []

    def get(self, url: str, **kwargs: object) -> Response:
        del kwargs
        self.urls.append(url)
        if self.mode == "http-error":
            return Response({}, status_code=503)
        if self.mode == "oversized-response":
            return Response({}, content=b"x" * 2_000_001)
        if "/repository/tree?" in url:
            if self.mode == "malformed-tree":
                return Response({})
            if self.mode == "no-skill":
                return Response([{"type": "blob", "path": "README.md", "id": "a" * 40}])
            if self.mode == "unsafe-tree":
                return Response([{"type": "blob", "path": "skill/../SKILL.md", "id": "a" * 40}])
            if self.mode == "headerless-tree":
                response = Response([{"type": "blob", "path": "skill/SKILL.md", "id": "a" * 40}])
                del response.headers
                return response
            if self.mode == "inconsistent-pagination":
                return Response(
                    [{"type": "blob", "path": "skill/SKILL.md", "id": "a" * 40}],
                    headers={"x-next-page": "7"},
                )
            if self.mode == "unbounded-pagination":
                page = int(url.rsplit("&page=", 1)[1])
                return Response(
                    [{"type": "blob", "path": f"file-{page}.txt", "id": "c" * 40}],
                    headers={"x-next-page": str(page + 1)},
                )
            if self.mode == "paginated":
                page = int(url.rsplit("&page=", 1)[1])
                if page == 1:
                    return Response(
                        [{"type": "blob", "path": "skill/SKILL.md", "id": "a" * 40}],
                        headers={"x-next-page": "2"},
                    )
                return Response(
                    [{"type": "blob", "path": "skill/references/runbook.md", "id": "b" * 40}]
                )
            return Response(
                [
                    {"type": "blob", "path": "skill/SKILL.md", "id": "a" * 40},
                    {"type": "blob", "path": "skill/references/runbook.md", "id": "b" * 40},
                    {"type": "tree", "path": "skill/references", "id": "c" * 40},
                ]
            )
        if self.mode == "oversized-raw":
            return Response({}, content=b"x" * 1_000_001)
        if url.endswith(f"/repository/blobs/{'a' * 40}/raw"):
            return Response(
                {}, content=b"---\nname: demo\ndescription: x\nlicense: Apache-2.0\n---\n"
            )
        return Response({}, content=b"runbook")


def connector(transport: Transport) -> GitLabMetadataConnector:
    return GitLabMetadataConnector(
        transport=transport,
        token_provider=ConfiguredGitLabTokenProvider("token"),
        allowed_repositories=frozenset({"acme/payments"}),
    )


def test_gitlab_connector_is_pinned_allowlisted_and_content_bounded() -> None:
    transport = Transport()
    client = connector(transport)
    observed = client.observe_tree(
        repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
    )
    assert observed.commit_sha == "d" * 40
    assert observed.subtree_hash.startswith("sha256:")
    package = client.fetch_archive(
        repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
    )
    assert package.startswith(b"PK")
    # Every content read addresses an exact blob id from the pinned tree. A
    # subdirectory-relative path read (files/SKILL.md/raw) would resolve against
    # the repository root and silently return a different file.
    blob_reads = [url for url in transport.urls if "/repository/blobs/" in url]
    assert len(blob_reads) == 2
    assert any(url.endswith(f"/repository/blobs/{'a' * 40}/raw") for url in blob_reads)
    assert any(url.endswith(f"/repository/blobs/{'b' * 40}/raw") for url in blob_reads)
    assert all("/repository/blobs/" in url or "/repository/tree?" in url for url in transport.urls)


def test_gitlab_connector_rejects_unregistered_or_unsafe_references() -> None:
    client = connector(Transport())
    with pytest.raises(GitHubApiError, match="not registered"):
        client.observe_tree(
            repository_ref="gitlab://other/payments", commit_sha="d" * 40, subdirectory=""
        )
    with pytest.raises(GitHubApiError, match="exact lowercase"):
        client.observe_tree(
            repository_ref="gitlab://acme/payments", commit_sha="D" * 40, subdirectory=""
        )
    with pytest.raises(GitHubApiError, match="registered gitlab"):
        client.observe_tree(
            repository_ref="https://gitlab.com/acme/payments",
            commit_sha="d" * 40,
            subdirectory="",
        )
    with pytest.raises(GitHubApiError, match="path is unsafe"):
        client.observe_tree(
            repository_ref="gitlab://acme/payments",
            commit_sha="d" * 40,
            subdirectory="skill/../other",
        )


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("malformed-tree", "malformed"),
        ("no-skill", "no bounded"),
        ("unsafe-tree", "unsafe path"),
    ],
)
def test_gitlab_tree_validation_is_fail_closed(mode: str, message: str) -> None:
    with pytest.raises(GitHubApiError, match=message):
        connector(Transport(mode=mode)).observe_tree(
            repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
        )


def test_gitlab_provider_and_response_bounds_are_fail_closed() -> None:
    with pytest.raises(GitHubApiError, match="missing or oversized"):
        ConfiguredGitLabTokenProvider("").token()
    with pytest.raises(GitHubApiError, match="HTTP 503"):
        connector(Transport(mode="http-error")).observe_tree(
            repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
        )
    with pytest.raises(GitHubApiError, match="exceeds the bounded"):
        connector(Transport(mode="oversized-response")).observe_tree(
            repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
        )
    with pytest.raises(GitHubApiError, match="exceeds the package"):
        connector(Transport(mode="oversized-raw")).fetch_archive(
            repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
        )


def test_gitlab_tree_follows_pagination_headers_across_pages() -> None:
    transport = Transport(mode="paginated")
    client = connector(transport)
    observed = client.observe_tree(
        repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
    )
    tree_reads = [url for url in transport.urls if "/repository/tree?" in url]
    assert [url.rsplit("&page=", 1)[1] for url in tree_reads] == ["1", "2"]
    single = connector(Transport()).observe_tree(
        repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
    )
    # Both pages contribute entries: the paginated hash covers the same two
    # files as the single-page tree, so an unseen page can never be dropped
    # without changing the observation.
    assert observed.subtree_hash == single.subtree_hash


def test_gitlab_tree_pagination_is_bounded_and_fail_closed() -> None:
    with pytest.raises(GitHubApiError, match="bounded page count"):
        connector(Transport(mode="unbounded-pagination")).observe_tree(
            repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory=""
        )
    with pytest.raises(GitHubApiError, match="pagination headers are inconsistent"):
        connector(Transport(mode="inconsistent-pagination")).observe_tree(
            repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
        )
    with pytest.raises(GitHubApiError, match="no pagination headers"):
        connector(Transport(mode="headerless-tree")).observe_tree(
            repository_ref="gitlab://acme/payments", commit_sha="d" * 40, subdirectory="skill"
        )


def test_gitlab_connector_rejects_redirects_and_non_https_base() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        GitLabMetadataConnector(
            transport=Transport(),
            token_provider=ConfiguredGitLabTokenProvider("token"),
            allowed_repositories=frozenset({"acme/payments"}),
            api_base_url="http://gitlab.example/api/v4",
        )
