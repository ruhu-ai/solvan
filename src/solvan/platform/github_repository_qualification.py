"""Read-only, bounded GitHub repository material for code-change qualification."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import quote

from solvan.platform.github import (
    GitHubApiError,
    GitHubApiTransport,
    GitHubTokenProvider,
)


@dataclass(frozen=True, slots=True)
class GitHubRegularFile:
    path: str
    mode: str
    blob_sha: str
    content: bytes
    content_hash: str


class GitHubRepositoryQualificationReader:
    """Installation-token reader with no repository mutation method."""

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

    def _get_object(self, url: str) -> dict[str, Any]:
        response = self._transport.get(
            url, headers=self._headers(), timeout=30, allow_redirects=False
        )
        if response.status_code != 200 or len(response.content) > 2_000_000:
            raise GitHubApiError("GitHub qualification read failed or exceeded its bound")
        value = response.json()
        if not isinstance(value, dict):
            raise GitHubApiError("GitHub qualification response is not an object")
        return cast(dict[str, Any], value)

    def regular_file_tree(
        self,
        *,
        owner: str,
        name: str,
        commit_sha: str,
        maximum_files: int = 512,
        maximum_bytes: int = 8_000_000,
    ) -> tuple[GitHubRegularFile, ...]:
        """Read a bounded complete pinned tree with literal regular-file bytes."""

        if len(commit_sha) != 40 or any(char not in "0123456789abcdef" for char in commit_sha):
            raise GitHubApiError("GitHub qualification requires an exact lowercase commit SHA")
        if not 1 <= maximum_files <= 2_000 or not 1 <= maximum_bytes <= 32_000_000:
            raise GitHubApiError("GitHub regular-tree bounds are invalid")
        prefix = f"{self._base}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
        tree = self._get_object(f"{prefix}/git/trees/{commit_sha}?recursive=1")
        raw = tree.get("tree")
        if tree.get("truncated") is True or not isinstance(raw, list) or len(raw) > 10_000:
            raise GitHubApiError("GitHub complete tree is unavailable or truncated")
        selected: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for item in raw:
            if not isinstance(item, dict):
                raise GitHubApiError("GitHub tree entry is malformed")
            if item.get("type") == "tree":
                continue
            path, mode, blob_sha = item.get("path"), item.get("mode"), item.get("sha")
            if (
                item.get("type") != "blob"
                or mode not in {"100644", "100755"}
                or not isinstance(path, str)
                or not isinstance(blob_sha, str)
                or len(blob_sha) != 40
                or any(char not in "0123456789abcdef" for char in blob_sha)
                or path in seen
            ):
                raise GitHubApiError("GitHub tree contains a non-regular or malformed object")
            seen.add(path)
            selected.append((path, mode, blob_sha))
        if not selected or len(selected) > maximum_files:
            raise GitHubApiError("GitHub regular tree exceeds the file-count bound")
        result: list[GitHubRegularFile] = []
        total = 0
        for path, mode, blob_sha in sorted(selected, key=lambda item: item[0].encode("utf-8")):
            blob = self._get_object(f"{prefix}/git/blobs/{quote(blob_sha, safe='')}")
            encoded = blob.get("content")
            if blob.get("encoding") != "base64" or not isinstance(encoded, str):
                raise GitHubApiError("GitHub blob encoding is unsupported")
            try:
                content = base64.b64decode("".join(encoded.split()), validate=True)
            except (ValueError, TypeError) as error:
                raise GitHubApiError("GitHub blob content is invalid") from error
            total += len(content)
            if total > maximum_bytes:
                raise GitHubApiError("GitHub regular tree exceeds the content bound")
            git_object = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
            if hashlib.sha1(git_object, usedforsecurity=False).hexdigest() != blob_sha:
                raise GitHubApiError("GitHub blob bytes do not reproduce their object ID")
            result.append(
                GitHubRegularFile(
                    path,
                    mode,
                    blob_sha,
                    content,
                    "sha256:" + hashlib.sha256(content).hexdigest(),
                )
            )
        return tuple(result)
