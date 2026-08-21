"""Registered GitHub connector for Agent Skills repository ingestion."""

from __future__ import annotations

from dataclasses import dataclass

from solvan.application.skills_governance import RepositoryObservation
from solvan.platform.github import GitHubApiError, GitHubClient
from solvan.platform.github_app_auth import StaticGitHubTokenProvider


class ConfiguredGitHubTokenProvider(StaticGitHubTokenProvider):
    """The fixed-token provider under the name the skills root imports.

    A deployed ingestion path belongs on `GitHubAppInstallationTokenProvider`:
    a fixed token stops working within the hour GitHub issued it for, and this
    holder cannot renew one.
    """


@dataclass(frozen=True, slots=True)
class GitHubMetadataConnector:
    """Allowlisted, pinned metadata and archive connector."""

    client: GitHubClient
    allowed_repositories: frozenset[str]

    def _repository(self, repository_ref: str) -> tuple[str, str]:
        if not repository_ref.startswith("github://"):
            raise GitHubApiError("repository reference must use the registered github:// scheme")
        identity = repository_ref.removeprefix("github://")
        owner, separator, name = identity.partition("/")
        if (
            not owner
            or not name
            or separator != "/"
            or f"{owner}/{name}" not in self.allowed_repositories
        ):
            raise GitHubApiError("repository is not registered for this tenant")
        return owner, name

    def observe_tree(
        self, *, repository_ref: str, commit_sha: str, subdirectory: str
    ) -> RepositoryObservation:
        owner, name = self._repository(repository_ref)
        return RepositoryObservation(
            commit_sha=commit_sha,
            subtree_hash=self.client.subtree_tree_hash(
                owner=owner, name=name, commit_sha=commit_sha, subdirectory=subdirectory
            ),
        )

    def observe_ref(
        self, *, repository_ref: str, upstream_ref: str, subdirectory: str
    ) -> RepositoryObservation:
        owner, name = self._repository(repository_ref)
        commit_sha = self.client.resolve_commit(owner=owner, name=name, ref=upstream_ref)
        return self.observe_tree(
            repository_ref=repository_ref,
            commit_sha=commit_sha,
            subdirectory=subdirectory,
        )

    def fetch_archive(self, *, repository_ref: str, commit_sha: str, subdirectory: str) -> bytes:
        owner, name = self._repository(repository_ref)
        archive_root = subdirectory.strip("/").rsplit("/", 1)[-1] or name
        return self.client.subtree_archive(
            owner=owner,
            name=name,
            commit_sha=commit_sha,
            subdirectory=subdirectory,
            archive_root=archive_root,
        )
