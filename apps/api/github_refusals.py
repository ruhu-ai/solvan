"""The closed refusal vocabulary the GitHub onboarding surface answers with.

Its own module so the routes, the App configuration, and the connect paths can
all raise the same codes without importing each other. Every refusal an
operator sees from these routes is one of these: they name the next step
without quoting a GitHub response body, an exception message, or anything
derived from a credential.
"""

from __future__ import annotations

from typing import Literal

from fastapi import HTTPException

GitHubOnboardingReason = Literal[
    "GITHUB_APP_NOT_CONFIGURED",
    "GITHUB_APP_UNREACHABLE",
    "GITHUB_INSTALLATION_NOT_FOUND",
    "GITHUB_INSTALLATION_SUSPENDED",
    "GITHUB_REPOSITORY_NOT_REACHABLE",
    "GITHUB_REPOSITORY_ARCHIVED",
    "GITHUB_RELEASE_POSTURE_DISABLED",
    "GITHUB_OPERATIONS_INVALID",
    "GITHUB_BINDING_EXISTS",
    "GITHUB_BINDING_REFUSED",
    "GITHUB_ADMINISTRATOR_REQUIRED",
]


class GitHubOnboardingError(RuntimeError):
    """A refusal carrying one closed reason code and no external text."""

    def __init__(self, reason: GitHubOnboardingReason, *, http_status: int) -> None:
        super().__init__(reason)
        self.reason: GitHubOnboardingReason = reason
        self.http_status = http_status

    def as_http(self) -> HTTPException:
        return HTTPException(self.http_status, self.reason)
