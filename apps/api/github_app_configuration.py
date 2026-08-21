"""How this deployment reaches GitHub as its own App.

Split from the onboarding routes because it answers a different question. The
routes decide what an operator may bind; this decides what credentials exist at
all and how a client is built from them, which is deployment configuration and
has no request in scope.

Keeping it apart matters for review: everything here touches Secret Manager
references and token minting, and it is short enough to read in full before
trusting the routes that import it.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import cast

import requests
from fastapi import status

from apps.api.github_refusals import GitHubOnboardingError
from solvan.platform.github import (
    GitHubApiTransport,
    GitHubAppClient,
    GitHubClient,
)
from solvan.platform.github_app_auth import (
    GitHubAppInstallationTokenProvider,
    InstallationTokenTransport,
)
from solvan.platform.google_rest import authorized_session
from solvan.platform.secret_manager import SecretManagerReader

#: A pinned Secret Manager reference, matching what the release provider and
#: the store already accept. A pasted key cannot satisfy it, and neither can a
#: value an operator typed into the browser: these are read from this
#: deployment's configuration and never from a request.
_SECRET_REFERENCE = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/secrets/[A-Za-z0-9_-]{1,255}"
    r"/versions/(?:[1-9][0-9]*|latest)$"
)
#: The App's URL slug, which is what an install link is built from. GitHub
#: lowercases and hyphenates it when the App is created.
_APP_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$")


@dataclass(frozen=True, slots=True)
class GitHubAppConfiguration:
    """What this deployment knows about its GitHub App.

    Every field is deployment-level. None of it is ever accepted from, or
    echoed back beyond, what an operator needs to complete the install: the
    two secret references are recorded on the binding and never resolved here.
    """

    app_slug: str
    app_id_secret_ref: str
    private_key_secret_ref: str
    credential_secret_ref: str
    webhook_secret_ref: str
    api_base_url: str
    web_base_url: str
    release_enabled: bool

    @property
    def install_url(self) -> str:
        return f"{self.web_base_url}/apps/{self.app_slug}/installations/new"

    @property
    def app_url(self) -> str:
        return f"{self.web_base_url}/apps/{self.app_slug}"


def configured_github_app() -> GitHubAppConfiguration:
    """Read the App posture, refusing rather than half-working.

    An App with no slug has no install link, an App with no identifier or key
    cannot authenticate, and a binding with no webhook reference cannot be
    reconciled. Any of those missing means the connect flow would appear to
    work and then fail somewhere an operator cannot see, so all of them are
    required together and absence is a refusal.
    """

    slug = os.environ.get("SOLVAN_GITHUB_APP_SLUG", "").strip()
    app_id_ref = os.environ.get("SOLVAN_GITHUB_APP_ID_SECRET_REF", "").strip()
    private_key_ref = os.environ.get("SOLVAN_GITHUB_APP_PRIVATE_KEY_SECRET_REF", "").strip()
    webhook_ref = os.environ.get("SOLVAN_GITHUB_WEBHOOK_SECRET_REF", "").strip()
    # The credential a binding records is the App private key unless this
    # deployment names a different reference, so a working App does not have to
    # be configured twice.
    credential_ref = (
        os.environ.get("SOLVAN_GITHUB_CREDENTIAL_SECRET_REF", "").strip() or private_key_ref
    )
    api_base_url = os.environ.get("SOLVAN_GITHUB_API_BASE_URL", "https://api.github.com").strip()
    web_base_url = os.environ.get("SOLVAN_GITHUB_WEB_BASE_URL", "https://github.com").strip()
    references = (app_id_ref, private_key_ref, webhook_ref, credential_ref)
    if (
        _APP_SLUG.fullmatch(slug) is None
        or any(_SECRET_REFERENCE.fullmatch(value) is None for value in references)
        or not api_base_url.startswith("https://")
        or api_base_url.endswith("/")
        or not web_base_url.startswith("https://")
        or web_base_url.endswith("/")
    ):
        raise GitHubOnboardingError(
            "GITHUB_APP_NOT_CONFIGURED", http_status=status.HTTP_503_SERVICE_UNAVAILABLE
        )
    return GitHubAppConfiguration(
        app_slug=slug,
        app_id_secret_ref=app_id_ref,
        private_key_secret_ref=private_key_ref,
        credential_secret_ref=credential_ref,
        webhook_secret_ref=webhook_ref,
        api_base_url=api_base_url,
        web_base_url=web_base_url,
        # The same switch the coordinator reads before it will dispatch a
        # GitHub release operation. Recording a binding is not acting, so it is
        # always permitted; granting one authority to write to GitHub is, so it
        # is refused while the deployment's release posture is off.
        release_enabled=os.environ.get("SOLVAN_GITHUB_RELEASE_ENABLED", "false").lower() == "true",
    )


@lru_cache(maxsize=4)
def _token_provider(
    app_id_secret_ref: str, private_key_secret_ref: str, api_base_url: str
) -> GitHubAppInstallationTokenProvider:
    """Hold one provider per configuration so its token cache survives requests."""

    return GitHubAppInstallationTokenProvider(
        transport=cast(InstallationTokenTransport, requests.Session()),
        secrets=SecretManagerReader(authorized_session()),
        app_id_secret_ref=app_id_secret_ref,
        private_key_secret_ref=private_key_secret_ref,
        api_base_url=api_base_url,
    )


def _app_jwt_source(provider: GitHubAppInstallationTokenProvider) -> Callable[[], str]:
    """Reuse the App JWT the token provider already signs.

    Listing installations is the one GitHub read authenticated as the App
    itself rather than as an installation. The App private key is held solely
    by `GitHubAppInstallationTokenProvider`, and loading it a second time here
    would put key handling in a module that deliberately does not own it, so
    its existing signer is borrowed through this single named seam. A public
    accessor on that provider would remove the seam entirely.
    """

    return provider._app_jwt


def _app_client(configuration: GitHubAppConfiguration) -> GitHubAppClient:
    return GitHubAppClient(
        transport=cast(GitHubApiTransport, requests.Session()),
        app_jwt_provider=_app_jwt_source(
            _token_provider(
                configuration.app_id_secret_ref,
                configuration.private_key_secret_ref,
                configuration.api_base_url,
            )
        ),
        api_base_url=configuration.api_base_url,
    )


def _installation_client(
    configuration: GitHubAppConfiguration, installation_id: int
) -> GitHubClient:
    return GitHubClient(
        transport=cast(GitHubApiTransport, requests.Session()),
        token_provider=_token_provider(
            configuration.app_id_secret_ref,
            configuration.private_key_secret_ref,
            configuration.api_base_url,
        ),
        installation_id=installation_id,
        api_base_url=configuration.api_base_url,
    )
