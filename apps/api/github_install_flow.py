"""One continuous install: begin here, install on GitHub, land back here.

Connecting used to make an operator leave the product, find the App on GitHub
unprompted, install it, and return knowing to press a button. GitHub will
redirect them back to us instead, carrying the installation it just created.

The awkward part is authority. That redirect is an ordinary browser GET: no
CSRF header, no step-up challenge, and its one interesting parameter is a
number anybody can type. So the authority is established *before* the operator
leaves — they re-authenticate to begin — and carried across as an opaque state
that is single-use and short-lived.

Two things make a forged redirect uninteresting rather than dangerous. The
state has to match a pending intent this deployment minted, and the
`installation_id` is treated as a selector verified against `GET
/app/installations` rather than as a fact, so the worst a guessed number
achieves is selecting a real installation of our own App — which is what the
operator was about to do anyway.

Specification 24 §9 governs.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Request, status
from fastapi.responses import RedirectResponse
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from apps.api.github_app_configuration import (
    GitHubAppConfiguration,
    _app_client,
    _installation_client,
    configured_github_app,
)
from apps.api.github_connect import _request_probes
from apps.api.github_onboarding import (
    INVESTIGATE_ONLY,
    _policy_hash,
    _read_installations,
    _read_repositories,
    _selected_installation,
)
from apps.api.github_refusals import GitHubOnboardingError
from apps.api.session_authorization import recorded_principal, spend_challenge
from solvan.application.action_challenge import material_digest
from solvan.application.github import GitHubContractError, GitHubRepositoryBinding
from solvan.domain import Scope, new_identifier
from solvan.persistence.github_installation_store import (
    ClaimedIntent,
    GitHubInstallationIntentError,
    GitHubInstallationIntentStore,
)
from solvan.persistence.github_store import GitHubStore
from solvan.platform.database import connect_database
from solvan.platform.github import (
    GitHubAppClient,
    GitHubClient,
    GitHubInstallation,
    GitHubInstallationRepository,
)

_OPERATION = "github.bind"


def install_material(*, classification: str) -> str:
    """The exact thing an operator authorizes before leaving for GitHub.

    It names the authority and the classification, and deliberately not the
    account: which account to install on is chosen on GitHub's own screen,
    after this challenge is spent, and is shown to the operator there. Binding
    the challenge to an account we do not yet know would either require asking
    twice or asking for something the operator cannot yet answer.
    """

    return f"github-install:v1:{classification}:{','.join(sorted(INVESTIGATE_ONLY))}"


class BeginInstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL"] = "INTERNAL"


class BeginInstallResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    install_url: str
    expires_at: datetime


def github_install_router(
    *,
    scope_provider: Callable[[], Scope],
    configuration_provider: Callable[[], GitHubAppConfiguration] = configured_github_app,
    app_client_factory: Callable[[GitHubAppConfiguration], GitHubAppClient] = _app_client,
    installation_client_factory: Callable[
        [GitHubAppConfiguration, int], GitHubClient
    ] = _installation_client,
    connect: Callable[[], Any] = connect_database,
    administrator: Callable[..., str] | None = None,
    authorize: Callable[..., str] | None = None,
    probe: Callable[[list[str]], dict[str, str]] = _request_probes,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/github")

    def _console_url() -> str:
        return os.environ.get("SOLVAN_CONSOLE_BASE_URL", "").strip().rstrip("/")

    def _land(outcome: str, **extra: object) -> RedirectResponse:
        """Send the operator back to the console with what happened.

        A bare 200 would leave them on an API response wondering whether the
        install worked. Only enumerated outcomes travel, never a refusal
        message: this URL is produced by a redirect an attacker can trigger.
        """

        base = _console_url()
        query = urlencode({"github_install": outcome, **{k: str(v) for k, v in extra.items()}})
        target = f"{base}/integrations?{query}" if base else f"/integrations?{query}"
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/installations:begin", response_model=BeginInstallResponse)
    def begin_install(request: BeginInstallRequest, http_request: Request) -> BeginInstallResponse:
        """Re-authenticate, then hand back the URL that installs the App."""

        scope = scope_provider()
        if administrator is not None:
            administrator(http_request, scope)
        try:
            configuration = configuration_provider()
        except GitHubOnboardingError as error:
            raise error.as_http() from error
        now = datetime.now(UTC)
        material = install_material(classification=request.classification)
        with connect() as connection, connection.transaction():
            if authorize is not None:
                principal = authorize(connection, http_request, scope=scope, material=material)
                challenge_id = "injected"
            else:
                consumed = spend_challenge(
                    connection,
                    http_request,
                    scope=scope,
                    operation=_OPERATION,
                    material_digest=material_digest(material),
                    now=now,
                )
                principal = recorded_principal(connection, consumed.actor_id)
                challenge_id = consumed.challenge_id
            minted = GitHubInstallationIntentStore(connection).mint(
                scope=scope,
                classification=request.classification,
                actor_principal=principal,
                challenge_id=challenge_id,
                now=now,
            )
        # GitHub returns `state` unchanged on the setup redirect, which is the
        # only channel this flow has for carrying authority across.
        install_url = (
            f"{configuration.web_base_url}/apps/{quote(configuration.app_slug, safe='')}"
            f"/installations/new?state={quote(minted.state, safe='')}"
        )
        return BeginInstallResponse(install_url=install_url, expires_at=minted.expires_at)

    @router.get("/installations/callback")
    def complete_install(
        http_request: Request,
        state: str = "",
        installation_id: int = 0,
        setup_action: str = "",
    ) -> RedirectResponse:
        """Where GitHub lands the operator after they install the App."""

        scope = scope_provider()
        if setup_action not in {"install", "update", ""}:
            return _land("REFUSED", reason="UNSUPPORTED_SETUP_ACTION")
        if installation_id <= 0:
            return _land("REFUSED", reason="NO_INSTALLATION")
        try:
            with connect() as connection, connection.transaction():
                intents = GitHubInstallationIntentStore(connection)
                claimed = intents.claim(scope=scope, state=state, now=datetime.now(UTC))
        except GitHubInstallationIntentError:
            # Deliberately one outcome for absent, expired, and already-used:
            # this endpoint answers an unauthenticated redirect, and telling
            # them apart would make it an oracle for valid states.
            return _land("REFUSED", reason="LINK_NOT_VALID")

        try:
            configuration = configuration_provider()
            installation = _selected_installation(
                _read_installations(configuration, app_client_factory), installation_id
            )
            repositories = _read_repositories(
                configuration, installation_client_factory, installation.installation_id
            )
        except GitHubOnboardingError as error:
            with connect() as connection, connection.transaction():
                GitHubInstallationIntentStore(connection).refuse(
                    scope=scope, intent_id=claimed.intent_id, error_class=error.reason
                )
            return _land("REFUSED", reason=error.reason)

        bound: list[str] = []
        already = 0
        try:
            bound, already = _bind_everything(
                scope=scope,
                configuration=configuration,
                installation=installation,
                repositories=repositories,
                claimed=claimed,
            )
        except GitHubInstallationIntentError:
            # The intent stopped being completable underneath us. The bindings
            # this request would have created roll back with it, so the
            # operator lands on the same refusal a replayed link gets rather
            # than on an error page describing a race they cannot act on.
            return _land("REFUSED", reason="LINK_NOT_VALID")

        probe(bound)
        return _land(
            "CONNECTED",
            account=installation.account_login,
            bound=len(bound),
            already_bound=already,
        )

    def _bind_everything(
        *,
        scope: Scope,
        configuration: GitHubAppConfiguration,
        installation: GitHubInstallation,
        repositories: tuple[GitHubInstallationRepository, ...],
        claimed: ClaimedIntent,
    ) -> tuple[list[str], int]:
        """Bind every repository the installation reaches, and close the intent.

        One transaction, so an intent that can no longer be completed takes the
        bindings of that attempt with it rather than leaving half a connect
        behind an intent nobody can account for.
        """

        bound: list[str] = []
        already = 0
        with connect() as connection, connection.transaction():
            store = GitHubStore(connection)
            for repository in repositories:
                binding = GitHubRepositoryBinding(
                    scope=scope,
                    repository_id=new_identifier("ghr"),
                    installation_id=installation.installation_id,
                    owner=repository.owner,
                    name=repository.name,
                    default_branch=repository.default_branch,
                    api_base_url=configuration.api_base_url,
                    classification=claimed.classification,  # type: ignore[arg-type]
                    policy_hash=_policy_hash(
                        scope=scope,
                        installation_id=installation.installation_id,
                        owner=repository.owner,
                        name=repository.name,
                        classification=claimed.classification,
                        allowed_operations=INVESTIGATE_ONLY,
                        api_base_url=configuration.api_base_url,
                    ),
                    allowed_operations=INVESTIGATE_ONLY,
                    status="PENDING",
                )
                try:
                    with connection.transaction():
                        bound.append(
                            store.register_repository(
                                binding=binding,
                                credential_secret_ref=configuration.credential_secret_ref,
                                webhook_secret_ref=configuration.webhook_secret_ref,
                                actor=claimed.actor_principal,
                            )
                        )
                except UniqueViolation:
                    already += 1
                except (GitHubContractError, ValidationError):
                    continue
            GitHubInstallationIntentStore(connection).complete(
                scope=scope,
                intent_id=claimed.intent_id,
                installation_id=installation.installation_id,
                bound_count=len(bound),
                now=datetime.now(UTC),
            )
        return bound, already

    return router


__all__ = ["github_install_router", "install_material"]
