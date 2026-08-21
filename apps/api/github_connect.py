"""One-click GitHub connect, and the narrow path that widens a binding.

The shape here follows the stakes rather than the plumbing.

Connecting a repository so Solvan can *investigate* grants exactly
`SYNC_PULL_REQUEST` — the one operation that changes nothing on GitHub. For
that case reach and authority are the same thing, so there is nothing to decide
per repository and no reason to ask: the operator installs the App, and every
repository the installation can reach is bound investigate-only in one call.
This is the flow the comparison connector has, and for read-only work it is
sufficient for the same reason it is sufficient there.

Widening a binding is the opposite. Merge authority, pull-request authorship,
and a voice in a thread are per-repository judgements with no equivalent in an
App installation, which grants *reach* and is coarse — all repositories, or a
set chosen once on GitHub. So `regrant_repository` asks the questions the bulk
path skips, one repository at a time, and only when someone wants more than
reading.

Both paths spend an `github.bind` step-up challenge inside the transaction that
records what it authorizes. Neither accepts a pasted identity token.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from apps.api.github_app_configuration import (
    GitHubAppConfiguration,
    _app_client,
    _installation_client,
    configured_github_app,
)
from apps.api.github_binding_material import connect_all_material, regrant_material
from apps.api.github_onboarding import (
    _EXTERNAL_WRITE_OPERATIONS,
    INVESTIGATE_ONLY,
    _authorized_operations,
    _policy_hash,
    _read_installations,
    _read_repositories,
    _selected_installation,
)
from apps.api.github_refusals import GitHubOnboardingError
from apps.api.session_authorization import (
    recorded_principal,
    require_administrator,
    spend_challenge,
)
from solvan.application.action_challenge import material_digest
from solvan.application.github import (
    GITHUB_CONVERSATION_OPERATIONS,
    GitHubContractError,
    GitHubOperationKind,
    GitHubRepositoryBinding,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.github_store import GitHubStore
from solvan.platform.database import connect_database
from solvan.platform.github import GitHubAppClient, GitHubClient
from solvan.platform.github_release import (
    GitHubReleaseProviderClient,
    GitHubReleaseProviderConfiguration,
    GoogleIdentityTokenProvider,
)

#: The step-up operation both paths spend. It is ADMIN in the challenge
#: registry, and binding or widening a repository is the same class of decision.
_OPERATION = "github.bind"


def _request_probes(repository_ids: list[str]) -> dict[str, str]:
    """Ask the provider to observe each new binding, and report what happened.

    A binding is written PENDING and only the provider's own observation may
    promote it, so without this an operator who pressed Connect would watch
    every repository sit PENDING until somebody ran release tooling by hand.
    Requesting the observation is not making it: the provider re-reads GitHub
    with its own credentials and refuses if the default branch drifted.

    Failures are reported per repository rather than raised. The bindings are
    already committed and correct; an unreachable provider means they are not
    yet confirmed, which is exactly what PENDING says.
    """

    base = os.environ.get("SOLVAN_GITHUB_PROVIDER_URL", "").strip()
    audience = os.environ.get("SOLVAN_GITHUB_PROVIDER_AUDIENCE", "").strip()
    if not base or base == "DISABLED" or not audience:
        return dict.fromkeys(repository_ids, "PROVIDER_NOT_CONFIGURED")
    outcomes: dict[str, str] = {}
    try:
        config = GitHubReleaseProviderConfiguration(
            base_url=base, audience=audience, repository_id=repository_ids[0]
        )
    except ValueError:
        return dict.fromkeys(repository_ids, "PROVIDER_NOT_CONFIGURED")
    with httpx.Client(timeout=60) as transport:
        client = GitHubReleaseProviderClient(
            config=config, client=transport, token_provider=GoogleIdentityTokenProvider()
        )
        for repository_id in repository_ids:
            try:
                client.probe_repository(repository_id)
                outcomes[repository_id] = "ACTIVE"
            except (RuntimeError, ValueError, httpx.HTTPError):
                outcomes[repository_id] = "PROBE_FAILED"
    return outcomes


class ConnectAllRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    installation_id: int = Field(gt=0)
    #: Applied to every repository bound by this call. RESTRICTED is absent
    #: deliberately: it is a per-repository judgement about one repository's
    #: sensitivity, and applying it to everything an installation reaches would
    #: be a guess wearing a policy value.
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL"] = "INTERNAL"


class ConnectedRepository(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repository_id: str | None
    owner: str
    name: str
    default_branch: str
    outcome: str
    detail: str | None = None


class ConnectAllResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    installation_id: int
    account_login: str
    bound: int
    already_bound: int
    skipped: int
    repositories: list[ConnectedRepository]


class RegrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    #: The complete authority the binding should carry afterwards, not a delta.
    #: A caller stating the whole set cannot widen a binding by accident while
    #: describing an addition.
    allowed_operations: tuple[GitHubOperationKind, ...] = Field(min_length=1, max_length=8)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]


class RegrantResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repository_id: str
    owner: str
    name: str
    previous_operations: list[str]
    allowed_operations: list[str]
    classification: str
    policy_hash: str
    status: str
    investigate_only: bool
    grants_conversation: bool


def github_connect_router(
    *,
    scope_provider: Callable[[], Scope],
    administrator: Callable[..., str] | None = None,
    configuration_provider: Callable[[], GitHubAppConfiguration] = configured_github_app,
    app_client_factory: Callable[[GitHubAppConfiguration], GitHubAppClient] = _app_client,
    installation_client_factory: Callable[
        [GitHubAppConfiguration, int], GitHubClient
    ] = _installation_client,
    connect: Callable[[], Any] = connect_database,
    authorize: Callable[..., str] | None = None,
) -> APIRouter:
    """Build the connect routes.

    `authorize` is injected so tests can supply a principal without a session,
    and it has no permissive default in production: when it is absent the real
    step-up spender is used, which refuses without a live session, a matching
    CSRF pair, and an unspent challenge for this exact material.
    """

    router = APIRouter(prefix="/api/v1/github")

    def _require_administrator(request: Request, scope: Scope) -> None:
        """Refuse before any GitHub read.

        Without this the routes would authenticate inside the transaction, by
        which point an unauthenticated caller has already made this service
        enumerate a customer's private repositories.
        """

        if administrator is not None:
            administrator(request, scope)
            return
        require_administrator(request, scope)

    def _authorize(connection: Any, request: Request, *, scope: Scope, material: str) -> str:
        if authorize is not None:
            return authorize(connection, request, scope=scope, material=material)
        consumed = spend_challenge(
            connection,
            request,
            scope=scope,
            operation=_OPERATION,
            material_digest=material_digest(material),
            now=datetime.now(UTC),
        )
        return recorded_principal(connection, consumed.actor_id)

    @router.post("/installations/{installation_id}:connect-all", response_model=ConnectAllResponse)
    def connect_all(
        installation_id: int, request: ConnectAllRequest, http_request: Request
    ) -> ConnectAllResponse:
        """Bind every repository this installation reaches, investigate-only.

        Repositories already bound are reported and left exactly as they are —
        a bulk connect never narrows or widens an existing grant, because the
        operator authorizing "connect everything" is not thereby deciding to
        change a binding somebody previously reasoned about.
        """

        if installation_id != request.installation_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "GITHUB_OPERATIONS_INVALID")
        scope = scope_provider()
        _require_administrator(http_request, scope)
        try:
            configuration = configuration_provider()
            installation = _selected_installation(
                _read_installations(configuration, app_client_factory), installation_id
            )
            repositories = _read_repositories(
                configuration, installation_client_factory, installation.installation_id
            )
        except GitHubOnboardingError as error:
            raise error.as_http() from error

        results: list[ConnectedRepository] = []
        bound = already = skipped = 0
        material = connect_all_material(
            installation_id=installation_id,
            classification=request.classification,
        )
        with connect() as connection, connection.transaction():
            principal = _authorize(connection, http_request, scope=scope, material=material)
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
                    classification=request.classification,
                    policy_hash=_policy_hash(
                        scope=scope,
                        installation_id=installation.installation_id,
                        owner=repository.owner,
                        name=repository.name,
                        classification=request.classification,
                        allowed_operations=INVESTIGATE_ONLY,
                        api_base_url=configuration.api_base_url,
                    ),
                    allowed_operations=INVESTIGATE_ONLY,
                    status="PENDING",
                )
                # Each repository gets its own savepoint so one already-bound
                # name does not abandon the rest of the installation.
                try:
                    with connection.transaction():
                        repository_id = store.register_repository(
                            binding=binding,
                            credential_secret_ref=configuration.credential_secret_ref,
                            webhook_secret_ref=configuration.webhook_secret_ref,
                            actor=principal,
                        )
                except UniqueViolation:
                    already += 1
                    results.append(
                        ConnectedRepository(
                            repository_id=None,
                            owner=repository.owner,
                            name=repository.name,
                            default_branch=repository.default_branch,
                            outcome="ALREADY_BOUND",
                            detail="left exactly as it was",
                        )
                    )
                    continue
                except (GitHubContractError, ValidationError):
                    skipped += 1
                    results.append(
                        ConnectedRepository(
                            repository_id=None,
                            owner=repository.owner,
                            name=repository.name,
                            default_branch=repository.default_branch,
                            outcome="REFUSED",
                            detail="GITHUB_BINDING_REFUSED",
                        )
                    )
                    continue
                bound += 1
                results.append(
                    ConnectedRepository(
                        repository_id=repository_id,
                        owner=repository.owner,
                        name=repository.name,
                        default_branch=repository.default_branch,
                        outcome="BOUND",
                        detail=None,
                    )
                )
        # After the bindings are committed, not inside the transaction: a probe
        # is a network call to another service, and holding a database
        # transaction open across it would couple one slow provider to the
        # lock on every row just written.
        probed = _request_probes([item.repository_id for item in results if item.repository_id])
        results = [
            item.model_copy(update={"outcome": probed.get(item.repository_id, item.outcome)})
            if item.repository_id and probed.get(item.repository_id) == "ACTIVE"
            else item
            for item in results
        ]
        return ConnectAllResponse(
            installation_id=installation.installation_id,
            account_login=installation.account_login,
            bound=bound,
            already_bound=already,
            skipped=skipped,
            repositories=results,
        )

    @router.post("/repositories/{repository_id}/authority", response_model=RegrantResponse)
    def regrant_repository(
        repository_id: str, request: RegrantRequest, http_request: Request
    ) -> RegrantResponse:
        """Change what one bound repository may do."""

        scope = scope_provider()
        _require_administrator(http_request, scope)
        try:
            configuration = configuration_provider()
            operations = _authorized_operations(
                request.allowed_operations, release_enabled=configuration.release_enabled
            )
        except GitHubOnboardingError as error:
            raise error.as_http() from error

        material = regrant_material(
            repository_id=repository_id,
            allowed_operations=tuple(operations),
            classification=request.classification,
        )
        try:
            with connect() as connection, connection.transaction():
                principal = _authorize(connection, http_request, scope=scope, material=material)
                store = GitHubStore(connection)
                current = store.binding_for_regrant(scope=scope, repository_id=repository_id)
                # Validated through the binding contract before the write, so a
                # refusal such as merge authority over a RESTRICTED repository
                # is reported rather than left to the column constraint.
                GitHubRepositoryBinding(
                    scope=scope,
                    repository_id=repository_id,
                    installation_id=int(current["installation_id"]),
                    owner=str(current["owner"]),
                    name=str(current["name"]),
                    default_branch=str(current["default_branch"]),
                    api_base_url=str(current["api_base_url"]),
                    classification=request.classification,
                    policy_hash=_policy_hash(
                        scope=scope,
                        installation_id=int(current["installation_id"]),
                        owner=str(current["owner"]),
                        name=str(current["name"]),
                        classification=request.classification,
                        allowed_operations=operations,
                        api_base_url=str(current["api_base_url"]),
                    ),
                    allowed_operations=operations,
                    status="PENDING",
                )
                regranted = store.regrant_repository(
                    scope=scope,
                    repository_id=repository_id,
                    allowed_operations=operations,
                    classification=request.classification,
                    policy_hash=_policy_hash(
                        scope=scope,
                        installation_id=int(current["installation_id"]),
                        owner=str(current["owner"]),
                        name=str(current["name"]),
                        classification=request.classification,
                        allowed_operations=operations,
                        api_base_url=str(current["api_base_url"]),
                    ),
                    actor=principal,
                )
        except GitHubOnboardingError as error:
            raise error.as_http() from error
        except (GitHubContractError, ValidationError) as error:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "GITHUB_BINDING_REFUSED"
            ) from error
        return RegrantResponse(
            repository_id=regranted.repository_id,
            owner=regranted.owner,
            name=regranted.name,
            previous_operations=list(regranted.previous_operations),
            allowed_operations=list(regranted.allowed_operations),
            classification=regranted.classification,
            policy_hash=regranted.policy_hash,
            status=regranted.status,
            investigate_only=not (set(regranted.allowed_operations) & _EXTERNAL_WRITE_OPERATIONS),
            grants_conversation=bool(
                set(regranted.allowed_operations) & GITHUB_CONVERSATION_OPERATIONS
            ),
        )

    return router


__all__ = [
    "GitHubOperationKind",
    "connect_all_material",
    "github_connect_router",
    "regrant_material",
]


def include_github_routes(
    app: Any,
    *,
    scope_provider: Callable[[], Scope],
    approval_principal: Callable[[str | None], str],
    administrator: Callable[[Request, Scope], str],
    connect: Callable[[], Any] = connect_database,
) -> None:
    """Attach every GitHub surface in one place.

    Together they are one product area with one authority story — discover,
    bind, widen, converse — and registering them side by side keeps that story
    readable rather than scattering it through the application factory.
    """

    from apps.api.github_conversation import github_conversation_router
    from apps.api.github_install_flow import github_install_router
    from apps.api.github_onboarding import github_onboarding_router

    app.include_router(
        github_onboarding_router(
            # The signed-in operator, refused unless they hold ADMIN in this
            # scope right now: these routes disclose private repository names,
            # so they need a live session, not a pasted bearer token.
            principal_provider=lambda request: administrator(request, scope_provider()),
            scope_provider=scope_provider,
        )
    )
    app.include_router(
        github_connect_router(
            scope_provider=scope_provider, administrator=administrator, connect=connect
        )
    )
    app.include_router(
        github_install_router(
            scope_provider=scope_provider, administrator=administrator, connect=connect
        )
    )
    app.include_router(
        github_conversation_router(
            session_principal=approval_principal,
            scope_provider=scope_provider,
            connect=connect,
        )
    )
