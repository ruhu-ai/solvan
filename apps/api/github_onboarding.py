"""Administrator-only GitHub App discovery and repository binding routes.

Before this module the only way to bind a repository was `register-github` in
`tools/release_admin.py`, which needs nine environment variables including an
installation id an operator has to find by reading a GitHub URL. The console
consequently read "Not configured" forever. These routes replace the hand
transcription with observation: the App JWT lists the App's own installations,
the installation token lists exactly the repositories that installation can
reach, and the binding is built from those responses.

Three properties hold for every route here.

Nothing is taken on the caller's word. Owner, name, installation id, and
default branch are read back from GitHub and the operator's typed values are
used only to select among what GitHub returned, so a binding cannot name a
repository the installation cannot open.

No credential crosses this boundary in either direction. The App private key
and webhook secret are deployment-level Secret Manager references read from
configuration; the request models forbid extra fields, so a caller sending a
reference — let alone a key — is refused rather than ignored. No token, JWT, or
secret value appears in any response, log, or error.

No route can create an ACTIVE binding. Every binding is written `PENDING` and
only the release provider's probe, which observes GitHub independently,
promotes it. The schema enforces the same thing from underneath with
`CHECK ((status <> 'ACTIVE') OR last_probe_result = 'SUCCEEDED')`.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal, cast

from fastapi import APIRouter, HTTPException, Path, Request, status
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from apps.api.github_app_configuration import (
    GitHubAppConfiguration,
    _app_client,
    _installation_client,
    configured_github_app,
)
from apps.api.github_binding_material import binding_material
from apps.api.github_refusals import GitHubOnboardingError
from apps.api.session_authorization import recorded_principal, spend_challenge
from solvan.application.action_challenge import material_digest
from solvan.application.github import (
    GITHUB_CONVERSATION_OPERATIONS,
    GitHubContractError,
    GitHubOperationKind,
    GitHubRepositoryBinding,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.github_store import GitHubStore
from solvan.platform.database import connect_database
from solvan.platform.github import (
    GitHubApiError,
    GitHubAppClient,
    GitHubClient,
    GitHubInstallation,
    GitHubInstallationRepository,
)
from solvan.platform.github_app_auth import (
    GitHubAppAuthenticationError,
)

#: Release authority: opening, closing, or merging a pull request. Gated behind
#: this deployment's release posture. `SYNC_PULL_REQUEST` is absent because it
#: reads a pull request back rather than changing one.
_WRITE_OPERATIONS: frozenset[str] = frozenset(
    {"CREATE_PULL_REQUEST", "MERGE_PULL_REQUEST", "CLOSE_PULL_REQUEST"}
)
#: Everything that changes anything on GitHub, release authority plus the
#: conversational publications. The two sets differ because the release posture
#: governs release authority specifically, and conversation is granted
#: independently of it (specification 24 §1) — but "does this binding change
#: anything at all" needs the wider set. An archived repository accepts none of
#: these, and `investigate_only` means none of them are held.
_EXTERNAL_WRITE_OPERATIONS: frozenset[str] = _WRITE_OPERATIONS | GITHUB_CONVERSATION_OPERATIONS
#: The default an operator gets unless they deliberately choose otherwise. The
#: schema requires a non-empty allowlist, so investigate-only is expressed as
#: the one operation that changes nothing on GitHub rather than as an empty
#: set. This is the value the console's "Investigate only · cannot open pull
#: requests" badge reports.
INVESTIGATE_ONLY: tuple[GitHubOperationKind, ...] = ("SYNC_PULL_REQUEST",)


class GitHubAppProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    app_slug: str
    app_url: str
    install_url: str
    api_base_url: str
    release_enabled: bool
    investigate_only_operations: tuple[GitHubOperationKind, ...]
    write_operations: tuple[GitHubOperationKind, ...]


class GitHubInstallationProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    installation_id: int
    account_login: str
    account_type: str
    target_type: str
    repository_selection: str
    html_url: str
    suspended: bool


class GitHubRepositoryProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    owner: str
    name: str
    default_branch: str
    private: bool
    archived: bool
    html_url: str


class RepositoryBindingRequest(BaseModel):
    """What the operator chooses. Everything else is observed or configured.

    `extra="forbid"` is the enforcement, not the documentation: a request
    carrying `credential_secret_ref`, `webhook_secret_ref`, `status`,
    `policy_hash`, or `default_branch` is refused outright rather than silently
    ignored, so a client that still sends one learns it carries no authority.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    #: Selectors, not assertions. Each is matched against what GitHub returned
    #: and the recorded binding uses GitHub's values, never these.
    installation_id: int = Field(gt=0)
    owner: str = Field(min_length=1, max_length=39)
    name: str = Field(min_length=1, max_length=100)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] = "INTERNAL"
    allowed_operations: tuple[GitHubOperationKind, ...] = INVESTIGATE_ONLY


class RepositoryBindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repository_id: str
    installation_id: int
    owner: str
    name: str
    default_branch: str
    classification: str
    policy_hash: str
    allowed_operations: tuple[GitHubOperationKind, ...]
    investigate_only: bool
    #: Always PENDING. The release provider's probe is the only writer that may
    #: promote a binding, and it must observe GitHub to do so.
    status: Literal["PENDING"] = "PENDING"


def _read_installations(
    configuration: GitHubAppConfiguration,
    app_client_factory: Callable[[GitHubAppConfiguration], GitHubAppClient],
) -> tuple[GitHubInstallation, ...]:
    try:
        return app_client_factory(configuration).installations()
    except (GitHubApiError, GitHubAppAuthenticationError, ValueError, OSError) as error:
        raise GitHubOnboardingError(
            "GITHUB_APP_UNREACHABLE", http_status=status.HTTP_502_BAD_GATEWAY
        ) from error


def _read_repositories(
    configuration: GitHubAppConfiguration,
    installation_client_factory: Callable[[GitHubAppConfiguration, int], GitHubClient],
    installation_id: int,
) -> tuple[GitHubInstallationRepository, ...]:
    client = installation_client_factory(configuration, installation_id)
    try:
        return client.installation_repositories()
    except (GitHubApiError, GitHubAppAuthenticationError, ValueError, OSError) as error:
        raise GitHubOnboardingError(
            "GITHUB_APP_UNREACHABLE", http_status=status.HTTP_502_BAD_GATEWAY
        ) from error


def _selected_installation(
    installations: tuple[GitHubInstallation, ...], installation_id: int
) -> GitHubInstallation:
    """Resolve the installation from GitHub's own list, never from the request."""

    for installation in installations:
        if installation.installation_id == installation_id:
            if installation.suspended:
                raise GitHubOnboardingError(
                    "GITHUB_INSTALLATION_SUSPENDED", http_status=status.HTTP_409_CONFLICT
                )
            return installation
    raise GitHubOnboardingError(
        "GITHUB_INSTALLATION_NOT_FOUND", http_status=status.HTTP_404_NOT_FOUND
    )


def _selected_repository(
    repositories: tuple[GitHubInstallationRepository, ...], *, owner: str, name: str
) -> GitHubInstallationRepository:
    """Match the operator's choice against reachability, case-insensitively.

    GitHub compares repository identity without regard to case, so a match is
    made the same way — and the recorded binding then takes GitHub's spelling,
    not the operator's.
    """

    for repository in repositories:
        if repository.owner.lower() == owner.lower() and repository.name.lower() == name.lower():
            return repository
    raise GitHubOnboardingError(
        "GITHUB_REPOSITORY_NOT_REACHABLE", http_status=status.HTTP_404_NOT_FOUND
    )


def _authorized_operations(
    requested: tuple[GitHubOperationKind, ...], *, release_enabled: bool
) -> tuple[GitHubOperationKind, ...]:
    """Settle what this binding may do before anything is written.

    An empty allowlist is refused because the schema requires a non-empty one,
    and a duplicate is refused because an allowlist that repeats itself was not
    authored deliberately. Write authority additionally requires this
    deployment's release posture to be on, which is the same switch the
    coordinator consults before it will dispatch a GitHub release operation:
    a binding that could open a pull request no service is permitted to open
    would be a stated authority nothing enforces.
    """

    if not requested or len(set(requested)) != len(requested):
        raise GitHubOnboardingError(
            "GITHUB_OPERATIONS_INVALID", http_status=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    if not release_enabled and any(operation in _WRITE_OPERATIONS for operation in requested):
        raise GitHubOnboardingError(
            "GITHUB_RELEASE_POSTURE_DISABLED", http_status=status.HTTP_409_CONFLICT
        )
    return requested


def _policy_hash(
    *,
    scope: Scope,
    installation_id: int,
    owner: str,
    name: str,
    classification: str,
    allowed_operations: tuple[GitHubOperationKind, ...],
    api_base_url: str,
) -> str:
    """Digest the policy this binding is being created under.

    The hash covers the scope, the observed repository identity, and the
    authority granted, so any later change to what the binding may do produces
    a different digest instead of silently reusing the one it was approved
    under.
    """

    return canonical_sha256(
        {
            "schema_version": 1,
            **scope.canonical_dict(),
            "api_base_url": api_base_url,
            "installation_id": installation_id,
            "owner": owner,
            "name": name,
            "classification": classification,
            "allowed_operations": sorted(allowed_operations),
        }
    )


def github_onboarding_router(
    *,
    principal_provider: Callable[[Request], str],
    scope_provider: Callable[[], Scope],
    authorize: Callable[..., str] | None = None,
    configuration_provider: Callable[[], GitHubAppConfiguration] = configured_github_app,
    app_client_factory: Callable[[GitHubAppConfiguration], GitHubAppClient] = _app_client,
    installation_client_factory: Callable[
        [GitHubAppConfiguration, int], GitHubClient
    ] = _installation_client,
    connect: Callable[[], Any] = connect_database,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/github")

    def _authorize(connection: Any, request: Request, *, scope: Scope, material: str) -> str:
        """Spend the binding challenge, or use the injected test authorizer.

        There is no permissive default: with nothing injected this refuses
        unless the caller holds a live session, a matching CSRF pair, and an
        unspent `github.bind` challenge for this exact material.
        """

        if authorize is not None:
            return authorize(connection, request, scope=scope, material=material)
        consumed = spend_challenge(
            connection,
            request,
            scope=scope,
            operation="github.bind",
            material_digest=material_digest(material),
            now=datetime.now(UTC),
        )
        return recorded_principal(connection, consumed.actor_id)

    def _admin(request: Request, scope: Scope) -> str:
        """Establish the principal from the signed-in session, then its role.

        The principal comes from `principal_provider`, which reads the session
        cookie rather than a pasted bearer token: these routes disclose a
        customer's private repository names, so they need a live operator, not
        a string somebody could paste from anywhere. Nothing here reads a
        header, body, or query parameter for a principal or a scope.
        """

        principal = principal_provider(request)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM solvan.actor_role_bindings
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND principal = %(principal)s AND role = 'ADMIN'
                      AND (expires_at IS NULL OR expires_at > now())) AS active""",
                {**scope.canonical_dict(), "principal": principal},
            )
            row = cursor.fetchone()
        if row is None or not row[0]:
            raise GitHubOnboardingError(
                "GITHUB_ADMINISTRATOR_REQUIRED", http_status=status.HTTP_403_FORBIDDEN
            ).as_http()
        return principal

    @router.get("/app", response_model=GitHubAppProjection)
    def app_posture(
        http_request: Request,
    ) -> GitHubAppProjection:
        """Where the operator installs the App, and what a binding may be granted."""

        _admin(http_request, scope_provider())
        try:
            configuration = configuration_provider()
        except GitHubOnboardingError as error:
            raise error.as_http() from error
        return GitHubAppProjection(
            app_slug=configuration.app_slug,
            app_url=configuration.app_url,
            install_url=configuration.install_url,
            api_base_url=configuration.api_base_url,
            release_enabled=configuration.release_enabled,
            investigate_only_operations=INVESTIGATE_ONLY,
            write_operations=cast(
                "tuple[GitHubOperationKind, ...]", tuple(sorted(_WRITE_OPERATIONS))
            ),
        )

    @router.get("/installations", response_model=list[GitHubInstallationProjection])
    def list_installations(
        http_request: Request,
    ) -> list[GitHubInstallationProjection]:
        """List the App's real installations. Nothing here is operator-supplied."""

        _admin(http_request, scope_provider())
        try:
            configuration = configuration_provider()
            installations = _read_installations(configuration, app_client_factory)
        except GitHubOnboardingError as error:
            raise error.as_http() from error
        return [
            GitHubInstallationProjection(
                installation_id=installation.installation_id,
                account_login=installation.account_login,
                account_type=installation.account_type,
                target_type=installation.target_type,
                repository_selection=installation.repository_selection,
                html_url=installation.html_url,
                suspended=installation.suspended,
            )
            for installation in installations
        ]

    @router.get(
        "/installations/{installation_id}/repositories",
        response_model=list[GitHubRepositoryProjection],
    )
    def list_repositories(
        http_request: Request,
        installation_id: int = Path(gt=0),
    ) -> list[GitHubRepositoryProjection]:
        """List exactly what one installation can reach, read with its own token."""

        _admin(http_request, scope_provider())
        try:
            configuration = configuration_provider()
            # Resolved against the App's own installations first, so an
            # unrelated identifier is a named refusal rather than a token
            # exchange failure an operator cannot interpret.
            installation = _selected_installation(
                _read_installations(configuration, app_client_factory), installation_id
            )
            repositories = _read_repositories(
                configuration, installation_client_factory, installation.installation_id
            )
        except GitHubOnboardingError as error:
            raise error.as_http() from error
        return [
            GitHubRepositoryProjection(
                owner=repository.owner,
                name=repository.name,
                default_branch=repository.default_branch,
                private=repository.private,
                archived=repository.archived,
                html_url=repository.html_url,
            )
            for repository in repositories
        ]

    @router.post("/repositories", response_model=RepositoryBindingResponse)
    def register_repository(
        request: RepositoryBindingRequest,
        http_request: Request,
    ) -> RepositoryBindingResponse:
        """Record one PENDING binding against a repository GitHub confirmed."""

        scope = scope_provider()
        # The identity and role gate runs first, so an unauthenticated or
        # non-administrator caller cannot make this service talk to GitHub at
        # all. The challenge is spent later, inside the transaction that
        # records what it authorizes.
        _admin(http_request, scope)
        try:
            configuration = configuration_provider()
            operations = _authorized_operations(
                request.allowed_operations, release_enabled=configuration.release_enabled
            )
            installation = _selected_installation(
                _read_installations(configuration, app_client_factory), request.installation_id
            )
            repository = _selected_repository(
                _read_repositories(
                    configuration, installation_client_factory, installation.installation_id
                ),
                owner=request.owner,
                name=request.name,
            )
            if repository.archived and any(
                operation in _EXTERNAL_WRITE_OPERATIONS for operation in operations
            ):
                raise GitHubOnboardingError(
                    "GITHUB_REPOSITORY_ARCHIVED", http_status=status.HTTP_409_CONFLICT
                )
            policy_hash = _policy_hash(
                scope=scope,
                installation_id=installation.installation_id,
                owner=repository.owner,
                name=repository.name,
                classification=request.classification,
                allowed_operations=operations,
                api_base_url=configuration.api_base_url,
            )
            binding = GitHubRepositoryBinding(
                scope=scope,
                repository_id=new_identifier("ghr"),
                # Every identity field below is GitHub's answer, not the
                # request's. The request only chose which answer to use.
                installation_id=installation.installation_id,
                owner=repository.owner,
                name=repository.name,
                default_branch=repository.default_branch,
                api_base_url=configuration.api_base_url,
                classification=request.classification,
                policy_hash=policy_hash,
                allowed_operations=operations,
                status="PENDING",
            )
            with connect() as connection, connection.transaction():
                # Spent inside the transaction that records what it authorizes.
                # Spending without recording burns the re-authentication and
                # binds nothing; recording without spending leaves the
                # challenge replayable against a different repository.
                principal = _authorize(
                    connection,
                    http_request,
                    scope=scope,
                    material=binding_material(
                        installation_id=installation.installation_id,
                        owner=repository.owner,
                        name=repository.name,
                        classification=request.classification,
                        allowed_operations=operations,
                    ),
                )
                repository_id = GitHubStore(connection).register_repository(
                    binding=binding,
                    # Deployment configuration, never the request. The store
                    # refuses anything that is not a Secret Manager reference.
                    credential_secret_ref=configuration.credential_secret_ref,
                    webhook_secret_ref=configuration.webhook_secret_ref,
                    actor=principal,
                )
        except GitHubOnboardingError as error:
            raise error.as_http() from error
        except UniqueViolation as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "GITHUB_BINDING_EXISTS") from error
        except (GitHubContractError, ValidationError) as error:
            # The binding contract refuses combinations this route deliberately
            # does not restate — merge authority over a RESTRICTED repository,
            # a duplicate allowlist, a secret reference that is not one. Its
            # refusal is reported as a code, never as its text.
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "GITHUB_BINDING_REFUSED"
            ) from error
        return RepositoryBindingResponse(
            repository_id=repository_id,
            installation_id=binding.installation_id,
            owner=binding.owner,
            name=binding.name,
            default_branch=binding.default_branch,
            classification=binding.classification,
            policy_hash=binding.policy_hash,
            allowed_operations=operations,
            investigate_only=not any(
                operation in _EXTERNAL_WRITE_OPERATIONS for operation in operations
            ),
            status="PENDING",
        )

    return router
