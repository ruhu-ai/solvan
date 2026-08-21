"""Policy-bound GitHub App integration for repository release operations.

The service accepts signed GitHub webhooks and coordinator-authenticated
commands.  It never accepts browser/model identity, arbitrary repository paths,
or a caller-supplied scope.  The webhook secret is injected from Secret Manager
at deploy time; the App identifier and private key are read through Secret
Manager references so no GitHub credential material reaches the environment,
and installation tokens are minted here rather than pasted in.  No GitHub
credential is persisted or projected.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, cast

import requests
from fastapi import FastAPI, Header, HTTPException, Request, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from apps.github_provider.code_change import execute_create_pr
from apps.github_provider.code_change_merge import execute_merge_pr
from apps.github_provider.code_change_sync import execute_sync_pr
from apps.github_provider.conversation import execute_publish_conversation
from apps.github_provider.conversation_ingest import project_conversation
from apps.github_provider.conversation_reads import register_conversation_reads
from apps.github_provider.evidence_requests import (
    CommitRangeReadRequest,
    PullRequestDiffReadRequest,
    WorkflowRunReadRequest,
)
from apps.github_provider.qualification import execute_qualification
from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    PrivateCommandEnvelope,
)
from solvan.application.github import GitHubContractError
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence.github_store import GitHubStore
from solvan.platform.database import connect_database
from solvan.platform.github import (
    GitHubApiTransport,
    GitHubClient,
    GitHubTokenProvider,
    project_webhook,
    verified_webhook_payload,
    webhook_repository_identity,
)
from solvan.platform.github_app_auth import (
    GitHubAppInstallationTokenProvider,
    InstallationTokenTransport,
)
from solvan.platform.github_code_change import GitHubCodeChangeClient
from solvan.platform.github_conversation import GitHubConversationClient
from solvan.platform.github_delivery_reads import GitHubDeliveryReadClient
from solvan.platform.github_repository_qualification import (
    GitHubRepositoryQualificationReader,
)
from solvan.platform.google_rest import authorized_session
from solvan.platform.secret_manager import SecretManagerReader

_SECRET_REFERENCE = (
    r"^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/secrets/[A-Za-z0-9_-]{1,255}"
    r"/versions/(?:[1-9][0-9]*|latest)$"
)


class GitHubProviderSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    installation_id: int = Field(gt=0)
    webhook_secret: str = Field(min_length=16, max_length=4096)
    app_id_secret_ref: str = Field(pattern=_SECRET_REFERENCE)
    private_key_secret_ref: str = Field(pattern=_SECRET_REFERENCE)
    coordinator_audience: str = Field(pattern=r"^https://")
    coordinator_principal: str = Field(min_length=3, max_length=255)
    evidence_principal: str = Field(min_length=3, max_length=255)
    runtime_bucket: str = Field(min_length=3, max_length=255)
    service_revision: str = Field(min_length=1, max_length=255)
    service_principal: str = Field(min_length=3, max_length=255)
    api_base_url: str = Field(default="https://api.github.com", pattern=r"^https://")
    #: The console API, admitted only to request a probe. Empty admits nobody,
    #: so a deployment that has not named it simply has no second caller.
    api_principal: str = Field(default="", max_length=255)
    #: The App's own GitHub handle, used to recognise a mention. Absent means
    #: this deployment answers no mention at all, which is the safe default:
    #: guessing a handle would make Solvan respond to threads addressed at
    #: somebody else.
    app_handle: str = Field(default="", pattern=r"^$|^[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?$")
    #: Labels whose application addresses Solvan. Empty means labels trigger
    #: nothing.
    trigger_labels: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> GitHubProviderSettings:
        required = (
            "SOLVAN_ORGANIZATION_ID",
            "SOLVAN_SCOPE_PROJECT_ID",
            "SOLVAN_ENVIRONMENT_ID",
            "SOLVAN_GITHUB_REPOSITORY_ID",
            "SOLVAN_GITHUB_INSTALLATION_ID",
            "SOLVAN_GITHUB_WEBHOOK_SECRET",
            "SOLVAN_GITHUB_APP_ID_SECRET_REF",
            "SOLVAN_GITHUB_APP_PRIVATE_KEY_SECRET_REF",
            "SOLVAN_GITHUB_COORDINATOR_AUDIENCE",
            "SOLVAN_GITHUB_COORDINATOR_PRINCIPAL",
            "SOLVAN_GITHUB_EVIDENCE_PRINCIPAL",
            "SOLVAN_RUNTIME_BUCKET",
            "SOLVAN_GITHUB_PROVIDER_SERVICE_ACCOUNT",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise RuntimeError("missing GitHub provider settings: " + ",".join(missing))
        return cls(
            scope=Scope(
                os.environ["SOLVAN_ORGANIZATION_ID"],
                os.environ["SOLVAN_SCOPE_PROJECT_ID"],
                os.environ["SOLVAN_ENVIRONMENT_ID"],
            ),
            repository_id=os.environ["SOLVAN_GITHUB_REPOSITORY_ID"],
            installation_id=int(os.environ["SOLVAN_GITHUB_INSTALLATION_ID"]),
            webhook_secret=os.environ["SOLVAN_GITHUB_WEBHOOK_SECRET"],
            app_id_secret_ref=os.environ["SOLVAN_GITHUB_APP_ID_SECRET_REF"],
            private_key_secret_ref=os.environ["SOLVAN_GITHUB_APP_PRIVATE_KEY_SECRET_REF"],
            coordinator_audience=os.environ["SOLVAN_GITHUB_COORDINATOR_AUDIENCE"],
            coordinator_principal=os.environ["SOLVAN_GITHUB_COORDINATOR_PRINCIPAL"],
            evidence_principal=os.environ["SOLVAN_GITHUB_EVIDENCE_PRINCIPAL"],
            runtime_bucket=os.environ["SOLVAN_RUNTIME_BUCKET"],
            service_revision=os.environ.get("K_REVISION", "LOCAL_UNQUALIFIED"),
            service_principal=(
                "serviceAccount:" + os.environ["SOLVAN_GITHUB_PROVIDER_SERVICE_ACCOUNT"]
            ),
            api_base_url=os.environ.get("SOLVAN_GITHUB_API_BASE_URL", "https://api.github.com"),
            api_principal=(
                "serviceAccount:" + os.environ["SOLVAN_GITHUB_API_SERVICE_ACCOUNT"]
                if os.environ.get("SOLVAN_GITHUB_API_SERVICE_ACCOUNT")
                else ""
            ),
            app_handle=os.environ.get("SOLVAN_GITHUB_APP_HANDLE", ""),
            trigger_labels=tuple(
                label.strip()
                for label in os.environ.get("SOLVAN_GITHUB_TRIGGER_LABELS", "").split(",")
                if label.strip()
            )[:16],
        )


@lru_cache(maxsize=1)
def _token_provider(
    app_id_secret_ref: str, private_key_secret_ref: str, api_base_url: str
) -> GitHubTokenProvider:
    """Hold one provider per process so its token cache survives a request."""

    return GitHubAppInstallationTokenProvider(
        transport=cast(InstallationTokenTransport, requests.Session()),
        secrets=SecretManagerReader(authorized_session()),
        app_id_secret_ref=app_id_secret_ref,
        private_key_secret_ref=private_key_secret_ref,
        api_base_url=api_base_url,
    )


def _principal(
    authorization: str | None,
    settings: GitHubProviderSettings,
    *,
    expected_principal: str | None = None,
    admitted_principals: tuple[str, ...] | None = None,
) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing coordinator identity")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "),
            GoogleRequest(),
            audience=settings.coordinator_audience,
        )
    except (GoogleAuthError, ValueError) as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid coordinator identity") from error
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "verified coordinator identity is required")
    admitted = {
        value.removeprefix("serviceAccount:").lower()
        for value in (
            admitted_principals
            if admitted_principals is not None
            else (expected_principal or settings.coordinator_principal,)
        )
        if value
    }
    if email.lower() not in admitted:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not an admitted identity")
    return f"serviceAccount:{email.lower()}"


def _client(
    settings: GitHubProviderSettings,
    *,
    installation_id: int | None = None,
    api_base_url: str | None = None,
) -> GitHubClient:
    """Build a client for one installation.

    The installation is a property of the binding being acted on, not of this
    deployment. Taking it from the environment worked only while a single
    repository was configured by hand; a token minted for the wrong
    installation cannot read the repository it is presented for.
    """

    base = api_base_url or settings.api_base_url
    return GitHubClient(
        transport=cast(GitHubApiTransport, requests.Session()),
        token_provider=_token_provider(
            settings.app_id_secret_ref,
            settings.private_key_secret_ref,
            base,
        ),
        installation_id=installation_id or settings.installation_id,
        api_base_url=base,
    )


def _qualification_reader(
    settings: GitHubProviderSettings, *, installation_id: int
) -> GitHubRepositoryQualificationReader:
    return GitHubRepositoryQualificationReader(
        transport=cast(GitHubApiTransport, requests.Session()),
        token_provider=_token_provider(
            settings.app_id_secret_ref,
            settings.private_key_secret_ref,
            settings.api_base_url,
        ),
        installation_id=installation_id,
        api_base_url=settings.api_base_url,
    )


def _conversation_client(
    settings: GitHubProviderSettings, *, installation_id: int, api_base_url: str | None = None
) -> GitHubConversationClient:
    """Build a conversation client for one binding's installation and host.

    The base URL comes from the binding rather than this deployment's
    configuration, because a conversational read may target a repository on a
    different GitHub host than the one this service was configured with.
    """

    base = api_base_url or settings.api_base_url
    return GitHubConversationClient(
        transport=cast(GitHubApiTransport, requests.Session()),
        token_provider=_token_provider(
            settings.app_id_secret_ref,
            settings.private_key_secret_ref,
            base,
        ),
        installation_id=installation_id,
        api_base_url=base,
    )


def _delivery_reader(
    settings: GitHubProviderSettings, *, installation_id: int, api_base_url: str
) -> GitHubDeliveryReadClient:
    return GitHubDeliveryReadClient(
        transport=cast(GitHubApiTransport, requests.Session()),
        token_provider=_token_provider(
            settings.app_id_secret_ref,
            settings.private_key_secret_ref,
            api_base_url,
        ),
        installation_id=installation_id,
        api_base_url=api_base_url,
    )


def _code_change_client(
    settings: GitHubProviderSettings, *, installation_id: int
) -> GitHubCodeChangeClient:
    return GitHubCodeChangeClient(
        transport=cast(GitHubApiTransport, requests.Session()),
        token_provider=_token_provider(
            settings.app_id_secret_ref,
            settings.private_key_secret_ref,
            settings.api_base_url,
        ),
        installation_id=installation_id,
        api_base_url=settings.api_base_url,
    )


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan GitHub Release Provider", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/commands:execute")
    def execute_private_command(
        envelope: PrivateCommandEnvelope,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = GitHubProviderSettings.from_env()
        caller = _principal(authorization, settings)
        try:
            with connect_database() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT command_kind FROM solvan_delivery.private_command_dispatches "
                    "WHERE id=%s",
                    (envelope.command_id,),
                )
                row = cursor.fetchone()
            if row is None:
                raise DeliveryCommandError("private command does not exist")
            kind = DeliveryCommandKind(str(row[0]))
            if kind is DeliveryCommandKind.QUALIFY_CODE_CHANGE:
                return execute_qualification(
                    envelope=envelope,
                    caller=caller,
                    settings=settings,
                    client_factory=lambda installation_id: _client(
                        settings, installation_id=installation_id
                    ),
                    reader_factory=lambda installation_id: _qualification_reader(
                        settings, installation_id=installation_id
                    ),
                )
            if kind is DeliveryCommandKind.CREATE_PR:
                return execute_create_pr(
                    envelope=envelope,
                    caller=caller,
                    settings=settings,
                    client_factory=lambda installation_id: _client(
                        settings, installation_id=installation_id
                    ),
                    code_client_factory=lambda installation_id: _code_change_client(
                        settings, installation_id=installation_id
                    ),
                    reader_factory=lambda installation_id: _qualification_reader(
                        settings, installation_id=installation_id
                    ),
                )
            if kind is DeliveryCommandKind.SYNC_PR:
                return execute_sync_pr(
                    envelope=envelope,
                    caller=caller,
                    settings=settings,
                    code_client_factory=lambda installation_id: _code_change_client(
                        settings, installation_id=installation_id
                    ),
                    reader_factory=lambda installation_id: _qualification_reader(
                        settings, installation_id=installation_id
                    ),
                )
            if kind is DeliveryCommandKind.MERGE_PR:
                return execute_merge_pr(
                    envelope=envelope,
                    caller=caller,
                    settings=settings,
                    code_client_factory=lambda installation_id: _code_change_client(
                        settings, installation_id=installation_id
                    ),
                    reader_factory=lambda installation_id: _qualification_reader(
                        settings, installation_id=installation_id
                    ),
                )
            if kind is DeliveryCommandKind.PUBLISH_GITHUB_CONVERSATION:
                return execute_publish_conversation(
                    envelope=envelope,
                    caller=caller,
                    settings=settings,
                    client_factory=lambda installation_id, api_base_url: _conversation_client(
                        settings,
                        installation_id=installation_id,
                        api_base_url=api_base_url,
                    ),
                )
            raise DeliveryCommandError("GitHub Provider command kind is not implemented")
        except DeliveryCommandError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    @app.post("/internal/github/repositories:probe")
    def probe_repository(
        authorization: str | None = Header(default=None),
        repository_id: str | None = None,
    ) -> dict[str, Any]:
        """Probe one binding, named by the caller or by configuration.

        A binding created from the console has its own identifier and its own
        installation. Probing only the environment-named repository left every
        other binding permanently PENDING, which the schema then correctly
        refused to let become ACTIVE.
        """

        settings = GitHubProviderSettings.from_env()
        # Requesting a probe is not attesting to one. The console's connect
        # flow asks for it so a new binding does not sit PENDING until somebody
        # runs release tooling by hand; the observation that promotes it is
        # still this service reading GitHub with its own credentials.
        _principal(
            authorization,
            settings,
            admitted_principals=(settings.coordinator_principal, settings.api_principal),
        )
        target_id = repository_id or settings.repository_id
        with connect_database() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT owner, name, default_branch, installation_id
                         FROM solvan.github_repositories
                       WHERE organization_id = %(organization_id)s
                         AND project_id = %(project_id)s
                         AND environment_id = %(environment_id)s
                         AND id = %(id)s""",
                    {**settings.scope.canonical_dict(), "id": target_id},
                )
                row = cursor.fetchone()
            if row is None:
                raise HTTPException(
                    status.HTTP_404_NOT_FOUND, "GitHub repository binding not found"
                )
            try:
                observed = _client(settings, installation_id=int(row[3])).repository(
                    owner=str(row[0]), name=str(row[1])
                )
                observed_default = observed.get("default_branch")
                if observed_default != row[2]:
                    raise GitHubContractError("GitHub default branch changed from the binding")
            except (GitHubContractError, RuntimeError, ValueError) as error:
                with connection.transaction():
                    GitHubStore(connection).record_probe(
                        scope=settings.scope,
                        repository_id=target_id,
                        success=False,
                        result=f"FAILED:{type(error).__name__}",
                    )
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "GitHub repository probe failed"
                ) from error
            with connection.transaction():
                GitHubStore(connection).record_probe(
                    scope=settings.scope,
                    repository_id=target_id,
                    success=True,
                    result="SUCCEEDED",
                )
        return {"repository_id": target_id, "status": "ACTIVE"}

    def evidence_binding(
        settings: GitHubProviderSettings, repository_id: str | None = None
    ) -> tuple[str, str, int, str]:
        """Resolve one ACTIVE binding, and everything a read against it needs.

        The binding carries its own installation and API host, so a read is
        performed with the credentials that binding was granted rather than
        with whatever this deployment happened to be configured with. Falling
        back to the configured repository kept a deployment serving exactly one
        repository however many an operator had connected.
        """

        target = repository_id or settings.repository_id
        with connect_database() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT owner,name,installation_id,api_base_url
                     FROM solvan.github_repositories
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(repository_id)s AND status='ACTIVE'""",
                {**settings.scope.canonical_dict(), "repository_id": target},
            )
            row = cursor.fetchone()
        if row is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "GitHub repository is not active")
        return str(row[0]), str(row[1]), int(row[2]), str(row[3])

    @app.post("/internal/github/evidence/commit-range")
    def read_commit_range(
        request: CommitRangeReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = GitHubProviderSettings.from_env()
        _principal(authorization, settings, expected_principal=settings.evidence_principal)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        client = _client(settings, installation_id=installation_id, api_base_url=api_base_url)
        return client.compare_commits(
            owner=owner,
            name=name,
            base_sha=request.base_sha,
            head_sha=request.head_sha,
        )

    @app.post("/internal/github/evidence/pull-request-diff")
    def read_pull_request_diff(
        request: PullRequestDiffReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = GitHubProviderSettings.from_env()
        _principal(authorization, settings, expected_principal=settings.evidence_principal)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        client = _client(settings, installation_id=installation_id, api_base_url=api_base_url)
        return client.pull_request_diff(
            owner=owner,
            name=name,
            number=request.pull_request_number,
            maximum_patch_bytes=request.maximum_patch_bytes,
        )

    @app.post("/internal/github/evidence/workflow-run")
    def read_workflow_run(
        request: WorkflowRunReadRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = GitHubProviderSettings.from_env()
        _principal(authorization, settings, expected_principal=settings.evidence_principal)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        owner, name, installation_id, api_base_url = evidence_binding(
            settings, request.repository_id
        )
        client = _client(settings, installation_id=installation_id, api_base_url=api_base_url)
        return client.check_run_detail(
            owner=owner,
            name=name,
            check_run_id=request.check_run_id,
            expected_head_sha=request.expected_head_sha,
        )

    register_conversation_reads(
        app,
        settings_factory=GitHubProviderSettings.from_env,
        principal=lambda authorization, settings: _principal(
            authorization, settings, expected_principal=settings.evidence_principal
        ),
        evidence_binding=lambda settings, repository_id=None: evidence_binding(
            settings, repository_id
        ),
        client_factory=lambda settings, installation_id, api_base_url: _conversation_client(
            settings, installation_id=installation_id, api_base_url=api_base_url
        ),
        tree_reader_factory=lambda settings, installation_id: _qualification_reader(
            settings, installation_id=installation_id
        ),
        delivery_reader_factory=lambda settings, installation_id, api_base_url: _delivery_reader(
            settings, installation_id=installation_id, api_base_url=api_base_url
        ),
    )

    @app.post("/internal/github/webhooks", status_code=status.HTTP_202_ACCEPTED)
    async def webhook(
        request: Request,
        x_github_delivery: str | None = Header(default=None),
        x_github_event: str | None = Header(default=None),
        x_hub_signature_256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = GitHubProviderSettings.from_env()
        body = await request.body()
        try:
            # Authenticate first, then let the authenticated payload say which
            # repository this is. The App delivers every bound repository to
            # this one URL, so taking the binding from configuration would
            # refuse every repository but one — and a webhook that keeps
            # returning 4xx is one GitHub eventually disables outright.
            payload = verified_webhook_payload(
                body=body,
                delivery_id=x_github_delivery,
                event_name=x_github_event,
                signature=x_hub_signature_256,
                webhook_secret=settings.webhook_secret.encode(),
            )
            owner, name = webhook_repository_identity(payload)
            with connect_database() as connection, connection.transaction():
                store = GitHubStore(connection)
                repository_id = store.binding_for_delivery(
                    scope=settings.scope, owner=owner, name=name
                )
                envelope = project_webhook(
                    payload=payload,
                    body=body,
                    delivery_id=str(x_github_delivery),
                    event_name=str(x_github_event),
                    repository_id=repository_id,
                )
                event_id, created = store.accept_webhook(scope=settings.scope, envelope=envelope)
                store.process_webhook(scope=settings.scope, event_id=event_id)
                trigger_admission = (
                    project_conversation(
                        connection,
                        settings=settings,
                        repository_id=repository_id,
                        payload=payload,
                        event_name=envelope.event_name,
                        event_id=event_id,
                    )
                    if created
                    else None
                )
            return {
                "event_id": event_id,
                "duplicate": not created,
                "payload_hash": envelope.payload_hash,
                "conversation_trigger": trigger_admission,
            }
        except (GitHubContractError, RuntimeError, ValueError) as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error

    return app


app = instrument_fastapi(create_app(), service_name="github-release-provider")
