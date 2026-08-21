"""Session-bound GitHub reviewer identity links with no repository mutation authority."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from functools import lru_cache
from typing import Any, cast

import requests
from fastapi import Cookie, FastAPI, Header, HTTPException, Path, Request, Response, status
from fastapi.responses import RedirectResponse
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.github_identity import (
    GitHubIdentityError,
    authorization_url,
    new_link_challenge,
    requested_permission_hash,
    session_binding_hash,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence.github_identity_store import (
    ConsumedLink,
    GitHubIdentityStoreError,
    PostgresGitHubIdentityStore,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.github_user_oauth import GitHubUserOAuthClient, GitHubUserOAuthError
from solvan.platform.google_rest import authorized_session
from solvan.platform.kms_envelope import KmsEnvelopeCipher
from solvan.platform.secret_manager import SecretManagerReader

_COOKIE = "__Host-solvan-github-link"


class BrokerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    approval_audience: str = Field(pattern=r"^https://")
    pkce_kms_key: str
    cookie_secret_ref: str
    evidence_bucket: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]$")
    success_url: str = Field(pattern=r"^https://")
    refusal_url: str = Field(pattern=r"^https://")

    @classmethod
    def from_env(cls) -> BrokerSettings:
        names = (
            "SOLVAN_ORGANIZATION_ID",
            "SOLVAN_SCOPE_PROJECT_ID",
            "SOLVAN_ENVIRONMENT_ID",
            "SOLVAN_GITHUB_IDENTITY_APPROVAL_AUDIENCE",
            "SOLVAN_GITHUB_IDENTITY_PKCE_KMS_KEY",
            "SOLVAN_GITHUB_IDENTITY_COOKIE_SECRET_REF",
            "SOLVAN_EVIDENCE_BUCKET",
            "SOLVAN_GITHUB_IDENTITY_SUCCESS_URL",
            "SOLVAN_GITHUB_IDENTITY_REFUSAL_URL",
        )
        missing = [name for name in names if not os.environ.get(name)]
        if missing:
            raise RuntimeError("missing GitHub identity broker settings: " + ",".join(missing))
        return cls(
            scope=Scope(
                os.environ["SOLVAN_ORGANIZATION_ID"],
                os.environ["SOLVAN_SCOPE_PROJECT_ID"],
                os.environ["SOLVAN_ENVIRONMENT_ID"],
            ),
            approval_audience=os.environ["SOLVAN_GITHUB_IDENTITY_APPROVAL_AUDIENCE"],
            pkce_kms_key=os.environ["SOLVAN_GITHUB_IDENTITY_PKCE_KMS_KEY"],
            cookie_secret_ref=os.environ["SOLVAN_GITHUB_IDENTITY_COOKIE_SECRET_REF"],
            evidence_bucket=os.environ["SOLVAN_EVIDENCE_BUCKET"],
            success_url=os.environ["SOLVAN_GITHUB_IDENTITY_SUCCESS_URL"],
            refusal_url=os.environ["SOLVAN_GITHUB_IDENTITY_REFUSAL_URL"],
        )


class LinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repository_binding_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")


class LinkStartResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_url: str
    expires_in_seconds: int = 600


class PrincipalProof(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: str
    subject: str
    issued_at: int


def _human(token: str | None, *, audience: str, require_fresh: bool) -> PrincipalProof:
    if token is None or not token.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GITHUB_IDENTITY_SIGN_IN_REQUIRED")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            token.removeprefix("Bearer "), GoogleRequest(), audience=audience
        )
    except (GoogleAuthError, ValueError) as error:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "GITHUB_IDENTITY_SIGN_IN_INVALID"
        ) from error
    email = claims.get("email")
    subject = claims.get("sub")
    issued_at = claims.get("iat")
    if (
        claims.get("email_verified") is not True
        or not isinstance(email, str)
        or not isinstance(subject, str)
        or not isinstance(issued_at, int)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "GITHUB_IDENTITY_VERIFIED_USER_REQUIRED")
    if require_fresh and not 0 <= int(time.time()) - issued_at <= 300:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GITHUB_IDENTITY_FRESH_SIGN_IN_REQUIRED")
    return PrincipalProof(principal=f"user:{email.lower()}", subject=subject, issued_at=issued_at)


@lru_cache(maxsize=4)
def _secret(resource: str) -> bytes:
    return SecretManagerReader(authorized_session()).access(resource, max_bytes=4096)


def _cookie_value(*, transaction_id: str, binding_hash: str, secret: bytes) -> str:
    signature = hmac.new(secret, f"{transaction_id}:{binding_hash}".encode(), hashlib.sha256)
    return f"{transaction_id}.{signature.hexdigest()}"


def _verify_cookie(
    value: str | None, *, transaction_id: str, binding_hash: str, secret: bytes
) -> bool:
    if value is None or len(value) > 256:
        return False
    expected = _cookie_value(
        transaction_id=transaction_id, binding_hash=binding_hash, secret=secret
    )
    return hmac.compare_digest(value, expected)


def _aad(*, settings: BrokerSettings, transaction_id: str, binding_hash: str) -> bytes:
    return canonical_sha256(
        {
            "schema_version": 1,
            **settings.scope.canonical_dict(),
            "transaction_id": transaction_id,
            "session_binding_hash": binding_hash,
        }
    ).encode()


def create_app(*, settings: BrokerSettings | None = None) -> FastAPI:
    configured = settings or BrokerSettings.from_env()
    google_session = authorized_session()
    cipher = KmsEnvelopeCipher(key=configured.pkce_kms_key, session=google_session)
    evidence = GcsEvidenceWriter(bucket=configured.evidence_bucket, session=google_session)
    app = FastAPI(title="Solvan GitHub Identity Broker", version="1.0.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/api/v1/github/reviewer-links", response_model=LinkStartResponse)
    def start_link(
        request: LinkRequest,
        response: Response,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> LinkStartResponse:
        proof = _human(human_token, audience=configured.approval_audience, require_fresh=True)
        binding_hash = session_binding_hash(
            principal=proof.principal, subject=proof.subject, issued_at=proof.issued_at
        )
        challenge = new_link_challenge()
        try:
            with connect_database() as connection, connection.transaction():
                store = PostgresGitHubIdentityStore(connection, scope=configured.scope)
                store.expire_pending()
                authority = store.authority(
                    repository_binding_id=request.repository_binding_id,
                    principal=proof.principal,
                )
                transaction_id = new_link_challenge_transaction_id()
                encrypted = cipher.encrypt(
                    challenge.verifier.encode(),
                    aad=_aad(
                        settings=configured,
                        transaction_id=transaction_id,
                        binding_hash=binding_hash,
                    ),
                )
                transaction_id = store.create_transaction(
                    authority=authority,
                    principal=proof.principal,
                    session_binding_hash=binding_hash,
                    state_hash=challenge.state_hash,
                    encrypted_verifier=encrypted.ciphertext,
                    pkce_key_version=encrypted.key_version,
                    requested_permission_hash=requested_permission_hash(
                        repository_binding_id=authority.repository_binding_id,
                        reviewer_policy_hash=authority.reviewer_policy_hash,
                    ),
                    transaction_id=transaction_id,
                )
                store.append_audit(
                    stream_id=transaction_id,
                    event_type="GITHUB_REVIEWER_LINK_STARTED",
                    actor_principal=proof.principal,
                    payload={
                        "schema_version": 1,
                        "transaction_id": transaction_id,
                        "repository_binding_id": authority.repository_binding_id,
                        "oauth_profile_hash": authority.profile.configuration_hash,
                        "outcome": "PENDING",
                    },
                )
        except (GitHubIdentityStoreError, GitHubIdentityError, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        response.set_cookie(
            _COOKIE,
            _cookie_value(
                transaction_id=transaction_id,
                binding_hash=binding_hash,
                secret=_secret(configured.cookie_secret_ref),
            ),
            max_age=600,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/github/oauth/callback",
        )
        return LinkStartResponse(
            authorization_url=authorization_url(profile=authority.profile, challenge=challenge)
        )

    @app.get("/github/oauth/callback")
    def oauth_callback(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        callback_cookie: str | None = Cookie(default=None, alias=_COOKIE),
    ) -> Response:
        redirect = RedirectResponse(configured.refusal_url, status_code=status.HTTP_303_SEE_OTHER)
        redirect.delete_cookie(_COOKIE, path="/github/oauth/callback")
        allowed_query = {"code", "state", "error", "error_description"}
        if set(request.query_params.keys()).difference(allowed_query):
            return redirect
        if state is None or len(state) > 256:
            return redirect
        state_hash = f"sha256:{hashlib.sha256(state.encode()).hexdigest()}"
        transaction_id = callback_cookie.split(".", 1)[0] if callback_cookie else ""
        if not transaction_id.startswith("glt_"):
            return redirect
        link: ConsumedLink | None = None
        try:
            with connect_database() as connection:
                store = PostgresGitHubIdentityStore(connection, scope=configured.scope)
                binding_hash = store.pending_session_binding(
                    transaction_id=transaction_id, state_hash=state_hash
                )
            if not _verify_cookie(
                callback_cookie,
                transaction_id=transaction_id,
                binding_hash=binding_hash,
                secret=_secret(configured.cookie_secret_ref),
            ):
                return redirect
            if error is not None or code is None:
                failure_code = (
                    "GITHUB_OAUTH_PROVIDER_REFUSED"
                    if error is not None
                    else "GITHUB_OAUTH_CODE_MISSING"
                )
                with connect_database() as connection, connection.transaction():
                    store = PostgresGitHubIdentityStore(connection, scope=configured.scope)
                    principal = store.refuse_pending(
                        transaction_id=transaction_id,
                        state_hash=state_hash,
                        failure_code=failure_code,
                    )
                    store.append_audit(
                        stream_id=transaction_id,
                        event_type="GITHUB_REVIEWER_LINK_REFUSED",
                        actor_principal=principal,
                        payload={
                            "schema_version": 1,
                            "transaction_id": transaction_id,
                            "outcome": "REFUSED",
                            "failure_code": failure_code,
                        },
                    )
                return redirect
            with connect_database() as connection, connection.transaction():
                link = PostgresGitHubIdentityStore(connection, scope=configured.scope).consume(
                    transaction_id=transaction_id,
                    state_hash=state_hash,
                    session_binding_hash=binding_hash,
                )
            verifier = cipher.decrypt(
                link.encrypted_verifier,
                key_version=link.pkce_key_version,
                aad=_aad(
                    settings=configured,
                    transaction_id=link.transaction_id,
                    binding_hash=binding_hash,
                ),
            ).decode("ascii")
            client = GitHubUserOAuthClient(
                transport=cast(Any, requests.Session()),
                token_endpoint=link.profile.token_endpoint,
                api_base_url=link.profile.api_base_url,
            )
            identity = client.exchange_and_identify(
                client_id=link.profile.client_id,
                client_secret=_secret(link.profile.client_secret_ref).decode("utf-8"),
                callback_uri=link.profile.callback_uri,
                code=code,
                verifier=verifier,
            )
            verifier = ""
            receipt = evidence.put_json(
                object_name=f"github-reviewer-links/{link.transaction_id}.json",
                value={
                    "schema_version": 1,
                    **configured.scope.canonical_dict(),
                    "transaction_id": link.transaction_id,
                    "repository_binding_id": link.repository_binding_id,
                    "principal": link.principal,
                    "github_account_node_id": identity.node_id,
                    "github_login": identity.login,
                    "oauth_profile_hash": link.profile.configuration_hash,
                    "reviewer_policy_hash": link.reviewer_policy_hash,
                    "outcome": "LINKED",
                },
            )
            with connect_database() as connection, connection.transaction():
                store = PostgresGitHubIdentityStore(connection, scope=configured.scope)
                binding_id = store.create_binding(
                    link=link,
                    github_account_node_id=identity.node_id,
                    github_login=identity.login,
                    proof_ref=receipt.uri,
                    proof_hash=receipt.content_hash,
                    actor_identity=link.principal,
                )
                store.append_audit(
                    stream_id=link.transaction_id,
                    event_type="GITHUB_REVIEWER_LINKED",
                    actor_principal=link.principal,
                    payload={
                        "schema_version": 1,
                        "transaction_id": link.transaction_id,
                        "binding_id": binding_id,
                        "repository_binding_id": link.repository_binding_id,
                        "binding_proof_hash": receipt.content_hash,
                        "outcome": "LINKED",
                    },
                )
        except (
            GitHubIdentityStoreError,
            GitHubUserOAuthError,
            UnicodeDecodeError,
            RuntimeError,
            ValueError,
        ):
            if link is not None:
                try:
                    with connect_database() as connection, connection.transaction():
                        PostgresGitHubIdentityStore(
                            connection, scope=configured.scope
                        ).append_audit(
                            stream_id=link.transaction_id,
                            event_type="GITHUB_REVIEWER_LINK_FAILED",
                            actor_principal=link.principal,
                            payload={
                                "schema_version": 1,
                                "transaction_id": link.transaction_id,
                                "outcome": "FAILED_AFTER_CONSUMPTION",
                            },
                        )
                except RuntimeError:
                    pass
            return redirect
        success = RedirectResponse(
            f"{configured.success_url}?github_link=success&binding_id={binding_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        success.delete_cookie(_COOKIE, path="/github/oauth/callback")
        return success

    @app.get("/api/v1/github/reviewer-links/me")
    def list_links(
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[dict[str, Any]]:
        proof = _human(human_token, audience=configured.approval_audience, require_fresh=False)
        with connect_database() as connection, connection.transaction():
            store = PostgresGitHubIdentityStore(connection, scope=configured.scope)
            store.expire_pending()
            return store.list_for_principal(principal=proof.principal)

    @app.delete("/api/v1/github/reviewer-links/{binding_id}", status_code=204)
    def disconnect(
        binding_id: str = Path(pattern=r"^grb_[0-7][0-9A-HJKMNP-TV-Z]{25}$"),
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> Response:
        proof = _human(human_token, audience=configured.approval_audience, require_fresh=True)
        receipt = evidence.put_json(
            object_name=f"github-reviewer-links/{binding_id}/disconnect-{int(time.time())}.json",
            value={
                "schema_version": 1,
                **configured.scope.canonical_dict(),
                "binding_id": binding_id,
                "principal": proof.principal,
                "outcome": "REVOKED",
            },
        )
        try:
            with connect_database() as connection, connection.transaction():
                store = PostgresGitHubIdentityStore(connection, scope=configured.scope)
                store.disconnect(
                    binding_id=binding_id,
                    principal=proof.principal,
                    receipt_ref=receipt.uri,
                    receipt_hash=receipt.content_hash,
                )
                store.append_audit(
                    stream_id=binding_id,
                    event_type="GITHUB_REVIEWER_LINK_REVOKED",
                    actor_principal=proof.principal,
                    payload={
                        "schema_version": 1,
                        "binding_id": binding_id,
                        "receipt_hash": receipt.content_hash,
                        "outcome": "REVOKED",
                    },
                )
        except GitHubIdentityStoreError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return Response(status_code=204)

    instrument_fastapi(app, service_name="github-identity-broker")
    return app


def new_link_challenge_transaction_id() -> str:
    from solvan.domain.identifiers import new_identifier

    return new_identifier("glt")


app = create_app()
