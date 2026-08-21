"""Sign-in, session, and sign-out for the operator console (spec 05 §4.2).

A backend-for-frontend flow. The browser is redirected to Google, returns with a
code, and receives one opaque session cookie; the code, the tokens, and the
values protecting the exchange never reach browser JavaScript.

Nothing here decides what a person may do. It decides who they are and hands the
rest of the API a session to resolve roles against, per operation.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from psycopg import Connection
from pydantic import BaseModel, ConfigDict, Field

from apps.api.session_authorization import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    require_csrf,
)
from solvan.application.action_challenge import (
    ActionChallengeError,
)
from solvan.application.action_challenge import (
    operation as registered_operation,
)
from solvan.application.approval_audience import ApprovalAudienceError, accepted_audiences
from solvan.application.oauth_login import (
    OAuthLoginError,
    begin_login,
    credential_hash,
    session_credential,
    verify_callback,
    verify_nonce,
)
from solvan.application.operator_identity import (
    OperatorIdentityError,
    VerifiedAssertion,
    admitted_domain,
)
from solvan.application.operator_step_up import (
    CODE_LIFETIME,
    MAX_ATTEMPTS,
    OperatorStepUpError,
    issue_code,
    masked_email,
    matches,
)
from solvan.domain import Scope
from solvan.persistence.action_challenge_store import ActionChallengeStore
from solvan.persistence.operator_identity_store import OperatorIdentityStore
from solvan.persistence.operator_session_store import OperatorSessionStore
from solvan.persistence.operator_step_up_store import OperatorStepUpStore
from solvan.platform.google_oauth import (
    authorization_endpoint,
    google_is_the_issuer,
    issuer_display_name,
)
from solvan.platform.operator_step_up_email import (
    OperatorStepUpDeliveryError,
    OperatorStepUpSender,
)


class AssertionVerifier(Protocol):
    """Verifies a Google authorization code and returns its identity claims."""

    def exchange(
        self, *, code: str, pkce_verifier: str, redirect_uri: str, audiences: tuple[str, ...]
    ) -> dict[str, Any]: ...


def _now() -> datetime:
    return datetime.now(UTC)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"{name} is not configured, so sign-in cannot be offered",
        )
    return value


def _audiences() -> tuple[str, ...]:
    try:
        return accepted_audiences(
            os.environ.get("SOLVAN_APPROVAL_AUDIENCE"),
            rotating_to=os.environ.get("SOLVAN_APPROVAL_AUDIENCE_SUCCESSOR"),
            google_issuer=google_is_the_issuer(),
        )
    except ApprovalAudienceError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error


def _no_session_detail() -> dict[str, str | bool]:
    """Why there is no session, and what the sign-in page may truthfully say.

    Carried on the refusal itself rather than fetched from a second route. The
    second route was `/api/auth/mode`, whose absence or 404 the console read as
    "this deployment needs no sign-in" — so the negotiation that existed to
    inform the page was also the way past it. There is nothing to negotiate: a
    401 means sign in, and these fields only decide what the button is called.
    """

    return {
        "reason": "no session",
        # A button reading "Continue with Google" that goes to the harness
        # fixture is a false statement, and hosts running the fixture are
        # exactly where nobody would notice.
        "provider": issuer_display_name(),
        "provider_is_production": google_is_the_issuer(),
    }


def _set_session_cookies(response: Response, *, credential: str, csrf: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, credential, httponly=True, secure=True, samesite="lax", path="/"
    )
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=True, samesite="lax", path="/")


class StepUpRequest(BaseModel):
    """What is being authorized, carried in a body rather than a URL.

    The material digest identifies the exact thing being decided. A query
    parameter travels into browser history, referrer headers, and server logs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: str = Field(min_length=1, max_length=64)
    material_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class StepUpVerification(BaseModel):
    """The opaque delivery handle and code; neither can choose an action."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    step_up_handle: str = Field(pattern=r"^sup_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    code: str = Field(pattern=r"^[0-9]{8}$")


def auth_router(
    *,
    connect: Callable[[], Connection[Any]],
    scope_provider: Callable[[], Scope],
    verifier: AssertionVerifier,
    admitted_domains_provider: Callable[[Scope], frozenset[str]],
    step_up_sender_provider: Callable[[], OperatorStepUpSender],
    step_up_pepper_provider: Callable[[], str],
) -> APIRouter:
    """Sign-in, session, and the step-up that authorizes one action.

    The sender is resolved per request rather than when this router is built.
    Resolving it here made an unconfigured code transport prevent the router
    from existing at all — so a deployment that could perfectly well establish
    who somebody is served no sign-in, and the console reported that it could
    not identify anybody. Identity and authority are separate in this system by
    design: a session establishes who you are and grants nothing. A transport
    that cannot deliver a code refuses the action that needs one, at the point
    of that action, and leaves signing in and reading intact.
    """

    router = APIRouter()

    @router.get("/api/auth/login")
    def start_sign_in(request: Request, return_path: str = "/") -> Response:
        """Begin a sign-in and send the browser to Google."""

        audiences = _audiences()
        redirect_uri = _required("SOLVAN_OAUTH_REDIRECT_URI")
        try:
            start = begin_login(
                client_id=audiences[0],
                redirect_uri=redirect_uri,
                return_path=return_path,
                now=_now(),
                hosted_domain_hint=os.environ.get("SOLVAN_ADMITTED_DOMAIN_HINT"),
                authorization_endpoint=authorization_endpoint(),
            )
        except OAuthLoginError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        with connect() as connection, connection.transaction():
            OperatorSessionStore(connection).start_login(
                state_hash=start.state_hash,
                nonce_hash=start.nonce_hash,
                pkce_verifier=start.pkce_verifier,
                audience=audiences[0],
                return_path=return_path,
                expires_at=start.expires_at,
                now=_now(),
            )
        return RedirectResponse(start.authorization_url, status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/api/auth/step-up")
    def request_step_up(request: Request, command: StepUpRequest) -> dict[str, str | int]:
        """Freeze one action and deliver a transaction-bound presence code."""

        require_csrf(request)
        operation = command.operation
        material_digest = command.material_digest
        try:
            operation_contract = registered_operation(operation)
        except ActionChallengeError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        credential = request.cookies.get(SESSION_COOKIE)
        if not credential:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
        scope = scope_provider()
        now = _now()
        try:
            pepper = step_up_pepper_provider()
        except RuntimeError as error:
            # The same answer an undeliverable code gets below: this deployment
            # can identify people and cannot authorize consequential actions,
            # which is a coherent state reported at the action — not a 500.
            # A missing verifier secret used to escape as one, freezing
            # nothing and explaining nothing.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"This action needs a one-use code and this deployment cannot mint "
                f"one, so the action cannot be prepared. Signing in and reading "
                f"are unaffected. ({error})",
            ) from error
        try:
            with connect() as connection, connection.transaction():
                sessions = OperatorSessionStore(connection)
                live = sessions.touch(credential_hash=credential_hash(credential), now=now)
                if live is None:
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
                roles = OperatorIdentityStore(connection).roles(
                    scope=scope, actor_id=live.actor_id, now=now
                )
                if operation_contract.required_role not in roles:
                    raise HTTPException(
                        status.HTTP_403_FORBIDDEN,
                        f"{operation_contract.required_role} is required for {operation}",
                    )
                presence = OperatorStepUpStore(connection)
                email = presence.verified_google_email(actor_id=live.actor_id)
                # The code verifier binds the transaction identifier, so the
                # action must be frozen before the code can be minted.
                step_up_id = ActionChallengeStore(connection).freeze(
                    scope=scope,
                    session_id=live.session_id,
                    actor_id=live.actor_id,
                    operation_key=operation,
                    material_digest=material_digest,
                    expires_at=now + CODE_LIFETIME,
                    now=now,
                )
                issued = issue_code(now=now, step_up_transaction_id=step_up_id, pepper=pepper)
                code_id = presence.start(
                    scope=scope,
                    step_up_transaction_id=step_up_id,
                    requesting_session_id=live.session_id,
                    actor_id=live.actor_id,
                    email=email,
                    issued=issued,
                    now=now,
                )
        except (ActionChallengeError, OperatorStepUpError) as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error

        # Delivery is an external effect and therefore outside the transaction
        # that records the pending attempt. A crash leaves a non-verifiable
        # PENDING delivery; requesting again supersedes it durably.
        try:
            sender = step_up_sender_provider()
        except RuntimeError as error:
            # Named plainly: this is a deployment that can identify people and
            # cannot yet authorize consequential actions, which is a coherent
            # state and not a broken one.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"This action needs a one-use code and no delivery is configured "
                f"for this deployment, so it cannot be sent. Signing in and "
                f"reading are unaffected. ({error})",
            ) from error

        try:
            receipt = sender.send(
                address=email,
                code=issued.code,
                step_up_id=code_id,
                operation=operation_contract.summary,
            )
        except OperatorStepUpDeliveryError as error:
            with connect() as connection, connection.transaction():
                OperatorStepUpStore(connection).mark_delivery_failed(code_id=code_id, now=_now())
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
        with connect() as connection, connection.transaction():
            OperatorStepUpStore(connection).mark_delivered(
                code_id=code_id, receipt=receipt, now=_now()
            )
        return {
            "schema_version": 1,
            "step_up_handle": code_id,
            "destination": masked_email(email),
            "expires_in_seconds": int((issued.expires_at - now).total_seconds()),
        }

    @router.post("/api/auth/step-up/verify")
    def verify_step_up(
        request: Request, response: Response, command: StepUpVerification
    ) -> dict[str, str | int]:
        """Prove presence, rotate the session, and issue one exact challenge."""

        require_csrf(request)
        credential = request.cookies.get(SESSION_COOKIE)
        if not credential:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
        scope = scope_provider()
        now = _now()
        refusal: str | None = None
        try:
            pepper = step_up_pepper_provider()
        except RuntimeError as error:
            # A deployment that could not mint a code can never verify one;
            # refuse as the unconfigured deployment it is, not as a 500.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"This action needs a one-use code and this deployment cannot verify "
                f"one. Signing in and reading are unaffected. ({error})",
            ) from error
        try:
            with connect() as connection, connection.transaction():
                sessions = OperatorSessionStore(connection)
                live = sessions.touch(credential_hash=credential_hash(credential), now=now)
                if live is None:
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
                presence = OperatorStepUpStore(connection)
                pending = presence.lock(scope=scope, code_id=command.step_up_handle)
                if (
                    pending is None
                    or pending.status != "PENDING"
                    or pending.delivery_status != "DELIVERED"
                    or pending.actor_id != live.actor_id
                    or pending.requesting_session_id != live.session_id
                ):
                    refusal = "that step-up code is not valid"
                elif now >= pending.expires_at:
                    presence.end_expired(code_id=pending.code_id, now=now)
                    refusal = "that step-up code has expired"
                elif pending.attempts >= MAX_ATTEMPTS:
                    refusal = "too many attempts; request a new code"
                elif not matches(
                    submitted=command.code,
                    stored_verifier=pending.verifier_hmac,
                    step_up_transaction_id=pending.step_up_transaction_id,
                    pepper=pepper,
                ):
                    presence.record_wrong_attempt(code_id=pending.code_id, now=now)
                    refusal = "that step-up code is not valid"
                else:
                    new_credential, stored_credential = session_credential()
                    new_csrf, _stored_csrf = session_credential()
                    new_session_id = sessions.create_session(
                        actor_id=live.actor_id,
                        credential_hash=stored_credential,
                        authentication_event_id=live.authentication_event_id,
                        now=now,
                        rotated_from_session_id=live.session_id,
                        absolute_expires_at=live.absolute_expires_at,
                    )
                    presence.consume(code_id=pending.code_id, now=now)
                    presence_id = presence.record_presence(
                        step_up_transaction_id=pending.step_up_transaction_id,
                        code_id=pending.code_id,
                        actor_id=live.actor_id,
                        requesting_session_id=live.session_id,
                        resulting_session_id=new_session_id,
                        now=now,
                    )
                    sessions.revoke(session_id=live.session_id, now=now)
                    challenge_id = ActionChallengeStore(connection).issue(
                        scope=scope,
                        step_up_transaction_id=pending.step_up_transaction_id,
                        session_id=new_session_id,
                        actor_id=live.actor_id,
                        presence_event_id=presence_id,
                        csrf_token_hash=credential_hash(new_csrf),
                        now=now,
                    )
        except OperatorStepUpError as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
        if refusal is not None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, refusal)
        _set_session_cookies(response, credential=new_credential, csrf=new_csrf)
        return {
            "schema_version": 1,
            "challenge": challenge_id,
            "notice": "One use, one operation, one material.",
        }

    @router.get("/api/auth/callback")
    def complete_sign_in(request: Request, code: str = "", state: str = "") -> Response:
        """Verify the assertion, resolve the actor, and open a session."""

        if not code or not state:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "the callback is incomplete")
        audiences = _audiences()
        redirect_uri = _required("SOLVAN_OAUTH_REDIRECT_URI")
        scope = scope_provider()
        now = _now()
        with connect() as connection, connection.transaction():
            sessions = OperatorSessionStore(connection)
            claimed = sessions.claim_login(state_hash=credential_hash(state), now=now)
            try:
                verify_callback(
                    returned_state=state,
                    pending=None if claimed is None else claimed[1],
                    now=now,
                )
            except OAuthLoginError as error:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
            assert claimed is not None
            _transaction_id, pending = claimed
            csrf_credential, _csrf_hash = session_credential()
            claims = verifier.exchange(
                code=code,
                pkce_verifier=pending.pkce_verifier,
                redirect_uri=redirect_uri,
                audiences=audiences,
            )
            try:
                verify_nonce(claimed_nonce=claims.get("nonce"), pending=pending)
                assertion = VerifiedAssertion(
                    provider="GOOGLE",
                    issuer=str(claims.get("iss", "")),
                    subject=str(claims.get("sub", "")),
                    email=str(claims.get("email", "")),
                    email_verified=claims.get("email_verified") is True,
                    hosted_domain=claims.get("hd"),
                    authenticated_at_epoch=int(claims.get("auth_time", 0)),
                ).resolved()
                admitted_domain(assertion, admitted=admitted_domains_provider(scope))
            except (OAuthLoginError, OperatorIdentityError) as error:
                raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
            identity = OperatorIdentityStore(connection)
            try:
                actor_id = identity.resolve_actor(assertion, now=now)
                # The first administrator cannot be invited, because there is
                # nobody to invite them. This is refused once anyone holds ADMIN,
                # so it starts an environment rather than opening one.
                identity.claim_founding_administrator(
                    scope=scope,
                    actor_id=actor_id,
                    email=assertion.email,
                    founding_email=os.environ.get("SOLVAN_FOUNDING_ADMINISTRATOR", ""),
                    now=now,
                )
                identity.redeem_invitation(
                    scope=scope,
                    actor_id=actor_id,
                    email=assertion.email,
                    hosted_domain=assertion.hosted_domain or "",
                    now=now,
                )
            except OperatorIdentityError as error:
                raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
            # Eligibility is not admission. A verified account at an admitted
            # domain proves who someone is; a membership is what lets them in.
            # Without this, onboarding one colleague admitted their whole
            # company to a console whose scope comes from configuration.
            if not identity.roles(scope=scope, actor_id=actor_id, now=now):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "This account is verified but holds no access to this environment. "
                    "An administrator invites people to it explicitly.",
                )
            # Absent stays absent. Reading a missing `auth_time` as epoch zero
            # made "the provider said nothing" indistinguishable from "the
            # provider said 1970", and the refusal that followed named the wrong
            # cause.
            claimed_auth_time = claims.get("auth_time")
            authenticated_at = (
                datetime.fromtimestamp(int(claimed_auth_time), tz=UTC)
                if claimed_auth_time is not None
                else None
            )
            event_id = sessions.record_authentication(
                actor_id=actor_id,
                canonical_issuer=assertion.canonical_issuer,
                subject=assertion.subject,
                audience=audiences[0],
                # Google often omits `auth_time`; observation time is recorded
                # in its place rather than fabricating issuer-proven recency.
                # Step-up presence is a separate event and never relies on it.
                authenticated_at=authenticated_at or now,
                hosted_domain=assertion.hosted_domain,
                now=now,
            )
            # Rotation, actually performed. A new credential without ending the
            # old one leaves two live sessions for one person, and a fresh
            # absolute ceiling on every step-up would let a session be kept
            # alive indefinitely by stepping up — a ceiling that bounds nothing.
            prior = None
            prior_credential = request.cookies.get(SESSION_COOKIE)
            if prior_credential:
                prior = sessions.touch(credential_hash=credential_hash(prior_credential), now=now)
            inherits = prior is not None and prior.actor_id == actor_id
            credential, stored = session_credential()
            sessions.create_session(
                actor_id=actor_id,
                credential_hash=stored,
                authentication_event_id=event_id,
                now=now,
                rotated_from_session_id=prior.session_id if inherits and prior else None,
                absolute_expires_at=prior.absolute_expires_at if inherits and prior else None,
            )
            if prior is not None:
                # Ended whether or not it was the same person: this browser now
                # holds one session, and a different actor signing in must not
                # leave the previous one usable.
                sessions.revoke(session_id=prior.session_id, now=now)
        # One origin serves the console and proxies this API, so a relative path
        # resolves against the console the operator started from. It was
        # validated as relative when the sign-in began, so a callback cannot
        # redirect anybody off this deployment. This previously prefixed a
        # separately configured console origin, which is what a cross-origin
        # arrangement required — and that arrangement is what made the session
        # cookie land on a host the console could not read.
        response = RedirectResponse(pending.return_path, status_code=status.HTTP_303_SEE_OTHER)
        _set_session_cookies(response, credential=credential, csrf=csrf_credential)
        return response

    @router.get("/api/auth/session")
    def current_session(request: Request) -> dict[str, Any]:
        """Who this browser is, and what that lets them do in this scope."""

        credential = request.cookies.get(SESSION_COOKIE)
        if not credential:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _no_session_detail())
        scope = scope_provider()
        now = _now()
        with connect() as connection, connection.transaction():
            live = OperatorSessionStore(connection).touch(
                credential_hash=credential_hash(credential), now=now
            )
            if live is None:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, _no_session_detail())
            roles = OperatorIdentityStore(connection).roles(
                scope=scope, actor_id=live.actor_id, now=now
            )
            email = connection.execute(
                """SELECT email FROM solvan_identity.external_identities
                    WHERE actor_id=%s ORDER BY last_seen_at DESC LIMIT 1""",
                (live.actor_id,),
            ).fetchone()
        return {
            "schema_version": 1,
            "actor_id": live.actor_id,
            "email": None if email is None else str(email[0]),
            # Read per request rather than carried in the session, so a
            # revocation takes effect now rather than at next sign-in.
            "roles": sorted(roles),
            "absolute_expires_at": live.absolute_expires_at.isoformat(),
            "notice": "A session establishes identity. Consequential actions require a challenge.",
        }

    @router.post("/api/auth/logout")
    def sign_out(request: Request, response: Response) -> dict[str, str]:
        credential = request.cookies.get(SESSION_COOKIE)
        if credential:
            now = _now()
            with connect() as connection, connection.transaction():
                sessions = OperatorSessionStore(connection)
                live = sessions.touch(credential_hash=credential_hash(credential), now=now)
                if live is not None:
                    sessions.revoke(session_id=live.session_id, now=now)
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie(CSRF_COOKIE, path="/")
        return {"status": "signed out"}

    return router


__all__ = [
    "AssertionVerifier",
    "StepUpRequest",
    "StepUpVerification",
    "auth_router",
]
