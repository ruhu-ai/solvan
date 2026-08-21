"""What this deployment is configured to do about identity (spec 05 §4.2).

Separated from the flow itself because they answer different questions. The
flow decides who somebody is; this decides whether this process may ask at all,
which domains it admits, and what it refuses to start without.

Every refusal here points the same way. Sign-in used to be conditional on its
own configuration, absence travelled outward as "sign-in unavailable", and a
console read that as a deployment needing none — so a missing environment
variable, which was the deployed state, admitted everybody who could reach it.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from psycopg import Connection

from apps.api.auth_routes import AssertionVerifier, auth_router
from solvan.application.approval_audience import ApprovalAudienceError, accepted_audiences
from solvan.domain import Scope
from solvan.platform.google_oauth import google_is_the_issuer
from solvan.platform.operator_step_up_email import (
    GoogleOperatorStepUpSender,
    LoopbackOperatorStepUpSender,
    OperatorStepUpSender,
)


def admitted_domains(_scope: Scope | None = None) -> frozenset[str]:
    """Which Google Workspace domains may sign in to this deployment.

    Configured explicitly and never inferred. An empty set admits nobody, which
    is the safe direction: a deployment that has not said who may sign in should
    refuse everyone rather than accept anyone holding a verified Google account.
    """

    declared = os.environ.get("SOLVAN_ADMITTED_DOMAINS", "")
    return frozenset(part.strip().lower() for part in declared.split(",") if part.strip())


class SignInConfigurationError(RuntimeError):
    """This deployment cannot complete a sign-in, so it must not serve."""


def operator_step_up_sender() -> OperatorStepUpSender:
    """Select the production relay or a structurally confined local sink.

    Two local shapes exist. The harness fixture issuer pairs sign-in and
    mailbox for the browser suite. And a local host signed in with real Google
    and holding no mailbox relay delivers codes to a loopback sink, so the
    connected-development path exercises the same request, delivery, and
    verification flow instead of refusing every consequential action. Neither
    shape may exist where Google Cloud holds authority, and a misconfigured
    sink is a deployment fact the caller reports, not a 500.
    """

    cloud_authority = os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM"
    test_issuer = os.environ.get("SOLVAN_TEST_ISSUER", "").rstrip("/")
    if test_issuer:
        if cloud_authority:
            raise RuntimeError("a Google Cloud authority process cannot use the test step-up sink")
        return _loopback_sender(
            relay_url=f"{test_issuer}/operator-step-up-messages",
            bearer_token=os.environ.get("SOLVAN_TEST_STEP_UP_SINK_TOKEN", ""),
        )
    relay_url = os.environ.get("SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL", "").strip()
    if relay_url:
        return GoogleOperatorStepUpSender(relay_url=relay_url)
    sink_url = os.environ.get("SOLVAN_OPERATOR_STEP_UP_SINK_URL", "").strip()
    if sink_url:
        if cloud_authority:
            raise RuntimeError(
                "a Google Cloud authority process cannot use a loopback step-up sink"
            )
        return _loopback_sender(
            relay_url=sink_url,
            bearer_token=os.environ.get("SOLVAN_OPERATOR_STEP_UP_SINK_TOKEN", ""),
        )
    raise RuntimeError("operator step-up email delivery is not configured")


def _loopback_sender(*, relay_url: str, bearer_token: str) -> LoopbackOperatorStepUpSender:
    try:
        return LoopbackOperatorStepUpSender(relay_url=relay_url, bearer_token=bearer_token)
    except ValueError as error:
        raise RuntimeError(f"the loopback step-up sink is misconfigured: {error}") from error


def operator_step_up_pepper() -> str:
    """Read the dedicated code-verifier secret, refusing weak configuration."""

    value = os.environ.get("SOLVAN_OPERATOR_STEP_UP_PEPPER", "")
    if len(value.encode("utf-8")) < 32:
        raise RuntimeError("operator step-up pepper is not configured")
    return value


def sign_in_is_configured() -> bool:
    """Whether this process holds everything a sign-in needs.

    Consulted for one purpose only: whether to mount the routes. It is no longer
    an answer given to a console. Absence used to travel outward as "sign-in
    unavailable", and the console read that as a hermetic harness and rendered
    itself as a signed-in reader — so a missing environment variable, which was
    the deployed state, admitted everyone who could reach the console. A console
    now requires a session unconditionally and reads the absence of these routes
    as a broken deployment, which is what it is.
    """

    if not os.environ.get("SOLVAN_OAUTH_REDIRECT_URI"):
        return False
    if google_is_the_issuer() and not os.environ.get("SOLVAN_OAUTH_CLIENT_SECRET"):
        return False
    # Step-up delivery is deliberately not required here. It authorizes
    # consequential actions; it does not establish identity, and gating sign-in
    # on it meant an unconfigured code transport served no sign-in at all — the
    # console then reported that it could not establish who anybody was, which
    # was true and was caused by the check rather than by identity being
    # unavailable. An action that needs a code refuses at that action.
    if not admitted_domains():
        return False
    try:
        accepted_audiences(
            os.environ.get("SOLVAN_APPROVAL_AUDIENCE"),
            rotating_to=os.environ.get("SOLVAN_APPROVAL_AUDIENCE_SUCCESSOR"),
            google_issuer=google_is_the_issuer(),
        )
    except ApprovalAudienceError:
        return False
    return True


def require_sign_in_configuration() -> None:
    """Refuse to build an app that carries production authority and no sign-in.

    Scoped to `GOOGLE_CLOUD_IAM` deliberately, and that scope is the honest
    claim: a process holding Google Cloud authority serves real operators over
    real records, so an unauthenticated one is a defect rather than a posture.
    A harness process holds no such authority, mounts no sign-in, and issues no
    session — and the console refuses to render against it rather than treating
    it as permission.

    This is the same direction `_configured_issuer` already takes: authority
    mode narrows what configuration may do, and never widens it.
    """

    if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") != "GOOGLE_CLOUD_IAM":
        return
    missing = []
    if not os.environ.get("SOLVAN_OAUTH_REDIRECT_URI"):
        missing.append(
            "SOLVAN_OAUTH_REDIRECT_URI (this deployment's console origin "
            "followed by /api/auth/callback)"
        )
    if not os.environ.get("SOLVAN_OAUTH_CLIENT_SECRET"):
        missing.append("SOLVAN_OAUTH_CLIENT_SECRET (the confidential client's secret)")
    if not os.environ.get("SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL", "").startswith("https://"):
        missing.append("SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL (a private HTTPS delivery service)")
    if len(os.environ.get("SOLVAN_OPERATOR_STEP_UP_PEPPER", "").encode("utf-8")) < 32:
        missing.append(
            "SOLVAN_OPERATOR_STEP_UP_PEPPER (at least 32 secret bytes, from Secret Manager)"
        )
    if not admitted_domains():
        missing.append("SOLVAN_ADMITTED_DOMAINS (the Google Workspace domains admitted here)")
    try:
        accepted_audiences(
            os.environ.get("SOLVAN_APPROVAL_AUDIENCE"),
            rotating_to=os.environ.get("SOLVAN_APPROVAL_AUDIENCE_SUCCESSOR"),
            google_issuer=True,
        )
    except ApprovalAudienceError as error:
        missing.append(f"SOLVAN_APPROVAL_AUDIENCE ({error})")
    if missing:
        raise SignInConfigurationError(
            "This deployment carries Google Cloud authority and cannot sign anybody in. "
            "Configure: " + "; ".join(missing)
        )


def include_identity_routes(
    app: Any,
    *,
    connect: Callable[[], Connection[Any]],
    scope_provider: Callable[[], Scope],
    verifier: AssertionVerifier,
    step_up_sender_provider: Callable[[], OperatorStepUpSender],
    step_up_pepper_provider: Callable[[], str],
) -> None:
    """Mount sign-in and the surface that administers who may use it.

    They mount together because the second administers what the first
    establishes, and it is unreachable without a session to resolve an ADMIN
    role against.

    A deployment carrying Google Cloud authority has already refused to reach
    here unconfigured, so the branch below is the harness case alone: no client,
    no secret, nobody to sign in. What changed is what absence means downstream —
    a console requires a session unconditionally and reads these routes going
    missing as a broken deployment, where it used to read it as permission.
    """

    from apps.api.operator_administration import operator_administration_router

    require_sign_in_configuration()
    if not sign_in_is_configured():
        return
    app.include_router(
        auth_router(
            connect=connect,
            scope_provider=scope_provider,
            verifier=verifier,
            admitted_domains_provider=admitted_domains,
            step_up_sender_provider=step_up_sender_provider,
            step_up_pepper_provider=step_up_pepper_provider,
        )
    )
    app.include_router(
        operator_administration_router(
            connect=connect,
            scope_provider=scope_provider,
            admitted_domains_provider=admitted_domains,
        )
    )


__all__ = [
    "SignInConfigurationError",
    "admitted_domains",
    "include_identity_routes",
    "operator_step_up_pepper",
    "operator_step_up_sender",
    "require_sign_in_configuration",
    "sign_in_is_configured",
]
