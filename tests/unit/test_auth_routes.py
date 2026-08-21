"""The sign-in flow as the browser experiences it (specification 05 §4.2).

The verifier is injected, so these cover the flow without a network or a Google
account. What they assert is what the browser is given and what it is refused.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.auth_routes import auth_router
from apps.api.session_authorization import CSRF_COOKIE, SESSION_COOKIE
from solvan.domain import Scope

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
CLIENT = "111111111111-abc123.apps.googleusercontent.com"


def _unused_connection() -> Any:
    """A database this test must never reach.

    A browser holding no cookie is refused before any query runs. Raising here
    proves that ordering rather than assuming it: a refusal that first opened a
    connection would make an unauthenticated request cost database work.
    """

    raise AssertionError("a session refusal must not open a database connection")


class _RecordingVerifier:
    """Stands in for the token endpoint, and records what it was asked to redeem."""

    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims
        self.seen: dict[str, Any] = {}

    def exchange(
        self, *, code: str, pkce_verifier: str, redirect_uri: str, audiences: tuple[str, ...]
    ) -> dict[str, Any]:
        self.seen = {
            "code": code,
            "pkce_verifier": pkce_verifier,
            "redirect_uri": redirect_uri,
            "audiences": audiences,
        }
        return dict(self.claims)


class _RecordingStepUpSender:
    def send(self, *, address: str, code: str, step_up_id: str, operation: str) -> str:
        return "email-relay:test-message"


def _step_up_pepper() -> str:
    return "test-only-step-up-pepper-is-at-least-32-bytes"


@pytest.fixture(autouse=True)
def _configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLVAN_APPROVAL_AUDIENCE", CLIENT)
    monkeypatch.setenv("SOLVAN_OAUTH_REDIRECT_URI", "https://console.example/api/auth/callback")
    monkeypatch.delenv("SOLVAN_APPROVAL_AUDIENCE_SUCCESSOR", raising=False)


def _client(verifier: Any) -> TestClient:
    app = FastAPI()
    app.include_router(
        auth_router(
            connect=_unusable_connection,
            scope_provider=lambda: SCOPE,
            verifier=verifier,
            admitted_domains_provider=lambda _scope: frozenset({"example.com"}),
            step_up_sender_provider=lambda: _RecordingStepUpSender(),
            step_up_pepper_provider=_step_up_pepper,
        )
    )
    return TestClient(app)


def _unusable_connection() -> Any:
    raise AssertionError("this case must be refused before any database work")


def test_sign_in_redirects_to_google_with_pkce_and_a_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, Any] = {}

    class _Store:
        def __init__(self, _connection: Any) -> None: ...

        def start_login(self, **kwargs: Any) -> str:
            recorded.update(kwargs)
            return "lgn_x"

    monkeypatch.setattr("apps.api.auth_routes.OperatorSessionStore", _Store)
    monkeypatch.setattr("apps.api.auth_routes.OperatorIdentityStore", _Store)

    class _Connection:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_args: Any) -> None: ...

        def transaction(self) -> Any:
            return self

    app = FastAPI()
    app.include_router(
        auth_router(
            connect=lambda: _Connection(),  # type: ignore[arg-type,return-value]
            scope_provider=lambda: SCOPE,
            verifier=_RecordingVerifier({}),
            admitted_domains_provider=lambda _scope: frozenset({"example.com"}),
            step_up_sender_provider=lambda: _RecordingStepUpSender(),
            step_up_pepper_provider=_step_up_pepper,
        )
    )
    with TestClient(app) as client:
        response = client.get(
            "/api/auth/login", params={"return_path": "/incidents"}, follow_redirects=False
        )
    assert response.status_code == 303
    parameters = {
        k: v[0] for k, v in parse_qs(urlparse(response.headers["location"]).query).items()
    }
    assert parameters["client_id"] == CLIENT
    assert parameters["code_challenge_method"] == "S256"
    assert parameters["scope"] == "openid email profile"
    assert parameters["state"] != parameters["nonce"]
    # The verifier is stored, never handed to the browser.
    assert recorded["pkce_verifier"] not in response.headers["location"]
    assert recorded["return_path"] == "/incidents"


def test_an_absolute_return_target_is_refused_before_any_redirect() -> None:
    """Otherwise sign-in is an open redirect wearing this deployment's name."""

    with _client(_RecordingVerifier({})) as client:
        response = client.get(
            "/api/auth/login",
            params={"return_path": "https://elsewhere.example/steal"},
            follow_redirects=False,
        )
    assert response.status_code == 400


def test_sign_in_is_not_offered_without_an_owned_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deployment that cannot name its client cannot verify what comes back."""

    monkeypatch.delenv("SOLVAN_APPROVAL_AUDIENCE", raising=False)
    with _client(_RecordingVerifier({})) as client:
        assert client.get("/api/auth/login", follow_redirects=False).status_code == 503


def test_sign_in_is_not_offered_against_a_shared_public_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_APPROVAL_AUDIENCE", "32555940559.apps.googleusercontent.com")
    with _client(_RecordingVerifier({})) as client:
        assert client.get("/api/auth/login", follow_redirects=False).status_code == 503


def test_an_incomplete_callback_is_refused_before_any_database_work() -> None:
    with _client(_RecordingVerifier({})) as client:
        assert client.get("/api/auth/callback", follow_redirects=False).status_code == 400
        assert (
            client.get(
                "/api/auth/callback", params={"code": "c"}, follow_redirects=False
            ).status_code
            == 400
        )


def test_a_request_without_a_session_cookie_is_unauthenticated() -> None:
    with _client(_RecordingVerifier({})) as client:
        assert client.get("/api/auth/session").status_code == 401


def test_signing_out_without_a_session_still_clears_the_cookies() -> None:
    with _client(_RecordingVerifier({})) as client:
        response = client.post("/api/auth/logout")
    assert response.status_code == 200
    cleared = response.headers.get_list("set-cookie")
    assert any(SESSION_COOKIE in value for value in cleared)
    assert any(CSRF_COOKIE in value for value in cleared)


def test_a_deployment_that_names_no_domain_admits_nobody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The safe direction: silence refuses everyone rather than accepting anyone.

    A deployment that has not said who may sign in must not admit every holder
    of a verified Google account.
    """

    from apps.api.identity_configuration import admitted_domains

    monkeypatch.delenv("SOLVAN_ADMITTED_DOMAINS", raising=False)
    assert admitted_domains(SCOPE) == frozenset()


def test_admitted_domains_are_read_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.api.identity_configuration import admitted_domains

    monkeypatch.setenv("SOLVAN_ADMITTED_DOMAINS", " Example.com , ruhu.ai ,, ")
    assert admitted_domains(SCOPE) == frozenset({"example.com", "ruhu.ai"})


def test_a_deployment_with_google_authority_refuses_to_start_without_sign_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hole this closes was the deployed configuration, not a hypothetical.

    Terraform set no callback, no client secret and no admitted domains, so the
    API reported "sign-in unavailable" and the console rendered itself as a
    signed-in reader. A process holding Google Cloud authority now refuses to
    exist rather than serve records to an unauthenticated browser.
    """

    from apps.api.identity_configuration import (
        SignInConfigurationError,
        require_sign_in_configuration,
    )

    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "GOOGLE_CLOUD_IAM")
    for name in (
        "SOLVAN_OAUTH_REDIRECT_URI",
        "SOLVAN_OAUTH_CLIENT_SECRET",
        "SOLVAN_ADMITTED_DOMAINS",
        "SOLVAN_APPROVAL_AUDIENCE",
        "SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL",
        "SOLVAN_OPERATOR_STEP_UP_PEPPER",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(SignInConfigurationError) as refusal:
        require_sign_in_configuration()
    # Every missing setting is named at once: a deployment fixed one at a time
    # learns of the next only after another failed rollout.
    message = str(refusal.value)
    assert "SOLVAN_OAUTH_REDIRECT_URI" in message
    assert "SOLVAN_OAUTH_CLIENT_SECRET" in message
    assert "SOLVAN_ADMITTED_DOMAINS" in message
    assert "SOLVAN_APPROVAL_AUDIENCE" in message
    assert "SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL" in message
    assert "SOLVAN_OPERATOR_STEP_UP_PEPPER" in message


def test_a_harness_without_google_authority_still_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Narrowing, never widening: authority mode decides, and configuration cannot.

    A harness process holds no Google Cloud authority, mounts no sign-in and
    issues no session. What changed is what that absence means to a console: it
    is read as a broken deployment rather than as permission to render.
    """

    from apps.api.identity_configuration import require_sign_in_configuration

    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "NO_PRODUCTION_AUTHORITY")
    monkeypatch.delenv("SOLVAN_OAUTH_REDIRECT_URI", raising=False)
    require_sign_in_configuration()


def test_the_refusal_to_serve_a_session_names_the_provider_it_would_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sign-in page renders from this refusal, so the refusal carries its wording.

    A second route answered this before, and its absence was what the console
    read as "no sign-in needed". A 401 is not negotiable, so the naming rides on
    the 401 and there is no separate answer to misread.
    """

    monkeypatch.delenv("SOLVAN_TEST_ISSUER", raising=False)
    app = FastAPI()
    app.include_router(
        auth_router(
            connect=_unused_connection,
            scope_provider=lambda: SCOPE,
            verifier=_RecordingVerifier({}),
            admitted_domains_provider=lambda _scope: frozenset({"solvan.ai"}),
            step_up_sender_provider=lambda: _RecordingStepUpSender(),
            step_up_pepper_provider=_step_up_pepper,
        )
    )
    with TestClient(app) as client:
        response = client.get("/api/auth/session")
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["provider"] == "Google"
    assert detail["provider_is_production"] is True


def test_a_host_running_the_test_fixture_never_calls_it_google(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A button reading "Continue with Google" that goes elsewhere is a false claim.

    Google is the product's only provider, but while a host can still run the
    harness fixture the page must say so — and those hosts are exactly where a
    false label would go unnoticed.
    """

    monkeypatch.setenv("SOLVAN_TEST_ISSUER", "http://127.0.0.1:20006")
    monkeypatch.delenv("SOLVAN_PLATFORM_AUTHORITY_MODE", raising=False)
    app = FastAPI()
    app.include_router(
        auth_router(
            connect=_unused_connection,
            scope_provider=lambda: SCOPE,
            verifier=_RecordingVerifier({}),
            admitted_domains_provider=lambda _scope: frozenset({"solvan.local"}),
            step_up_sender_provider=lambda: _RecordingStepUpSender(),
            step_up_pepper_provider=_step_up_pepper,
        )
    )
    with TestClient(app) as client:
        response = client.get("/api/auth/session")
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["provider"] != "Google"
    assert detail["provider_is_production"] is False


def test_a_step_up_carries_its_material_in_a_body_not_a_url() -> None:
    """A digest in a query parameter travels into history, referrers and logs."""

    from apps.api.auth_routes import StepUpRequest

    command = StepUpRequest(
        operation="estate.connect",
        material_digest="sha256:" + "b" * 64,
    )
    assert command.operation == "estate.connect"
    with pytest.raises(ValueError):
        StepUpRequest(operation="estate.connect", material_digest="not-a-digest")


def test_a_step_up_without_a_session_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(_RecordingVerifier({})) as client:
        response = client.post(
            "/api/auth/step-up",
            json={
                "operation": "estate.connect",
                "material_digest": "sha256:" + "b" * 64,
            },
        )
    # Refused for want of the double-submit token before anything else is read.
    assert response.status_code == 403


def test_a_step_up_for_an_unregistered_operation_is_refused() -> None:
    with _client(_RecordingVerifier({})) as client:
        client.cookies.set("__Host-solvan_csrf", "token")
        response = client.post(
            "/api/auth/step-up",
            json={
                "operation": "something.invented",
                "material_digest": "sha256:" + "b" * 64,
            },
            headers={"X-Solvan-CSRF": "token"},
        )
    assert response.status_code in {400, 401}


def _unconfigured_pepper() -> str:
    raise RuntimeError("operator step-up pepper is not configured")


def _client_without_step_up_configuration() -> TestClient:
    """A deployment that can identify people and cannot mint a presence code."""

    app = FastAPI()
    app.include_router(
        auth_router(
            connect=_unused_connection,
            scope_provider=lambda: SCOPE,
            verifier=_RecordingVerifier({}),
            admitted_domains_provider=lambda _scope: frozenset({"example.com"}),
            step_up_sender_provider=lambda: _RecordingStepUpSender(),
            step_up_pepper_provider=_unconfigured_pepper,
        )
    )
    return TestClient(app)


def test_an_unconfigured_step_up_refuses_the_action_not_the_server() -> None:
    """A missing verifier secret is a deployment fact, never a 500.

    The real-Google local path once reached this: sign-in worked, and every
    challenge-bound action failed at preparation with an unhandled
    RuntimeError. The connect double-submits and carries a session cookie, so
    the refusal comes from the pepper check itself — and `_unused_connection`
    proves nothing was frozen on the way out.
    """

    with _client_without_step_up_configuration() as client:
        client.cookies.set("__Host-solvan_csrf", "token")
        client.cookies.set(SESSION_COOKIE, "credential")
        response = client.post(
            "/api/auth/step-up",
            json={
                "operation": "estate.connect",
                "material_digest": "sha256:" + "b" * 64,
            },
            headers={"X-Solvan-CSRF": "token"},
        )
    assert response.status_code == 503
    assert "cannot mint" in response.json()["detail"]


def test_an_unconfigured_step_up_cannot_verify_a_code_either() -> None:
    with _client_without_step_up_configuration() as client:
        client.cookies.set("__Host-solvan_csrf", "token")
        client.cookies.set(SESSION_COOKIE, "credential")
        response = client.post(
            "/api/auth/step-up/verify",
            json={
                "step_up_handle": "sup_0" + "1" * 25,
                "code": "12345678",
            },
            headers={"X-Solvan-CSRF": "token"},
        )
    assert response.status_code == 503
    assert "cannot verify" in response.json()["detail"]
