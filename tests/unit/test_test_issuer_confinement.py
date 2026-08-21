"""The harness fixture issuer cannot reach a deployment (specification 05 §4.2).

Google is the only issuer of human identity for this product. `SOLVAN_TEST_ISSUER`
exists so the browser suite performs a genuine sign-in — callback, nonce, and
PKCE — instead of injecting a fabricated cookie and testing
nothing. That is worth keeping only while it is structurally incapable of
admitting anyone to a real deployment.

Two things hold it there: authority mode refuses it in code, and no deployment
configuration names it. The first is the control; the second keeps the first
from ever being asked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from solvan.application.oauth_login import OAuthLoginError
from solvan.platform import google_oauth
from solvan.platform.google_oauth import authorization_endpoint, google_is_the_issuer

REPOSITORY = Path(__file__).parents[2]


def test_a_deployment_refuses_the_fixture_issuer_however_it_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Narrowing, never widening: authority mode decides and configuration cannot.

    Naming the fixture is not a setting a deployment may have. It raises rather
    than falling back to Google, because a host that believes it is pointed at a
    test provider and is silently pointed at Google is a host whose operator
    does not know which identities they are admitting.
    """

    monkeypatch.setenv("SOLVAN_TEST_ISSUER", "http://127.0.0.1:20006")
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "GOOGLE_CLOUD_IAM")

    with pytest.raises(OAuthLoginError):
        google_is_the_issuer()


def test_google_is_the_issuer_wherever_the_fixture_is_unnamed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absence resolves to Google, so a dropped variable never weakens anything."""

    monkeypatch.delenv("SOLVAN_TEST_ISSUER", raising=False)
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "GOOGLE_CLOUD_IAM")

    assert google_is_the_issuer() is True


def test_no_deployment_configuration_names_the_fixture_issuer() -> None:
    """Terraform must not be able to ask the question the control above answers.

    The refusal in code is what protects a deployment. This keeps the fixture
    out of the files that describe one, so nobody adds it to an environment and
    discovers the refusal from a crash loop.
    """

    named = [
        path.relative_to(REPOSITORY)
        for path in (REPOSITORY / "infra").rglob("*")
        if path.is_file()
        and path.suffix in {".tf", ".tfvars", ".example", ".yaml", ".yml"}
        and "SOLVAN_TEST_ISSUER" in path.read_text(encoding="utf-8", errors="ignore")
    ]
    assert named == [], f"deployment configuration names the fixture issuer: {named}"


def test_a_discovery_document_naming_another_issuer_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Where the browser is sent is not taken on the document's word alone.

    This returned whatever address the document named. The fixture provider
    published a hardcoded port that belonged to a different worktree service, so
    the API discovered it correctly and then sent every sign-in to an address
    nothing served — a failure that presented as the login page hanging. A
    document that could be tampered with would send them somewhere worse, so
    the endpoint is now taken only from a document that names the issuer asked
    for, exactly as the token exchange already required.
    """

    class _Disagreeing:
        status_code = 200

        @staticmethod
        def json() -> dict[str, str]:
            return {
                "issuer": "http://127.0.0.1:30165",
                "authorization_endpoint": "http://127.0.0.1:30165/authorize",
            }

    monkeypatch.setenv("SOLVAN_TEST_ISSUER", "http://127.0.0.1:30167")
    monkeypatch.delenv("SOLVAN_PLATFORM_AUTHORITY_MODE", raising=False)
    monkeypatch.setattr(google_oauth.requests, "get", lambda *_a, **_k: _Disagreeing())

    with pytest.raises(OAuthLoginError, match="does not agree"):
        authorization_endpoint()
