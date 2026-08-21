"""The mutation-path services establish identity from verified claims.

Cloud Run IAM authenticates at the boundary. These cases prove the application
layer does not treat network position as proof: every refusal below happens
before any route logic runs.
"""

from __future__ import annotations

from typing import Any

import pytest

from solvan.platform.service_identity import (
    ServiceIdentityError,
    VerifiedCaller,
    require_agent_principal,
    verify_service_caller,
)

AUDIENCE_VARIABLE = "SOLVAN_TEST_AUDIENCE"
AUDIENCE = "https://actuator.example.invalid"


def _claims(**overrides: Any) -> dict[str, Any]:
    base = {
        "sub": "1234567890",
        "iss": "https://accounts.google.com",
        "aud": AUDIENCE,
        "email": "caller@solvan.iam.gserviceaccount.com",
    }
    base.update(overrides)
    return base


def _verifier(claims: dict[str, Any]) -> Any:
    def verify(token: str, *, audience: str) -> dict[str, Any]:
        del token, audience
        return claims

    return verify


def test_a_verified_caller_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUDIENCE_VARIABLE, AUDIENCE)
    caller = verify_service_caller(
        "Bearer any-token",
        audience_variable=AUDIENCE_VARIABLE,
        verifier=_verifier(_claims()),
    )
    assert caller.subject == "1234567890"
    assert caller.audience == AUDIENCE


@pytest.mark.parametrize(
    "authorization",
    [None, "", "certificate-bound-agent-token", "Basic abc", "Bearer ", "Bearer    "],
)
def test_a_bare_or_malformed_header_is_refused(
    monkeypatch: pytest.MonkeyPatch, authorization: str | None
) -> None:
    """The previous gate accepted any string beginning "Bearer "."""

    monkeypatch.setenv(AUDIENCE_VARIABLE, AUDIENCE)
    with pytest.raises(ServiceIdentityError):
        verify_service_caller(
            authorization,
            audience_variable=AUDIENCE_VARIABLE,
            verifier=_verifier(_claims()),
        )


def test_an_unconfigured_audience_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Absent configuration is a missing control, not a reason to skip the check."""

    monkeypatch.delenv(AUDIENCE_VARIABLE, raising=False)
    with pytest.raises(ServiceIdentityError, match="not configured"):
        verify_service_caller(
            "Bearer any-token",
            audience_variable=AUDIENCE_VARIABLE,
            verifier=_verifier(_claims()),
        )


def test_a_token_minted_for_another_service_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid token for service A must not authorize a call to service B."""

    monkeypatch.setenv(AUDIENCE_VARIABLE, AUDIENCE)
    with pytest.raises(ServiceIdentityError, match="audience"):
        verify_service_caller(
            "Bearer any-token",
            audience_variable=AUDIENCE_VARIABLE,
            verifier=_verifier(_claims(aud="https://verifier.example.invalid")),
        )


@pytest.mark.parametrize("issuer", ["https://evil.example", "", "accounts.google.com.evil"])
def test_an_unaccepted_issuer_is_refused(monkeypatch: pytest.MonkeyPatch, issuer: str) -> None:
    monkeypatch.setenv(AUDIENCE_VARIABLE, AUDIENCE)
    with pytest.raises(ServiceIdentityError, match="issuer"):
        verify_service_caller(
            "Bearer any-token",
            audience_variable=AUDIENCE_VARIABLE,
            verifier=_verifier(_claims(iss=issuer)),
        )


def test_a_token_without_a_subject_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUDIENCE_VARIABLE, AUDIENCE)
    with pytest.raises(ServiceIdentityError, match="subject"):
        verify_service_caller(
            "Bearer any-token",
            audience_variable=AUDIENCE_VARIABLE,
            verifier=_verifier(_claims(sub="")),
        )


def test_an_invalid_signature_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUDIENCE_VARIABLE, AUDIENCE)

    def reject(token: str, *, audience: str) -> dict[str, Any]:
        del token, audience
        raise ServiceIdentityError("invalid caller identity token")

    with pytest.raises(ServiceIdentityError):
        verify_service_caller(
            "Bearer any-token", audience_variable=AUDIENCE_VARIABLE, verifier=reject
        )


_SPIFFE = (
    "principal://agents.global.project-123.system.id.goog/resources/aiplatform/"
    "projects/123/locations/europe-west1/reasoningEngines/abc123"
)


def _caller(subject: str, email: str | None) -> VerifiedCaller:
    return VerifiedCaller(
        subject=subject,
        email=email,
        audience=AUDIENCE,
        issuer="https://accounts.google.com",
    )


@pytest.mark.parametrize("principal", [_SPIFFE, _SPIFFE.removeprefix("principal://")])
def test_the_exact_attested_agent_identity_is_admitted_in_both_spellings(
    principal: str,
) -> None:
    """Google attests one identity with and without the principal:// scheme."""

    caller = _caller(subject=principal, email=None)

    assert require_agent_principal(caller, admitted=frozenset({_SPIFFE})) == principal


def test_a_matching_email_claim_is_admitted() -> None:
    caller = _caller(subject="opaque-subject", email=_SPIFFE)

    assert require_agent_principal(caller, admitted=frozenset({_SPIFFE})) == _SPIFFE


def test_a_different_verified_workload_is_not_admitted() -> None:
    """A valid token for this audience from another workload is not admission."""

    caller = _caller(
        subject=_SPIFFE.replace("abc123", "other-engine"),
        email="attacker@example.iam.gserviceaccount.com",
    )

    with pytest.raises(ServiceIdentityError, match="not an admitted agent identity"):
        require_agent_principal(caller, admitted=frozenset({_SPIFFE}))


def test_admission_compares_every_admitted_principal() -> None:
    other = _SPIFFE.replace("reasoningEngines/abc123", "reasoningEngines/def456")
    caller = _caller(subject=other, email=None)

    assert require_agent_principal(caller, admitted=frozenset({_SPIFFE, other})) == other
