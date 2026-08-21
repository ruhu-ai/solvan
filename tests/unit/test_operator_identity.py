"""Resolving a verified assertion to an actor, and refusing what it cannot.

Governing record: specification 05 §4.2 (actor identity, sign-in).
"""

from __future__ import annotations

import pytest

from solvan.application.operator_identity import (
    OperatorIdentityError,
    ResolvedAssertion,
    VerifiedAssertion,
    admitted_domain,
    canonical_email,
    canonical_issuer,
)


def _assertion(**overrides: object) -> VerifiedAssertion:
    base: dict[str, object] = {
        "provider": "GOOGLE",
        "issuer": "https://accounts.google.com",
        "subject": "108000000000000000001",
        "email": "Operator@Example.com",
        "email_verified": True,
        "hosted_domain": "example.com",
        "authenticated_at_epoch": 1_760_000_000,
    }
    base.update(overrides)
    return VerifiedAssertion(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "issuer",
    [
        "accounts.google.com",
        "https://accounts.google.com",
        "HTTPS://Accounts.Google.com/",
        "  accounts.google.com/  ",
    ],
)
def test_equivalent_issuer_spellings_resolve_to_one_issuer(issuer: str) -> None:
    """Two spellings would key two external identities for one person.

    They would then hold two sets of roles, and revoking one would leave the
    other intact.
    """

    assert canonical_issuer(issuer) == "accounts.google.com"


def test_an_assertion_without_an_issuer_is_refused() -> None:
    with pytest.raises(OperatorIdentityError, match="no issuer"):
        canonical_issuer("   ")


def test_an_email_differing_only_in_case_is_one_address() -> None:
    assert canonical_email("Operator@Example.com") == "operator@example.com"


@pytest.mark.parametrize("value", ["", "operator", "operator@", "@example.com", "a b@c.com"])
def test_something_that_is_not_an_address_is_refused(value: str) -> None:
    with pytest.raises(OperatorIdentityError):
        canonical_email(value)


def test_a_resolved_assertion_keys_on_issuer_and_subject_not_email() -> None:
    resolved = _assertion().resolved()
    assert resolved.external_key == ("GOOGLE", "accounts.google.com", "108000000000000000001")
    assert resolved.email == "operator@example.com"


def test_an_unverified_email_cannot_identify_an_operator() -> None:
    with pytest.raises(OperatorIdentityError, match="unverified"):
        _assertion(email_verified=False).resolved()


def test_an_assertion_without_a_subject_is_refused() -> None:
    with pytest.raises(OperatorIdentityError, match="no subject"):
        _assertion(subject="   ").resolved()


def test_only_an_admitted_provider_resolves() -> None:
    with pytest.raises(OperatorIdentityError, match="not an admitted identity provider"):
        _assertion(provider="OKTA").resolved()


def test_an_admitted_domain_makes_an_identity_eligible() -> None:
    resolved = _assertion().resolved()
    assert admitted_domain(resolved, admitted=frozenset({"example.com"})) == "example.com"


def test_a_personal_account_is_refused_rather_than_matched_by_its_address() -> None:
    """`hd` is a claim the provider asserts; an address ending is not.

    Without this, anyone whose address happens to end in an admitted domain is
    eligible, including at a provider that never verified the domain.
    """

    resolved = _assertion(hosted_domain=None).resolved()
    with pytest.raises(OperatorIdentityError, match="personal account"):
        admitted_domain(resolved, admitted=frozenset({"example.com"}))


def test_an_unadmitted_domain_is_refused() -> None:
    resolved = _assertion(hosted_domain="elsewhere.com", email="op@elsewhere.com").resolved()
    with pytest.raises(OperatorIdentityError, match="not an admitted domain"):
        admitted_domain(resolved, admitted=frozenset({"example.com"}))


def test_a_hosted_domain_disagreeing_with_the_email_is_refused() -> None:
    """A mismatch is either a misconfiguration or an attempt to borrow a domain."""

    resolved = _assertion(email="operator@other.com").resolved()
    with pytest.raises(OperatorIdentityError, match="disagree"):
        admitted_domain(resolved, admitted=frozenset({"example.com"}))


def test_no_admitted_domain_admits_nobody() -> None:
    """An organization with no domain policy refuses rather than admitting all."""

    with pytest.raises(OperatorIdentityError, match="no domain is admitted"):
        admitted_domain(_assertion().resolved(), admitted=frozenset())


def test_eligibility_is_not_admission() -> None:
    """The rule returns a domain, never a decision to admit.

    Membership is a separate record, so one onboarded colleague cannot admit
    their whole company by sharing a domain with them.
    """

    resolved: ResolvedAssertion = _assertion().resolved()
    assert isinstance(admitted_domain(resolved, admitted=frozenset({"example.com"})), str)
