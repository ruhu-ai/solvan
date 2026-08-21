"""Turning a verified provider assertion into an actor this deployment knows.

Specification 05 §4.2. An assertion says who a person is to their identity
provider. It does not say who they are here, and it never says what they may do.
This module holds the rules that answer the first question; role bindings answer
the second, and an action challenge answers the third.

Nothing here trusts an email. An email changes, and a reassigned address must
not inherit the authority of whoever held it before.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class OperatorIdentityError(RuntimeError):
    """An assertion cannot be resolved to an actor of this deployment."""


#: Google's issuer, canonically. Assertions may carry it with or without the
#: scheme, and both forms name the same issuer.
GOOGLE_ISSUER = "accounts.google.com"
_ISSUER_SCHEME = re.compile(r"^https?://", re.IGNORECASE)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def canonical_issuer(issuer: str) -> str:
    """One spelling per issuer.

    Google issues `accounts.google.com` and `https://accounts.google.com` for
    the same issuer. Stored as they arrive, the two would key two external
    identities for one person, who would then hold two sets of roles and be
    revoked from only one of them.
    """

    candidate = _ISSUER_SCHEME.sub("", issuer.strip().lower()).rstrip("/")
    if not candidate:
        raise OperatorIdentityError("an assertion carries no issuer")
    return candidate


def canonical_email(email: str) -> str:
    """Lowercased, and rejected if it is not an address.

    Local-part case is significant to some providers but is not a distinction
    Solvan honours: two rows differing only in case would be two actors.
    """

    candidate = email.strip().lower()
    if _EMAIL.fullmatch(candidate) is None:
        raise OperatorIdentityError("an assertion carries no usable email address")
    return candidate


def domain_of(email: str) -> str:
    return canonical_email(email).rsplit("@", 1)[1]


@dataclass(frozen=True, slots=True)
class VerifiedAssertion:
    """What an OAuth callback proved, reduced to what identity resolution needs.

    Constructed only after signature, audience, nonce, and expiry have been
    checked. Holding one is not authority; it is the input to deciding whether
    this deployment knows the person at all.
    """

    provider: str
    issuer: str
    subject: str
    email: str
    email_verified: bool
    hosted_domain: str | None
    authenticated_at_epoch: int

    def resolved(self) -> ResolvedAssertion:
        if self.provider != "GOOGLE":
            raise OperatorIdentityError(f"{self.provider} is not an admitted identity provider")
        if not self.subject.strip():
            raise OperatorIdentityError("an assertion carries no subject")
        if not self.email_verified:
            raise OperatorIdentityError("an unverified email cannot identify an operator")
        return ResolvedAssertion(
            provider=self.provider,
            canonical_issuer=canonical_issuer(self.issuer),
            subject=self.subject.strip(),
            email=canonical_email(self.email),
            hosted_domain=(self.hosted_domain or "").strip().lower() or None,
            authenticated_at_epoch=self.authenticated_at_epoch,
        )


@dataclass(frozen=True, slots=True)
class ResolvedAssertion:
    """A canonical external identity, ready to key an actor."""

    provider: str
    canonical_issuer: str
    subject: str
    email: str
    hosted_domain: str | None
    authenticated_at_epoch: int

    @property
    def external_key(self) -> tuple[str, str, str]:
        return (self.provider, self.canonical_issuer, self.subject)


def admitted_domain(assertion: ResolvedAssertion, *, admitted: frozenset[str]) -> str:
    """The organization domain this assertion is eligible under.

    Eligibility is not admission. A domain match means an identity *may* be
    invited; an explicit membership or invitation is what lets it in. Without
    that distinction one onboarded colleague admits their whole company.

    The hosted domain is preferred over the email's, because a Workspace account
    carries `hd` as a claim the provider asserts, while an address can be
    anything the local part happens to end in. A personal account carries no
    `hd` at all and is refused here rather than matched by its address.
    """

    if not admitted:
        raise OperatorIdentityError("no domain is admitted for this organization")
    if assertion.hosted_domain is None:
        raise OperatorIdentityError(
            "the assertion carries no hosted domain, so it is a personal account "
            "rather than an organization identity"
        )
    if assertion.hosted_domain not in admitted:
        raise OperatorIdentityError(
            f"{assertion.hosted_domain} is not an admitted domain for this organization"
        )
    if domain_of(assertion.email) != assertion.hosted_domain:
        raise OperatorIdentityError("the asserted hosted domain and the email domain disagree")
    return assertion.hosted_domain
