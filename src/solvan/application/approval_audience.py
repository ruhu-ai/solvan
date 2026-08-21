"""Which OAuth client audiences a verified operator assertion may carry.

Specification 05 §9 requires an approval token to be verified against "the
explicit OAuth client audience configured for the release". The audience check
exists to prove a token was minted *for Solvan*; an audience belonging to a
client shared with the world proves only that it was minted for some other
application, and every such token then satisfies the check.

The Google Cloud SDK's own client is exactly that. Solvan defaulted to it, so
the release verified tokens against an audience it does not own and any
`gcloud auth print-identity-token` output, obtained in any context, passed.

This module is the one definition of the rule. It is pure so the release gate
can read the same constant the API enforces, rather than a second copy that
drifts.
"""

from __future__ import annotations

import re

#: Google OAuth client IDs are digits, optionally a hyphenated project part,
#: then the fixed host. Terraform validates `approval_token_audience` with the
#: same shape, so a value Terraform would reject cannot reach a running API.
GOOGLE_OAUTH_CLIENT_ID = re.compile(r"^[0-9]+(?:-[a-z0-9]+)?\.apps\.googleusercontent\.com$")

#: Clients Google publishes for shared tooling. Their IDs are public and every
#: installation mints tokens against them, so they identify a program rather
#: than a deployment and are never an audience.
SHARED_PUBLIC_CLIENT_IDS: frozenset[str] = frozenset(
    {
        # google-cloud-sdk: the audience of `gcloud auth print-identity-token`
        # for a user credential, which cannot be given a custom audience
        # without impersonation.
        "32555940559.apps.googleusercontent.com",
    }
)


class ApprovalAudienceError(RuntimeError):
    """The configured approval audience is absent, malformed, or not ours."""


#: An opaque client identifier for a non-Google issuer. Google's dotted form is
#: a naming convention, not a security property; what matters is that the
#: audience names a client this deployment owns.
OPAQUE_CLIENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


def accepted_audiences(
    active: str | None,
    *,
    rotating_to: str | None = None,
    google_issuer: bool = True,
) -> tuple[str, ...]:
    """The audiences an assertion may carry, newest client last.

    A client is replaced by naming its successor while both are accepted, so a
    rotation does not require a moment where every operator's token is invalid.
    The set is bounded at two: an unbounded list of accepted audiences would
    re-admit, one entry at a time, exactly what this rule exists to refuse.
    """

    accepted = tuple(
        _validated(value, field=field, google_issuer=google_issuer)
        for value, field in ((active, "SOLVAN_APPROVAL_AUDIENCE"), (rotating_to, "successor"))
        if value is not None and value.strip()
    )
    if not accepted:
        raise ApprovalAudienceError(
            "no approval token audience is configured; set SOLVAN_APPROVAL_AUDIENCE to the "
            "OAuth client ID this environment owns"
        )
    if len(set(accepted)) != len(accepted):
        raise ApprovalAudienceError("the successor audience repeats the active one")
    return accepted


def _validated(value: str, *, field: str, google_issuer: bool = True) -> str:
    candidate = value.strip()
    pattern = GOOGLE_OAUTH_CLIENT_ID if google_issuer else OPAQUE_CLIENT_ID
    if pattern.fullmatch(candidate) is None:
        raise ApprovalAudienceError(
            f"{field} is not a usable OAuth client ID; a service URL or free-form string "
            "cannot bind a token to this deployment"
        )
    if not google_issuer and "/" in candidate:
        raise ApprovalAudienceError(f"{field} looks like a URL rather than a client ID")
    if candidate in SHARED_PUBLIC_CLIENT_IDS:
        raise ApprovalAudienceError(
            f"{field} names a shared public Google client. Every installation mints tokens "
            "against it, so it proves nothing about this deployment. Create an OAuth client "
            "in this environment's project and configure its ID"
        )
    return candidate
