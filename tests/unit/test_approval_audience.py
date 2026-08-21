"""An approval audience must name a client this deployment owns.

The audience check exists to prove a token was minted for Solvan. Solvan
defaulted it to the Google Cloud SDK's own client, so the check was satisfied by
any `gcloud auth print-identity-token` output produced anywhere by anyone — it
proved the token was minted for gcloud, which is not a claim about this
deployment at all.

Governing record: specification 05 §9, and §4.2 for the target end state.
"""

from __future__ import annotations

import pytest

from solvan.application.approval_audience import (
    SHARED_PUBLIC_CLIENT_IDS,
    ApprovalAudienceError,
    accepted_audiences,
)

OWNED = "111111111111-abc123.apps.googleusercontent.com"
SUCCESSOR = "222222222222-def456.apps.googleusercontent.com"


def test_an_owned_client_is_accepted() -> None:
    assert accepted_audiences(OWNED) == (OWNED,)


@pytest.mark.parametrize("client", sorted(SHARED_PUBLIC_CLIENT_IDS))
def test_a_shared_public_client_is_refused(client: str) -> None:
    """The defect this rule exists for, asserted against the real constant."""

    with pytest.raises(ApprovalAudienceError, match="shared public"):
        accepted_audiences(client)


def test_the_cloud_sdk_client_is_among_the_refused() -> None:
    """Named explicitly, because it is the one that shipped as the default."""

    assert "32555940559.apps.googleusercontent.com" in SHARED_PUBLIC_CLIENT_IDS


@pytest.mark.parametrize(
    "value",
    ["", "   ", None, "https://api.example", "not-a-client", "client.apps.googleusercontent.com"],
)
def test_an_absent_or_malformed_audience_refuses(value: str | None) -> None:
    """Absent or unparsable configuration refuses rather than defaulting.

    A service URL is the specific wrong value specification 05 §9 calls out: it
    is what an audience-free verifier would otherwise be handed.
    """

    with pytest.raises(ApprovalAudienceError):
        accepted_audiences(value)


def test_a_rotation_accepts_both_clients_newest_last() -> None:
    """Replacing a client cannot require a moment where every token is invalid."""

    assert accepted_audiences(OWNED, rotating_to=SUCCESSOR) == (OWNED, SUCCESSOR)


def test_a_successor_repeating_the_active_client_is_refused() -> None:
    with pytest.raises(ApprovalAudienceError, match="repeats"):
        accepted_audiences(OWNED, rotating_to=OWNED)


def test_a_successor_is_validated_like_the_active_client() -> None:
    """A rotation is not a way to admit a client the rule would otherwise refuse."""

    with pytest.raises(ApprovalAudienceError, match="shared public"):
        accepted_audiences(OWNED, rotating_to="32555940559.apps.googleusercontent.com")


def test_an_absent_successor_leaves_one_accepted_audience() -> None:
    """Outside a declared rotation the set has one member."""

    assert accepted_audiences(OWNED, rotating_to=None) == (OWNED,)
    assert accepted_audiences(OWNED, rotating_to="  ") == (OWNED,)
