"""Who may read which part, and on whose behalf the Liaison may read at all.

Two classes of leak are covered. The first is the *uncited* one -- a wider
reader quoting a restricted fact into a shared thread -- which an envelope
keyed only to citations would let through vacuously. The second is the
confused deputy: the service identity reading on its own account.

Specification 14 §5, §10.2, and fixtures 9-15, 65-66.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.liaison import (
    AccessMode,
    AccessReference,
    Audience,
    GrantError,
    GrantIssuer,
    Part,
    PartKind,
    reader_may_see,
    verify_read_request,
)
from solvan.application.liaison.parts import user_part, withheld_part
from solvan.domain import Scope

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


def _claim_part(records: tuple[tuple[str, str], ...]) -> Part:
    return Part(
        kind=PartKind.CLAIM,
        sequence=0,
        payload={"sentence": "a claim"},
        classification="INTERNAL",
        access_mode=AccessMode.RECORD_SET,
        access_set=tuple(
            AccessReference(record_type, record_id, "CITES") for record_type, record_id in records
        ),
    )


def test_a_reader_sees_a_claim_only_when_it_covers_every_citation() -> None:
    part = _claim_part((("incident", "INC-1042"), ("evidence_item", "evd_A12B")))
    assert reader_may_see(
        part,
        reader_principal="wide@example.com",
        authorized_records=[("incident", "INC-1042"), ("evidence_item", "evd_A12B")],
        participants=[],
    )
    # Covering one of two citations is not covering the claim.
    assert not reader_may_see(
        part,
        reader_principal="narrow@example.com",
        authorized_records=[("incident", "INC-1042")],
        participants=[],
    )


def test_an_empty_record_set_denies_rather_than_defaulting_to_visible() -> None:
    """Fixture 65: the vacuous pass that the first design shipped."""

    part = _claim_part(())
    assert not reader_may_see(
        part,
        reader_principal="anyone@example.com",
        authorized_records=[("incident", "INC-1042")],
        participants=["anyone@example.com"],
    )


def test_uncited_user_text_is_participant_scoped_not_thread_wide() -> None:
    """Fixture 15: quoting something restricted does not publish it."""

    part = user_part(
        "the customer's card ends 4411",
        sequence=1,
        author_principal="wide@example.com",
        membership_epoch=1,
        classification="CONFIDENTIAL",
    )
    assert part.access_mode is AccessMode.PARTICIPANTS_AT_EPOCH
    assert reader_may_see(
        part,
        reader_principal="wide@example.com",
        authorized_records=[],
        participants=["wide@example.com"],
    )
    assert not reader_may_see(
        part,
        reader_principal="scope-reader@example.com",
        authorized_records=[("incident", "INC-1042")],
        participants=["wide@example.com"],
    )


def test_a_withheld_part_says_so_rather_than_vanishing() -> None:
    part = withheld_part(
        sequence=2, verdict_ref="reader-authority", reason="outside your authority"
    )
    assert part.kind is PartKind.CONTENT_WITHHELD
    assert reader_may_see(
        part, reader_principal="anyone@example.com", authorized_records=[], participants=[]
    )


def _grant(issuer: GrantIssuer, **overrides: object):
    defaults: dict[str, object] = {
        "principal": "operator@example.com",
        "scope": SCOPE,
        "thread_id": "thr_1",
        "message_id": "lms_1",
        "attempt": 1,
        "anchor_label": "incident:INC-1042",
        "classification_ceiling": "INTERNAL",
        "policy_epoch": 1,
    }
    defaults.update(overrides)
    return issuer.read_grant(**defaults)  # type: ignore[arg-type]


def test_a_read_grant_is_reusable_within_a_turn_but_digest_bound_per_request() -> None:
    """A turn makes many reads, so one nonce would be the wrong shape (§10.2)."""

    issuer = GrantIssuer()
    grant = _grant(issuer)
    first = grant.request_digest("read_projection", {"record": "INC-1042"})
    second = grant.request_digest("read_projection", {"record": "INC-1039"})
    assert first != second

    verify_read_request(
        grant,
        method="read_projection",
        arguments={"record": "INC-1042"},
        presented_digest=first,
    )
    # A digest minted for one read cannot carry another.
    with pytest.raises(GrantError, match="does not match its grant"):
        verify_read_request(
            grant,
            method="read_projection",
            arguments={"record": "INC-1039"},
            presented_digest=first,
        )


def test_a_read_grant_cannot_authorize_a_method_it_never_named() -> None:
    issuer = GrantIssuer()
    grant = _grant(issuer, methods=frozenset({"read_projection"}))
    with pytest.raises(GrantError, match="does not authorize"):
        grant.authorize("search_records")


def test_an_expired_read_grant_is_refused() -> None:
    issuer = GrantIssuer()
    grant = _grant(issuer)
    with pytest.raises(GrantError, match="expired"):
        grant.authorize("read_projection", now=grant.expires_at + timedelta(seconds=1))


def test_a_steer_grant_is_one_time_and_coordinator_addressed() -> None:
    """Fixture 66: a projection grant is not proof of steer authority."""

    issuer = GrantIssuer()
    steer = issuer.steer_grant(
        parked_request_id="prk_1",
        decided_payload_hash="sha256:" + "a" * 64,
        initiating_principal="operator@example.com",
        confirming_principal="approver@example.com",
        scope=SCOPE,
        expected_workflow_version=12,
        expected_plan_version=2,
        nonce="n-1",
    )
    assert steer.audience is Audience.COORDINATOR_INBOX
    envelope = issuer.consume_steer_grant(steer)
    # The coordinator receives the decision, both principals, and the versions
    # it will revalidate for itself.
    assert envelope["decided_payload_hash"] == "sha256:" + "a" * 64
    assert envelope["confirming_principal"] == "approver@example.com"
    assert envelope["expected_workflow_version"] == 12

    with pytest.raises(GrantError, match="already been used"):
        issuer.consume_steer_grant(steer)


def test_an_expired_steer_grant_cannot_be_spent() -> None:
    issuer = GrantIssuer()
    steer = issuer.steer_grant(
        parked_request_id="prk_2",
        decided_payload_hash="sha256:" + "b" * 64,
        initiating_principal="operator@example.com",
        confirming_principal="approver@example.com",
        scope=SCOPE,
        expected_workflow_version=None,
        expected_plan_version=None,
        nonce="n-2",
        now=datetime.now(UTC) - timedelta(hours=1),
    )
    with pytest.raises(GrantError, match="expired"):
        issuer.consume_steer_grant(steer)
