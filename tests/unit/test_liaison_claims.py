"""The truth gate: a model must not be able to say what the ledger denies.

These are the second-review fixtures (specification 14 §22, cases 51-55 and
1-8). Each one is an attempt to get an ungated affirmation out of the surface;
each one must fail deterministically, not probabilistically.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from solvan.application.liaison import (
    Citation,
    ClaimDraft,
    ClaimOutcome,
    Polarity,
    TemplateRegistryError,
    compose_claim,
    load_registry,
    pin_registry,
)
from solvan.application.liaison.predicates import KNOWN_PREDICATES

REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config/liaison-claim-templates.yaml"


class _Ledger:
    """A scripted projection reader: exactly what the ledger holds, no more."""

    def __init__(self, records: dict[tuple[str, str], dict[str, Any]]) -> None:
        self._records = records

    def read(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        return self._records.get((record_type, record_id))


@pytest.fixture(scope="module")
def registry():
    return load_registry(REGISTRY_PATH, known_predicates=KNOWN_PREDICATES)


@pytest.fixture
def mid_window() -> _Ledger:
    """Mitigation reconciled; verification still running. The dangerous moment."""

    return _Ledger(
        {
            ("incident", "INC-1042"): {"id": "INC-1042", "state": "VERIFYING_MITIGATION"},
            ("verification_run", "VER-1042"): {
                "id": "VER-1042",
                "incident": "INC-1042",
                "verdict": "RUNNING",
                "threshold": "error ratio < 2.0% for 5m",
                "synthetic": "no synthetic payment accepted yet",
            },
        }
    )


@pytest.fixture
def verified() -> _Ledger:
    return _Ledger(
        {
            ("incident", "INC-1042"): {"id": "INC-1042", "state": "MITIGATED"},
            ("verification_run", "VER-1042"): {
                "id": "VER-1042",
                "incident": "INC-1042",
                "verdict": "PASSED",
                "threshold": "error ratio < 2.0% for 5m",
                "synthetic": "one fresh synthetic payment committed",
            },
        }
    )


def _recovery_draft(citation_id: str = "VER-1042") -> ClaimDraft:
    return ClaimDraft(
        template_id="RECOVERY_VERIFIED",
        subject_ref="INC-1042",
        # Slot values are supplied but ignored: the sentence is read from the
        # cited record, so a model cannot choose the words.
        values={"subject_label": "INC-1042", "verdict_detail": "everything is fine"},
        citations=(Citation("verification_run", citation_id),),
    )


def test_recovery_is_held_while_the_verification_window_is_open(registry, mid_window) -> None:
    claim = compose_claim(_recovery_draft(), registry=registry, reader=mid_window)
    assert claim.outcome is ClaimOutcome.HELD
    assert claim.polarity is Polarity.HOLDING
    assert "not confirmed yet" in claim.sentence
    # The answer says what would release it, so the reader knows when to ask again.
    assert claim.releasing_record == "verification_run"
    assert "RUNNING" in claim.reason


def test_recovery_is_affirmed_once_verification_passes(registry, verified) -> None:
    claim = compose_claim(_recovery_draft(), registry=registry, reader=verified)
    assert claim.outcome is ClaimOutcome.VERIFIED
    assert claim.polarity is Polarity.AFFIRMATIVE
    assert claim.sentence.startswith("Recovery is independently verified for INC-1042")
    # The detail came from the verification record, not from the draft.
    assert "error ratio < 2.0% for 5m" in claim.sentence
    assert "everything is fine" not in claim.sentence
    assert claim.citations == (Citation("verification_run", "VER-1042"),)


def test_a_valid_but_unrelated_verification_cannot_carry_the_claim(registry) -> None:
    """Case 54: relevance, not mere validity. Another incident proves nothing."""

    ledger = _Ledger(
        {
            ("verification_run", "VER-9999"): {
                "id": "VER-9999",
                "incident": "INC-1039",  # a different incident
                "verdict": "PASSED",
                "threshold": "error ratio < 2.0% for 5m",
            }
        }
    )
    claim = compose_claim(_recovery_draft("VER-9999"), registry=registry, reader=ledger)
    assert claim.outcome is ClaimOutcome.HELD
    assert "not about INC-1042" in claim.reason


def test_mislabelling_a_recovery_claim_cannot_evade_the_gate(registry, mid_window) -> None:
    """Case 52: kind comes from the template, so a harmless id gets that
    template's predicate — and its slots come from the cited record, so the
    words it renders are the ledger's rather than the drafter's."""

    draft = ClaimDraft(
        template_id="STATE_REPORT",
        subject_ref="INC-1042",
        values={"subject_label": "INC-1042", "state": "fully recovered"},
        citations=(Citation("incident", "INC-1042"),),
    )
    claim = compose_claim(draft, registry=registry, reader=mid_window)
    # The claim survives, but says what the incident record actually says. The
    # evasion is neutralised rather than merely refused.
    assert claim.outcome is ClaimOutcome.VERIFIED
    assert "fully recovered" not in claim.sentence
    assert "VERIFYING_MITIGATION" in claim.sentence


def test_polarity_and_kind_are_never_model_authored(registry) -> None:
    """Case 53: the draft carries neither field; only the template does."""

    assert not hasattr(ClaimDraft("X", "Y", {}), "polarity")
    assert not hasattr(ClaimDraft("X", "Y", {}), "kind")
    template = registry.claim("RECOVERY_VERIFIED")
    assert template.polarity is Polarity.AFFIRMATIVE
    assert template.kind == "RECOVERY"


def test_an_unresolvable_citation_suppresses_rather_than_hedges(registry) -> None:
    """Case 6: a claim that cannot be checked is not softened; it is withheld."""

    draft = ClaimDraft(
        template_id="MEASURED_VALUE",
        subject_ref="INC-1042",
        values={
            "metric": "18.4% error ratio",
            "scope_label": "POST /v1/payments",
            "value": "18.4%",
            "detail": "peak",
        },
        citations=(Citation("evidence_item", "evd_nonexistent"),),
    )
    claim = compose_claim(draft, registry=registry, reader=_Ledger({}))
    assert claim.outcome is ClaimOutcome.SUPPRESSED
    assert claim.sentence == ""


def test_a_verbatim_quote_must_match_the_stored_text_byte_for_byte(registry) -> None:
    """Case 55: RECORD_STATEMENT is how answers stay rich without going free."""

    stored = "Revision v2.8.1 retains checked-out database connections."
    # The projection stamps every evidence item with the incident it belongs
    # to, which is what makes the quote's relevance checkable in code.
    ledger = _Ledger({("evidence_item", "evd_A12B"): {"incident": "INC-1042", "statement": stored}})
    good = ClaimDraft(
        template_id="RECORD_STATEMENT",
        subject_ref="INC-1042",
        values={"quoted_text": stored},
        citations=(Citation("evidence_item", "evd_A12B"),),
    )
    assert compose_claim(good, registry=registry, reader=ledger).outcome is ClaimOutcome.VERIFIED

    altered = ClaimDraft(
        template_id="RECORD_STATEMENT",
        subject_ref="INC-1042",
        values={"quoted_text": stored.replace("retains", "released")},
        citations=(Citation("evidence_item", "evd_A12B"),),
    )
    suppressed = compose_claim(altered, registry=registry, reader=ledger)
    assert suppressed.outcome is ClaimOutcome.SUPPRESSED


def test_an_unknown_template_is_a_defect_not_a_claim(registry) -> None:
    draft = ClaimDraft("EVERYTHING_IS_FINE", "INC-1042", {})
    claim = compose_claim(draft, registry=registry, reader=_Ledger({}))
    assert claim.outcome is ClaimOutcome.SUPPRESSED
    assert claim.reason == "unknown claim template"


def test_deployment_claims_need_a_reconciled_receipt(registry) -> None:
    pending = _Ledger(
        {
            ("action", "ACT-1043"): {
                "id": "ACT-1043",
                "name": "Rollback Cloud Run traffic",
                "status": "AWAITING_APPROVAL",
            }
        }
    )
    draft = ClaimDraft(
        template_id="CHANGE_DEPLOYED",
        subject_ref="ACT-1043",
        values={"subject_label": "ACT-1043", "receipt_detail": "applied", "status": "done"},
        citations=(Citation("action", "ACT-1043"),),
    )
    held = compose_claim(draft, registry=registry, reader=pending)
    assert held.outcome is ClaimOutcome.HELD
    assert "no receipt" in held.reason
    assert "has not been applied" in held.sentence

    done = _Ledger(
        {
            ("action", "ACT-1043"): {
                "id": "ACT-1043",
                "name": "Rollback Cloud Run traffic",
                "status": "VERIFIED",
                "receipt": "rcp_98F2 · effect reconciled",
            }
        }
    )
    assert compose_claim(draft, registry=registry, reader=done).outcome is ClaimOutcome.VERIFIED


def test_registry_pinning_refuses_a_drifted_template_file(registry) -> None:
    """§7 governance: a changed registry cannot reach production silently."""

    assert pin_registry(registry, registry.digest) is registry
    with pytest.raises(TemplateRegistryError, match="refusing to serve"):
        pin_registry(registry, "sha256:" + "0" * 64)


def test_every_held_template_names_its_release_and_its_holding_form(registry) -> None:
    for template_id in registry.held_ids():
        template = registry.claim(template_id)
        assert template.releasing_record, f"{template_id} names no releasing record"
        holding = registry.claim(template.holding_template or "")
        assert not holding.held, f"{template_id} holds into another held template"


def test_a_true_predicate_cannot_carry_a_fabricated_sentence(registry) -> None:
    """The review's P0: EVIDENCE_COVERS only proved that *some* evidence
    resolved, so the model could render any prose it liked beside it.

    Slots are now read from the cited record, so the sentence is the ledger's
    words rather than the model's.
    """

    ledger = _Ledger(
        {
            ("evidence_item", "evd_1"): {
                "incident": "INC-1042",
                "source": "Cloud Trace · payments-api",
                "label": "no error propagated past payments-api",
            }
        }
    )
    draft = ClaimDraft(
        template_id="BLAST_RADIUS_CONTAINED",
        subject_ref="INC-1042",
        values={
            "subject_label": "payments-api",
            "evidence_detail": "no customers were affected and no downstream systems saw errors",
        },
        citations=(Citation("evidence_item", "evd_1"),),
    )
    claim = compose_claim(draft, registry=registry, reader=ledger)
    assert claim.outcome is ClaimOutcome.VERIFIED
    # The fabricated reassurance is absent; the record's own words are present.
    assert "no customers were affected" not in claim.sentence
    assert "no error propagated past payments-api" in claim.sentence


def test_containment_cannot_be_released_by_another_incidents_evidence(registry) -> None:
    """Case 54 for containment: the weakest predicate in the registry.

    `EVIDENCE_COVERS` asked only whether the cited evidence resolved, so a
    perfectly real trace about a different incident released "the fault stayed
    inside …" — and, because the sentence's words are read from the first
    evidence citation that resolves, that unrelated record supplied them too.
    The claim now holds, and the holding form says only what is established.
    """

    ledger = _Ledger(
        {
            ("evidence_item", "evd_9"): {
                "incident": "INC-9999",
                "source": "Cloud Trace · checkout",
                "label": "no error propagated past checkout",
            }
        }
    )
    draft = ClaimDraft(
        template_id="BLAST_RADIUS_CONTAINED",
        subject_ref="INC-1042",
        values={"subject_label": "payments-api", "evidence_detail": "nothing else was touched"},
        citations=(Citation("evidence_item", "evd_9"),),
    )
    claim = compose_claim(draft, registry=registry, reader=ledger)
    assert claim.outcome is ClaimOutcome.HELD
    assert claim.sentence == (
        "The blast radius of INC-1042 is not established from stored evidence."
    )
    assert "not about INC-1042" in claim.reason
    assert "checkout" not in claim.sentence


def test_a_claim_standing_partly_on_nothing_is_not_delivered(registry) -> None:
    """One unresolvable citation fails the whole claim, not just that citation."""

    ledger = _Ledger(
        {
            ("verification_run", "VER-1042"): {
                "id": "VER-1042",
                "incident": "INC-1042",
                "verdict": "PASSED",
                "threshold": "error ratio < 2.0% for 5m",
            }
        }
    )
    draft = ClaimDraft(
        template_id="RECOVERY_VERIFIED",
        subject_ref="INC-1042",
        values={"subject_label": "INC-1042", "verdict_detail": "x"},
        citations=(
            Citation("verification_run", "VER-1042"),
            Citation("evidence_item", "evd_missing"),
        ),
    )
    claim = compose_claim(draft, registry=registry, reader=ledger)
    assert claim.outcome is ClaimOutcome.SUPPRESSED
    assert "do not resolve" in claim.reason


def test_a_held_template_may_never_render_model_text(registry) -> None:
    """Enforced at load: an affirmative claim whose words the model wrote is
    the exact failure the registry exists to prevent."""

    for template_id in registry.held_ids():
        template = registry.claim(template_id)
        sources = {slot: template.slot_sources[slot].kind for slot in template.slots}
        assert "MODEL_QUOTED" not in sources.values(), f"{template_id} renders model text"


def test_a_closed_case_is_never_said_to_be_waiting_on_a_person(registry) -> None:
    """§7 template governance: `AWAITING_HUMAN` asserts something about now.

    Its old predicate proved only that the rendered words existed somewhere on
    the incident, which the fixture string "None; the case is closed" satisfied
    perfectly — so a closed case was delivered as a verified statement that it
    was waiting on somebody. The claim is now held by the record's present
    state, and a terminal incident releases nothing.
    """

    ledger = _Ledger(
        {
            ("incident", "INC-1039"): {
                "id": "INC-1039",
                "state": "CLOSED",
                "waiting_on_human": False,
                "next_action": "None; the case is closed",
            }
        }
    )
    draft = ClaimDraft(
        template_id="AWAITING_HUMAN",
        subject_ref="INC-1039",
        values={"subject_label": "INC-1039", "detail": "None; the case is closed"},
        citations=(Citation("incident", "INC-1039"),),
    )
    claim = compose_claim(draft, registry=registry, reader=ledger)
    assert claim.outcome is ClaimOutcome.HELD
    assert claim.polarity is Polarity.HOLDING
    assert claim.sentence == "INC-1039 is not waiting on a person; its committed state is CLOSED."
    assert "CLOSED" in claim.reason


def test_an_open_case_blocked_on_a_person_still_says_so(registry) -> None:
    """The gate withholds; it does not mute. A real block is still delivered."""

    ledger = _Ledger(
        {
            ("incident", "INC-1042"): {
                "id": "INC-1042",
                "state": "AWAITING_APPROVAL",
                "waiting_on_human": True,
                "next_action": "Approve the exact rollback of payments-api",
            }
        }
    )
    draft = ClaimDraft(
        template_id="AWAITING_HUMAN",
        subject_ref="INC-1042",
        values={
            "subject_label": "INC-1042",
            "detail": "Approve the exact rollback of payments-api",
        },
        citations=(Citation("incident", "INC-1042"),),
    )
    claim = compose_claim(draft, registry=registry, reader=ledger)
    assert claim.outcome is ClaimOutcome.VERIFIED
    assert claim.sentence == (
        "INC-1042 is waiting on a person: Approve the exact rollback of payments-api."
    )


def test_an_attention_claim_cannot_borrow_another_incidents_block(registry) -> None:
    """Relevance, not mere validity: a block on one case proves nothing here."""

    ledger = _Ledger(
        {
            ("incident", "INC-2000"): {
                "id": "INC-2000",
                "state": "AWAITING_APPROVAL",
                "waiting_on_human": True,
                "next_action": "Approve something else entirely",
            }
        }
    )
    draft = ClaimDraft(
        template_id="AWAITING_HUMAN",
        subject_ref="INC-1042",
        values={"subject_label": "INC-1042", "detail": "Approve something else entirely"},
        citations=(Citation("incident", "INC-2000"),),
    )
    claim = compose_claim(draft, registry=registry, reader=ledger)
    # The holding form is a statement about the subject too, so it may not
    # borrow the other incident's committed state to fill its slots. With no
    # record about INC-1042 cited, there is nothing to say and nothing is said.
    assert claim.outcome is ClaimOutcome.SUPPRESSED
    assert "not INC-1042" in claim.reason


def test_shipped_registry_matches_the_production_pin() -> None:
    """The pin and the shipped template file must move together.

    Editing config/liaison-claim-templates.yaml changes the operator-facing
    sentence forms. Without this, the drift is only discovered when the API
    refuses to serve at startup.
    """

    from apps.api.liaison_http_support import _PINNED_REGISTRY_DIGEST, liaison_registry

    assert liaison_registry().digest == _PINNED_REGISTRY_DIGEST


def test_an_edited_registry_refuses_to_serve() -> None:
    """A template edit without a matching pin must refuse, not serve."""

    from apps.api.liaison_http_support import _PINNED_REGISTRY_DIGEST

    registry = load_registry(REGISTRY_PATH, known_predicates=KNOWN_PREDICATES)
    drifted = replace(registry, digest="sha256:" + "1" * 64)
    with pytest.raises(TemplateRegistryError):
        pin_registry(drifted, _PINNED_REGISTRY_DIGEST)
