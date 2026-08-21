"""Classification runs before persistence, or it is not a control.

Specification 14 §11.1. The property under test is not "secrets are detected"
— no shape-based detector can promise that. It is that a detected secret never
becomes durable, never reaches the model, and never leaves through a channel,
and that the refusal says so without repeating what it refused.
"""

from __future__ import annotations

import pytest

from solvan.application.liaison.redaction import Classification, classify

ORDINARY = [
    "Why did the payment error ratio spike at 14:02?",
    "Show me the rollback receipt for ACT-1043.",
    "Was INC-1042 verified? The request id was 4111111111111 in the trace.",
]

CREDENTIALS = [
    "the key is AKIAIOSFODNN7EXAMPLE",
    "use AIzaSyD-1234567890abcdefghijklmnopqrstu to reach the API",
    "token ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "our bot uses xoxb-1234567890-abcdefghijkl",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
    'the file starts {"type": "service_account", "project_id": "x"}',
    "password = hunter2hunter2",
    "the card is 4111 1111 1111 1111",
]


@pytest.mark.parametrize("text", ORDINARY)
def test_an_ordinary_question_is_confidential_and_passes_through(text: str) -> None:
    verdict = classify(text)
    assert verdict.classification is Classification.CONFIDENTIAL
    assert not verdict.withheld
    assert verdict.text == text, "nothing is rewritten when nothing is found"
    assert verdict.findings == ()


@pytest.mark.parametrize("text", CREDENTIALS)
def test_a_credential_is_withheld_whole_rather_than_masked(text: str) -> None:
    verdict = classify(text)
    assert verdict.classification is Classification.RESTRICTED
    assert verdict.withheld
    assert verdict.findings, "a restricted verdict names why"
    # The words themselves are gone — not starred out, not truncated, gone.
    assert verdict.text == ""
    assert text not in verdict.placeholder()


def test_the_placeholder_never_restates_what_it_refused() -> None:
    verdict = classify("password = hunter2hunter2 and AKIAIOSFODNN7EXAMPLE")
    assert "hunter2" not in verdict.placeholder()
    assert "AKIA" not in verdict.placeholder()
    assert "AKIA" not in " ".join(verdict.findings)
    # A digest survives so a purge leaves something checkable.
    assert verdict.digest.startswith("sha256:")


def test_the_digest_is_of_the_original_so_a_replay_is_recognisable() -> None:
    assert (
        classify("password = hunter2hunter2").digest == classify("password = hunter2hunter2").digest
    )
    assert classify("a").digest != classify("b").digest


def test_a_long_digit_run_that_is_not_a_card_is_not_withheld() -> None:
    """Trace ids and request ids look exactly like cards to a regex."""

    assert classify("trace 1234567890123456").classification is Classification.CONFIDENTIAL
