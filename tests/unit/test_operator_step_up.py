"""Transaction-bound operator presence proof rules (specification 05 §4.2)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from solvan.application.operator_step_up import (
    CODE_DIGITS,
    OperatorStepUpError,
    issue_code,
    masked_email,
    matches,
    verifier,
)
from solvan.platform.operator_step_up_email import (
    LoopbackOperatorStepUpSender,
    OperatorStepUpDeliveryError,
)

NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
PEPPER = "test-only-pepper-with-at-least-thirty-two-bytes"
STEP_UP = "stu_01J00000000000000000000000"


def test_code_is_fixed_width_random_and_stored_only_as_a_keyed_verifier() -> None:
    issued = [
        issue_code(now=NOW, step_up_transaction_id=STEP_UP, pepper=PEPPER) for _ in range(200)
    ]
    assert all(len(item.code) == CODE_DIGITS and item.code.isdigit() for item in issued)
    assert len({item.code for item in issued}) > 190
    assert all(item.verifier_hmac.startswith("hmac-sha256:") for item in issued)
    assert all(item.code not in item.verifier_hmac for item in issued)


def test_database_only_cannot_verify_the_numeric_code() -> None:
    issued = issue_code(now=NOW, step_up_transaction_id=STEP_UP, pepper=PEPPER)
    assert matches(
        submitted=issued.code,
        stored_verifier=issued.verifier_hmac,
        step_up_transaction_id=STEP_UP,
        pepper=PEPPER,
    )
    assert not matches(
        submitted=issued.code,
        stored_verifier=issued.verifier_hmac,
        step_up_transaction_id=STEP_UP,
        pepper="another-secret-that-is-at-least-thirty-two-bytes",
    )


def test_a_verifier_cannot_be_rebound_to_another_action() -> None:
    code = "12345678"
    stored = verifier(pepper=PEPPER, step_up_transaction_id=STEP_UP, code=code)
    assert not matches(
        submitted=code,
        stored_verifier=stored,
        step_up_transaction_id="stu_01J00000000000000000000001",
        pepper=PEPPER,
    )


@pytest.mark.parametrize("value", ["1234567", "123456789", "abcdefgh", "1234 678"])
def test_malformed_codes_are_refused(value: str) -> None:
    stored = verifier(pepper=PEPPER, step_up_transaction_id=STEP_UP, code="12345678")
    assert not matches(
        submitted=value,
        stored_verifier=stored,
        step_up_transaction_id=STEP_UP,
        pepper=PEPPER,
    )


def test_weak_pepper_is_refused() -> None:
    with pytest.raises(OperatorStepUpError, match="not strong enough"):
        issue_code(now=NOW, step_up_transaction_id=STEP_UP, pepper="too-short")


def test_email_mask_keeps_destination_context_without_disclosing_the_address() -> None:
    assert masked_email("operator@example.com") == "op******@example.com"
    with pytest.raises(OperatorStepUpError):
        masked_email("not-an-address")


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:9000/operator-step-up-messages",
        "http://example.com/operator-step-up-messages",
        "http://127.0.0.1:9000/another-path",
    ],
)
def test_the_browser_fixture_sender_cannot_leave_loopback(url: str) -> None:
    with pytest.raises(ValueError):
        LoopbackOperatorStepUpSender(relay_url=url, bearer_token=PEPPER)


def test_the_browser_fixture_sender_binds_delivery_and_returns_a_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class Accepted:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"message_id": STEP_UP}

    def post(url: str, **kwargs: object) -> Accepted:
        observed.update(url=url, **kwargs)
        return Accepted()

    monkeypatch.setattr("solvan.platform.operator_step_up_email.httpx.post", post)
    sender = LoopbackOperatorStepUpSender(
        relay_url="http://127.0.0.1:9000/operator-step-up-messages",
        bearer_token=PEPPER,
    )

    receipt = sender.send(
        address="operator@solvan.local",
        code="12345678",
        step_up_id=STEP_UP,
        operation="estate.connect",
    )

    assert receipt == f"test-email-relay:{STEP_UP}"
    assert observed["headers"] == {
        "Authorization": f"Bearer {PEPPER}",
        "Idempotency-Key": STEP_UP,
    }
    assert observed["json"] == {
        "schema_version": 1,
        "to_address": "operator@solvan.local",
        "code": "12345678",
        "step_up_id": STEP_UP,
        "operation": "estate.connect",
    }


def test_the_browser_fixture_sender_requires_a_delivery_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MissingReceipt:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {}

    monkeypatch.setattr(
        "solvan.platform.operator_step_up_email.httpx.post",
        lambda *_args, **_kwargs: MissingReceipt(),
    )
    sender = LoopbackOperatorStepUpSender(
        relay_url="http://localhost:9000/operator-step-up-messages",
        bearer_token=PEPPER,
    )
    with pytest.raises(OperatorStepUpDeliveryError, match="no delivery receipt"):
        sender.send(
            address="operator@solvan.local",
            code="12345678",
            step_up_id=STEP_UP,
            operation="estate.connect",
        )


def test_a_loopback_sink_serves_a_local_host_signed_in_with_google(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connected development: real Google sign-in, no relay, codes on loopback."""

    from apps.api.identity_configuration import operator_step_up_sender

    monkeypatch.delenv("SOLVAN_TEST_ISSUER", raising=False)
    monkeypatch.delenv("SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL", raising=False)
    monkeypatch.setenv(
        "SOLVAN_OPERATOR_STEP_UP_SINK_URL", "http://127.0.0.1:20006/operator-step-up-messages"
    )
    monkeypatch.setenv("SOLVAN_OPERATOR_STEP_UP_SINK_TOKEN", PEPPER)
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "NO_PRODUCTION_AUTHORITY")

    assert isinstance(operator_step_up_sender(), LoopbackOperatorStepUpSender)


def test_no_loopback_sink_where_google_cloud_holds_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sink is a local-development shape; a deployment cannot ask for it."""

    from apps.api.identity_configuration import operator_step_up_sender

    monkeypatch.delenv("SOLVAN_TEST_ISSUER", raising=False)
    monkeypatch.delenv("SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL", raising=False)
    monkeypatch.setenv(
        "SOLVAN_OPERATOR_STEP_UP_SINK_URL", "http://127.0.0.1:20006/operator-step-up-messages"
    )
    monkeypatch.setenv("SOLVAN_OPERATOR_STEP_UP_SINK_TOKEN", PEPPER)
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "GOOGLE_CLOUD_IAM")

    with pytest.raises(RuntimeError, match="loopback step-up sink"):
        operator_step_up_sender()


def test_a_configured_relay_takes_precedence_over_a_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.api.identity_configuration import operator_step_up_sender
    from solvan.platform.operator_step_up_email import GoogleOperatorStepUpSender

    monkeypatch.delenv("SOLVAN_TEST_ISSUER", raising=False)
    monkeypatch.setenv("SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL", "https://relay.example/send")
    monkeypatch.setenv(
        "SOLVAN_OPERATOR_STEP_UP_SINK_URL", "http://127.0.0.1:20006/operator-step-up-messages"
    )
    monkeypatch.setenv("SOLVAN_OPERATOR_STEP_UP_SINK_TOKEN", PEPPER)

    assert isinstance(operator_step_up_sender(), GoogleOperatorStepUpSender)


def test_a_misconfigured_sink_is_a_deployment_fact_not_a_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The route translates RuntimeError into a 503; a ValueError would be a 500."""

    from apps.api.identity_configuration import operator_step_up_sender

    monkeypatch.delenv("SOLVAN_TEST_ISSUER", raising=False)
    monkeypatch.delenv("SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL", raising=False)
    monkeypatch.setenv(
        "SOLVAN_OPERATOR_STEP_UP_SINK_URL", "http://127.0.0.1:20006/operator-step-up-messages"
    )
    monkeypatch.setenv("SOLVAN_OPERATOR_STEP_UP_SINK_TOKEN", "too-short")
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "NO_PRODUCTION_AUTHORITY")

    with pytest.raises(RuntimeError, match="misconfigured"):
        operator_step_up_sender()
