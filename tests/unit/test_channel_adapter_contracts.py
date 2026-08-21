import httpx
import pytest
from pydantic import ValidationError

from apps.api.liaison_channel_routes import EnrollmentRequest
from apps.email_liaison import main as email_liaison
from apps.mcp_facade.main import TOOL_LIST_HASH, TOOLS, AskArguments
from solvan.platform.email_enrollment import GoogleEmailEnrollmentSender


@pytest.mark.parametrize(
    ("kind", "email_address"),
    [
        ("SLACK", None),
        ("EMAIL", "Operator@Example.com"),
        ("DISCORD", None),
    ],
)
def test_enrollment_accepts_only_user_supplied_email_identity(
    kind: str, email_address: str | None
) -> None:
    request = EnrollmentRequest(
        schema_version=1,
        channel_kind=kind,  # type: ignore[arg-type]
        email_address=email_address,
    )
    assert request.email_address == (email_address.casefold() if email_address else None)


def test_enrollment_refuses_browser_asserted_slack_or_discord_identity() -> None:
    with pytest.raises(ValidationError, match="signed provider event"):
        EnrollmentRequest(
            schema_version=1,
            channel_kind="SLACK",
            email_address="operator@example.com",
        )


def test_enrollment_requires_valid_email_address() -> None:
    with pytest.raises(ValidationError, match="valid email"):
        EnrollmentRequest(schema_version=1, channel_kind="EMAIL", email_address="not-email")


def test_mcp_facade_publishes_exact_closed_tool_set() -> None:
    assert [item["name"] for item in TOOLS] == ["ask", "catch_up", "resolve_ref"]
    assert (
        TOOL_LIST_HASH == "sha256:c6f253424a22c456cd56f1c87d13773e0e29ce3b82ca29b26ac80c8e61d4bfb0"
    )


def test_mcp_runtime_refuses_undeclared_tool_arguments() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        AskArguments.model_validate(
            {
                "record_type": "incident",
                "record_id": "INC-1042",
                "question": "What changed?",
                "approval": True,
            }
        )


def test_email_delivery_uses_relay_audience_identity_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_EMAIL_RELAY_URL", "https://relay.example.test/v1/send")
    observed: dict[str, object] = {}

    def token(_request: object, audience: str) -> str:
        observed["audience"] = audience
        return "signed-id-token"

    def post(url: str, **kwargs: object) -> httpx.Response:
        observed["url"] = url
        observed.update(kwargs)
        return httpx.Response(200, json={"message_id": "msg-1"})

    monkeypatch.setattr(email_liaison.id_token, "fetch_id_token", token)
    monkeypatch.setattr(email_liaison.httpx, "post", post)

    response = email_liaison._post_to_relay(
        payload={"schema_version": 1}, idempotency_key="delivery-1"
    )

    assert response.status_code == 200
    assert observed["audience"] == "https://relay.example.test/v1/send"
    assert observed["url"] == "https://relay.example.test/v1/send"
    assert observed["headers"] == {
        "Authorization": "Bearer signed-id-token",
        "Idempotency-Key": "delivery-1",
    }


def test_email_enrollment_sender_uses_oidc_and_never_places_proof_in_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def token(_request: object, audience: str) -> str:
        observed["audience"] = audience
        return "signed-id-token"

    def post(url: str, **kwargs: object) -> httpx.Response:
        observed["url"] = url
        observed.update(kwargs)
        return httpx.Response(
            200,
            json={"message_id": "msg-enrollment"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr("solvan.platform.email_enrollment.id_token.fetch_id_token", token)
    monkeypatch.setattr("solvan.platform.email_enrollment.httpx.post", post)
    sender = GoogleEmailEnrollmentSender(
        relay_url="https://relay.example.test/v1/send",
        console_base_url="https://solvan.example.test",
    )

    receipt = sender.send(
        address="operator@example.com",
        code="one-time-proof",
        challenge_id="enr_01KZMEK6J01N4NZRBJM6TA38RS",
    )

    assert receipt == "email-relay:msg-enrollment"
    assert observed["url"] == "https://relay.example.test/v1/send"
    assert "one-time-proof" not in str(observed["url"])
    assert observed["headers"] == {
        "Authorization": "Bearer signed-id-token",
        "Idempotency-Key": "enr_01KZMEK6J01N4NZRBJM6TA38RS",
    }
