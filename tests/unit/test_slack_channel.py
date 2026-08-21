from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.slack_channel import (
    SlackIngressError,
    SlackUrlVerification,
    peek_slack_team_id,
    slack_channel_identity,
    slack_conversation_id,
    verify_slack_event,
    verify_slack_request,
)

SECRET = b"slack-signing-secret"
NOW = datetime(2026, 8, 10, 12, tzinfo=UTC)


def _body(**event_changes: object) -> bytes:
    event = {
        "type": "message",
        "user": "U123ABC",
        "channel": "C123ABC",
        "ts": "1786363200.000001",
        "text": "What changed on the payments incident?",
        **event_changes,
    }
    return json.dumps(
        {
            "type": "event_callback",
            "team_id": "T123ABC",
            "event_id": "Ev123ABC",
            "event_time": 1786363200,
            "event": event,
        },
        separators=(",", ":"),
    ).encode()


def _signature(body: bytes, timestamp: str = "1786363200") -> str:
    base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(SECRET, base, hashlib.sha256).hexdigest()


def test_slack_event_requires_fresh_signature_and_normalizes_no_identity() -> None:
    body = _body()
    event = verify_slack_event(
        signing_secret=SECRET,
        timestamp="1786363200",
        signature=_signature(body),
        body=body,
        now=NOW,
    )
    assert event.event.text.startswith("What changed")
    assert slack_channel_identity(team_id=event.team_id, user_id=event.event.user) == (
        "slack:T123ABC:U123ABC"
    )
    assert slack_conversation_id(event.event) == "slack:C123ABC:1786363200.000001"
    assert peek_slack_team_id(body) == "T123ABC"


def test_slack_thread_reply_uses_root_timestamp() -> None:
    body = _body(thread_ts="1786363100.000009")
    event = verify_slack_event(
        signing_secret=SECRET,
        timestamp="1786363200",
        signature=_signature(body),
        body=body,
        now=NOW,
    )
    assert slack_conversation_id(event.event) == "slack:C123ABC:1786363100.000009"


def test_slack_url_verification_is_signed_before_challenge_is_returned() -> None:
    body = json.dumps(
        {"type": "url_verification", "team_id": "T123ABC", "challenge": "challenge-value"},
        separators=(",", ":"),
    ).encode()
    result = verify_slack_request(
        signing_secret=SECRET,
        timestamp="1786363200",
        signature=_signature(body),
        body=body,
        now=NOW,
    )
    assert isinstance(result, SlackUrlVerification)
    assert result.challenge == "challenge-value"


@pytest.mark.parametrize(
    ("timestamp", "signature", "body", "now", "reason"),
    [
        ("1786363200", "v0=" + "0" * 64, _body(), NOW, "verification failed"),
        ("1786363200", None, _body(), NOW, "material is missing"),
        (
            "1786363200",
            _signature(_body()),
            _body(),
            NOW + timedelta(minutes=6),
            "replay window",
        ),
        ("not-a-time", "v0=" + "0" * 64, _body(), NOW, "malformed"),
    ],
)
def test_slack_event_refuses_forgery_and_replay(
    timestamp: str, signature: str | None, body: bytes, now: datetime, reason: str
) -> None:
    with pytest.raises(SlackIngressError, match=reason):
        verify_slack_event(
            signing_secret=SECRET,
            timestamp=timestamp,
            signature=signature,
            body=body,
            now=now,
        )


def test_slack_event_refuses_bot_messages_before_ledger_use() -> None:
    body = _body(bot_id="B123ABC")
    with pytest.raises(SlackIngressError, match="bot"):
        verify_slack_event(
            signing_secret=SECRET,
            timestamp="1786363200",
            signature=_signature(body),
            body=body,
            now=NOW,
        )
