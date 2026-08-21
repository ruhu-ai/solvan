from __future__ import annotations

import base64

import pytest

from solvan.platform.secret_manager import SecretManagerReader
from solvan.platform.slack import SlackDeliveryError, SlackPost, SlackWebClient


class Response:
    def __init__(self, payload: object, *, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("http failure")

    def json(self) -> object:
        return self._payload


class Session:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, *, timeout: int) -> Response:
        self.calls.append((url, {"timeout": timeout}))
        return self.response

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, object],
        timeout: int,
    ) -> Response:
        self.calls.append((url, {"headers": headers, "json": json, "timeout": timeout}))
        return self.response


def test_secret_manager_reader_decodes_only_a_bounded_exact_resource() -> None:
    session = Session(Response({"payload": {"data": base64.b64encode(b"secret").decode()}}))
    value = SecretManagerReader(session).access(
        "projects/solvan-demo/secrets/slack-signing/versions/1"
    )
    assert value == b"secret"
    assert session.calls[0][0].endswith("/versions/1:access")
    with pytest.raises(ValueError, match="resource name"):
        SecretManagerReader(session).access("projects/other/secrets/no-version")


def test_slack_post_is_plain_accessible_and_idempotent() -> None:
    session = Session(Response({"ok": True, "ts": "1786363201.000001"}))
    result = SlackWebClient(session).post_message(
        bot_token=b"xoxb-safe-test-token",
        post=SlackPost(
            channel="C123ABC",
            thread_ts="1786363200.000001",
            text="Service recovery is verified.",
        ),
        client_message_id="1bf8b8fa-cd5f-4e40-9d18-aebc5b37188f",
    )
    assert result == "1786363201.000001"
    request = session.calls[0][1]
    assert request["json"] == {
        "channel": "C123ABC",
        "thread_ts": "1786363200.000001",
        "text": "Service recovery is verified.",
        "mrkdwn": False,
        "unfurl_links": False,
        "unfurl_media": False,
        "client_msg_id": "1bf8b8fa-cd5f-4e40-9d18-aebc5b37188f",
    }


def test_slack_provider_errors_are_safe_and_classified_for_retry() -> None:
    session = Session(Response({"ok": False, "error": "channel_not_found"}))
    with pytest.raises(SlackDeliveryError) as caught:
        SlackWebClient(session).post_message(
            bot_token=b"xoxb-safe-test-token",
            post=SlackPost(
                channel="C123ABC",
                thread_ts="1786363200.000001",
                text="safe",
            ),
            client_message_id="1bf8b8fa-cd5f-4e40-9d18-aebc5b37188f",
        )
    assert caught.value.code == "CHANNEL_NOT_FOUND"
    assert not caught.value.retryable
