"""Minimal deterministic Slack Web API client for receipt-bearing delivery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class HttpResponse(Protocol):
    status_code: int

    def json(self) -> object: ...


class HttpClient(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, object],
        timeout: int,
    ) -> HttpResponse: ...


class SlackDeliveryError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(f"Slack delivery failed: {code}")
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class SlackPost:
    channel: str
    thread_ts: str
    text: str

    def __post_init__(self) -> None:
        if not self.channel or self.channel[0] not in "CDG" or len(self.channel) > 32:
            raise ValueError("Slack channel is invalid")
        seconds, dot, micros = self.thread_ts.partition(".")
        if not dot or not seconds.isdigit() or not micros.isdigit() or len(micros) != 6:
            raise ValueError("Slack thread timestamp is invalid")
        if not self.text or len(self.text) > 4_000:
            raise ValueError("Slack delivery text is empty or exceeds 4,000 characters")


class SlackWebClient:
    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def post_message(self, *, bot_token: bytes, post: SlackPost, client_message_id: str) -> str:
        if not bot_token.startswith(b"xoxb-") or len(bot_token) > 4_096:
            raise SlackDeliveryError("INVALID_TOKEN_SHAPE", retryable=False)
        if not client_message_id or len(client_message_id) > 64:
            raise ValueError("Slack client message id is invalid")
        response = self._client.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {bot_token.decode('ascii')}",
                "Content-Type": "application/json; charset=utf-8",
            },
            json={
                "channel": post.channel,
                "thread_ts": post.thread_ts,
                "text": post.text,
                "mrkdwn": False,
                "unfurl_links": False,
                "unfurl_media": False,
                "client_msg_id": client_message_id,
            },
            timeout=10,
        )
        body = response.json()
        if not isinstance(body, dict):
            raise SlackDeliveryError("INVALID_RESPONSE", retryable=True)
        if response.status_code == 429:
            raise SlackDeliveryError("RATE_LIMITED", retryable=True)
        if not body.get("ok"):
            code = str(body.get("error", "UNKNOWN"))[:80].upper()
            non_retryable = {
                "INVALID_AUTH",
                "ACCOUNT_INACTIVE",
                "CHANNEL_NOT_FOUND",
                "IS_ARCHIVED",
                "MISSING_SCOPE",
                "NOT_IN_CHANNEL",
            }
            raise SlackDeliveryError(code, retryable=code not in non_retryable)
        message_id = body.get("ts")
        if not isinstance(message_id, str) or not message_id:
            raise SlackDeliveryError("MISSING_MESSAGE_ID", retryable=True)
        return message_id
