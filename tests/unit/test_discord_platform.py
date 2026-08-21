from __future__ import annotations

import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from solvan.platform.discord import (
    DiscordDeliveryError,
    DiscordError,
    DiscordPost,
    DiscordWebClient,
    verify_interaction,
)


class _Response:
    def __init__(self, status_code: int, value: object) -> None:
        self.status_code = status_code
        self._value = value

    def json(self) -> object:
        return self._value


class _Client:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append({"url": url, **kwargs})
        return self.response


def _signed(value: object) -> tuple[str, str, bytes, str]:
    private = Ed25519PrivateKey.generate()
    body = json.dumps(value).encode()
    timestamp = "1710000000"
    signature = private.sign(timestamp.encode() + body).hex()
    public = private.public_key().public_bytes_raw().hex()
    return public, signature, body, timestamp


def test_discord_interaction_signature_is_verified() -> None:
    public, signature, body, timestamp = _signed({"type": 1})
    assert verify_interaction(
        public_key_hex=public,
        signature_hex=signature,
        timestamp=timestamp,
        body=body,
    ) == {"type": 1}


@pytest.mark.parametrize(
    ("public_key", "signature", "timestamp", "body"),
    [
        ("00", None, "1", b"{}"),
        ("00", "00", None, b"{}"),
        ("00", "00", "1", b"not-json"),
        ("00", "00", "1", b"x" * (64 * 1024 + 1)),
    ],
)
def test_discord_interaction_refuses_invalid_proof(
    public_key: str, signature: str | None, timestamp: str | None, body: bytes
) -> None:
    with pytest.raises(DiscordError):
        verify_interaction(
            public_key_hex=public_key,
            signature_hex=signature,
            timestamp=timestamp,
            body=body,
        )


def test_discord_interaction_requires_an_object() -> None:
    public, signature, body, timestamp = _signed(["not", "an", "object"])
    with pytest.raises(DiscordError, match="object"):
        verify_interaction(
            public_key_hex=public,
            signature_hex=signature,
            timestamp=timestamp,
            body=body,
        )


@pytest.mark.parametrize("channel,content", [("not-a-snowflake", "ok"), ("123", "")])
def test_discord_post_is_bounded(channel: str, content: str) -> None:
    with pytest.raises(DiscordError, match="invalid"):
        DiscordPost(channel, content)


def test_discord_delivery_disables_mentions_and_returns_receipt() -> None:
    client = _Client(_Response(200, {"id": "998877"}))
    result = DiscordWebClient(client).post_message(  # type: ignore[arg-type]
        bot_token=b"secret", post=DiscordPost("123456", "incident update")
    )
    assert result == "998877"
    assert client.calls[0]["json"]["allowed_mentions"] == {"parse": []}
    assert client.calls[0]["headers"] == {"Authorization": "Bot secret"}


@pytest.mark.parametrize(("status_code", "retryable"), [(429, True), (503, True), (401, False)])
def test_discord_delivery_classifies_provider_failure(status_code: int, retryable: bool) -> None:
    client = _Client(_Response(status_code, {}))
    with pytest.raises(DiscordDeliveryError) as caught:
        DiscordWebClient(client).post_message(  # type: ignore[arg-type]
            bot_token=b"secret", post=DiscordPost("123456", "update")
        )
    assert caught.value.retryable is retryable


def test_discord_delivery_requires_provider_receipt() -> None:
    client = _Client(_Response(200, {}))
    with pytest.raises(DiscordError, match="no message id"):
        DiscordWebClient(client).post_message(  # type: ignore[arg-type]
            bot_token=b"secret", post=DiscordPost("123456", "update")
        )
