"""Bounded Discord interaction verification and deterministic delivery client."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class DiscordError(RuntimeError):
    pass


class DiscordDeliveryError(DiscordError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


def verify_interaction(
    *, public_key_hex: str, signature_hex: str | None, timestamp: str | None, body: bytes
) -> dict[str, Any]:
    if len(body) > 64 * 1024 or signature_hex is None or timestamp is None:
        raise DiscordError("Discord interaction proof is incomplete")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(signature_hex), timestamp.encode("ascii") + body)
        value = json.loads(body)
    except (ValueError, UnicodeError, InvalidSignature, json.JSONDecodeError) as error:
        raise DiscordError("Discord interaction signature is invalid") from error
    if not isinstance(value, dict):
        raise DiscordError("Discord interaction body must be an object")
    return value


@dataclass(frozen=True, slots=True)
class DiscordPost:
    channel_id: str
    content: str

    def __post_init__(self) -> None:
        if not self.channel_id.isdigit() or not self.content or len(self.content) > 2_000:
            raise DiscordError("Discord post is invalid")


class DiscordWebClient:
    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    def post_message(self, *, bot_token: bytes, post: DiscordPost) -> str:
        response = self._client.post(
            f"https://discord.com/api/v10/channels/{post.channel_id}/messages",
            headers={"Authorization": f"Bot {bot_token.decode('utf-8')}"},
            json={"content": post.content, "allowed_mentions": {"parse": []}},
            timeout=15,
        )
        if response.status_code >= 400:
            raise DiscordDeliveryError(
                f"Discord delivery failed with {response.status_code}",
                retryable=response.status_code in {408, 409, 429} or response.status_code >= 500,
            )
        value = response.json()
        message_id = value.get("id") if isinstance(value, dict) else None
        if not isinstance(message_id, str) or not message_id:
            raise DiscordError("Discord delivery returned no message id")
        return message_id
