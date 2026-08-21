"""Audience-bound delivery of one-time email enrollment proofs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token


class EmailEnrollmentError(RuntimeError):
    """The private relay did not accept an enrollment message."""


class EmailEnrollmentSender(Protocol):
    def send(self, *, address: str, code: str, challenge_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class GoogleEmailEnrollmentSender:
    relay_url: str
    console_base_url: str
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if not self.relay_url.startswith("https://"):
            raise ValueError("email enrollment relay URL must use HTTPS")
        if not self.console_base_url.startswith("https://"):
            raise ValueError("console base URL must use HTTPS")
        if not 1 <= self.timeout_seconds <= 30:
            raise ValueError("email enrollment timeout is out of bounds")

    def send(self, *, address: str, code: str, challenge_id: str) -> str:
        token = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
            GoogleRequest(), self.relay_url
        )
        payload: dict[str, Any] = {
            "schema_version": 1,
            "to_address": address,
            "external_thread_id": f"solvan-enrollment:{challenge_id}",
            "subject": "Verify your Solvan email connection",
            "plain_text": (
                "Reply to this message with the following line within ten minutes:\n\n"
                f"solvan enroll {code}\n\n"
                "If you did not request this connection, do not reply. "
                f"Review channel access at {self.console_base_url.rstrip('/')}/?section=channels"
            ),
        }
        try:
            response = httpx.post(
                self.relay_url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": challenge_id,
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            value = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise EmailEnrollmentError("email verification delivery was refused") from error
        message_id = value.get("message_id") if isinstance(value, dict) else None
        if not isinstance(message_id, str) or not message_id:
            raise EmailEnrollmentError("email relay returned no delivery receipt")
        return f"email-relay:{message_id}"
