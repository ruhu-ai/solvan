"""Audience-bound delivery of operator step-up presence codes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token


class OperatorStepUpDeliveryError(RuntimeError):
    """The private email relay did not accept the message."""


class OperatorStepUpSender(Protocol):
    def send(self, *, address: str, code: str, step_up_id: str, operation: str) -> str: ...


@dataclass(frozen=True, slots=True)
class GoogleOperatorStepUpSender:
    relay_url: str
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if not self.relay_url.startswith("https://"):
            raise ValueError("operator step-up relay URL must use HTTPS")
        if not 1 <= self.timeout_seconds <= 30:
            raise ValueError("operator step-up delivery timeout is out of bounds")

    def send(self, *, address: str, code: str, step_up_id: str, operation: str) -> str:
        token = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
            GoogleRequest(), self.relay_url
        )
        payload: dict[str, Any] = {
            "schema_version": 1,
            "to_address": address,
            "external_thread_id": f"solvan-operator-step-up:{step_up_id}",
            "subject": "Your Solvan verification code",
            "plain_text": (
                f"Your Solvan code for {operation} is {code}.\n\n"
                "It expires in five minutes and can be used once. Solvan support "
                "will never ask you for this code. If you did not request it, do "
                "not share it and end your Solvan sessions."
            ),
        }
        try:
            response = httpx.post(
                self.relay_url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": step_up_id,
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            value = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise OperatorStepUpDeliveryError("operator verification email was refused") from error
        message_id = value.get("message_id") if isinstance(value, dict) else None
        if not isinstance(message_id, str) or not message_id:
            raise OperatorStepUpDeliveryError("email relay returned no delivery receipt")
        return f"email-relay:{message_id}"


@dataclass(frozen=True, slots=True)
class LoopbackOperatorStepUpSender:
    """Deliver a code to the local identity fixture, never to a deployment.

    The browser suite must exercise the same request, delivery receipt, and
    verification path as production without depending on a person's mailbox.
    This sender therefore permits only a literal loopback HTTP endpoint and
    requires an explicit fixture bearer. It cannot be pointed at a network
    service, and the API composition selects it only for the non-production
    test issuer.
    """

    relay_url: str
    bearer_token: str
    timeout_seconds: int = 5

    def __post_init__(self) -> None:
        parsed = urlparse(self.relay_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("test step-up relay must be a loopback HTTP endpoint")
        if parsed.path != "/operator-step-up-messages":
            raise ValueError("test step-up relay path is not the fixture mailbox")
        if len(self.bearer_token.encode("utf-8")) < 32:
            raise ValueError("test step-up relay bearer is not strong enough")
        if not 1 <= self.timeout_seconds <= 10:
            raise ValueError("test step-up delivery timeout is out of bounds")

    def send(self, *, address: str, code: str, step_up_id: str, operation: str) -> str:
        try:
            response = httpx.post(
                self.relay_url,
                json={
                    "schema_version": 1,
                    "to_address": address,
                    "code": code,
                    "step_up_id": step_up_id,
                    "operation": operation,
                },
                headers={
                    "Authorization": f"Bearer {self.bearer_token}",
                    "Idempotency-Key": step_up_id,
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            value = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise OperatorStepUpDeliveryError("test verification delivery was refused") from error
        message_id = value.get("message_id") if isinstance(value, dict) else None
        if not isinstance(message_id, str) or not message_id:
            raise OperatorStepUpDeliveryError("test relay returned no delivery receipt")
        return f"test-email-relay:{message_id}"


__all__ = [
    "GoogleOperatorStepUpSender",
    "LoopbackOperatorStepUpSender",
    "OperatorStepUpDeliveryError",
    "OperatorStepUpSender",
]
