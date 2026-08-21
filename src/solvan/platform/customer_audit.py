"""Idempotent customer-owned Cloud Logging receipt sink."""

from __future__ import annotations

import re
from typing import Protocol

import httpx

from solvan.application.actuator import CustomerAuditRecord

_LOG_NAME = re.compile(r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/logs/[A-Za-z0-9._%+/=-]+$")


class AccessTokenProvider(Protocol):
    def token(self, *, scopes: tuple[str, ...]) -> str: ...


class CustomerAuditUnavailable(RuntimeError):
    """The customer-owned copy was not acknowledged; Solvan must not settle."""


class CloudLoggingCustomerAuditSink:
    """Write one stable insert ID and identical content hash to customer logging."""

    def __init__(
        self,
        *,
        token_provider: AccessTokenProvider,
        client: httpx.Client,
        api_url: str = "https://logging.googleapis.com",
    ) -> None:
        self._token_provider = token_provider
        self._client = client
        self._api_url = api_url.rstrip("/")

    def write(self, *, sink_ref: str, record: CustomerAuditRecord) -> str:
        if not _LOG_NAME.fullmatch(sink_ref):
            raise CustomerAuditUnavailable("customer audit sink reference is invalid")
        token = self._token_provider.token(
            scopes=("https://www.googleapis.com/auth/logging.write",)
        )
        try:
            response = self._client.post(
                f"{self._api_url}/v2/entries:write",
                headers={
                    "authorization": f"Bearer {token}",
                    "content-type": "application/json",
                },
                json={
                    "logName": sink_ref,
                    "entries": [
                        {
                            "insertId": record.dispatch_id,
                            "jsonPayload": {
                                "action_id": record.action_id,
                                "content": dict(record.content),
                                "content_hash": record.content_hash,
                                "dispatch_id": record.dispatch_id,
                            },
                            "severity": "NOTICE",
                        }
                    ],
                    "partialSuccess": False,
                },
            )
            response.raise_for_status()
        except (httpx.HTTPError, ValueError) as error:
            raise CustomerAuditUnavailable("customer audit write was not acknowledged") from error
        return f"{sink_ref}#insertId={record.dispatch_id}&hash={record.content_hash}"
