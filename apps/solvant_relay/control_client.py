"""Outbound-only, closed client for the Relay control-plane protocol."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any, Protocol, cast
from urllib.parse import urlparse

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token

from apps.solvant_relay.runtime import RelayRuntimeError


class RelayIdentityTokenProvider(Protocol):
    def token(self, *, audience: str) -> str: ...


class GoogleRelayIdentityTokenProvider:
    def token(self, *, audience: str) -> str:
        try:
            return cast(
                str,
                id_token.fetch_id_token(  # type: ignore[no-untyped-call]
                    GoogleAuthRequest(), audience
                ),
            )
        except Exception as error:
            raise RelayRuntimeError(
                "customer Relay could not mint an OIDC identity token"
            ) from error


class RelayControlClient:
    """The customer process can call only named, cell-local protocol routes."""

    def __init__(
        self,
        *,
        audience: str,
        token_provider: RelayIdentityTokenProvider | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        parsed = urlparse(audience)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("Relay control-plane audience must be one exact HTTPS origin")
        self._audience = audience.rstrip("/")
        self._tokens = token_provider or GoogleRelayIdentityTokenProvider()
        self._client = client or httpx.Client(timeout=45.0, follow_redirects=False)

    @classmethod
    def from_environment(cls) -> RelayControlClient:
        audience = os.environ.get("SOLVAN_RELAY_CONTROL_AUDIENCE")
        if not audience:
            raise RelayRuntimeError("SOLVAN_RELAY_CONTROL_AUDIENCE is required")
        return cls(audience=audience)

    def readiness_challenge(self, *, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._post("/internal/v1/relay/readiness-challenges", body=body)

    def readiness_proof(self, *, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._post("/internal/v1/relay/readiness-proofs", body=body)

    def poll(self, *, body: Mapping[str, Any]) -> Mapping[str, Any] | None:
        response = self._request("POST", "/internal/v1/relay/poll", body=body)
        if response.status_code == 204:
            return None
        return self._json(response)

    def claim(
        self, *, collection_job_id: str, job_digest: str, process_boot_id: str
    ) -> Mapping[str, Any]:
        return self._post(
            f"/internal/v1/relay/jobs/{_identifier(collection_job_id)}/claim",
            body={
                "schema_version": 1,
                "job_digest": job_digest,
                "claim_request_nonce": f"claim:{process_boot_id}:{collection_job_id}",
                "process_boot_id": process_boot_id,
                "accepted_at": _now(),
            },
        )

    def upload_grant(self, *, collection_job_id: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._post(
            f"/internal/v1/relay/jobs/{_identifier(collection_job_id)}/upload-grant", body=body
        )

    def receipt(self, *, collection_job_id: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._post(
            f"/internal/v1/relay/jobs/{_identifier(collection_job_id)}/receipt", body=body
        )

    def retryable_outcome(
        self, *, collection_job_id: str, body: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self._post(
            f"/internal/v1/relay/jobs/{_identifier(collection_job_id)}/attempt-outcome", body=body
        )

    def status(self, *, collection_job_id: str) -> Mapping[str, Any]:
        return self._json(
            self._request("GET", f"/internal/v1/relay/jobs/{_identifier(collection_job_id)}")
        )

    def cancel_ack(self, *, collection_job_id: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._post(
            f"/internal/v1/relay/jobs/{_identifier(collection_job_id)}/cancel-ack", body=body
        )

    def _post(self, path: str, *, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._json(self._request("POST", path, body=body))

    def _request(
        self, method: str, path: str, *, body: Mapping[str, Any] | None = None
    ) -> httpx.Response:
        if not path.startswith("/internal/v1/relay/") or "?" in path or "#" in path:
            raise RelayRuntimeError("Relay control-plane path is outside the closed protocol")
        encoded = (
            None if body is None else json.dumps(dict(body), separators=(",", ":")).encode("utf-8")
        )
        if encoded is not None and len(encoded) > 64 * 1024:
            raise RelayRuntimeError("Relay control-plane request exceeds the protocol bound")
        try:
            response = self._client.request(
                method,
                self._audience + path,
                content=encoded,
                headers={
                    "Authorization": f"Bearer {self._tokens.token(audience=self._audience)}",
                    "Content-Type": "application/json",
                }
                if encoded is not None
                else {"Authorization": f"Bearer {self._tokens.token(audience=self._audience)}"},
            )
        except httpx.HTTPError as error:
            raise RelayRuntimeError("Relay control-plane request did not complete") from error
        if response.is_error:
            raise RelayRuntimeError(
                f"Relay control-plane refused request with HTTP {response.status_code}"
            )
        return response

    @staticmethod
    def _json(response: httpx.Response) -> Mapping[str, Any]:
        try:
            value = response.json()
        except ValueError as error:
            raise RelayRuntimeError("Relay control-plane response is not JSON") from error
        if not isinstance(value, Mapping):
            raise RelayRuntimeError("Relay control-plane response is not an object")
        return value


class HttpObjectUploader:
    """Uses a one-shot upload grant; it cannot read, list, or choose an object."""

    def __init__(self, *, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(timeout=30.0, follow_redirects=False)

    def upload(
        self,
        *,
        url: str,
        content: bytes,
        content_type: str,
        required_headers: Mapping[str, str],
    ) -> Mapping[str, str]:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
            raise RelayRuntimeError("Relay upload grant URL is invalid")
        if not content or len(content) > 1_048_576 or content_type != "application/json":
            raise RelayRuntimeError("Relay upload content is outside the closed bound")
        headers = {str(key): str(value) for key, value in required_headers.items()}
        headers["Content-Type"] = content_type
        try:
            response = self._client.put(url, content=content, headers=headers)
        except httpx.HTTPError as error:
            raise RelayRuntimeError("Relay evidence upload did not complete") from error
        if response.status_code not in (200, 201):
            raise RelayRuntimeError(
                f"Relay evidence upload failed with HTTP {response.status_code}"
            )
        # The signed GCS XML upload response does not promise to contain object
        # generation or a canonical metadata digest.  Receipt settlement asks
        # the control plane to retrieve and verify those independently.
        result: dict[str, str] = {}
        if generation := response.headers.get("x-goog-generation"):
            result["object_generation"] = generation
        if metadata_hash := response.headers.get("x-goog-metageneration-hash"):
            result["object_metadata_hash"] = metadata_hash
        return result


def _identifier(value: str) -> str:
    if not value.startswith("rcj_") or len(value) != 30:
        raise RelayRuntimeError("collection job identifier is invalid")
    return value


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
