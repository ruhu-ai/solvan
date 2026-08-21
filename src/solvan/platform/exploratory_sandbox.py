"""Workspace-Adapter client for catalog-only exploratory sandbox execution."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.workspace_candidate import CatalogCommand
from solvan.application.workspace_hashing import canonical_sha256

_SHA256 = r"^sha256:[0-9a-f]{64}$"


class IdentityTokenProvider(Protocol):
    def token(self, *, audience: str) -> str: ...


class GoogleIdentityTokenProvider:
    def token(self, *, audience: str) -> str:
        token = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
            GoogleAuthRequest(), audience
        )
        if not token:
            raise RuntimeError("exploratory sandbox identity token is unavailable")
        return str(token)


@dataclass(frozen=True, slots=True)
class ExploratorySandboxConfiguration:
    base_url: str
    audience: str
    timeout_seconds: int = 150
    max_response_bytes: int = 300_000

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://") or self.base_url.endswith("/"):
            raise ValueError("exploratory sandbox URL must be one HTTPS origin")
        if not self.audience.startswith("https://"):
            raise ValueError("exploratory sandbox audience must be HTTPS")
        if not 1 <= self.timeout_seconds <= 180:
            raise ValueError("exploratory sandbox timeout is outside policy")
        if not 1 <= self.max_response_bytes <= 1_000_000:
            raise ValueError("exploratory sandbox response ceiling is outside policy")


class _ExploratoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    request_hash: str = Field(pattern=_SHA256)
    sandbox_resource: str = Field(min_length=1, max_length=512)
    run_kind: Literal["EXPLORATORY"]
    command_id: str
    exit_code: int = Field(ge=0, le=255)
    stdout_base64: str
    stderr_base64: str
    output_bytes: int = Field(ge=0, le=131_072)


@dataclass(frozen=True, slots=True)
class ExploratorySandboxReceipt:
    request_hash: str
    sandbox_resource: str
    command_id: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    output_bytes: int


class CloudRunExploratorySandboxExecutor:
    """Execute one Adapter-resolved command; no model field chooses authority."""

    def __init__(
        self,
        *,
        config: ExploratorySandboxConfiguration,
        client: httpx.Client,
        token_provider: IdentityTokenProvider,
    ) -> None:
        self._config = config
        self._client = client
        self._tokens = token_provider

    def execute(
        self,
        *,
        execution_name: str,
        command: CatalogCommand,
        candidate_manifest: dict[str, Any],
        candidate_manifest_hash: str,
    ) -> ExploratorySandboxReceipt:
        if canonical_sha256(candidate_manifest) != candidate_manifest_hash:
            raise ValueError("candidate manifest hash does not match its body")
        body: dict[str, Any] = {
            "schema_version": 1,
            "execution_name": execution_name,
            "command_id": command.command_id,
            "command_argv": list(command.argv),
            "working_directory": command.working_directory,
            "timeout_seconds": max(1, (command.timeout_ms + 999) // 1_000),
            "output_byte_limit": command.output_byte_limit,
            "candidate_manifest": candidate_manifest,
            "candidate_manifest_hash": candidate_manifest_hash,
        }
        request_hash = canonical_sha256(body)
        body["request_hash"] = request_hash
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        try:
            response = self._client.post(
                f"{self._config.base_url}/internal/v1/exploratory-sandbox:execute",
                content=encoded,
                headers={
                    "Authorization": f"Bearer {self._tokens.token(audience=self._config.audience)}",
                    "Content-Type": "application/json",
                },
                timeout=self._config.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException as error:
            raise TimeoutError("exploratory sandbox request timed out") from error
        except httpx.HTTPError as error:
            raise RuntimeError("exploratory sandbox request failed") from error
        if len(response.content) > self._config.max_response_bytes:
            raise RuntimeError("exploratory sandbox response exceeds its byte ceiling")
        try:
            parsed = _ExploratoryResponse.model_validate_json(response.content)
        except ValueError as error:
            raise RuntimeError("exploratory sandbox returned a malformed receipt") from error
        if parsed.request_hash != request_hash or parsed.command_id != command.command_id:
            raise RuntimeError("exploratory sandbox receipt differs from the frozen request")
        try:
            stdout = base64.b64decode(parsed.stdout_base64, validate=True)
            stderr = base64.b64decode(parsed.stderr_base64, validate=True)
        except ValueError as error:
            raise RuntimeError("exploratory sandbox returned invalid base64 output") from error
        if len(stdout) + len(stderr) != parsed.output_bytes:
            raise RuntimeError("exploratory sandbox output byte receipt is inconsistent")
        return ExploratorySandboxReceipt(
            request_hash=request_hash,
            sandbox_resource=parsed.sandbox_resource,
            command_id=parsed.command_id,
            exit_code=parsed.exit_code,
            stdout=stdout,
            stderr=stderr,
            output_bytes=parsed.output_bytes,
        )
