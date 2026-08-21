"""Fail-closed client for the private regional Cloud Run Sandbox executor."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_EXECUTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_PROVIDER_BYTES = 10_000_000


class IdentityTokenProvider(Protocol):
    def token(self, *, audience: str) -> str: ...


@dataclass(frozen=True, slots=True)
class CloudRunSandboxConfiguration:
    base_url: str
    audience: str
    region: str = "europe-west1"
    max_request_bytes: int = 2_000_000
    max_response_bytes: int = 2_000_000
    execution_timeout_seconds: int = 300

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://") or self.base_url.endswith("/"):
            raise ValueError("Cloud Run sandbox URL must be one HTTPS origin")
        if not self.audience.startswith("https://"):
            raise ValueError("Cloud Run sandbox audience must be HTTPS")
        if re.fullmatch(r"[a-z]+-[a-z]+[0-9]+", self.region) is None:
            raise ValueError("Cloud Run sandbox region is malformed")
        for value in (self.max_request_bytes, self.max_response_bytes):
            if not 1 <= value <= _MAX_PROVIDER_BYTES:
                raise ValueError("Cloud Run sandbox byte ceiling is outside the supported range")
        if not 1 <= self.execution_timeout_seconds <= 300:
            raise ValueError("Cloud Run sandbox timeout must be between 1 and 300 seconds")


@dataclass(frozen=True, slots=True)
class SandboxInputFile:
    name: str
    content: bytes

    def __post_init__(self) -> None:
        if _FILE_NAME.fullmatch(self.name) is None:
            raise ValueError("sandbox input filename must be a safe basename")


@dataclass(frozen=True, slots=True)
class SandboxOutputFile:
    name: str
    content: bytes


@dataclass(frozen=True, slots=True)
class SandboxExecutionResult:
    sandbox_name: str
    exit_code: int
    stdout: str
    stderr: str
    output_files: tuple[SandboxOutputFile, ...]

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


class _InputFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_FILE_NAME.pattern)
    content_base64: str = Field(min_length=1)


class _ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    execution_name: str = Field(pattern=_EXECUTION_NAME.pattern)
    reproduction_argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    test_argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    input_files: tuple[_InputFile, ...]
    output_names: tuple[str, ...]
    request_hash: str = Field(pattern=_SHA256.pattern)


class _OutputFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_FILE_NAME.pattern)
    content_base64: str


class _ExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    request_hash: str = Field(pattern=_SHA256.pattern)
    sandbox_resource: str = Field(min_length=1, max_length=512)
    #: Specification 12 §8.2. The sandbox derives this from the authenticated
    #: caller, so a response reaching this client should always be an
    #: adjudication — this client is the coordinator's. Pinning the literal
    #: rather than parsing a string means an exploratory result can never be
    #: accepted as a patch outcome, even if the sandbox misidentified its
    #: caller: the response fails to parse instead of quietly counting.
    run_kind: Literal["ADJUDICATION"]
    exit_code: int = Field(ge=0, le=255)
    stdout: str
    stderr: str
    output_files: tuple[_OutputFile, ...]

    @model_validator(mode="after")
    def supported_schema(self) -> _ExecutionResponse:
        if self.schema_version != 1:
            raise ValueError("unsupported Cloud Run sandbox response schema")
        return self


class CloudRunSandboxExecutor:
    """Submit one atomic, identity-bound, no-egress nested-sandbox execution."""

    def __init__(
        self,
        *,
        config: CloudRunSandboxConfiguration,
        client: httpx.Client,
        token_provider: IdentityTokenProvider,
    ) -> None:
        self._config = config
        self._client = client
        self._token_provider = token_provider

    def execute(
        self,
        *,
        execution_name: str,
        reproduction_argv: tuple[str, ...],
        test_argv: tuple[str, ...],
        files: tuple[SandboxInputFile, ...] = (),
        output_names: tuple[str, ...],
    ) -> SandboxExecutionResult:
        if _EXECUTION_NAME.fullmatch(execution_name) is None:
            raise ValueError("sandbox execution name is malformed")
        for argv in (reproduction_argv, test_argv):
            if not argv or any(not item or len(item) > 512 for item in argv):
                raise ValueError("sandbox command arguments are invalid")
        input_names = [item.name for item in files]
        if len(input_names) != len(set(input_names)):
            raise ValueError("sandbox input filenames must be unique")
        if (
            not output_names
            or len(output_names) != len(set(output_names))
            or any(_FILE_NAME.fullmatch(name) is None for name in output_names)
        ):
            raise ValueError("sandbox output names must be unique safe basenames")

        input_files = tuple(
            _InputFile(name=item.name, content_base64=base64.b64encode(item.content).decode())
            for item in files
        )
        body_without_hash = {
            "schema_version": 1,
            "execution_name": execution_name,
            "reproduction_argv": list(reproduction_argv),
            "test_argv": list(test_argv),
            "input_files": [item.model_dump(mode="json") for item in input_files],
            "output_names": list(output_names),
        }
        request_hash = _canonical_hash(body_without_hash)
        request = _ExecutionRequest(
            schema_version=1,
            execution_name=execution_name,
            reproduction_argv=reproduction_argv,
            test_argv=test_argv,
            input_files=input_files,
            output_names=output_names,
            request_hash=request_hash,
        )
        encoded = request.model_dump_json().encode()
        if len(encoded) > self._config.max_request_bytes:
            raise ValueError("sandbox request exceeds the configured byte ceiling")
        token = self._token_provider.token(audience=self._config.audience)
        try:
            response = self._client.post(
                f"{self._config.base_url}/internal/v1/sandbox:execute",
                content=encoded,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=self._config.execution_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException as error:
            raise TimeoutError("Cloud Run sandbox request timed out") from error
        except httpx.HTTPError as error:
            raise RuntimeError("Cloud Run sandbox request failed") from error
        if len(response.content) > self._config.max_response_bytes:
            raise RuntimeError("sandbox response exceeds the configured byte ceiling")
        try:
            receipt = _ExecutionResponse.model_validate_json(response.content)
        except ValueError as error:
            raise RuntimeError("Cloud Run sandbox returned a malformed receipt") from error
        if receipt.request_hash != request_hash:
            raise RuntimeError("Cloud Run sandbox receipt is not bound to the request")
        returned_names = [item.name for item in receipt.output_files]
        if returned_names != list(output_names):
            raise RuntimeError("Cloud Run sandbox returned an incomplete or reordered artifact set")
        outputs: list[SandboxOutputFile] = []
        for item in receipt.output_files:
            try:
                content = base64.b64decode(item.content_base64, validate=True)
            except ValueError as error:
                raise RuntimeError("Cloud Run sandbox returned invalid base64 output") from error
            outputs.append(SandboxOutputFile(name=item.name, content=content))
        return SandboxExecutionResult(
            sandbox_name=receipt.sandbox_resource,
            exit_code=receipt.exit_code,
            stdout=receipt.stdout,
            stderr=receipt.stderr,
            output_files=tuple(outputs),
        )


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"
