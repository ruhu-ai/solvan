"""Identity-bound no-egress Cloud Run Sandbox execution service.

The service process only stages exact bytes and launches the fixed runner in a
fresh nested Cloud Run sandbox. It has no SQL, GCS, Secret Manager, Vertex AI,
or production permissions, and never executes request code in its host process.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.observability import instrument_fastapi

_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_EXECUTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SANDBOX_BINARY = "/usr/local/gcp/bin/sandbox"
_MAX_REQUEST_BYTES = 2_000_000
_MAX_OUTPUT_BYTES = 2_000_000
_MAX_LOG_BYTES = 100_000
_RELATIVE_DIRECTORY = re.compile(r"^(?:\.|[A-Za-z0-9][A-Za-z0-9._/-]{0,254})$")


class SandboxRunKind(StrEnum):
    """Specification 12 §8.2. Which run this is, decided here and not by the caller.

    An `EXPLORATORY` run belongs to the workspace's own loop: its output is
    visible to the model, it is EXPERIMENTAL trust class, and it never proves a
    patch works however many times it succeeded. An `ADJUDICATION` run happens
    after the workspace terminates, against the submitted diff, in a sandbox the
    producer never observed — only it yields a patch test outcome.

    The kind is a function of the authenticated caller. There is deliberately no
    request field for it, so a workspace cannot ask for adjudication, and the
    producer never adjudicates its own output.
    """

    EXPLORATORY = "EXPLORATORY"
    ADJUDICATION = "ADJUDICATION"


class SandboxSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    region: str = Field(pattern=r"^[a-z]+-[a-z]+[0-9]+$")
    audience: str = Field(pattern=r"^https://")
    coordinator_principal: str = Field(min_length=3, max_length=255)
    #: The deterministic Workspace Adapter, not the model provider, owns the
    #: exploratory route. It is the component that resolves a frozen command
    #: catalog entry before literal argv reaches this service. Separating that
    #: identity prevents a provider/model from choosing a shell command while
    #: preserving the structural exploratory/adjudication split.
    workspace_adapter_principal: str = Field(min_length=3, max_length=255)
    service_revision: str = Field(min_length=1, max_length=128)

    @classmethod
    def from_env(cls) -> SandboxSettings:
        required = (
            "SOLVAN_GCP_REGION",
            "SOLVAN_WORKSPACE_SANDBOX_AUDIENCE",
            "SOLVAN_COORDINATOR_SERVICE_ACCOUNT",
            "SOLVAN_WORKSPACE_ADAPTER_SERVICE_ACCOUNT",
            "SOLVAN_WORKSPACE_SANDBOX_REVISION",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise RuntimeError("missing workspace sandbox settings: " + ",".join(missing))
        settings = cls(
            region=os.environ["SOLVAN_GCP_REGION"],
            audience=os.environ["SOLVAN_WORKSPACE_SANDBOX_AUDIENCE"],
            coordinator_principal=(
                f"serviceAccount:{os.environ['SOLVAN_COORDINATOR_SERVICE_ACCOUNT']}"
            ),
            workspace_adapter_principal=(
                f"serviceAccount:{os.environ['SOLVAN_WORKSPACE_ADAPTER_SERVICE_ACCOUNT']}"
            ),
            service_revision=os.environ["SOLVAN_WORKSPACE_SANDBOX_REVISION"],
        )
        return settings


class InputFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_FILE_NAME.pattern)
    content_base64: str = Field(min_length=1)


class SandboxExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    execution_name: str = Field(pattern=_EXECUTION_NAME.pattern)
    reproduction_argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    test_argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    input_files: tuple[InputFile, ...]
    output_names: tuple[str, ...]
    request_hash: str = Field(pattern=_SHA256.pattern)

    @model_validator(mode="after")
    def validate_contract(self) -> SandboxExecutionRequest:
        if self.schema_version != 1:
            raise ValueError("unsupported workspace sandbox request schema")
        for argv in (self.reproduction_argv, self.test_argv):
            if any(not item or len(item) > 512 for item in argv):
                raise ValueError("workspace sandbox command arguments are invalid")
        input_names = [item.name for item in self.input_files]
        if len(input_names) != len(set(input_names)):
            raise ValueError("workspace sandbox input names must be unique")
        if (
            not self.output_names
            or len(self.output_names) != len(set(self.output_names))
            or any(_FILE_NAME.fullmatch(name) is None for name in self.output_names)
        ):
            raise ValueError("workspace sandbox output names must be unique safe basenames")
        return self

    def body_without_hash(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"request_hash"})


class OutputFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    content_base64: str


class SandboxExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    request_hash: str
    sandbox_resource: str
    run_kind: SandboxRunKind
    exit_code: int
    stdout: str
    stderr: str
    output_files: tuple[OutputFile, ...]


class ExploratorySandboxRequest(BaseModel):
    """One catalog-resolved command over one immutable candidate manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    execution_name: str = Field(pattern=_EXECUTION_NAME.pattern)
    command_id: str = Field(pattern=r"^rcc_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    command_argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    working_directory: str = Field(pattern=_RELATIVE_DIRECTORY.pattern)
    timeout_seconds: int = Field(ge=1, le=120)
    output_byte_limit: int = Field(ge=1, le=131_072)
    candidate_manifest: dict[str, Any]
    candidate_manifest_hash: str = Field(pattern=_SHA256.pattern)
    request_hash: str = Field(pattern=_SHA256.pattern)

    @model_validator(mode="after")
    def validate_contract(self) -> ExploratorySandboxRequest:
        if any(not item or len(item) > 512 for item in self.command_argv):
            raise ValueError("exploratory command arguments are invalid")
        body = self.model_dump(mode="json", exclude={"request_hash"})
        if _canonical_hash(body) != self.request_hash:
            raise ValueError("exploratory sandbox request hash does not match its body")
        if _canonical_hash(self.candidate_manifest) != self.candidate_manifest_hash:
            raise ValueError("candidate manifest hash does not match its body")
        return self


class ExploratorySandboxResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    request_hash: str = Field(pattern=_SHA256.pattern)
    sandbox_resource: str = Field(min_length=1, max_length=512)
    run_kind: SandboxRunKind
    command_id: str
    exit_code: int = Field(ge=0, le=255)
    stdout_base64: str
    stderr_base64: str
    output_bytes: int = Field(ge=0, le=131_072)


def _run_kind(authorization: str | None, settings: SandboxSettings) -> SandboxRunKind:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing caller identity")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "),
            GoogleRequest(),
            audience=settings.audience,
        )
    except (GoogleAuthError, ValueError) as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid caller identity") from error
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "a verified caller identity is required")
    caller = email.lower()
    coordinator = settings.coordinator_principal.removeprefix("serviceAccount:").lower()
    workspace_adapter = settings.workspace_adapter_principal.removeprefix("serviceAccount:").lower()
    if caller == coordinator:
        return SandboxRunKind.ADJUDICATION
    if caller == workspace_adapter:
        return SandboxRunKind.EXPLORATORY
    raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not an admitted sandbox identity")


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _decoded_file(item: InputFile) -> bytes:
    try:
        return base64.b64decode(item.content_base64, validate=True)
    except ValueError as error:
        raise ValueError("workspace sandbox input is not valid base64") from error


def _repair_runner_code(request: SandboxExecutionRequest) -> str:
    """Return the fixed repair runner; no request ever supplies program source."""

    reproduction = json.dumps(list(request.reproduction_argv), separators=(",", ":"))
    test = json.dumps(list(request.test_argv), separators=(",", ":"))
    return f"""import json
import pathlib
import subprocess

root = pathlib.Path("/workspace/workspace")
root.mkdir()
snapshot = json.loads(pathlib.Path("/workspace/snapshot.json").read_text())
for item in snapshot["files"]:
    path = root / item["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(item["content"])
patch = pathlib.Path("/workspace/proposal.patch").read_bytes()
pathlib.Path("/workspace/repair.patch").write_bytes(patch)
reproduction = subprocess.run({reproduction}, cwd=root, stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT, timeout=120)
pathlib.Path("/workspace/reproduction-output.txt").write_bytes(reproduction.stdout[:131072])
applied = subprocess.run(["git", "apply", "--whitespace=error-all", "/workspace/proposal.patch"],
    cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
if applied.returncode == 0:
    tested = subprocess.run({test}, cwd=root, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=120)
    test_code, test_output = tested.returncode, applied.stdout + tested.stdout
else:
    test_code, test_output = applied.returncode, applied.stdout
pathlib.Path("/workspace/test-output.txt").write_bytes(test_output[:131072])
changed = [line.split(" b/", 1)[0].removeprefix("diff --git a/")
           for line in patch.decode("utf-8").splitlines() if line.startswith("diff --git a/")]
pathlib.Path("/workspace/receipt.json").write_text(json.dumps({{
  "changed_paths": list(dict.fromkeys(changed)),
  "reproduction_exit_code": reproduction.returncode,
  "test_exit_code": test_code,
}}, sort_keys=True))
"""


def _exploratory_runner_code(request: ExploratorySandboxRequest) -> str:
    """Return a fixed manifest materializer and one-command runner."""

    argv = json.dumps(list(request.command_argv), separators=(",", ":"))
    working_directory = json.dumps(request.working_directory)
    timeout = request.timeout_seconds
    output_limit = request.output_byte_limit
    return f"""import base64
import json
import pathlib
import subprocess

root = pathlib.Path('/workspace/workspace')
root.mkdir()
manifest = json.loads(pathlib.Path('/workspace/candidate.json').read_text())
if set(manifest) != {{'schema_version', 'files'}} or manifest['schema_version'] != 1:
    raise RuntimeError('candidate manifest schema is invalid')
seen = set()
for item in manifest['files']:
    if set(item) != {{'path', 'content_base64', 'content_hash'}}:
        raise RuntimeError('candidate manifest entry is invalid')
    relative = pathlib.PurePosixPath(item['path'])
    if (not item['path'] or item['path'].startswith('/') or '\\\\' in item['path']
            or '..' in relative.parts or item['path'] in seen):
        raise RuntimeError('candidate manifest path is unsafe')
    content = base64.b64decode(item['content_base64'], validate=True)
    import hashlib
    if 'sha256:' + hashlib.sha256(content).hexdigest() != item['content_hash']:
        raise RuntimeError('candidate manifest content hash is invalid')
    target = root.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    seen.add(item['path'])
if {working_directory} == '.':
    cwd = root
else:
    cwd = root.joinpath(*pathlib.PurePosixPath({working_directory}).parts)
if not cwd.is_dir() or not cwd.resolve().is_relative_to(root.resolve()):
    raise RuntimeError('catalog working directory is invalid')
result = subprocess.run({argv}, cwd=cwd, stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout={timeout}, check=False)
pathlib.Path('/workspace/stdout.bin').write_bytes(result.stdout[:{output_limit}])
remaining = max(0, {output_limit} - min(len(result.stdout), {output_limit}))
pathlib.Path('/workspace/stderr.bin').write_bytes(result.stderr[:remaining])
pathlib.Path('/workspace/exit-code.txt').write_text(str(result.returncode))
"""


def _execute_exploratory(
    request: ExploratorySandboxRequest,
    settings: SandboxSettings,
) -> ExploratorySandboxResponse:
    manifest_bytes = json.dumps(
        request.candidate_manifest, sort_keys=True, separators=(",", ":")
    ).encode()
    if len(manifest_bytes) > _MAX_REQUEST_BYTES:
        raise ValueError("candidate manifest exceeds the sandbox input ceiling")
    with tempfile.TemporaryDirectory(prefix="solvan-exploratory-") as temporary:
        root = Path(temporary).resolve()
        (root / "candidate.json").write_bytes(manifest_bytes)
        (root / "runner.py").write_text(_exploratory_runner_code(request), encoding="utf-8")
        result = subprocess.run(
            [
                _SANDBOX_BINARY,
                "do",
                "--mount",
                f"type=bind,source={root},destination=/workspace",
                "--",
                "/usr/bin/python3",
                "/workspace/runner.py",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=request.timeout_seconds + 30,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("nested exploratory sandbox execution failed")
        try:
            exit_code = int((root / "exit-code.txt").read_text())
        except (OSError, ValueError) as error:
            raise RuntimeError("exploratory sandbox omitted its exit receipt") from error
        stdout = (root / "stdout.bin").read_bytes()
        stderr = (root / "stderr.bin").read_bytes()
        output_bytes = len(stdout) + len(stderr)
        if output_bytes > request.output_byte_limit:
            raise RuntimeError("exploratory sandbox output exceeds its command ceiling")
        return ExploratorySandboxResponse(
            request_hash=request.request_hash,
            sandbox_resource=(
                f"cloud-run-sandbox://{settings.region}/{settings.service_revision}/"
                f"{request.execution_name}/{request.request_hash.removeprefix('sha256:')[:16]}"
            ),
            run_kind=SandboxRunKind.EXPLORATORY,
            command_id=request.command_id,
            exit_code=exit_code,
            stdout_base64=base64.b64encode(stdout).decode(),
            stderr_base64=base64.b64encode(stderr).decode(),
            output_bytes=output_bytes,
        )


def _execute(
    request: SandboxExecutionRequest,
    settings: SandboxSettings,
    *,
    run_kind: SandboxRunKind,
) -> SandboxExecutionResponse:
    if _canonical_hash(request.body_without_hash()) != request.request_hash:
        raise ValueError("workspace sandbox request hash does not match its body")
    decoded = [(item.name, _decoded_file(item)) for item in request.input_files]
    if sum(len(name.encode()) + len(content) for name, content in decoded) > _MAX_REQUEST_BYTES:
        raise ValueError("workspace sandbox input exceeds its byte ceiling")

    with tempfile.TemporaryDirectory(prefix="solvan-sandbox-") as temporary:
        root = Path(temporary).resolve()
        for name, content in decoded:
            (root / name).write_bytes(content)
        runner = root / "runner.py"
        runner.write_text(_repair_runner_code(request), encoding="utf-8")
        command = [
            _SANDBOX_BINARY,
            "do",
            "--mount",
            f"type=bind,source={root},destination=/workspace",
            "--",
            "/usr/bin/python3",
            "/workspace/runner.py",
        ]
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("nested Cloud Run sandbox execution failed")
        output_files: list[OutputFile] = []
        total = 0
        for name in request.output_names:
            path = root / name
            if path.is_symlink() or not path.is_file() or path.parent != root:
                raise RuntimeError("nested sandbox omitted a required output")
            content = path.read_bytes()
            total += len(content)
            if total > _MAX_OUTPUT_BYTES:
                raise RuntimeError("nested sandbox outputs exceed their byte ceiling")
            output_files.append(
                OutputFile(name=name, content_base64=base64.b64encode(content).decode())
            )
        return SandboxExecutionResponse(
            run_kind=run_kind,
            request_hash=request.request_hash,
            sandbox_resource=(
                f"cloud-run-sandbox://{settings.region}/{settings.service_revision}/"
                f"{request.execution_name}/{request.request_hash.removeprefix('sha256:')[:16]}"
            ),
            exit_code=result.returncode,
            stdout=result.stdout[:_MAX_LOG_BYTES].decode("utf-8", errors="replace"),
            stderr=result.stderr[:_MAX_LOG_BYTES].decode("utf-8", errors="replace"),
            output_files=tuple(output_files),
        )


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Workspace Sandbox", version="1.0.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/sandbox:execute", response_model=SandboxExecutionResponse)
    def execute(
        request: SandboxExecutionRequest,
        authorization: str | None = Header(default=None),
    ) -> SandboxExecutionResponse:
        settings = SandboxSettings.from_env()
        run_kind = _run_kind(authorization, settings)
        try:
            return _execute(request, settings, run_kind=run_kind)
        except subprocess.TimeoutExpired as error:
            raise HTTPException(
                status.HTTP_504_GATEWAY_TIMEOUT, "sandbox execution timed out"
            ) from error
        except (RuntimeError, ValueError) as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error

    @app.post(
        "/internal/v1/exploratory-sandbox:execute",
        response_model=ExploratorySandboxResponse,
    )
    def execute_exploratory(
        request: ExploratorySandboxRequest,
        authorization: str | None = Header(default=None),
    ) -> ExploratorySandboxResponse:
        settings = SandboxSettings.from_env()
        if _run_kind(authorization, settings) is not SandboxRunKind.EXPLORATORY:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "only the Workspace Adapter may request exploratory execution",
            )
        try:
            return _execute_exploratory(request, settings)
        except subprocess.TimeoutExpired as error:
            raise HTTPException(
                status.HTTP_504_GATEWAY_TIMEOUT, "exploratory sandbox execution timed out"
            ) from error
        except (OSError, RuntimeError, ValueError) as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error

    instrument_fastapi(app, service_name="solvan-workspace-sandbox")
    return app


app = create_app()
