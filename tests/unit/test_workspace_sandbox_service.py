from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from apps.workspace_sandbox.main import (
    ExploratorySandboxRequest,
    SandboxExecutionRequest,
    SandboxRunKind,
    SandboxSettings,
    _execute,
    _execute_exploratory,
    _repair_runner_code,
    _run_kind,
)
from solvan.application.workspace_hashing import canonical_sha256

COORDINATOR = "serviceAccount:coordinator@example.iam.gserviceaccount.com"
WORKSPACE_ADAPTER = "serviceAccount:workspace-adapter@example.iam.gserviceaccount.com"


def request() -> SandboxExecutionRequest:
    body = {
        "schema_version": 1,
        "execution_name": "repair-rel-1",
        "reproduction_argv": ["true"],
        "test_argv": ["true"],
        "input_files": [
            {"name": "input.txt", "content_base64": base64.b64encode(b"input").decode()}
        ],
        "output_names": ["result.txt"],
    }
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    return SandboxExecutionRequest(
        **body, request_hash=f"sha256:{hashlib.sha256(encoded).hexdigest()}"
    )


def test_launches_nested_sandbox_without_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def run(command: list[str], **_: object) -> SimpleNamespace:
        seen.extend(command)
        mount = command[3]
        root = Path(mount.split("source=", 1)[1].split(",destination=", 1)[0])
        (root / "result.txt").write_text("ok")
        return SimpleNamespace(returncode=0, stdout=b"passed", stderr=b"")

    monkeypatch.setattr("apps.workspace_sandbox.main.subprocess.run", run)
    receipt = _execute(
        request(),
        SandboxSettings(
            region="europe-west1",
            audience="https://sandbox.example",
            coordinator_principal=COORDINATOR,
            workspace_adapter_principal=WORKSPACE_ADAPTER,
            service_revision="sandbox-v1",
        ),
        run_kind=SandboxRunKind.ADJUDICATION,
    )
    assert seen[:3] == ["/usr/local/gcp/bin/sandbox", "do", "--mount"]
    assert "--allow-egress" not in seen
    assert receipt.exit_code == 0
    assert receipt.output_files[0].content_base64 == base64.b64encode(b"ok").decode()


def test_rejects_hash_mismatch() -> None:
    invalid = request().model_copy(update={"request_hash": "sha256:" + "0" * 64})
    with pytest.raises(ValueError, match="hash"):
        _execute(
            invalid,
            SandboxSettings(
                region="europe-west1",
                audience="https://sandbox.example",
                coordinator_principal=COORDINATOR,
                workspace_adapter_principal=WORKSPACE_ADAPTER,
                service_revision="sandbox-v1",
            ),
            run_kind=SandboxRunKind.ADJUDICATION,
        )


def test_rejects_symlinked_output_from_nested_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(command: list[str], **_: object) -> SimpleNamespace:
        mount = command[3]
        root = Path(mount.split("source=", 1)[1].split(",destination=", 1)[0])
        (root / "result.txt").symlink_to("/etc/passwd")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("apps.workspace_sandbox.main.subprocess.run", run)
    with pytest.raises(RuntimeError, match="omitted"):
        _execute(
            request(),
            SandboxSettings(
                region="europe-west1",
                audience="https://sandbox.example",
                coordinator_principal=COORDINATOR,
                workspace_adapter_principal=WORKSPACE_ADAPTER,
                service_revision="sandbox-v1",
            ),
            run_kind=SandboxRunKind.ADJUDICATION,
        )


def _claims(email: str) -> dict[str, object]:
    return {"email": email, "email_verified": True}


def _settings() -> SandboxSettings:
    return SandboxSettings(
        region="europe-west1",
        audience="https://sandbox.example",
        coordinator_principal=COORDINATOR,
        workspace_adapter_principal=WORKSPACE_ADAPTER,
        service_revision="sandbox-v1",
    )


def test_the_run_kind_is_decided_by_the_caller_not_the_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specification 12 §8.2: a workspace cannot request an adjudication run.

    The kind is a function of the authenticated identity and there is no request
    field to set, so "the producer never adjudicates its own output" holds
    structurally rather than by a validation rule someone could relax. A caller
    that is neither identity gets nothing.
    """

    seen: dict[str, str] = {}

    def verify(token: str, _request: object, audience: str) -> dict[str, object]:
        return _claims(seen["email"])

    monkeypatch.setattr("apps.workspace_sandbox.main.id_token.verify_oauth2_token", verify)

    seen["email"] = "coordinator@example.iam.gserviceaccount.com"
    assert _run_kind("Bearer t", _settings()) is SandboxRunKind.ADJUDICATION

    seen["email"] = "workspace-adapter@example.iam.gserviceaccount.com"
    assert _run_kind("Bearer t", _settings()) is SandboxRunKind.EXPLORATORY

    seen["email"] = "someone-else@example.iam.gserviceaccount.com"
    with pytest.raises(HTTPException) as refused:
        _run_kind("Bearer t", _settings())
    assert refused.value.status_code == 403

    # There is no field to ask with, which is the point.
    assert "run_kind" not in SandboxExecutionRequest.model_fields


def test_the_sandbox_owns_its_runner_and_the_request_cannot_supply_code() -> None:
    request_value = request()
    assert "code" not in SandboxExecutionRequest.model_fields
    runner = _repair_runner_code(request_value)
    assert "subprocess.run" in runner
    assert "true" in runner
    with pytest.raises(ValidationError):
        SandboxExecutionRequest.model_validate(
            {**request_value.model_dump(mode="json"), "code": "import os"}
        )


def test_exploratory_execution_is_fixed_and_marked_experimental(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"print('ok')\n"
    manifest = {
        "schema_version": 1,
        "files": [
            {
                "path": "app.py",
                "content_base64": base64.b64encode(content).decode(),
                "content_hash": f"sha256:{hashlib.sha256(content).hexdigest()}",
            }
        ],
    }
    body = {
        "schema_version": 1,
        "execution_name": "explore-1",
        "command_id": "rcc_01J00000000000000000000000",
        "command_argv": ["python", "app.py"],
        "working_directory": ".",
        "timeout_seconds": 30,
        "output_byte_limit": 100,
        "candidate_manifest": manifest,
        "candidate_manifest_hash": canonical_sha256(manifest),
    }
    exploratory = ExploratorySandboxRequest(**body, request_hash=canonical_sha256(body))

    def run(command: list[str], **_: object) -> SimpleNamespace:
        root = Path(command[3].split("source=", 1)[1].split(",destination=", 1)[0])
        (root / "stdout.bin").write_bytes(b"ok\n")
        (root / "stderr.bin").write_bytes(b"")
        (root / "exit-code.txt").write_text("0")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("apps.workspace_sandbox.main.subprocess.run", run)
    receipt = _execute_exploratory(exploratory, _settings())
    assert receipt.run_kind is SandboxRunKind.EXPLORATORY
    assert base64.b64decode(receipt.stdout_base64) == b"ok\n"
