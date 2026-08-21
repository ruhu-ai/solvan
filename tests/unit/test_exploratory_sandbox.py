from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from solvan.application.workspace_candidate import CatalogCommand
from solvan.application.workspace_hashing import canonical_sha256
from solvan.platform.exploratory_sandbox import (
    CloudRunExploratorySandboxExecutor,
    ExploratorySandboxConfiguration,
)


class Tokens:
    def token(self, *, audience: str) -> str:
        assert audience == "https://sandbox.example"
        return "adapter-token"


def command() -> CatalogCommand:
    return CatalogCommand(
        command_id="rcc_01J00000000000000000000000",
        argv=("pytest", "-q"),
        working_directory=".",
        timeout_ms=30_000,
        cpu_millis=1_000,
        memory_mib=1_024,
        output_byte_limit=131_072,
        network_mode="NONE",
    )


def manifest() -> dict[str, Any]:
    content = b"print('ok')\n"
    return {
        "schema_version": 1,
        "files": [
            {
                "path": "app.py",
                "content_base64": base64.b64encode(content).decode(),
                "content_hash": "sha256:" + __import__("hashlib").sha256(content).hexdigest(),
            }
        ],
    }


def test_adapter_client_accepts_only_an_exploratory_bound_receipt() -> None:
    candidate = manifest()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer adapter-token"
        value = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "schema_version": 1,
                "request_hash": value["request_hash"],
                "sandbox_resource": "cloud-run-sandbox://europe-west1/rev/run/hash",
                "run_kind": "EXPLORATORY",
                "command_id": value["command_id"],
                "exit_code": 0,
                "stdout_base64": base64.b64encode(b"passed\n").decode(),
                "stderr_base64": "",
                "output_bytes": 7,
            },
        )

    executor = CloudRunExploratorySandboxExecutor(
        config=ExploratorySandboxConfiguration(
            base_url="https://sandbox.example", audience="https://sandbox.example"
        ),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        token_provider=Tokens(),
    )
    receipt = executor.execute(
        execution_name="repair-run-1",
        command=command(),
        candidate_manifest=candidate,
        candidate_manifest_hash=canonical_sha256(candidate),
    )
    assert receipt.stdout == b"passed\n"
    assert receipt.exit_code == 0


def test_adapter_client_refuses_changed_manifest_and_adjudication_response() -> None:
    candidate = manifest()
    executor = CloudRunExploratorySandboxExecutor(
        config=ExploratorySandboxConfiguration(
            base_url="https://sandbox.example", audience="https://sandbox.example"
        ),
        client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500))),
        token_provider=Tokens(),
    )
    with pytest.raises(ValueError, match="manifest hash"):
        executor.execute(
            execution_name="repair-run-1",
            command=command(),
            candidate_manifest=candidate,
            candidate_manifest_hash="sha256:" + "0" * 64,
        )
