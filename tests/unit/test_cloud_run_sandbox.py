from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from solvan.platform import (
    CloudRunSandboxConfiguration,
    CloudRunSandboxExecutor,
    SandboxInputFile,
)


class TokenProvider:
    def token(self, *, audience: str) -> str:
        assert audience == "https://sandbox.example"
        return "identity-token"


def configured(handler: Any, **changes: Any) -> CloudRunSandboxExecutor:
    values = {
        "base_url": "https://sandbox.example",
        "audience": "https://sandbox.example",
        "max_request_bytes": 10_000,
        "max_response_bytes": 10_000,
    }
    values.update(changes)
    return CloudRunSandboxExecutor(
        config=CloudRunSandboxConfiguration(**values),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        token_provider=TokenProvider(),
    )


def test_executes_only_explicit_bytes_and_accepts_bound_ordered_receipt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer identity-token"
        value = json.loads(request.content)
        assert value["input_files"] == [
            {
                "name": "snapshot.json",
                "content_base64": base64.b64encode(b"repository bytes").decode(),
            }
        ]
        return httpx.Response(
            200,
            json={
                "schema_version": 1,
                "request_hash": value["request_hash"],
                "sandbox_resource": "cloud-run-sandbox://europe-west1/rev/execution/hash",
                "run_kind": "ADJUDICATION",
                "exit_code": 0,
                "stdout": "1 passed\n",
                "stderr": "",
                "output_files": [
                    {
                        "name": "repair.patch",
                        "content_base64": base64.b64encode(b"diff --git").decode(),
                    }
                ],
            },
        )

    result = configured(handler).execute(
        execution_name="repair-rel-0001",
        reproduction_argv=("true",),
        test_argv=("true",),
        files=(SandboxInputFile("snapshot.json", b"repository bytes"),),
        output_names=("repair.patch",),
    )
    assert result.succeeded
    assert result.stdout == "1 passed\n"
    assert result.output_files[0].content == b"diff --git"


@pytest.mark.parametrize("location", ["global", "europewest4", "europe-west"])
def test_fails_closed_for_a_malformed_region(location: str) -> None:
    with pytest.raises(ValueError, match="malformed"):
        CloudRunSandboxConfiguration(
            base_url="https://sandbox.example",
            audience="https://sandbox.example",
            region=location,
        )


def test_accepts_a_qualified_regional_sandbox() -> None:
    configuration = CloudRunSandboxConfiguration(
        base_url="https://sandbox.example",
        audience="https://sandbox.example",
        region="europe-west4",
    )
    assert configuration.region == "europe-west4"


def test_rejects_paths_duplicate_files_and_oversized_input() -> None:
    executor = configured(lambda _: httpx.Response(500), max_request_bytes=200)
    with pytest.raises(ValueError, match="basename"):
        SandboxInputFile("../secret", b"x")
    with pytest.raises(ValueError, match="unique"):
        executor.execute(
            execution_name="test",
            reproduction_argv=("true",),
            test_argv=("true",),
            files=(SandboxInputFile("a.py", b"1"), SandboxInputFile("a.py", b"2")),
            output_names=("result.txt",),
        )
    with pytest.raises(ValueError, match="byte ceiling"):
        executor.execute(
            execution_name="test",
            reproduction_argv=("true",),
            test_argv=("true",),
            files=(SandboxInputFile("a.py", b"x" * 200),),
            output_names=("result.txt",),
        )


def test_rejects_unbound_or_reordered_receipt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        value = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "schema_version": 1,
                "request_hash": value["request_hash"],
                "sandbox_resource": "cloud-run-sandbox://europe-west1/rev/execution/hash",
                "run_kind": "ADJUDICATION",
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "output_files": [
                    {"name": "b.txt", "content_base64": ""},
                    {"name": "a.txt", "content_base64": ""},
                ],
            },
        )

    with pytest.raises(RuntimeError, match="reordered"):
        configured(handler).execute(
            execution_name="test",
            reproduction_argv=("true",),
            test_argv=("true",),
            output_names=("a.txt", "b.txt"),
        )


def test_the_producer_response_parses_in_the_consumer_and_refuses_an_exploratory_one() -> None:
    """The two halves of the sandbox boundary must agree on one schema.

    They stopped agreeing: adding a required `run_kind` to the service response
    while the client model forbade extras meant every real adjudication was
    rejected as malformed and failed closed. Both suites still passed, because
    each exercised its own half against its own fixture. This asserts the
    producer's actual model against the consumer's actual model.

    It also pins the stronger property: this client is the coordinator's, so it
    accepts an adjudication and nothing else. An exploratory result can never be
    counted as a patch outcome, even if the sandbox misidentified its caller.
    """

    from apps.workspace_sandbox.main import (
        OutputFile as ProducerOutputFile,
    )
    from apps.workspace_sandbox.main import (
        SandboxExecutionResponse,
        SandboxRunKind,
    )
    from solvan.platform.cloud_run_sandbox import _ExecutionResponse

    produced = SandboxExecutionResponse(
        request_hash=f"sha256:{'a' * 64}",
        sandbox_resource="cloud-run-sandbox://europe-west1/rev/execution/hash",
        run_kind=SandboxRunKind.ADJUDICATION,
        exit_code=0,
        stdout="ok",
        stderr="",
        output_files=(ProducerOutputFile(name="result.txt", content_base64="b2s="),),
    )
    consumed = _ExecutionResponse.model_validate(produced.model_dump(mode="json"))
    assert consumed.run_kind == "ADJUDICATION"
    assert consumed.request_hash == produced.request_hash

    exploratory = produced.model_copy(update={"run_kind": SandboxRunKind.EXPLORATORY})
    with pytest.raises(ValidationError):
        _ExecutionResponse.model_validate(exploratory.model_dump(mode="json"))
