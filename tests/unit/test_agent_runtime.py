import hashlib
import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from apps.coordinator.runtime_starters import _invoke_with_partial_receipt
from solvan.application import (
    PartialRuntimeInvocationReceipt,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
    WorkspaceArtifactDescriptor,
    WorkspaceInputMaterial,
    WorkspaceProviderKind,
    WorkspaceTaskBudget,
    WorkspaceTaskInvocation,
    WorkspaceTaskKind,
)
from solvan.application.effective_tool_set import (
    EffectiveToolBindingV1,
    EffectiveToolSetV1,
    ToolConnectionBindingKind,
    ToolRevisionRefV1,
    accepted_step_budget_hash,
)
from solvan.domain import Scope, StepBudget
from solvan.platform import (
    AgentRuntimeConfiguration,
    GeminiAgentRuntime,
    IncompleteRuntimeReceiptError,
    QueryJobCheck,
    QueryJobResult,
    structured_query_output,
)

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


class FakeQueryJobs:
    def __init__(self, result: QueryJobResult | None = None) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.result = result or QueryJobResult(
            "projects/test/locations/europe-west1/reasoningEngineQueryJobs/job-1",
            "gs://runtime/runs/run_input.json",
            (
                "gs://runtime/runs/org_00000000000000000000000000/"
                "prj_00000000000000000000000000/env_00000000000000000000000000/"
                "agent-runs/run_00000000000000000000000000.json"
            ),
        )

    def run_query_job(self, *, name: str, config: dict[str, str]) -> QueryJobResult:
        self.calls.append((name, config))
        return self.result

    def check_query_job(self, *, name: str, config: dict[str, bool]) -> QueryJobCheck:
        return QueryJobCheck(
            operation_name=name,
            output_gcs_uri="gs://runtime/runs/run_output.json",
            status="SUCCESS",
            result='{"schema_version":1}',
        )

    def cancel_query_job(self, *, name: str, config: dict[str, str]) -> None:
        self.calls.append((name, config))


def dispatch(**changes: object) -> RuntimeDispatch:
    values: dict[str, object] = {
        "run_id": "run_00000000000000000000000000",
        "invocation_id": "inv_00000000000000000000000000",
        "scope": SCOPE,
        "incident_id": "inc_00000000000000000000000000",
        "plan_id": "ipl_00000000000000000000000000",
        "plan_version": 1,
        "step_id": "ist_00000000000000000000000000",
        "step_key": "collect-telemetry",
        "logical_step_key": "incident:test:investigation:1:collect-telemetry",
        "agent_key": "evidence-agent",
        "agent_resource": (
            "projects/solvan-demo/locations/europe-west1/reasoningEngines/evidence-v1"
        ),
        "agent_revision": "evidence-20260808-01",
        "scope_ref": "scope:payments",
        "purpose": "inspect bounded service telemetry",
        "allowed_tool_names": ("cloud_monitoring_query",),
        "workflow_version": 3,
        "deadline": NOW + timedelta(seconds=60),
        "budget": StepBudget(60_000, 3, 16_000, max_model_calls=1),
        "input_ref": "db://step",
        "input_hash": "sha256:input",
        "trace_id": "0" * 32,
        "span_id": "1" * 16,
    }
    values.update(changes)
    if "context" not in changes:
        tools = tuple(
            ToolRevisionRefV1(tool_key=name, version="1")
            for name in values["allowed_tool_names"]  # type: ignore[union-attr]
        )
        effective = EffectiveToolSetV1(
            profile_material_hash="sha256:" + "2" * 64,
            accepted_tools=tools,
            agent_key=str(values["agent_key"]),
            agent_revision=str(values["agent_revision"]),
            scope=SCOPE.canonical_dict(),
            connection_bindings=tuple(
                EffectiveToolBindingV1(
                    binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY, tool=tool
                )
                for tool in tools
            ),
            runtime_region="europe-west1",
            accepted_data_classification="INTERNAL",
            classification_ceiling="INTERNAL",
            policy_head_epoch=0,
            placement_epoch=1,
            accepted_step_budget_hash=accepted_step_budget_hash(values["budget"]),
        )
        values["context"] = {
            "effective_tool_set": effective.canonical_dict(),
            "effective_tool_set_hash": effective.effective_tool_set_hash,
        }
    return RuntimeDispatch(**values)  # type: ignore[arg-type]


def runtime(client: FakeQueryJobs) -> GeminiAgentRuntime:
    return GeminiAgentRuntime(
        config=AgentRuntimeConfiguration("solvan-demo", "europe-west1", "gs://runtime/runs"),
        client=client,
        clock=FixedClock(),
    )


def workspace_invocation(**changes: object) -> WorkspaceTaskInvocation:
    content = "return payment()\n"
    content_hash = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
    budget = WorkspaceTaskBudget(
        max_runtime_seconds=120,
        max_model_calls=1,
        max_tool_calls=0,
        max_input_bytes=10_000,
        max_output_bytes=20_000,
    )
    effective = EffectiveToolSetV1(
        profile_material_hash=f"sha256:{'1' * 64}",
        accepted_tools=(),
        agent_key="workspace-agent",
        agent_revision="workspace-20260808-01",
        scope=SCOPE.canonical_dict(),
        connection_bindings=(),
        runtime_region="europe-west1",
        accepted_data_classification="INTERNAL",
        classification_ceiling="CONFIDENTIAL",
        policy_head_epoch=0,
        placement_epoch=1,
        accepted_step_budget_hash=accepted_step_budget_hash(budget),
    )
    values: dict[str, object] = {
        "schema_version": 1,
        "request_id": "req_00000000000000000000000000",
        "run_id": "run_00000000000000000000000001",
        "invocation_id": "inv_00000000000000000000000001",
        "logical_step_key": "workspace:repair:one",
        "attempt": 1,
        "scope": SCOPE,
        "workspace_id": "wsp_00000000000000000000000000",
        "workspace_generation": 1,
        "task_kind": WorkspaceTaskKind.REPAIR,
        "provider": WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE,
        "provider_resource": (
            "projects/solvan-demo/locations/europe-west1/reasoningEngines/workspace-v1"
        ),
        "provider_revision": "workspace-20260808-01",
        "implementation_sdk_distribution_hash": f"sha256:{'7' * 64}",
        "provider_artifact_digest": f"sha256:{'8' * 64}",
        "workflow_version": 4,
        "deadline": NOW + timedelta(seconds=120),
        "budget": budget,
        "input_manifest_ref": "gs://runtime/workspaces/input.json",
        "input_manifest_hash": f"sha256:{'2' * 64}",
        "effective_tool_set_hash": effective.effective_tool_set_hash,
        "effective_tool_set": effective,
        "effective_network_policy_hash": f"sha256:{'4' * 64}",
        "allowed_tool_names": (),
        "input_artifacts": (
            WorkspaceArtifactDescriptor(
                artifact_handle="wah_" + "1" * 32,
                path="repository/app.py",
                object_ref="gs://runtime/workspaces/app.py",
                content_hash=content_hash,
                size_bytes=len(content.encode()),
                media_type="text/x-python",
                provenance_refs=("fixture://repository",),
            ),
        ),
        "input_materials": (
            WorkspaceInputMaterial(
                path="repository/app.py",
                content=content,
                content_hash=content_hash,
                media_type="text/x-python",
            ),
        ),
        "objective": "Produce one bounded repair.",
        "task_parameters": {
            "base_commit_sha": "a" * 40,
            "reproduction_command": "pytest -q",
            "test_command": "pytest -q",
            "allowed_file_globs": ["*.py"],
            "reproduction_command_id": "rcc_" + "1" * 26,
            "test_command_id": "rcc_" + "2" * 26,
            "command_catalog_hash": "sha256:" + "3" * 64,
        },
        "trace_id": "5" * 32,
        "span_id": "6" * 16,
    }
    values.update(changes)
    return WorkspaceTaskInvocation.build(**values)


def test_runtime_launches_official_query_job_with_strict_invocation() -> None:
    client = FakeQueryJobs()
    receipt = runtime(client).invoke(dispatch())

    assert receipt.runtime_operation_name.endswith("job-1")
    assert receipt.runtime_input_ref == "gs://runtime/runs/run_input.json"
    resource, config = client.calls[0]
    assert resource.endswith("reasoningEngines/evidence-v1")
    query = json.loads(config["query"])
    assert query["input"]["user_id"] == SCOPE.environment_id
    invocation = json.loads(query["input"]["message"])
    assert invocation["allowed_tool_names"] == ["cloud_monitoring_query"]
    assert invocation["effective_tool_set_hash"].startswith("sha256:")
    assert invocation["effective_tool_set"]["accepted_tools"][0]["tool_key"] == (
        "cloud_monitoring_query"
    )
    assert invocation["budget"]["max_runtime_seconds"] == 60
    assert config["output_gcs_uri"].endswith("run_00000000000000000000000000.json")


def test_runtime_recomputes_effective_tool_set_before_provider_dispatch() -> None:
    valid = dispatch()
    changed_hash = replace(
        valid,
        context={**valid.context, "effective_tool_set_hash": f"sha256:{'f' * 64}"},
    )
    changed_material = json.loads(json.dumps(valid.context["effective_tool_set"]))
    changed_material["agent_revision"] = "another-revision"
    changed_preimage = replace(
        valid,
        context={**valid.context, "effective_tool_set": changed_material},
    )
    for candidate in (changed_hash, changed_preimage):
        client = FakeQueryJobs()
        with pytest.raises(ValueError, match="effective Tool"):
            runtime(client).invoke(candidate)
        assert client.calls == []


def test_runtime_launches_provider_neutral_workspace_query_job() -> None:
    client = FakeQueryJobs()
    invocation = workspace_invocation()
    receipt = runtime(client).invoke_workspace(invocation)
    assert receipt.runtime_operation_name.endswith("job-1")
    resource, config = client.calls[0]
    assert resource.endswith("reasoningEngines/workspace-v1")
    query = json.loads(config["query"])
    assert WorkspaceTaskInvocation.model_validate_json(query["input"]["message"]) == invocation
    assert config["output_gcs_uri"].endswith(f"workspace-runs/{invocation.run_id}.json")


def test_workspace_runtime_rejects_expired_and_incomplete_attempts() -> None:
    with pytest.raises(TimeoutError, match="deadline"):
        runtime(FakeQueryJobs()).invoke_workspace(
            workspace_invocation(deadline=NOW - timedelta(seconds=1))
        )
    with pytest.raises(RuntimeError, match="incomplete"):
        runtime(FakeQueryJobs(QueryJobResult(None, None, None))).invoke_workspace(
            workspace_invocation()
        )


@pytest.mark.parametrize(
    ("candidate", "message"),
    [
        (
            dispatch(
                agent_resource="projects/other-demo/locations/europe-west1/reasoningEngines/e"
            ),
            "project",
        ),
        (
            # An unapproved location, so the guard has something to reject: the
            # approved region is europe-west1, and a counterexample equal to it
            # would assert nothing.
            dispatch(agent_resource="projects/solvan-demo/locations/us-east4/reasoningEngines/e"),
            "location",
        ),
        (dispatch(deadline=NOW - timedelta(seconds=1)), "deadline"),
    ],
)
def test_runtime_fails_closed_on_resource_or_deadline_widening(
    candidate: RuntimeDispatch, message: str
) -> None:
    with pytest.raises((ValueError, TimeoutError), match=message):
        runtime(FakeQueryJobs()).invoke(candidate)


def test_incomplete_runtime_receipt_preserves_every_returned_field() -> None:
    client = FakeQueryJobs(
        QueryJobResult(
            "projects/test/locations/europe-west1/reasoningEngineQueryJobs/job-partial",
            None,
            "gs://runtime/runs/run_output.json",
        )
    )
    with pytest.raises(IncompleteRuntimeReceiptError, match="incomplete") as caught:
        runtime(client).invoke(dispatch())
    assert caught.value.receipt.runtime_operation_name is not None
    assert caught.value.receipt.runtime_input_ref is None
    assert caught.value.receipt.runtime_output_ref == "gs://runtime/runs/run_output.json"


def test_runtime_rejects_provider_output_identity_drift() -> None:
    client = FakeQueryJobs(
        QueryJobResult(
            "projects/test/locations/europe-west1/reasoningEngineQueryJobs/job-drift",
            "gs://runtime/runs/run_input.json",
            "gs://hostile/other-run.json",
        )
    )
    with pytest.raises(IncompleteRuntimeReceiptError) as caught:
        runtime(client).invoke(dispatch())
    assert caught.value.error_class == "DISPATCH_OUTPUT_INVALID"
    assert caught.value.receipt.runtime_output_ref == "gs://hostile/other-run.json"


def test_incomplete_runtime_receipt_is_persisted_before_error_escapes() -> None:
    partial = PartialRuntimeInvocationReceipt(
        runtime_operation_name=(
            "projects/test/locations/europe-west1/reasoningEngineQueryJobs/job-partial"
        ),
        runtime_output_ref=(
            "gs://runtime/runs/org_00000000000000000000000000/"
            "prj_00000000000000000000000000/env_00000000000000000000000000/"
            "agent-runs/run_00000000000000000000000000.json"
        ),
    )

    class FailingRuntime:
        def invoke(self, _dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt:
            raise IncompleteRuntimeReceiptError(partial)

    class Workflow:
        @contextmanager
        def transaction(self):  # type: ignore[no-untyped-def]
            yield

    class Runs:
        persisted: PartialRuntimeInvocationReceipt | None = None

        def record_partial_receipt(self, **values: object) -> None:
            self.persisted = values["receipt"]  # type: ignore[assignment]

    runs = Runs()
    with pytest.raises(IncompleteRuntimeReceiptError):
        _invoke_with_partial_receipt(
            runtime=FailingRuntime(),  # type: ignore[arg-type]
            workflow=Workflow(),  # type: ignore[arg-type]
            runs=runs,  # type: ignore[arg-type]
            dispatch=dispatch(),
        )
    assert runs.persisted == partial


def test_runtime_checks_durable_query_job_and_requires_output() -> None:
    result = runtime(FakeQueryJobs()).check(
        "projects/solvan-demo/locations/europe-west1/operations/job-1"
    )
    assert result.status == "SUCCESS"
    assert result.result == '{"schema_version":1}'


def test_runtime_accepts_project_number_resource_from_platform_receipt() -> None:
    client = FakeQueryJobs()
    configured = GeminiAgentRuntime(
        config=AgentRuntimeConfiguration(
            "solvan-demo",
            "europe-west1",
            "gs://runtime/runs",
            gcp_project_number="123456789",
        ),
        client=client,
        clock=FixedClock(),
    )
    configured.invoke(
        dispatch(
            agent_resource=(
                "projects/123456789/locations/europe-west1/reasoningEngines/evidence-v1"
            )
        )
    )


def test_runtime_cancels_query_job_through_reasoning_engine() -> None:
    client = FakeQueryJobs()
    runtime(client).cancel(
        agent_resource=("projects/solvan-demo/locations/europe-west1/reasoningEngines/evidence-v1"),
        operation_name="projects/solvan-demo/locations/europe-west1/operations/job-1",
    )
    assert client.calls[-1][1] == {
        "operation_name": "projects/solvan-demo/locations/europe-west1/operations/job-1"
    }


@pytest.mark.parametrize(
    "provider_result",
    [
        '{"output":{"schema_version":1,"status":"SUCCEEDED"}}',
        (
            '[{"content":{"parts":[{"text":"{\\"schema_version\\":1,'
            '\\"status\\":\\"SUCCEEDED\\"}"}]}}]'
        ),
    ],
)
def test_query_job_output_extracts_only_final_structured_result(
    provider_result: str,
) -> None:
    assert json.loads(structured_query_output(provider_result)) == {
        "schema_version": 1,
        "status": "SUCCEEDED",
    }


def test_query_job_output_rejects_unstructured_final_text() -> None:
    with pytest.raises(ValueError, match="structured JSON"):
        structured_query_output('{"output":"looks good"}')
