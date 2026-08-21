"""Agent Platform long-running query adapter used only by the coordinator."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import agentplatform  # type: ignore[import-untyped]

from solvan.application import (
    PartialRuntimeInvocationReceipt,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
    WorkspaceTaskInvocation,
)
from solvan.application.effective_tool_set import (
    EffectiveToolSetV1,
    accepted_step_budget_hash,
)
from solvan.domain import Scope

_RESOURCE = re.compile(
    r"^projects/(?P<project>(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]+))/"
    r"locations/(?P<location>[a-z0-9-]+)/reasoningEngines/(?P<engine>[A-Za-z0-9_-]+)$"
)


@dataclass(frozen=True, slots=True)
class QueryJobResult:
    job_name: str | None
    input_gcs_uri: str | None
    output_gcs_uri: str | None


@dataclass(frozen=True, slots=True)
class QueryJobCheck:
    operation_name: str
    output_gcs_uri: str | None
    status: str
    result: str | None


class QueryJobClient(Protocol):
    def run_query_job(self, *, name: str, config: dict[str, str]) -> QueryJobResult: ...

    def check_query_job(self, *, name: str, config: dict[str, bool]) -> QueryJobCheck: ...

    def cancel_query_job(self, *, name: str, config: dict[str, str]) -> None: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class IncompleteRuntimeReceiptError(RuntimeError):
    """Provider accepted the call but returned only part of its durable receipt."""

    def __init__(
        self,
        receipt: PartialRuntimeInvocationReceipt,
        *,
        error_class: str = "DISPATCH_RECEIPT_INCOMPLETE",
    ) -> None:
        super().__init__("Agent Runtime returned an incomplete durable job receipt")
        self.receipt = receipt
        self.error_class = error_class


@dataclass(frozen=True, slots=True)
class AgentRuntimeConfiguration:
    gcp_project_id: str
    location: str
    output_gcs_prefix: str
    gcp_project_number: str | None = None

    def __post_init__(self) -> None:
        if not self.gcp_project_id.strip() or not self.location.strip():
            raise ValueError("Agent Runtime project and location are required")
        if not self.output_gcs_prefix.startswith("gs://"):
            raise ValueError("Agent Runtime output prefix must be a GCS URI")
        if self.gcp_project_number is not None and not self.gcp_project_number.isdigit():
            raise ValueError("Agent Runtime project number must contain digits")


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class VertexAgentPlatformClient:
    """Thin typed wrapper around the current Agent Platform Python SDK."""

    def __init__(self, *, project: str, location: str) -> None:
        self._client = agentplatform.Client(project=project, location=location)

    def run_query_job(self, *, name: str, config: dict[str, str]) -> QueryJobResult:
        result = self._client.agent_engines.run_query_job(name=name, config=config)
        return QueryJobResult(
            job_name=cast(str | None, result.job_name),
            input_gcs_uri=cast(str | None, result.input_gcs_uri),
            output_gcs_uri=cast(str | None, result.output_gcs_uri),
        )

    def check_query_job(self, *, name: str, config: dict[str, bool]) -> QueryJobCheck:
        result = self._client.agent_engines.check_query_job(name=name, config=config)
        return QueryJobCheck(
            operation_name=cast(str, result.operation_name),
            output_gcs_uri=cast(str | None, result.output_gcs_uri),
            status=cast(str, result.status),
            result=cast(str | None, result.result),
        )

    def cancel_query_job(self, *, name: str, config: dict[str, str]) -> None:
        self._client.agent_engines.cancel_query_job(name=name, config=config)


class GeminiAgentRuntime:
    """Launch one idempotently named, bounded Runtime job for a durable attempt."""

    def __init__(
        self,
        *,
        config: AgentRuntimeConfiguration,
        client: QueryJobClient,
        clock: Clock | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._clock = clock or SystemClock()

    def invoke(self, dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt:
        self._validate_resource(dispatch.agent_resource)
        effective_tool_set = self._validate_effective_tool_set(dispatch)
        now = self._clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Runtime clock must be timezone-aware")
        remaining_seconds = math.ceil((dispatch.deadline - now).total_seconds())
        if remaining_seconds < 1:
            raise TimeoutError("agent attempt deadline elapsed before Runtime dispatch")
        if remaining_seconds > 4_200:
            raise ValueError("foreground Runtime dispatch exceeds the 70-minute ceiling")
        owner_payload = {
            "scope_ref": dispatch.scope_ref,
            "purpose": dispatch.purpose,
            "plan_id": dispatch.plan_id,
            "plan_version": dispatch.plan_version,
            "step_id": dispatch.step_id,
        }
        invocation: dict[str, Any] = {
            "schema_version": 1,
            "invocation_id": dispatch.invocation_id,
            "logical_step_key": dispatch.logical_step_key,
            **dispatch.scope.canonical_dict(),
            "incident_id": dispatch.incident_id,
            "reliability_case_id": None,
            "workflow_version": dispatch.workflow_version,
            "deadline": dispatch.deadline.isoformat(),
            "budget": {
                "max_runtime_seconds": remaining_seconds,
                "max_model_calls": dispatch.budget.max_model_calls,
                "max_tool_calls": dispatch.budget.max_tool_calls,
                "max_output_bytes": dispatch.budget.max_output_bytes,
                "max_replans": dispatch.budget.max_replans,
            },
            "evidence_refs": [],
            "allowed_tool_names": dispatch.allowed_tool_names,
            "effective_tool_set": effective_tool_set.canonical_dict(),
            "effective_tool_set_hash": effective_tool_set.effective_tool_set_hash,
            "input_payload": {
                **{
                    key: value
                    for key, value in dispatch.context.items()
                    if key not in {"effective_tool_set", "effective_tool_set_hash"}
                },
                **owner_payload,
            },
            "trace_context": {
                "trace_id": dispatch.trace_id,
                "span_id": dispatch.span_id,
                "trace_flags": "01",
            },
        }
        query = json.dumps(
            {
                "input": {
                    "user_id": dispatch.scope.environment_id,
                    "message": json.dumps(invocation, sort_keys=True, separators=(",", ":")),
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        output_uri = self.output_uri(scope=dispatch.scope, run_id=dispatch.run_id)
        result = self._client.run_query_job(
            name=dispatch.agent_resource,
            config={"query": query, "output_gcs_uri": output_uri},
        )
        if not result.job_name or not result.input_gcs_uri or not result.output_gcs_uri:
            raise IncompleteRuntimeReceiptError(
                PartialRuntimeInvocationReceipt(
                    runtime_operation_name=result.job_name,
                    runtime_input_ref=result.input_gcs_uri,
                    runtime_output_ref=result.output_gcs_uri,
                )
            )
        if result.output_gcs_uri != output_uri:
            raise IncompleteRuntimeReceiptError(
                PartialRuntimeInvocationReceipt(
                    runtime_operation_name=result.job_name,
                    runtime_input_ref=result.input_gcs_uri,
                    runtime_output_ref=result.output_gcs_uri,
                ),
                error_class="DISPATCH_OUTPUT_INVALID",
            )
        return RuntimeInvocationReceipt(
            runtime_operation_name=result.job_name,
            runtime_input_ref=result.input_gcs_uri,
            runtime_output_ref=result.output_gcs_uri,
        )

    @staticmethod
    def _validate_effective_tool_set(dispatch: RuntimeDispatch) -> EffectiveToolSetV1:
        material = dispatch.context.get("effective_tool_set")
        supplied_hash = dispatch.context.get("effective_tool_set_hash")
        if not isinstance(material, dict) or not isinstance(supplied_hash, str):
            raise ValueError("Runtime dispatch requires the canonical effective Tool set")
        effective = EffectiveToolSetV1.model_validate(material)
        if effective.effective_tool_set_hash != supplied_hash:
            raise ValueError("Runtime effective Tool-set digest does not match its preimage")
        if effective.scope != dispatch.scope.canonical_dict():
            raise ValueError("Runtime effective Tool set has another scope")
        if (effective.agent_key, effective.agent_revision) != (
            dispatch.agent_key,
            dispatch.agent_revision,
        ):
            raise ValueError("Runtime effective Tool set has another Agent revision")
        if tuple(tool.tool_key for tool in effective.accepted_tools) != dispatch.allowed_tool_names:
            raise ValueError("Runtime allowed Tools differ from the frozen effective set")
        if effective.accepted_step_budget_hash != accepted_step_budget_hash(dispatch.budget):
            raise ValueError("Runtime budget differs from the frozen effective Tool set")
        return effective

    def invoke_workspace(self, invocation: WorkspaceTaskInvocation) -> RuntimeInvocationReceipt:
        """Launch one provider-neutral Workspace Agent request on Agent Runtime."""

        self._validate_resource(invocation.provider_resource)
        if invocation.effective_tool_set is None:
            raise ValueError("workspace Runtime dispatch requires the effective Tool-set preimage")
        effective = invocation.effective_tool_set
        if effective.effective_tool_set_hash != invocation.effective_tool_set_hash:
            raise ValueError("workspace Runtime Tool-set digest does not match its preimage")
        if effective.scope != invocation.scope.canonical_dict():
            raise ValueError("workspace Runtime Tool set has another scope")
        if (effective.agent_key, effective.agent_revision) != (
            "workspace-agent",
            invocation.provider_revision,
        ):
            raise ValueError("workspace Runtime Tool set has another Agent revision")
        aliases = {
            "workspace.code-repair.read-artifact": "read_workspace_artifact",
            "workspace.code-repair.write-candidate-artifact": "write_candidate_artifact",
            "workspace.code-repair.run-in-sandbox": "run_in_exploratory_sandbox",
        }
        if tuple(aliases.get(tool.tool_key, "") for tool in effective.accepted_tools) != (
            invocation.allowed_tool_names
        ):
            raise ValueError("workspace Runtime tools differ from the frozen effective set")
        if effective.accepted_step_budget_hash != accepted_step_budget_hash(invocation.budget):
            raise ValueError("workspace Runtime budget differs from the frozen effective Tool set")
        now = self._clock.now()
        remaining_seconds = math.ceil((invocation.deadline - now).total_seconds())
        if remaining_seconds < 1:
            raise TimeoutError("workspace attempt deadline elapsed before Runtime dispatch")
        if remaining_seconds > 4_200:
            raise ValueError("workspace Runtime dispatch exceeds the 70-minute ceiling")
        query = json.dumps(
            {
                "input": {
                    "user_id": invocation.scope.environment_id,
                    "message": invocation.model_dump_json(),
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        output_uri = (
            f"{self._config.output_gcs_prefix.rstrip('/')}/"
            f"{invocation.scope.organization_id}/{invocation.scope.project_id}/"
            f"{invocation.scope.environment_id}/workspace-runs/{invocation.run_id}.json"
        )
        result = self._client.run_query_job(
            name=invocation.provider_resource,
            config={"query": query, "output_gcs_uri": output_uri},
        )
        if not result.job_name or not result.input_gcs_uri or not result.output_gcs_uri:
            raise IncompleteRuntimeReceiptError(
                PartialRuntimeInvocationReceipt(
                    runtime_operation_name=result.job_name,
                    runtime_input_ref=result.input_gcs_uri,
                    runtime_output_ref=result.output_gcs_uri,
                )
            )
        return RuntimeInvocationReceipt(
            runtime_operation_name=result.job_name,
            runtime_input_ref=result.input_gcs_uri,
            runtime_output_ref=result.output_gcs_uri,
        )

    def check(self, operation_name: str) -> QueryJobCheck:
        if not operation_name.startswith("projects/"):
            raise ValueError("Runtime operation name is not fully qualified")
        result = self._client.check_query_job(name=operation_name, config={"retrieve_result": True})
        if result.status not in {"RUNNING", "SUCCESS", "FAILED"}:
            raise RuntimeError("Agent Runtime returned an unknown query-job status")
        if result.status == "SUCCESS" and not result.result:
            raise RuntimeError("successful Agent Runtime job returned no output")
        return result

    def output_uri(self, *, scope: Scope, run_id: str) -> str:
        if not run_id.startswith("run_"):
            raise ValueError("Runtime run ID is invalid")
        return (
            f"{self._config.output_gcs_prefix.rstrip('/')}/"
            f"{scope.organization_id}/{scope.project_id}/"
            f"{scope.environment_id}/agent-runs/{run_id}.json"
        )

    def cancel(self, *, agent_resource: str, operation_name: str) -> None:
        self._validate_resource(agent_resource)
        if not operation_name.startswith("projects/"):
            raise ValueError("Runtime operation name is not fully qualified")
        self._client.cancel_query_job(
            name=agent_resource, config={"operation_name": operation_name}
        )

    def _validate_resource(self, agent_resource: str) -> re.Match[str]:
        match = _RESOURCE.fullmatch(agent_resource)
        if match is None:
            raise ValueError("agent resource is not an immutable reasoningEngine name")
        if match.group("project") not in {
            self._config.gcp_project_id,
            self._config.gcp_project_number,
        }:
            raise ValueError("agent resource project is outside the configured Runtime")
        if match.group("location") != self._config.location:
            raise ValueError("agent resource location is outside the configured Runtime")
        return match


def structured_query_output(result: str) -> bytes:
    """Extract only the final structured ADK output from a query-job response."""

    try:
        value = json.loads(result)
    except json.JSONDecodeError as error:
        raise ValueError("Agent Runtime result is not one JSON value") from error
    candidate: Any = value
    if isinstance(value, dict) and "output" in value:
        candidate = value["output"]
    elif isinstance(value, list):
        if not value:
            raise ValueError("Agent Runtime event list is empty")
        candidate = _event_text(value[-1])
    elif isinstance(value, dict) and "content" in value:
        candidate = _event_text(value)
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except json.JSONDecodeError as error:
            raise ValueError("final Agent Runtime text is not structured JSON") from error
    if not isinstance(candidate, dict):
        raise ValueError("final Agent Runtime output is not an object")
    return json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()


def _event_text(event: Any) -> str:
    if not isinstance(event, dict):
        raise ValueError("final Agent Runtime event is not an object")
    content = event.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        raise ValueError("final Agent Runtime event has no content parts")
    texts = [part.get("text") for part in parts if isinstance(part, dict) and part.get("text")]
    if len(texts) != 1 or not isinstance(texts[0], str):
        raise ValueError("final Agent Runtime event has no single text result")
    return texts[0]
