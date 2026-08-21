"""Fixed S3 durable agent-budget and fallback fixture for Google Cloud."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg.types.json import Jsonb

from apps.coordinator.contracts import (
    governed_agent_bindings_from_environment,
    governed_agent_resources_from_environment,
)
from apps.coordinator.tool_binding import PostgresAgentRunBinder
from solvan.application import (
    AgentCompletion,
    AgentResultConflict,
    AgentResultCoordinator,
    AgentSemanticStatus,
    CoordinatorAuthority,
    FindingCommit,
    FindingKind,
    InvestigationCoordinator,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
)
from solvan.domain import (
    AgentLimit,
    InvestigationPlanProposal,
    InvestigationStepKind,
    PlanValidationPolicy,
    ProposedStep,
    Scope,
    StepBudget,
    new_identifier,
)
from solvan.persistence import (
    AggregateType,
    EvidenceWrite,
    PostgresEvidenceToolStore,
    PostgresInvestigationResultStore,
    PostgresInvestigationStore,
    PostgresRuntimeRunStore,
    PostgresWorkflowStore,
    ToolAuthorizationError,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from tools.scenario_jobs import _read_calibration, _required
from tools.scripted_scenario_contracts import validate_scenario_run_id
from tools.scripted_scenario_jobs import _allocate_display
from tools.seed_demo import GRAPH_ID, SERVICE_ID


class ScriptedRuntime:
    """Record coordinator dispatches without granting the fixture an agent identity."""

    def __init__(self) -> None:
        self.dispatches: list[RuntimeDispatch] = []

    def invoke(self, dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt:
        self.dispatches.append(dispatch)
        preserved = dispatch.context.get("preserved_evidence_refs", [])
        preserved_ref = None
        if isinstance(preserved, list) and preserved and isinstance(preserved[0], dict):
            candidate = preserved[0].get("evidence_ref")
            if isinstance(candidate, str):
                preserved_ref = f"db://solvan/evidence-items/{candidate}"
        return RuntimeInvocationReceipt(
            runtime_operation_name=(
                f"projects/{_required('SOLVAN_GCP_PROJECT')}/locations/europe-west1/"
                f"operations/scenario-s3-{len(self.dispatches)}"
            ),
            runtime_input_ref=preserved_ref or f"db://solvan/agent-runs/{dispatch.run_id}",
            runtime_output_ref=f"gs://{_required('SOLVAN_EVIDENCE_BUCKET')}/pending/{dispatch.run_id}",
        )


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _sha(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _seed_incident_and_supervisor(*, scope: Scope, run_id: str) -> tuple[str, str]:
    incident_id = new_identifier("inc")
    supervisor_id = new_identifier("run")
    marker = f"scenario:s3:{run_id}"
    with connect_database() as connection, connection.transaction(), connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan.incidents
              (organization_id, project_id, environment_id, id, display_id,
               state_machine_version, state, severity, incident_class,
               primary_service_id, production_graph_snapshot_id, detected_at,
               detection_rule_id, detection_rule_version, deduplication_key,
               action_budget, repeated_action_limit)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                %(incident_id)s, %(display_id)s, '1', 'INVESTIGATING', 'SEV2',
                'connection_exhaustion', %(service_id)s, %(graph_id)s, now(),
                'payments-http-5xx-v1', 1, %(marker)s, 2, 1)""",
            {
                **scope.canonical_dict(),
                "incident_id": incident_id,
                "display_id": _allocate_display(cursor, scope=scope, entity_type="INC"),
                "service_id": SERVICE_ID,
                "graph_id": GRAPH_ID,
                "marker": marker,
            },
        )
        cursor.execute(
            """INSERT INTO solvan.agent_runs
              (organization_id, project_id, environment_id, id, incident_id,
               logical_step_key, agent_key, agent_resource, agent_revision,
               invocation_id, workflow_version, attempt, status, deadline,
               budget_json, input_ref, input_hash, output_ref, output_hash,
               started_at, completed_at)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                %(supervisor_id)s, %(incident_id)s, %(logical_key)s,
                'incident-supervisor', %(resource)s, 'scenario-supervisor-v1',
                %(invocation_id)s, 1, 1, 'SUCCEEDED', now() + interval '5 minutes',
                %(budget)s, %(input_ref)s, %(input_hash)s, %(output_ref)s,
                %(output_hash)s, now(), now())""",
            {
                **scope.canonical_dict(),
                "supervisor_id": supervisor_id,
                "incident_id": incident_id,
                "logical_key": f"{marker}:supervisor",
                "resource": (
                    f"projects/{_required('SOLVAN_GCP_PROJECT')}/locations/europe-west1/"
                    "reasoningEngines/scenario-supervisor"
                ),
                "invocation_id": new_identifier("inv"),
                "budget": Jsonb({}),
                "input_ref": f"scenario://s3/{run_id}/supervisor-input",
                "input_hash": _sha({"run_id": run_id, "kind": "supervisor-input"}),
                "output_ref": f"scenario://s3/{run_id}/supervisor-output",
                "output_hash": _sha({"run_id": run_id, "kind": "supervisor-output"}),
            },
        )
    return incident_id, supervisor_id


def _plan(*, project_id: str) -> tuple[InvestigationPlanProposal, PlanValidationPolicy]:
    budget = StepBudget(120_000, 2, 16_000)
    resource = (
        f"projects/{project_id}/locations/europe-west1/reasoningEngines/scenario-evidence-agent"
    )
    proposal = InvestigationPlanProposal(
        objective="prove bounded recovery from a looping evidence agent",
        completion_condition="fallback consumes preserved evidence and returns a cited result",
        uncertainties=("the first agent attempt may repeat a cached call",),
        steps=(
            ProposedStep(
                step_key="budget-loop-fallback",
                kind=InvestigationStepKind.INVOKE_AGENT,
                agent_key="evidence-agent",
                scope_ref="scope:payments",
                purpose="read one bounded metric and preserve it for one fallback",
                required=True,
                depends_on=(),
                budget=budget,
                fallback_ref="strategy://preserve-evidence-once",
            ),
        ),
    )
    policy = PlanValidationPolicy(
        agent_limits={
            "evidence-agent": AgentLimit(
                agent_resource=resource,
                agent_revision="scenario-evidence-v1",
                maximum=budget,
                allowed_scope_refs=frozenset({"scope:payments"}),
                allowed_tool_names=("cloud_monitoring_query",),
            )
        },
        allowed_scope_refs=frozenset({"scope:payments"}),
        maximum_steps=1,
    )
    return proposal, policy


def _persist_evidence(
    *, store: PostgresEvidenceToolStore, connection: Any, dispatch: RuntimeDispatch
) -> str:
    arguments_hash = _sha({"signal_kind": "HTTP_5XX_RATIO", "fixture": "S3"})
    with connection.transaction():
        reservation = store.reserve(
            invocation_id=dispatch.invocation_id,
            expected_agent_key="evidence-agent",
            tool_name="cloud_monitoring_query",
            service_id=SERVICE_ID,
            arguments_hash=arguments_hash,
            input_bytes=64,
            otel_span_id="0000000000000001",
        )
    now = datetime.now(UTC)
    content = {
        "schema_version": 1,
        "kind": "SOLVAN_S3_PRESERVED_EVIDENCE",
        "observed_at": now.isoformat(),
        "value": {"signal_kind": "HTTP_5XX_RATIO", "value": 0.12},
    }
    receipt = GcsEvidenceWriter(
        bucket=_required("SOLVAN_EVIDENCE_BUCKET"), session=authorized_session()
    ).put_json(object_name=f"scenarios/{dispatch.run_id}/preserved-evidence.json", value=content)
    with connection.transaction():
        return store.complete(
            reservation=reservation,
            write=EvidenceWrite(
                source_kind="CLOUD_MONITORING",
                source_resource="scenario://s3/cloud-monitoring",
                query_spec={"signal_kind": "HTTP_5XX_RATIO", "fixture": "S3"},
                window_start=now - timedelta(minutes=1),
                window_end=now,
                observed_at=now,
                content_ref=receipt.uri,
                content_hash=receipt.content_hash,
                classification="INTERNAL",
                residency="europe-west1",
                redaction_manifest_ref="deterministic-s3-v1",
                provenance={"scenario": "S3", "request_ids": ["scripted-gcp-s3"]},
                freshness_expires_at=now + timedelta(minutes=5),
            ),
            output_bytes=len(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()),
        )


def _complete_fallback(
    *,
    scope: Scope,
    authority: CoordinatorAuthority,
    dispatch: RuntimeDispatch,
    evidence_id: str,
    connection: Any,
) -> None:
    if dispatch.incident_id is None:
        raise RuntimeError("S3 fallback dispatch lost its incident anchor")
    output = GcsEvidenceWriter(
        bucket=_required("SOLVAN_EVIDENCE_BUCKET"), session=authorized_session()
    ).put_json(
        object_name=f"scenarios/{dispatch.run_id}/fallback-output.json",
        value={"schema_version": 1, "evidence_refs": [evidence_id], "status": "SUCCEEDED"},
    )
    completion = AgentCompletion(
        agent_resource=dispatch.agent_resource,
        agent_revision=dispatch.agent_revision,
        invocation_id=dispatch.invocation_id,
        incident_id=dispatch.incident_id,
        workflow_version=dispatch.workflow_version,
        input_scope_hash=dispatch.input_hash,
        output_ref=output.uri,
        output_hash=output.content_hash,
        output_size_bytes=100,
        semantic_status=AgentSemanticStatus.SUCCEEDED,
        summary="Fallback consumed the preserved bounded metric.",
        evidence_refs=(evidence_id,),
        findings=(
            FindingCommit(
                finding_key="s3-preserved-evidence-consumed",
                kind=FindingKind.OBSERVATION,
                statement="The fallback cited the evidence retained by the failed attempt.",
                evidence_refs=(evidence_id,),
            ),
        ),
        completed_at=datetime.now(UTC),
        trace_id=dispatch.trace_id,
    )
    AgentResultCoordinator(PostgresInvestigationResultStore(connection)).complete(
        scope=scope, authority=authority, completion=completion
    )


def inject_s3() -> bool:
    """Exercise the real durable budget, retry, evidence, and stale-write fences."""

    run_id = validate_scenario_run_id(_required("SOLVAN_SCENARIO_RUN_ID"))
    _read_calibration(authorized_session())
    scope = _scope()
    incident_id, supervisor_id = _seed_incident_and_supervisor(scope=scope, run_id=run_id)
    runtime = ScriptedRuntime()
    evidence_id = ""
    stale_output_fenced = False
    with connect_database() as connection:
        workflow = PostgresWorkflowStore(connection)
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=scope,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner=f"scenario-s3-{run_id}",
                lease_ttl_ms=120_000,
            )
        if lease is None:
            raise RuntimeError("S3 could not acquire the isolated incident lease")
        authority = CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version)
        store = PostgresInvestigationStore(connection)
        binder = PostgresAgentRunBinder(
            region=_required("SOLVAN_GCP_REGION"),
            bindings=governed_agent_bindings_from_environment(
                agent_resources=governed_agent_resources_from_environment()
            ),
            connection=connection,
        )
        proposal, policy = _plan(project_id=_required("SOLVAN_GCP_PROJECT"))
        try:
            InvestigationCoordinator(store, runtime, binder).accept_supervisor_plan(
                scope=scope,
                incident_id=incident_id,
                supervisor_run_id=supervisor_id,
                authority=authority,
                proposal=proposal,
                policy=policy,
            )
            InvestigationCoordinator(store, runtime, binder).dispatch_ready_steps(
                scope=scope, incident_id=incident_id, authority=authority
            )
            first = runtime.dispatches[0]
            evidence_store = PostgresEvidenceToolStore(connection)
            evidence_id = _persist_evidence(
                store=evidence_store, connection=connection, dispatch=first
            )
            with connection.transaction():
                cached = evidence_store.reserve(
                    invocation_id=first.invocation_id,
                    expected_agent_key="evidence-agent",
                    tool_name="cloud_monitoring_query",
                    service_id=SERVICE_ID,
                    arguments_hash=_sha({"signal_kind": "HTTP_5XX_RATIO", "fixture": "S3"}),
                    input_bytes=64,
                    otel_span_id="0000000000000002",
                )
            if cached.existing_evidence_id != evidence_id:
                raise RuntimeError("S3 identical retry did not consume the cached evidence")
            try:
                with connection.transaction():
                    evidence_store.reserve(
                        invocation_id=first.invocation_id,
                        expected_agent_key="evidence-agent",
                        tool_name="cloud_monitoring_query",
                        service_id=SERVICE_ID,
                        arguments_hash=_sha({"signal_kind": "HTTP_5XX_RATIO", "fixture": "S3"}),
                        input_bytes=64,
                        otel_span_id="0000000000000003",
                    )
            except ToolAuthorizationError as error:
                if "budget is exhausted" not in str(error):
                    raise
            else:
                raise RuntimeError("S3 identical retry bypassed the durable tool budget")
            pending = next(
                item
                for item in PostgresRuntimeRunStore(connection).pending(scope=scope)
                if item.run_id == first.run_id
            )
            with workflow.transaction():
                PostgresRuntimeRunStore(connection).fail(
                    scope=scope, run=pending, error_class="TOOL_CALL_BUDGET_EXHAUSTED"
                )
            InvestigationCoordinator(store, runtime, binder).dispatch_ready_steps(
                scope=scope, incident_id=incident_id, authority=authority
            )
            if len(runtime.dispatches) != 2:
                raise RuntimeError("S3 did not create exactly one fallback attempt")
            fallback = runtime.dispatches[1]
            if first.incident_id is None:
                raise RuntimeError("S3 initial dispatch lost its incident anchor")
            if not any(
                isinstance(item, dict) and item.get("evidence_ref") == evidence_id
                for item in fallback.context.get("preserved_evidence_refs", [])
            ):
                raise RuntimeError("S3 fallback input omitted preserved evidence")
            _complete_fallback(
                scope=scope,
                authority=authority,
                dispatch=fallback,
                evidence_id=evidence_id,
                connection=connection,
            )
            stale = AgentCompletion(
                agent_resource=first.agent_resource,
                agent_revision=first.agent_revision,
                invocation_id=first.invocation_id,
                incident_id=first.incident_id,
                workflow_version=first.workflow_version,
                input_scope_hash=first.input_hash,
                output_ref=f"scenario://s3/{run_id}/late-output",
                output_hash=_sha({"run_id": run_id, "kind": "late-output"}),
                output_size_bytes=10,
                semantic_status=AgentSemanticStatus.SUCCEEDED,
                summary="late output must not commit",
                evidence_refs=(evidence_id,),
                findings=(),
                completed_at=datetime.now(UTC),
                trace_id=first.trace_id,
            )
            try:
                AgentResultCoordinator(PostgresInvestigationResultStore(connection)).complete(
                    scope=scope, authority=authority, completion=stale
                )
            except AgentResultConflict:
                stale_output_fenced = True
            if not stale_output_fenced:
                raise RuntimeError("S3 late output was not fenced")
        finally:
            with workflow.transaction():
                workflow.release_lease(scope=scope, lease=lease)
    document = {
        "schema_version": 1,
        "kind": "SOLVAN_S3_SCRIPTED_FIXTURE",
        "project_id": _required("SOLVAN_GCP_PROJECT"),
        "release_commit": _required("SOLVAN_RELEASE_COMMIT"),
        "deployment_id": _required("SOLVAN_DEPLOYMENT_ID"),
        "scenario_run_id": run_id,
        "injector_identity": _required("SOLVAN_INJECTOR_IDENTITY"),
        "incident_id": incident_id,
        "attempt_run_ids": [item.run_id for item in runtime.dispatches],
        "preserved_evidence_id": evidence_id,
        "stale_output_fenced": stale_output_fenced,
        "agent_visible": False,
        "completed_at": datetime.now(UTC).isoformat(),
    }
    receipt = GcsEvidenceWriter(
        bucket=_required("SOLVAN_EVIDENCE_BUCKET"), session=authorized_session()
    ).put_json(object_name=_required("SOLVAN_SCENARIO_OBJECT_NAME"), value=document)
    print(f"S3_FIXTURE_WRITTEN:{receipt.uri}")
    return True
