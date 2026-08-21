from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from solvan.agents import (
    AgentBuildConfig,
    AgentInvocation,
    AgentOutput,
    InvocationBudget,
    TraceContext,
    build_evidence_agent,
    build_incident_supervisor,
    build_workspace_agent,
    parse_agent_result,
    parse_runtime_agent_output,
    parse_supervisor_plan,
    parse_workspace_model_proposal,
)
from solvan.agents.read_tools import cloud_monitoring_query
from solvan.application import WorkspaceModelProposal, WorkspaceTaskInvocation
from solvan.domain import AgentLimit, PlanValidationPolicy, StepBudget
from solvan.persistence import AgentRunMaterial


def invocation(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "invocation_id": "inv_00000000000000000000000000",
        "logical_step_key": "incident:test:collect",
        "organization_id": "org_00000000000000000000000000",
        "project_id": "prj_00000000000000000000000000",
        "environment_id": "env_00000000000000000000000000",
        "incident_id": "inc_00000000000000000000000000",
        "reliability_case_id": None,
        "workflow_version": 2,
        "deadline": datetime(2026, 8, 8, 12, tzinfo=UTC),
        "budget": InvocationBudget(
            max_runtime_seconds=60,
            max_model_calls=1,
            max_tool_calls=1,
            max_output_bytes=16_000,
            max_replans=0,
        ),
        "evidence_refs": (),
        "allowed_tool_names": ("cloud_monitoring_query",),
        "input_payload": {"scope_ref": "scope:payments"},
        "trace_context": TraceContext(trace_id="0" * 32, span_id="1" * 16, trace_flags="01"),
    }
    value.update(changes)
    return value


def test_invocation_requires_one_owner_and_forbids_authority_fields() -> None:
    assert AgentInvocation.model_validate(invocation()).incident_id is not None
    with pytest.raises(ValidationError, match="exactly one"):
        AgentInvocation.model_validate(invocation(incident_id=None))
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AgentInvocation.model_validate(invocation(action_id="act_forbidden"))


def test_agent_output_cannot_smuggle_actions_or_permissions() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AgentOutput.model_validate(
            {
                "schema_version": 1,
                "status": "INSUFFICIENT_EVIDENCE",
                "summary": "No bounded evidence was available.",
                "action": "restart-everything",
            }
        )


def test_adk_agents_are_single_turn_and_do_not_delegate() -> None:
    config = AgentBuildConfig("gemini-3.6-flash", 60, 1_024)
    supervisor = build_incident_supervisor(config)
    evidence = build_evidence_agent(config, tools=[cloud_monitoring_query])

    assert supervisor.tools == []
    assert supervisor.disallow_transfer_to_peers
    assert evidence.mode == "single_turn"
    assert evidence.output_schema is AgentOutput


def test_workspace_agent_has_no_tools_and_output_cannot_claim_test_success() -> None:
    agent = build_workspace_agent(AgentBuildConfig("gemini-3.6-flash", 60, 1_024))
    assert agent.tools == []
    assert agent.input_schema is WorkspaceTaskInvocation
    assert agent.output_schema is WorkspaceModelProposal
    output = parse_workspace_model_proposal(
        b'{"schema_version":1,"terminal_status":"SUCCEEDED",'
        b'"base_commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"unified_diff":"diff --git a/a.py b/a.py\\n",'
        b'"reproduction_command":"pytest -q tests/test_a.py",'
        b'"test_command":"pytest -q tests/test_a.py",'
        b'"summary":"Proposed a bounded repair.",'
        b'"mechanism":"The fixture leaks one connection.",'
        b'"hypotheses":[{"hypothesis_key":"connection-leak",'
        b'"statement":"The error path leaks a connection.",'
        b'"supporting_citations":["repository/a.py:1"],'
        b'"contradicting_citations":["repository/a.py:2"],"leading":true},'
        b'{"hypothesis_key":"pool-capacity","statement":"The pool is too small.",'
        b'"supporting_citations":["repository/a.py:2"],'
        b'"contradicting_citations":[],"leading":false}],'
        b'"candidate_artifact_paths":[],"citations":["repository/a.py:1"],'
        b'"residual_risks":[]}'
    )
    assert output.terminal_status.value == "SUCCEEDED"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        WorkspaceModelProposal.model_validate(
            {
                **output.model_dump(),
                "tests_passed": True,
            }
        )


def test_strict_agent_envelope_maps_to_application_commit() -> None:
    raw = b"""{
      "schema_version":1,
      "agent_resource":"projects/solvan-demo/locations/europe-west1/reasoningEngines/evidence-v1",
      "agent_revision":"evidence-20260808-01",
      "invocation_id":"inv_00000000000000000000000000",
      "incident_id":"inc_00000000000000000000000000",
      "reliability_case_id":null,
      "workflow_version":2,
      "input_scope_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "output":{
        "schema_version":1,
        "status":"SUCCEEDED",
        "summary":"Bounded evidence was collected.",
        "evidence_refs":["evd_00000000000000000000000000"],
        "findings":[{
          "finding_key":"elevated-errors",
          "kind":"OBSERVATION",
          "statement":"The approved error signal exceeded its threshold.",
          "evidence_refs":["evd_00000000000000000000000000"],
          "confidence":null,
          "contradiction_refs":[]
        }],
        "unresolved_questions":[]
      },
      "completed_at":"2026-08-08T12:00:00Z",
      "trace_id":"00000000000000000000000000000000"
    }"""
    completion = parse_agent_result(raw, output_ref="gs://runtime/output.json")

    assert completion.output_size_bytes == len(raw)
    assert completion.findings[0].finding_key == "elevated-errors"
    assert completion.output_hash.startswith("sha256:")


def test_query_job_agent_output_is_bound_to_stored_attempt_material() -> None:
    raw = b"""{
      "schema_version":1,
      "status":"SUCCEEDED",
      "summary":"The metric exceeded the approved threshold.",
      "evidence_refs":["evd_00000000000000000000000000"],
      "findings":[{
        "finding_key":"elevated-errors",
        "kind":"OBSERVATION",
        "statement":"Error ratio is elevated.",
        "evidence_refs":["evd_00000000000000000000000000"],
        "confidence":null,
        "contradiction_refs":[]
      }],
      "unresolved_questions":[]
    }"""
    completion = parse_runtime_agent_output(
        raw,
        material=AgentRunMaterial(
            agent_resource=("projects/123/locations/europe-west1/reasoningEngines/evidence-v1"),
            agent_revision="release-1",
            invocation_id="inv_00000000000000000000000000",
            incident_id="inc_00000000000000000000000000",
            workflow_version=2,
            input_hash=f"sha256:{'a' * 64}",
            output_ref="gs://runtime/result.json",
            trace_id="0" * 32,
        ),
        completed_at=datetime(2026, 8, 8, 12, tzinfo=UTC),
    )
    assert completion.agent_revision == "release-1"
    assert completion.findings[0].evidence_refs == ("evd_00000000000000000000000000",)


def test_supervisor_output_receives_coordinator_owned_budgets() -> None:
    maximum = StepBudget(300_000, 10, 128_000, 4, 1)
    policy = PlanValidationPolicy(
        agent_limits={
            "evidence-agent": AgentLimit(
                "projects/123/locations/europe-west1/reasoningEngines/evidence-v1",
                "release-1",
                maximum,
                frozenset({"scope:primary-service"}),
                ("cloud_monitoring_query",),
            )
        },
        allowed_scope_refs=frozenset({"scope:primary-service"}),
        maximum_steps=4,
    )
    proposal = parse_supervisor_plan(
        b"""{
          "schema_version":1,
          "objective":"Explain the elevated error ratio.",
          "steps":[{
            "step_key":"metrics",
            "kind":"invoke_agent",
            "agent":"evidence-agent",
            "scope_ref":"scope:primary-service",
            "purpose":"Read the approved error metric.",
            "depends_on":[],
            "required":true,
            "fallback_ref":null
          }],
          "completion_condition":"Metric evidence is cited.",
          "uncertainties":[]
        }""",
        policy=policy,
    )
    assert proposal.steps[0].budget == maximum
