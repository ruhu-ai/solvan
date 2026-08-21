import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from solvan.application import (
    RemediationPlan,
    RemediationStep,
    RemediationStepKind,
    WorkspaceArtifactDescriptor,
    WorkspaceArtifactManifest,
    WorkspaceClassification,
    WorkspaceCognitionArtifact,
    WorkspaceHypothesisProposal,
    WorkspaceInputMaterial,
    WorkspaceKind,
    WorkspaceManifestEntry,
    WorkspaceModelProposal,
    WorkspaceProviderKind,
    WorkspaceSpec,
    WorkspaceTaskBudget,
    WorkspaceTaskCoordinator,
    WorkspaceTaskInvocation,
    WorkspaceTaskKind,
    WorkspaceTaskResult,
    WorkspaceTerminalStatus,
    canonical_sha256,
)
from solvan.domain import Scope


def _identifier(prefix: str, digit: str) -> str:
    return f"{prefix}_{digit * 26}"


def _artifact() -> WorkspaceArtifactDescriptor:
    material = _material()
    return WorkspaceArtifactDescriptor(
        artifact_handle="wah_" + "1" * 32,
        path="repository/app.py",
        object_ref="gs://solvan-fixture/workspaces/input/app.py",
        content_hash=material.content_hash,
        size_bytes=len(material.content.encode()),
        media_type="text/x-python",
        provenance_refs=("synthetic-fixture-v1",),
    )


def _material() -> WorkspaceInputMaterial:
    content = "return payment()\n"
    return WorkspaceInputMaterial(
        path="repository/app.py",
        content=content,
        content_hash=f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
        media_type="text/x-python",
    )


def _invocation(**changes: object) -> WorkspaceTaskInvocation:
    values: dict[str, object] = {
        "schema_version": 1,
        "request_id": _identifier("req", "1"),
        "run_id": _identifier("run", "2"),
        "invocation_id": _identifier("inv", "3"),
        "logical_step_key": "workspace:repair:synthetic-leak",
        "attempt": 1,
        "scope": Scope(_identifier("org", "4"), _identifier("prj", "5"), _identifier("env", "6")),
        "workspace_id": _identifier("wsp", "7"),
        "workspace_generation": 1,
        "task_kind": WorkspaceTaskKind.REPAIR,
        "provider": WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
        "provider_resource": "https://antigravity.example.run.app",
        "provider_revision": "antigravity-workspace-20260808-01",
        "implementation_sdk_distribution_hash": f"sha256:{'8' * 64}",
        "provider_artifact_digest": f"sha256:{'9' * 64}",
        "workflow_version": 3,
        "deadline": datetime.now(UTC) + timedelta(minutes=5),
        "budget": WorkspaceTaskBudget(
            max_runtime_seconds=120,
            max_model_calls=3,
            max_tool_calls=4,
            max_input_bytes=50_000,
            max_output_bytes=100_000,
        ),
        "input_manifest_ref": "gs://solvan-fixture/workspaces/input/manifest.json",
        "input_manifest_hash": f"sha256:{'b' * 64}",
        "effective_tool_set_hash": f"sha256:{'c' * 64}",
        "effective_network_policy_hash": f"sha256:{'d' * 64}",
        "allowed_tool_names": ("read_workspace_artifact", "write_candidate_artifact"),
        "input_artifacts": (_artifact(),),
        "input_materials": (_material(),),
        "objective": "Repair the deterministic synthetic connection leak.",
        "task_parameters": {
            "base_commit_sha": "a" * 40,
            "reproduction_command": "pytest -q tests/test_app.py",
            "test_command": "pytest -q tests/test_app.py",
            "allowed_file_globs": ["*.py", "tests/*.py"],
        },
        "trace_id": "e" * 32,
        "span_id": "f" * 16,
    }
    values.update(changes)
    return WorkspaceTaskInvocation.build(**values)


def _result(invocation: WorkspaceTaskInvocation, **changes: object) -> WorkspaceTaskResult:
    values: dict[str, object] = {
        "schema_version": 1,
        "request_id": invocation.request_id,
        "request_hash": invocation.request_hash,
        "run_id": invocation.run_id,
        "invocation_id": invocation.invocation_id,
        "workspace_id": invocation.workspace_id,
        "workspace_generation": invocation.workspace_generation,
        "task_kind": invocation.task_kind,
        "provider": invocation.provider,
        "provider_revision": invocation.provider_revision,
        "provider_service_revision": "antigravity-workspace-00001-x7p",
        "provider_boot_hash": f"sha256:{'1' * 64}",
        "implementation_sdk": "google-antigravity",
        "implementation_sdk_version": "0.1.10",
        "implementation_sdk_distribution_hash": (invocation.implementation_sdk_distribution_hash),
        "provider_artifact_digest": invocation.provider_artifact_digest,
        "input_manifest_hash": invocation.input_manifest_hash,
        "effective_tool_set_hash": invocation.effective_tool_set_hash,
        "effective_network_policy_hash": invocation.effective_network_policy_hash,
        "budget": invocation.budget,
        "terminal_status": WorkspaceTerminalStatus.SUCCEEDED,
        "summary": "A bounded candidate patch was produced.",
        "mechanism": "The synthetic checkout retained a connection after the request.",
        "base_commit_sha": "a" * 40,
        "unified_diff": "diff --git a/app.py b/app.py\n",
        "reproduction_command": "pytest -q tests/test_app.py",
        "test_command": "pytest -q tests/test_app.py",
        "hypotheses": (
            WorkspaceHypothesisProposal(
                hypothesis_key="connection-not-released",
                statement="The handler retains a connection.",
                supporting_citations=("repository/app.py:1",),
                contradicting_citations=("repository/app.py:2",),
                leading=True,
            ),
            WorkspaceHypothesisProposal(
                hypothesis_key="pool-capacity-only",
                statement="The pool may only be undersized.",
                supporting_citations=("repository/app.py:2",),
                contradicting_citations=(),
                leading=False,
            ),
        ),
        "artifacts": (),
        "tool_receipts": (),
        "citations": ("repository/app.py:1",),
        "residual_risks": (),
        "output_ref": "gs://solvan-fixture/workspaces/results/result.json",
        "completed_at": datetime.now(UTC),
        "trace_id": invocation.trace_id,
        "span_id": invocation.span_id,
    }
    values.update(changes)
    return WorkspaceTaskResult.build(**values)


def test_workspace_invocation_hash_is_canonical_and_tamper_evident() -> None:
    invocation = _invocation()
    assert invocation.request_hash == canonical_sha256(
        invocation.model_dump(mode="json", exclude={"request_hash"})
    )
    tampered = invocation.model_dump(mode="python")
    tampered["objective"] = "Read production secrets."
    with pytest.raises(ValidationError, match="request hash"):
        WorkspaceTaskInvocation.model_validate(tampered)


def test_result_is_fenced_to_the_exact_durable_request() -> None:
    invocation = _invocation()
    result = _result(invocation)
    result.assert_matches(invocation)
    other = _invocation(workspace_generation=2)
    with pytest.raises(ValueError, match="durable request"):
        result.assert_matches(other)


def test_model_cannot_smuggle_trusted_result_fields_or_partial_patch() -> None:
    invocation = _invocation()
    result = _result(invocation)
    with pytest.raises(ValidationError, match="extra_forbidden"):
        WorkspaceTaskResult.model_validate({**result.model_dump(), "callback_url": "https://evil"})
    with pytest.raises(ValidationError, match="mechanism, base, diff, reproduction, and test"):
        _result(invocation, unified_diff=None)


def test_successful_repair_requires_mechanism_and_contradiction() -> None:
    invocation = _invocation()
    with pytest.raises(ValidationError, match="requires mechanism"):
        _result(invocation, mechanism=None)
    hypotheses = tuple(
        hypothesis.model_copy(update={"contradicting_citations": ()})
        for hypothesis in _result(invocation).hypotheses
    )
    with pytest.raises(ValidationError, match="contradiction evidence"):
        _result(invocation, hypotheses=hypotheses)


def test_cognition_artifact_binds_hypotheses_to_cited_evidence() -> None:
    invocation = _invocation()
    hypotheses = _result(invocation).hypotheses
    citations = tuple(
        dict.fromkeys(
            citation
            for hypothesis in hypotheses
            for citation in (
                *hypothesis.supporting_citations,
                *hypothesis.contradicting_citations,
            )
        )
    )
    values = {
        "trust_class": "PROPOSED",
        "workspace_id": invocation.workspace_id,
        "workspace_generation": invocation.workspace_generation,
        "agent_run_id": invocation.run_id,
        "confirmed_fast_lane_cause_id": _identifier("hyp", "1"),
        "mechanism": "The exceptional path retains a connection.",
        "hypotheses": hypotheses,
        "reproduction_command": "pytest -q tests/test_app.py",
        "citations": citations,
    }
    artifact = WorkspaceCognitionArtifact.model_validate(values)
    assert artifact.trust_class == "PROPOSED"
    with pytest.raises(ValidationError, match="present in cognition citations"):
        WorkspaceCognitionArtifact.model_validate({**values, "citations": (citations[0],)})
    with pytest.raises(ValidationError, match="unique"):
        WorkspaceCognitionArtifact.model_validate(
            {**values, "citations": (*citations, citations[0])}
        )


def test_antigravity_workspace_is_public_synthetic_attested_only() -> None:
    common = {
        "scope": Scope(_identifier("org", "1"), _identifier("prj", "2"), _identifier("env", "3")),
        "workspace_id": _identifier("wsp", "4"),
        "kind": WorkspaceKind.SERVICE,
        "service_id": _identifier("svc", "5"),
        "provider": WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
        "implementation_sdk": "google-antigravity",
        "implementation_sdk_version": "0.1.10",
        "provider_revision": "release-1",
        "registry_agent_key": "antigravity-workspace-provider",
        "provider_agent_resource": "run://antigravity-workspace",
        "provider_service_identity": "serviceAccount:antigravity@project.iam.gserviceaccount.com",
        "implementation_sdk_distribution_hash": f"sha256:{'1' * 64}",
        "provider_artifact_digest": f"sha256:{'2' * 64}",
        "effective_network_policy_hash": f"sha256:{'3' * 64}",
        "classification": WorkspaceClassification.PUBLIC,
        "synthetic": True,
        "synthetic_attestation_ref": "gs://solvan-fixture/attestation.json",
        "synthetic_attestation_hash": f"sha256:{'4' * 64}",
        "provider_eligibility_decision_id": _identifier("pol", "6"),
        "artifact_prefix": "gs://solvan-fixture/workspaces/wsp/",
        "input_manifest_ref": "gs://solvan-fixture/workspaces/input.json",
        "input_manifest_hash": f"sha256:{'5' * 64}",
        "created_by_principal": "coordinator@solvan",
    }
    WorkspaceSpec.model_validate(common)
    with pytest.raises(ValidationError, match="public synthetic"):
        WorkspaceSpec.model_validate({**common, "classification": "CONFIDENTIAL"})


def test_artifact_paths_reject_traversal() -> None:
    with pytest.raises(ValidationError, match="traversal-free"):
        WorkspaceArtifactDescriptor.model_validate(
            {**_artifact().model_dump(), "path": "../secret.txt"}
        )


def test_checkpoint_manifest_requires_complete_parent_lineage() -> None:
    entry = WorkspaceManifestEntry(
        path="repair.patch",
        object_ref="gs://solvan-fixture/workspaces/output/repair.patch",
        content_hash=f"sha256:{'a' * 64}",
        size_bytes=10,
        media_type="text/x-diff",
        provenance_refs=("gs://solvan-fixture/workspaces/result.json",),
    )
    values = {
        "manifest_kind": "CHECKPOINT",
        "workspace_id": _identifier("wsp", "1"),
        "workspace_generation": 1,
        "checkpoint_sequence": 1,
        "classification": WorkspaceClassification.PUBLIC,
        "synthetic": True,
        "entries": (entry,),
        "created_by": "serviceAccount:coordinator@example.iam.gserviceaccount.com",
        "created_at": datetime.now(UTC),
    }
    with pytest.raises(ValidationError, match="complete parent lineage"):
        WorkspaceArtifactManifest.model_validate(values)
    manifest = WorkspaceArtifactManifest.model_validate(
        {
            **values,
            "parent_manifest_ref": "gs://solvan-fixture/workspaces/input.json",
            "parent_manifest_hash": f"sha256:{'b' * 64}",
        }
    )
    assert manifest.checkpoint_sequence == 1


class FakeWorkspaceRepository:
    def __init__(self) -> None:
        self.events: list[str] = []

    def create_task(self, invocation: WorkspaceTaskInvocation) -> None:
        self.events.append(f"create:{invocation.request_id}")

    def mark_dispatched(self, invocation: WorkspaceTaskInvocation) -> None:
        self.events.append(f"dispatch:{invocation.request_id}")

    def complete_task(
        self, *, invocation: WorkspaceTaskInvocation, result: WorkspaceTaskResult
    ) -> None:
        self.events.append(f"complete:{result.request_id}")

    def fail_task(self, invocation: WorkspaceTaskInvocation, *, error_class: str) -> None:
        self.events.append(f"fail:{error_class}")


class FakeWorkspaceProvider:
    def __init__(self, result: WorkspaceTaskResult | None = None) -> None:
        self.result = result

    async def execute(self, invocation: WorkspaceTaskInvocation) -> WorkspaceTaskResult:
        if self.result is None:
            raise RuntimeError("provider unavailable")
        return self.result


def test_workspace_coordinator_persists_before_network_and_never_fails_over() -> None:
    invocation = _invocation()
    repository = FakeWorkspaceRepository()
    coordinator = WorkspaceTaskCoordinator(
        repository=repository,
        providers={invocation.provider: FakeWorkspaceProvider(_result(invocation))},
    )
    result = asyncio.run(coordinator.execute(invocation))
    assert result.request_id == invocation.request_id
    assert repository.events == [
        f"create:{invocation.request_id}",
        f"dispatch:{invocation.request_id}",
        f"complete:{invocation.request_id}",
    ]

    unavailable_repository = FakeWorkspaceRepository()
    unavailable = WorkspaceTaskCoordinator(repository=unavailable_repository, providers={})
    with pytest.raises(ValueError, match="unavailable"):
        asyncio.run(unavailable.execute(invocation))
    assert unavailable_repository.events == [
        f"create:{invocation.request_id}",
        "fail:WORKSPACE_PROVIDER_UNAVAILABLE",
    ]

    failed_repository = FakeWorkspaceRepository()
    failed = WorkspaceTaskCoordinator(
        repository=failed_repository,
        providers={invocation.provider: FakeWorkspaceProvider()},
    )
    with pytest.raises(RuntimeError, match="provider unavailable"):
        asyncio.run(failed.execute(invocation))
    assert failed_repository.events == [
        f"create:{invocation.request_id}",
        f"dispatch:{invocation.request_id}",
        "fail:WORKSPACE_PROVIDER_RuntimeError",
    ]


def _step(**changes: object) -> RemediationStep:
    values: dict[str, object] = {
        "kind": RemediationStepKind.RUNBOOK,
        "ordinal": 1,
        "title": "Drain and recycle the payments pool",
        "rationale": "Utilization held above 90% for 4m30s against a 41% baseline.",
        "citations": ("evd_00000000000000000000000002",),
        "steps": ("Drain the pool", "Confirm utilization falls below baseline"),
    }
    return RemediationStep(**{**values, **changes})  # type: ignore[arg-type]


def test_a_remediation_step_cannot_claim_one_kind_and_carry_another() -> None:
    """Specification 12 §7.2: the kind decides which material must be present.

    A step that declares itself a runbook while carrying a unified diff, or an
    action request with no payload, is the shape a reviewer would approve
    without reading — so the contract refuses it rather than the reviewer.
    """

    assert _step().kind is RemediationStepKind.RUNBOOK

    with pytest.raises(ValidationError, match="base commit, diff, reproduction"):
        _step(kind=RemediationStepKind.PATCH, steps=())
    with pytest.raises(ValidationError, match="cannot carry patch or action material"):
        _step(unified_diff="--- a/x\n+++ b/x\n")
    with pytest.raises(ValidationError, match="action type and payload"):
        _step(
            kind=RemediationStepKind.ENUMERATED_ACTION_REQUEST,
            steps=(),
            action_type="CLOUD_RUN_TRAFFIC_ROLLBACK",
        )
    with pytest.raises(ValidationError, match="cannot carry patch or procedure material"):
        _step(
            kind=RemediationStepKind.ENUMERATED_ACTION_REQUEST,
            action_type="CLOUD_RUN_TRAFFIC_ROLLBACK",
            action_payload_json="{}",
        )


def test_an_action_request_must_name_a_real_action_with_a_parsable_payload() -> None:
    """A proposal that could never become an action is a defect where it is written.

    Accepting any string meant a step could request NOT_AN_ACTION_TYPE carrying
    prose, and nothing noticed until something downstream tried to build
    authorized action material from it — by which point a reviewer had already
    been shown it.
    """

    request = _step(
        kind=RemediationStepKind.ENUMERATED_ACTION_REQUEST,
        steps=(),
        action_type="CLOUD_RUN_TRAFFIC_ROLLBACK",
        action_payload_json='{"service_name": "payments-api", "percent": 100}',
    )
    assert request.action_type == "CLOUD_RUN_TRAFFIC_ROLLBACK"

    with pytest.raises(ValidationError, match="names no enumerated action type"):
        _step(
            kind=RemediationStepKind.ENUMERATED_ACTION_REQUEST,
            steps=(),
            action_type="NOT_AN_ACTION_TYPE",
            action_payload_json="{}",
        )
    with pytest.raises(ValidationError, match="payload must be JSON"):
        _step(
            kind=RemediationStepKind.ENUMERATED_ACTION_REQUEST,
            steps=(),
            action_type="CLOUD_RUN_TRAFFIC_ROLLBACK",
            action_payload_json="roll it back please",
        )
    with pytest.raises(ValidationError, match="payload must be a JSON object"):
        _step(
            kind=RemediationStepKind.ENUMERATED_ACTION_REQUEST,
            steps=(),
            action_type="CLOUD_RUN_TRAFFIC_ROLLBACK",
            action_payload_json="[1, 2]",
        )
    with pytest.raises(ValidationError, match="expected observations"):
        _step(
            kind=RemediationStepKind.ENUMERATED_ACTION_REQUEST,
            steps=(),
            action_type="CLOUD_RUN_TRAFFIC_ROLLBACK",
            action_payload_json="{}",
            expected_observations=("error ratio returns to baseline",),
        )
    with pytest.raises(ValidationError, match="must cite its evidence"):
        _step(citations=())


def test_a_remediation_plan_is_ordered_and_never_empty() -> None:
    plan = RemediationPlan(steps=(_step(), _step(ordinal=2, title="Then verify")))
    assert [step.ordinal for step in plan.steps] == [1, 2]

    with pytest.raises(ValidationError):
        RemediationPlan(steps=())
    with pytest.raises(ValidationError, match="ordered from one without gaps"):
        RemediationPlan(steps=(_step(ordinal=2),))


def test_a_workspace_cannot_report_a_state_the_durable_record_cannot_hold() -> None:
    """Specification 12 §7.3 is declared, not implemented.

    `agent_runs.status` has no parked state, so `complete_task` maps every
    non-`SUCCEEDED` terminal status to a failed run. A workspace that could
    return `AWAITING_CLARIFICATION` would therefore have its task killed rather
    than parked, which is worse than being unable to ask. The status stays out
    of the contract, and out of the provider response schema it generates, until
    the durable park exists to receive it.
    """

    assert "AWAITING_CLARIFICATION" not in set(WorkspaceTerminalStatus)
    schema = json.dumps(WorkspaceModelProposal.model_json_schema())
    assert "AWAITING_CLARIFICATION" not in schema
    assert "clarification" not in schema

    for status in WorkspaceTerminalStatus:
        if status is WorkspaceTerminalStatus.SUCCEEDED:
            continue
        proposal = WorkspaceModelProposal(
            terminal_status=status,
            summary="Reached a terminal state the durable run can record.",
            hypotheses=(),
            citations=("evd_00000000000000000000000002",),
            residual_risks=(),
        )
        assert proposal.terminal_status is status
