import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from apps.antigravity_workspace.main import (
    ALLOWED_TOOLS,
    TOOL_SET_HASH,
    ProviderSettings,
    WorkspaceMaterialTools,
    create_app,
)
from solvan.application import (
    WorkspaceArtifactDescriptor,
    WorkspaceArtifactManifest,
    WorkspaceCandidateArtifact,
    WorkspaceHypothesisProposal,
    WorkspaceInputMaterial,
    WorkspaceManifestEntry,
    WorkspaceModelProposal,
    WorkspaceProviderAttemptReceipt,
    WorkspaceProviderKind,
    WorkspaceRehydrationReceipt,
    WorkspaceRehydrationRequest,
    WorkspaceTaskBudget,
    WorkspaceTaskInvocation,
    WorkspaceTaskKind,
    WorkspaceTerminalStatus,
    canonical_sha256,
)
from solvan.domain import Scope


def _id(prefix: str, digit: str) -> str:
    return f"{prefix}_{digit * 26}"


class FixedClock:
    value = datetime(2026, 8, 8, 12, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value


class FakeVerifier:
    def __init__(self, email: str = "coordinator@solvan-demo.iam.gserviceaccount.com") -> None:
        self.email = email
        self.audience: str | None = None

    def verify(self, token: str, *, audience: str) -> dict[str, Any]:
        if token != "valid-token":
            raise ValueError("bad token")
        self.audience = audience
        return {"email": self.email, "email_verified": True}


class FakeRunner:
    async def run(
        self,
        invocation: WorkspaceTaskInvocation,
        *,
        settings: ProviderSettings,
        tools: WorkspaceMaterialTools,
    ) -> WorkspaceModelProposal:
        assert settings.region == "europe-west1"
        assert settings.model_location == "global"
        source = tools.read_workspace_artifact("repository/app.py")
        assert "leak" in source
        tools.write_candidate_artifact(
            "candidate/fix.diff",
            "diff --git a/app.py b/app.py\n",
            "text/x-diff",
        )
        return WorkspaceModelProposal(
            schema_version=1,
            terminal_status=WorkspaceTerminalStatus.SUCCEEDED,
            summary="Produced a bounded synthetic repair candidate.",
            mechanism="The synthetic handler does not release its connection.",
            base_commit_sha="a" * 40,
            unified_diff="diff --git a/app.py b/app.py\n",
            reproduction_command="pytest -q tests/test_app.py",
            test_command="pytest -q tests/test_app.py",
            hypotheses=(
                WorkspaceHypothesisProposal(
                    hypothesis_key="connection-not-released",
                    statement="The handler does not return its connection.",
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
            candidate_artifact_paths=("candidate/fix.diff",),
            citations=("repository/app.py:1",),
            residual_risks=(),
        )


class FakeArmorGate:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def screen_input(
        self, invocation: WorkspaceTaskInvocation, *, settings: ProviderSettings
    ) -> None:
        assert invocation.input_materials
        assert settings.model_armor_template.endswith("/templates/agent-boundary")
        self.events.append("input")

    async def screen_output(
        self, proposal: WorkspaceModelProposal, *, settings: ProviderSettings
    ) -> None:
        assert proposal.summary
        assert settings.region == "europe-west1"
        assert settings.model_location == "global"
        self.events.append("output")


class FakeIsolationProbe:
    def observe(self, *, settings: ProviderSettings) -> dict[str, bool]:
        assert settings.region == "europe-west1"
        assert settings.model_location == "global"
        return {
            "gcs_authority_denied": True,
            "cloud_sql_authority_denied": True,
            "secret_authority_denied": True,
            "external_egress_denied": True,
            "model_armor_injection_denied": True,
            "undeclared_builtin_tools_denied": True,
        }


class BadCitationRunner(FakeRunner):
    async def run(
        self,
        invocation: WorkspaceTaskInvocation,
        *,
        settings: ProviderSettings,
        tools: WorkspaceMaterialTools,
    ) -> WorkspaceModelProposal:
        proposal = await super().run(invocation, settings=settings, tools=tools)
        return proposal.model_copy(update={"citations": ("production/secret.txt:1",)})


def _settings() -> ProviderSettings:
    return ProviderSettings(
        project_id="solvan-demo",
        region="europe-west1",
        model_location="global",
        model="gemini-3.1-pro-preview",
        provider_revision="antigravity-workspace-20260808-01",
        provider_artifact_digest=f"sha256:{'9' * 64}",
        service_revision="antigravity-workspace-00001-x7p",
        coordinator_service_account="coordinator@solvan-demo.iam.gserviceaccount.com",
        audience="https://antigravity-workspace.example.run.app",
        effective_network_policy_hash=f"sha256:{'d' * 64}",
        model_armor_template=(
            "projects/solvan-demo/locations/europe-west1/templates/agent-boundary"
        ),
    )


def _invocation(**changes: object) -> WorkspaceTaskInvocation:
    content = "def handler():  # synthetic leak\n    return connection\n"
    content_hash = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
    values: dict[str, object] = {
        "schema_version": 1,
        "request_id": _id("req", "1"),
        "run_id": _id("run", "2"),
        "invocation_id": _id("inv", "3"),
        "logical_step_key": "workspace:repair:synthetic-leak",
        "attempt": 1,
        "scope": Scope(_id("org", "4"), _id("prj", "5"), _id("env", "6")),
        "workspace_id": _id("wsp", "7"),
        "workspace_generation": 1,
        "task_kind": WorkspaceTaskKind.REPAIR,
        "provider": WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
        "provider_resource": "https://antigravity-workspace.example.run.app",
        "provider_revision": _settings().provider_revision,
        "implementation_sdk_distribution_hash": (
            "sha256:249c102cac831e290a4a62918a2e0c01482696b6533b2a02e8215890080d634a"
        ),
        "provider_artifact_digest": _settings().provider_artifact_digest,
        "workflow_version": 3,
        "deadline": FixedClock.value + timedelta(minutes=5),
        "budget": WorkspaceTaskBudget(
            max_runtime_seconds=120,
            max_model_calls=3,
            max_tool_calls=4,
            max_input_bytes=50_000,
            max_output_bytes=100_000,
        ),
        "input_manifest_ref": "gs://solvan-fixture/workspaces/input/manifest.json",
        "input_manifest_hash": f"sha256:{'b' * 64}",
        "effective_tool_set_hash": TOOL_SET_HASH,
        "effective_network_policy_hash": _settings().effective_network_policy_hash,
        "allowed_tool_names": ALLOWED_TOOLS,
        "input_artifacts": (
            WorkspaceArtifactDescriptor(
                artifact_handle="wah_" + "1" * 32,
                path="repository/app.py",
                object_ref="gs://solvan-fixture/workspaces/input/app.py",
                content_hash=content_hash,
                size_bytes=len(content.encode()),
                media_type="text/x-python",
                provenance_refs=("synthetic-fixture-v1",),
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
        "objective": "Repair the deterministic synthetic leak.",
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


def _client(
    *,
    runner: FakeRunner | None = None,
    verifier: FakeVerifier | None = None,
    armor: FakeArmorGate | None = None,
    isolation_probe: FakeIsolationProbe | None = None,
) -> TestClient:
    return TestClient(
        create_app(
            settings=_settings(),
            runner=runner or FakeRunner(),
            verifier=verifier or FakeVerifier(),
            clock=FixedClock(),
            armor=armor or FakeArmorGate(),
            isolation_probe=isolation_probe or FakeIsolationProbe(),
        )
    )


def test_private_provider_executes_bounded_request_and_returns_bound_receipt() -> None:
    verifier = FakeVerifier()
    armor = FakeArmorGate()
    invocation = _invocation()
    with _client(verifier=verifier, armor=armor) as client:
        response = client.post(
            "/internal/v1/workspace-tasks:execute",
            json=invocation.model_dump(mode="json"),
            headers={"Authorization": "Bearer valid-token"},
        )
    assert response.status_code == 200, response.text
    receipt = WorkspaceProviderAttemptReceipt.model_validate(response.json())
    assert receipt.request_hash == invocation.request_hash
    assert receipt.provider_service_revision == _settings().service_revision
    assert receipt.implementation_sdk == "google-antigravity"
    assert receipt.implementation_sdk_version == "0.1.10"
    assert receipt.proposal.citations == ("repository/app.py:1",)
    diff = "diff --git a/app.py b/app.py\n"
    assert receipt.candidate_artifacts == (
        WorkspaceCandidateArtifact(
            path="candidate/fix.diff",
            content=diff,
            content_hash=receipt.candidate_artifacts[0].content_hash,
            size_bytes=len(diff.encode()),
            media_type="text/x-diff",
        ),
    )
    assert len(receipt.tool_receipts) == 2
    assert verifier.audience == _settings().audience
    assert armor.events == ["input", "output"]


def test_provider_rejects_missing_identity_and_wrong_caller() -> None:
    invocation = _invocation().model_dump(mode="json")
    with _client() as client:
        response = client.post("/internal/v1/workspace-tasks:execute", json=invocation)
        assert response.status_code == 401
    with _client(verifier=FakeVerifier("intruder@example.com")) as client:
        response = client.post(
            "/internal/v1/workspace-tasks:execute",
            json=invocation,
            headers={"Authorization": "Bearer valid-token"},
        )
    assert response.status_code == 403


def test_provider_fails_closed_on_policy_hash_or_unsigned_citation() -> None:
    wrong_policy = _invocation(effective_tool_set_hash=f"sha256:{'0' * 64}")
    with _client() as client:
        response = client.post(
            "/internal/v1/workspace-tasks:execute",
            json=wrong_policy.model_dump(mode="json"),
            headers={"Authorization": "Bearer valid-token"},
        )
    assert response.status_code == 403

    with _client(runner=BadCitationRunner()) as client:
        response = client.post(
            "/internal/v1/workspace-tasks:execute",
            json=_invocation().model_dump(mode="json"),
            headers={"Authorization": "Bearer valid-token"},
        )
    assert response.status_code == 502
    assert response.json()["detail"].endswith("ValueError")


def test_provider_health_does_not_require_cloud_configuration() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/live")
    assert response.json() == {"status": "live", "sdk": "google-antigravity/0.1.10"}


def test_private_preflight_reports_exact_sdk_tools_and_live_denials() -> None:
    request = {
        "schema_version": 1,
        "nonce": "preflight-20260808",
        "expected_sdk_distribution_hash": (
            "sha256:249c102cac831e290a4a62918a2e0c01482696b6533b2a02e8215890080d634a"
        ),
        "expected_network_policy_hash": _settings().effective_network_policy_hash,
    }
    with _client() as client:
        unauthorized = client.post("/internal/v1/preflight", json=request)
        response = client.post(
            "/internal/v1/preflight",
            json=request,
            headers={"Authorization": "Bearer valid-token"},
        )
    assert unauthorized.status_code == 401
    assert response.status_code == 200
    value = response.json()
    assert value["enabled_builtin_tools"] == ["finish"]
    assert value["enabled_custom_tools"] == list(ALLOWED_TOOLS)
    assert all(value["observations"].values())


def _rehydration_request(**changes: object) -> WorkspaceRehydrationRequest:
    workspace_id = _id("wsp", "7")
    manifest = WorkspaceArtifactManifest(
        manifest_kind="CHECKPOINT",
        workspace_id=workspace_id,
        workspace_generation=1,
        checkpoint_sequence=1,
        parent_manifest_ref="gs://runtime/workspaces/input.json",
        parent_manifest_hash=f"sha256:{'1' * 64}",
        classification="PUBLIC",
        synthetic=True,
        entries=(
            WorkspaceManifestEntry(
                path="repair/repair.patch",
                object_ref="gs://runtime/workspaces/repair.patch",
                content_hash=f"sha256:{'2' * 64}",
                size_bytes=32,
                media_type="text/x-diff",
                provenance_refs=("gs://runtime/provider-output.json",),
            ),
        ),
        created_by="serviceAccount:coordinator@solvan-demo.iam.gserviceaccount.com",
        created_at=FixedClock.value,
    )
    values: dict[str, object] = {
        "schema_version": 1,
        "request_id": _id("req", "1"),
        "workspace_id": workspace_id,
        "workspace_generation": 1,
        "checkpoint_id": _id("wck", "2"),
        "provider_revision": _settings().provider_revision,
        "implementation_sdk_distribution_hash": (
            "sha256:249c102cac831e290a4a62918a2e0c01482696b6533b2a02e8215890080d634a"
        ),
        "provider_artifact_digest": _settings().provider_artifact_digest,
        "previous_provider_service_revision": "antigravity-workspace-00000-old",
        "previous_provider_boot_hash": f"sha256:{'0' * 64}",
        "input_manifest_ref": "gs://runtime/workspaces/input.json",
        "input_manifest_hash": f"sha256:{'1' * 64}",
        "artifact_manifest_ref": "gs://runtime/workspaces/checkpoint.json",
        "artifact_manifest_hash": canonical_sha256(manifest.model_dump(mode="json")),
        "artifact_manifest": manifest,
        "effective_tool_set_hash": TOOL_SET_HASH,
        "effective_network_policy_hash": _settings().effective_network_policy_hash,
        "trace_id": "e" * 32,
        "span_id": "f" * 16,
    }
    values.update(changes)
    return WorkspaceRehydrationRequest.build(**values)


def test_rehydration_consumes_manifest_only_after_fresh_revision_and_boot() -> None:
    request = _rehydration_request()
    with _client() as client:
        response = client.post(
            "/internal/v1/workspaces:rehydrate",
            json=request.model_dump(mode="json"),
            headers={"Authorization": "Bearer valid-token"},
        )
    assert response.status_code == 200, response.text
    receipt = WorkspaceRehydrationReceipt.model_validate(response.json())
    receipt.assert_matches(request)
    assert receipt.artifact_manifest_hash == request.artifact_manifest_hash
    assert receipt.provider_service_revision == _settings().service_revision


def test_rehydration_rejects_same_service_revision() -> None:
    request = _rehydration_request(previous_provider_service_revision=_settings().service_revision)
    with _client() as client:
        response = client.post(
            "/internal/v1/workspaces:rehydrate",
            json=request.model_dump(mode="json"),
            headers={"Authorization": "Bearer valid-token"},
        )
    assert response.status_code == 409
