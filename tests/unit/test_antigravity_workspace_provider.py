import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from functools import wraps

import httpx
import pytest

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
    workspace_artifact_handle,
)
from solvan.domain import Scope
from solvan.platform import (
    AntigravityProviderConfiguration,
    AntigravityProviderError,
    AntigravityWorkspaceProvider,
)
from solvan.platform.evidence_objects import ObjectReceipt

SDK_HASH = "sha256:f398664b362280037f8ed6df5cd61b996f3d02be1151ff665c6d09c87cc6a992"


def _synchronous(function: Callable[[], Awaitable[None]]) -> Callable[[], None]:
    @wraps(function)
    def run() -> None:
        asyncio.run(function())

    return run


def _id(prefix: str, digit: str) -> str:
    return f"{prefix}_{digit * 26}"


def _material_at(path: str, content: str) -> WorkspaceInputMaterial:
    return WorkspaceInputMaterial(
        path=path,
        content=content,
        content_hash=f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
        media_type="text/markdown",
    )


def _with_materials(*materials: WorkspaceInputMaterial) -> WorkspaceTaskInvocation:
    """Every materialized input needs its descriptor; the pairing is validated."""

    return _invocation(
        input_materials=materials,
        input_artifacts=tuple(
            WorkspaceArtifactDescriptor(
                artifact_handle=workspace_artifact_handle(material.path, material.content_hash),
                path=material.path,
                object_ref=f"gs://runtime/workspaces/{material.path}",
                content_hash=material.content_hash,
                size_bytes=len(material.content.encode("utf-8")),
                media_type=material.media_type,
                provenance_refs=("fixture://guidance",),
            )
            for material in materials
        ),
    )


def _invocation(**changes: object) -> WorkspaceTaskInvocation:
    content = "def leak():\n    return connection\n"
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
        "provider_resource": "https://antigravity.example.run.app",
        "provider_revision": "antigravity-workspace-20260808-01",
        "implementation_sdk_distribution_hash": SDK_HASH,
        "provider_artifact_digest": f"sha256:{'9' * 64}",
        "workflow_version": 2,
        "deadline": datetime.now(UTC) + timedelta(minutes=5),
        "budget": WorkspaceTaskBudget(
            max_runtime_seconds=120,
            max_model_calls=3,
            max_tool_calls=2,
            max_input_bytes=10_000,
            max_output_bytes=100_000,
        ),
        "input_manifest_ref": "gs://runtime/workspaces/input.json",
        "input_manifest_hash": f"sha256:{'a' * 64}",
        "effective_tool_set_hash": f"sha256:{'b' * 64}",
        "effective_network_policy_hash": f"sha256:{'c' * 64}",
        "allowed_tool_names": (
            "read_workspace_artifact",
            "write_candidate_artifact",
        ),
        "input_artifacts": (
            WorkspaceArtifactDescriptor(
                artifact_handle="wah_" + "2" * 32,
                path="repository/app.py",
                object_ref="gs://runtime/workspaces/app.py",
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
        "objective": "Repair the synthetic leak.",
        "task_parameters": {
            "base_commit_sha": "a" * 40,
            "reproduction_command": "pytest -q tests/test_app.py",
            "test_command": "pytest -q tests/test_app.py",
            "allowed_file_globs": ["*.py", "tests/*.py"],
        },
        "trace_id": "d" * 32,
        "span_id": "e" * 16,
    }
    values.update(changes)
    return WorkspaceTaskInvocation.build(**values)


def _attempt(
    invocation: WorkspaceTaskInvocation, **changes: object
) -> WorkspaceProviderAttemptReceipt:
    diff = "diff --git a/app.py b/app.py\n"
    candidate = WorkspaceCandidateArtifact(
        path="candidate/fix.diff",
        content=diff,
        content_hash=f"sha256:{hashlib.sha256(diff.encode()).hexdigest()}",
        size_bytes=len(diff.encode()),
        media_type="text/x-diff",
    )
    values: dict[str, object] = {
        "schema_version": 1,
        "request_id": invocation.request_id,
        "request_hash": invocation.request_hash,
        "run_id": invocation.run_id,
        "invocation_id": invocation.invocation_id,
        "workspace_id": invocation.workspace_id,
        "workspace_generation": invocation.workspace_generation,
        "provider_revision": invocation.provider_revision,
        "provider_service_revision": "antigravity-workspace-00001-x7p",
        "provider_boot_hash": f"sha256:{'f' * 64}",
        "implementation_sdk": "google-antigravity",
        "implementation_sdk_version": "0.1.13",
        "implementation_sdk_distribution_hash": SDK_HASH,
        "provider_artifact_digest": invocation.provider_artifact_digest,
        "input_manifest_hash": invocation.input_manifest_hash,
        "effective_tool_set_hash": invocation.effective_tool_set_hash,
        "effective_network_policy_hash": invocation.effective_network_policy_hash,
        "proposal": WorkspaceModelProposal(
            schema_version=1,
            terminal_status=WorkspaceTerminalStatus.SUCCEEDED,
            summary="Produced a bounded repair candidate.",
            mechanism="The synthetic handler retains its connection.",
            base_commit_sha="a" * 40,
            unified_diff=diff,
            reproduction_command="pytest -q tests/test_app.py",
            test_command="pytest -q tests/test_app.py",
            hypotheses=(
                WorkspaceHypothesisProposal(
                    hypothesis_key="connection-not-released",
                    statement="The synthetic handler retains its connection.",
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
            candidate_artifact_paths=(candidate.path,),
            citations=("repository/app.py:1",),
            residual_risks=(),
        ),
        "candidate_artifacts": (candidate,),
        "tool_receipts": (),
        "completed_at": datetime.now(UTC),
        "trace_id": invocation.trace_id,
        "span_id": invocation.span_id,
    }
    values.update(changes)
    return WorkspaceProviderAttemptReceipt.build(**values)


def _config() -> AntigravityProviderConfiguration:
    return AntigravityProviderConfiguration(
        base_url="https://antigravity.example.run.app",
        audience="https://antigravity.example.run.app",
        provider_revision="antigravity-workspace-20260808-01",
        implementation_sdk_distribution_hash=SDK_HASH,
        provider_artifact_digest=f"sha256:{'9' * 64}",
        effective_tool_set_hash=f"sha256:{'b' * 64}",
        effective_network_policy_hash=f"sha256:{'c' * 64}",
        artifact_bucket="runtime",
    )


class FakeTokenProvider:
    audience: str | None = None

    def token(self, *, audience: str) -> str:
        self.audience = audience
        return "identity-token"


class FakeWriter:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_bytes(self, *, object_name: str, content: bytes, content_type: str) -> ObjectReceipt:
        assert content_type
        existing = self.objects.get(object_name)
        if existing is not None and existing != content:
            raise RuntimeError("object changed")
        self.objects[object_name] = content
        return ObjectReceipt(
            uri=f"gs://runtime/{object_name}",
            content_hash=f"sha256:{hashlib.sha256(content).hexdigest()}",
            generation="1",
        )


def _rehydration_request() -> WorkspaceRehydrationRequest:
    manifest = WorkspaceArtifactManifest(
        manifest_kind="CHECKPOINT",
        workspace_id=_id("wsp", "7"),
        workspace_generation=1,
        checkpoint_sequence=1,
        parent_manifest_ref="gs://runtime/workspaces/input.json",
        parent_manifest_hash=f"sha256:{'a' * 64}",
        classification="PUBLIC",
        synthetic=True,
        entries=(
            WorkspaceManifestEntry(
                path="repair/fix.patch",
                object_ref="gs://runtime/workspaces/fix.patch",
                content_hash=f"sha256:{'f' * 64}",
                size_bytes=30,
                media_type="text/x-diff",
                provenance_refs=("gs://runtime/workspaces/result.json",),
            ),
        ),
        created_by="serviceAccount:coordinator@solvan-demo.iam.gserviceaccount.com",
        created_at=datetime.now(UTC),
    )
    return WorkspaceRehydrationRequest.build(
        schema_version=1,
        request_id=_id("req", "1"),
        workspace_id=manifest.workspace_id,
        workspace_generation=manifest.workspace_generation,
        checkpoint_id=_id("wck", "2"),
        provider_revision=_config().provider_revision,
        implementation_sdk_distribution_hash=SDK_HASH,
        provider_artifact_digest=_config().provider_artifact_digest,
        previous_provider_service_revision="antigravity-workspace-00001-old",
        previous_provider_boot_hash=f"sha256:{'0' * 64}",
        input_manifest_ref="gs://runtime/workspaces/input.json",
        input_manifest_hash=f"sha256:{'a' * 64}",
        artifact_manifest_ref="gs://runtime/workspaces/checkpoint.json",
        artifact_manifest_hash=canonical_sha256(manifest.model_dump(mode="json")),
        artifact_manifest=manifest,
        effective_tool_set_hash=_config().effective_tool_set_hash,
        effective_network_policy_hash=_config().effective_network_policy_hash,
        trace_id="d" * 32,
        span_id="e" * 16,
    )


@_synchronous
async def test_adapter_fences_receipt_and_persists_candidates_and_result() -> None:
    invocation = _invocation()
    attempt = _attempt(invocation)
    token_provider = FakeTokenProvider()
    writer = FakeWriter()

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer identity-token"
        assert request.url.path == "/internal/v1/workspace-tasks:execute"
        return httpx.Response(200, content=attempt.model_dump_json().encode())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        provider = AntigravityWorkspaceProvider(
            config=_config(),
            client=client,
            token_provider=token_provider,
            object_writer=writer,
        )
        result = await provider.execute(invocation)

    assert result.output_ref.endswith(f"runs/{invocation.run_id}/result.json")
    assert result.artifacts[0].object_ref.endswith("candidates/candidate/fix.diff")
    assert result.provider_boot_hash == attempt.provider_boot_hash
    assert result.implementation_sdk == "google-antigravity"
    assert len(writer.objects) == 2
    result_bytes = writer.objects[
        f"workspaces/{invocation.workspace_id}/generation-1/runs/{invocation.run_id}/result.json"
    ]
    assert f"sha256:{hashlib.sha256(result_bytes).hexdigest()}" == result.output_hash
    assert token_provider.audience == _config().audience


@_synchronous
async def test_adapter_rejects_receipt_from_another_durable_request() -> None:
    invocation = _invocation()
    other = _invocation(workspace_generation=2)
    attempt = _attempt(other)

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=attempt.model_dump_json().encode())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        provider = AntigravityWorkspaceProvider(
            config=_config(),
            client=client,
            token_provider=FakeTokenProvider(),
            object_writer=FakeWriter(),
        )
        with pytest.raises(AntigravityProviderError, match="receipt was rejected"):
            await provider.execute(invocation)


@_synchronous
async def test_adapter_rejects_sdk_provenance_drift_before_writing() -> None:
    invocation = _invocation()
    attempt = _attempt(
        invocation,
        implementation_sdk_distribution_hash=f"sha256:{'0' * 64}",
    )
    writer = FakeWriter()

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=attempt.model_dump_json().encode())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        provider = AntigravityWorkspaceProvider(
            config=_config(),
            client=client,
            token_provider=FakeTokenProvider(),
            object_writer=writer,
        )
        with pytest.raises(AntigravityProviderError, match="receipt was rejected"):
            await provider.execute(invocation)
    assert writer.objects == {}


@_synchronous
async def test_adapter_rejects_provider_image_drift_before_writing() -> None:
    invocation = _invocation()
    attempt = _attempt(invocation, provider_artifact_digest=f"sha256:{'0' * 64}")
    writer = FakeWriter()

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=attempt.model_dump_json().encode())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        provider = AntigravityWorkspaceProvider(
            config=_config(),
            client=client,
            token_provider=FakeTokenProvider(),
            object_writer=writer,
        )
        with pytest.raises(AntigravityProviderError, match="receipt was rejected"):
            await provider.execute(invocation)
    assert writer.objects == {}


@_synchronous
async def test_adapter_accepts_only_bound_fresh_rehydration_receipt() -> None:
    request = _rehydration_request()
    receipt = WorkspaceRehydrationReceipt(
        request_id=request.request_id,
        request_hash=request.request_hash,
        workspace_id=request.workspace_id,
        workspace_generation=request.workspace_generation,
        checkpoint_id=request.checkpoint_id,
        provider_revision=request.provider_revision,
        provider_service_revision="antigravity-workspace-00002-new",
        provider_boot_hash=f"sha256:{'1' * 64}",
        implementation_sdk="google-antigravity",
        implementation_sdk_version="0.1.13",
        implementation_sdk_distribution_hash=SDK_HASH,
        provider_artifact_digest=request.provider_artifact_digest,
        input_manifest_ref=request.input_manifest_ref,
        input_manifest_hash=request.input_manifest_hash,
        artifact_manifest_ref=request.artifact_manifest_ref,
        artifact_manifest_hash=request.artifact_manifest_hash,
        effective_tool_set_hash=request.effective_tool_set_hash,
        effective_network_policy_hash=request.effective_network_policy_hash,
        trace_id=request.trace_id,
        span_id=request.span_id,
    )

    def handle(http_request: httpx.Request) -> httpx.Response:
        assert http_request.url.path == "/internal/v1/workspaces:rehydrate"
        return httpx.Response(200, content=receipt.model_dump_json().encode())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        provider = AntigravityWorkspaceProvider(
            config=_config(),
            client=client,
            token_provider=FakeTokenProvider(),
            object_writer=FakeWriter(),
        )
        observed = await provider.rehydrate(request)
    assert observed == receipt
    with pytest.raises(ValueError, match="does not match its request"):
        receipt.model_copy(update={"workspace_id": _id("wsp", "6")}).assert_matches(request)
    with pytest.raises(ValueError, match="does not match its request"):
        receipt.model_copy(
            update={"provider_artifact_digest": f"sha256:{'0' * 64}"}
        ).assert_matches(request)
    with pytest.raises(ValueError, match="fresh provider"):
        receipt.model_copy(
            update={"provider_boot_hash": request.previous_provider_boot_hash}
        ).assert_matches(request)


def test_rehydration_request_rejects_manifest_and_request_hash_drift() -> None:
    request = _rehydration_request()
    wrong_manifest = request.model_dump(mode="json")
    wrong_manifest["artifact_manifest_hash"] = f"sha256:{'9' * 64}"
    with pytest.raises(ValueError, match="manifest does not match"):
        WorkspaceRehydrationRequest.model_validate(wrong_manifest)

    wrong_request = request.model_dump(mode="json")
    wrong_request["request_hash"] = f"sha256:{'9' * 64}"
    with pytest.raises(ValueError, match="request hash is not canonical"):
        WorkspaceRehydrationRequest.model_validate(wrong_request)


def test_guidance_materials_reach_the_skills_path_and_nothing_else_does(tmp_path) -> None:
    """Specification 12 §8.1: approved procedure is materialised, read-only.

    The coordinator materialises inputs in memory so the provider needs no
    storage credentials; the SDK loads skills from disk. The bridge is a
    request-scoped directory, and only guidance crosses it — evidence and
    repository inputs stay in memory behind the read tool.
    """

    from apps.antigravity_workspace.guidance import materialize_guidance

    invocation = _with_materials(
        _material_at("guidance/reliability/triage/SKILL.md", "# Triage\n1. Read the pool.\n"),
        _material_at("evidence/pool.json", '{"utilization": 0.94}'),
    )
    paths = materialize_guidance(invocation, root=tmp_path)

    assert paths == [str(tmp_path)]
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert written == ["reliability/triage/SKILL.md"]

    pack = tmp_path / "reliability/triage/SKILL.md"
    assert pack.read_text(encoding="utf-8").startswith("# Triage")
    # Read-only: a pack is procedure to follow, not a file to rewrite.
    assert pack.stat().st_mode & 0o222 == 0


def test_a_workspace_with_no_guidance_gets_no_skills_path(tmp_path) -> None:
    from apps.antigravity_workspace.guidance import materialize_guidance

    invocation = _with_materials(_material_at("evidence/pool.json", "{}"))
    assert materialize_guidance(invocation, root=tmp_path) == []
    assert not any(tmp_path.iterdir())
