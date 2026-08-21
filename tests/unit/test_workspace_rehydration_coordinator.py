from __future__ import annotations

from types import SimpleNamespace

from apps.coordinator.workspace_rehydration import _reconcile_completed_rehydration
from solvan.application import (
    WorkspaceCheckpoint,
    WorkspaceClassification,
    WorkspaceProviderKind,
    WorkspaceRef,
    WorkspaceRehydrationReceipt,
    WorkspaceStatus,
)
from solvan.domain import Scope


def _id(prefix: str, digit: str) -> str:
    return f"{prefix}_{digit * 26}"


def test_completed_rehydration_retries_only_evidence_reconciliation(monkeypatch) -> None:
    scope = Scope(_id("org", "1"), _id("prj", "2"), _id("env", "3"))
    workspace_id = _id("wsp", "4")
    checkpoint_id = _id("wck", "5")
    receipt_ref = "gs://runtime/rehydration-receipt.json"
    receipt_hash = f"sha256:{'6' * 64}"
    ref = WorkspaceRef(
        scope=scope,
        workspace_id=workspace_id,
        generation=1,
        kind="INCIDENT",
        provider=WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
        implementation_sdk="google-antigravity",
        implementation_sdk_version="0.1.10",
        implementation_sdk_distribution_hash=f"sha256:{'0' * 64}",
        provider_artifact_digest=f"sha256:{'1' * 64}",
        provider_revision="provider-v1",
        status=WorkspaceStatus.OPEN,
        classification=WorkspaceClassification.PUBLIC,
        synthetic=True,
        artifact_prefix="gs://runtime/workspaces/one/",
        input_manifest_ref="gs://runtime/input.json",
        input_manifest_hash=f"sha256:{'7' * 64}",
    )
    common = {
        "scope": scope,
        "workspace_id": workspace_id,
        "workspace_generation": 1,
        "provider": WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
        "implementation_sdk": "google-antigravity",
        "implementation_sdk_version": "0.1.10",
        "implementation_sdk_distribution_hash": ref.implementation_sdk_distribution_hash,
        "provider_artifact_digest": ref.provider_artifact_digest,
        "provider_revision": "provider-v1",
        "input_manifest_ref": ref.input_manifest_ref,
        "input_manifest_hash": ref.input_manifest_hash,
        "artifact_manifest_ref": "gs://runtime/checkpoint.json",
        "artifact_manifest_hash": f"sha256:{'8' * 64}",
        "effective_tool_set_hash": f"sha256:{'9' * 64}",
        "effective_network_policy_hash": f"sha256:{'a' * 64}",
        "created_by_principal": "serviceAccount:coordinator@example.com",
    }
    checkpoint = WorkspaceCheckpoint(
        **common,
        checkpoint_id=checkpoint_id,
        sequence_no=1,
        event_kind="CHECKPOINT",
        provider_request_hash=f"sha256:{'b' * 64}",
        provider_receipt_ref="gs://runtime/provider-result.json",
        provider_receipt_hash=f"sha256:{'c' * 64}",
        provider_boot_hash=f"sha256:{'d' * 64}",
        provider_service_revision="revision-before",
    )
    latest = WorkspaceCheckpoint(
        **common,
        checkpoint_id=_id("wck", "6"),
        sequence_no=2,
        event_kind="REHYDRATION",
        parent_checkpoint_id=checkpoint_id,
        provider_request_hash=f"sha256:{'e' * 64}",
        provider_receipt_ref=receipt_ref,
        provider_receipt_hash=receipt_hash,
        provider_boot_hash=f"sha256:{'f' * 64}",
        provider_service_revision="revision-after",
    )
    receipt = WorkspaceRehydrationReceipt(
        request_id=_id("req", "7"),
        request_hash=latest.provider_request_hash,
        workspace_id=workspace_id,
        workspace_generation=1,
        checkpoint_id=checkpoint_id,
        provider_revision="provider-v1",
        provider_service_revision=latest.provider_service_revision,
        provider_boot_hash=latest.provider_boot_hash,
        implementation_sdk="google-antigravity",
        implementation_sdk_version="0.1.10",
        implementation_sdk_distribution_hash=f"sha256:{'0' * 64}",
        provider_artifact_digest=ref.provider_artifact_digest,
        input_manifest_ref=ref.input_manifest_ref,
        input_manifest_hash=ref.input_manifest_hash,
        artifact_manifest_ref=latest.artifact_manifest_ref,
        artifact_manifest_hash=latest.artifact_manifest_hash,
        effective_tool_set_hash=latest.effective_tool_set_hash,
        effective_network_policy_hash=latest.effective_network_policy_hash,
        trace_id="1" * 32,
        span_id="2" * 16,
    )
    store = SimpleNamespace(
        latest_checkpoint=lambda _ref: latest,
        checkpoint_by_id=lambda _ref, _checkpoint_id: checkpoint,
    )
    reader = SimpleNamespace(
        get_json=lambda **kwargs: receipt.model_dump(mode="json")
        if kwargs == {"uri": receipt_ref, "expected_hash": receipt_hash, "max_bytes": 262_144}
        else None
    )
    reconciled: list[str] = []
    monkeypatch.setattr(
        "apps.coordinator.workspace_rehydration._write_qualification_receipt",
        lambda **kwargs: reconciled.append(kwargs["rehydration_receipt_ref"]),
    )
    result = _reconcile_completed_rehydration(
        settings=SimpleNamespace(),
        store=store,
        connection=object(),
        ref=ref,
        expected_checkpoint_id=checkpoint_id,
        reader=reader,
        evidence_writer=object(),
    )
    assert result == receipt
    assert reconciled == [receipt_ref]
