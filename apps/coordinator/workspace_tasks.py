"""Coordinator-owned workspace manifest, eligibility, and lifecycle preparation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from psycopg import Connection
from psycopg.rows import dict_row

from apps.coordinator.contracts import CoordinatorSettings
from apps.coordinator.workspace_tool_binding import production_workspace_tool_set
from solvan.application import (
    WorkspaceClassification,
    WorkspaceKind,
    WorkspaceProviderKind,
    WorkspaceRef,
    WorkspaceSpec,
    canonical_sha256,
    sha256_bytes,
    workspace_repair_budget,
)
from solvan.application.effective_tool_set import EffectiveToolSetV1
from solvan.application.repairs import RepairPlanRecord
from solvan.domain import new_identifier
from solvan.persistence import PostgresWorkspaceStore, WorkspaceConflict
from solvan.platform.evidence_objects import GcsEvidenceWriter

ADK_VERSION = "2.5.0"
ADK_DISTRIBUTION_HASH = "sha256:d247ca3639921a54a86feb797a88d08c1d2c9a60c3f5ff2805e49beb29a9cb8d"
ELIGIBILITY_POLICY_VERSION = "workspace-provider-eligibility-v1"


@dataclass(frozen=True, slots=True)
class PreparedWorkspace:
    ref: WorkspaceRef
    effective_tool_set_hash: str
    effective_network_policy_hash: str
    effective_tool_set: EffectiveToolSetV1 | None = None


def ensure_adk_incident_workspace(
    *,
    settings: CoordinatorSettings,
    connection: Connection[Any],
    plan: RepairPlanRecord,
    repository_files: list[dict[str, str]],
    guidance_files: list[dict[str, str]],
    writer: GcsEvidenceWriter,
) -> PreparedWorkspace:
    """Create policy and workspace before any Agent Runtime provider call."""

    store = PostgresWorkspaceStore(connection)
    effective_tool_set = production_workspace_tool_set(
        scope=settings.scope,
        agent_revision=settings.workspace_agent_revision,
        runtime_region=settings.gcp_region,
        binding=settings.governed_agent_bindings["workspace-agent"],
        budget=workspace_repair_budget(synthetic_provider=False),
    )
    tool_hash = effective_tool_set.effective_tool_set_hash
    network_hash = canonical_sha256(
        {
            "control_plane": "AGENT_RUNTIME",
            "location": settings.gcp_region,
            "policy_version": "regional-agent-runtime-v1",
        }
    )
    with connection.transaction():
        existing = store.active_for_case(scope=settings.scope, case_id=plan.reliability_case_id)
        if existing is not None:
            if (
                existing.provider is not WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE
                or existing.provider_revision != settings.workspace_agent_revision
            ):
                raise WorkspaceConflict("active case workspace has a different provider binding")
            return PreparedWorkspace(existing, tool_hash, network_hash, effective_tool_set)
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT i.primary_service_id, e.classification
              FROM solvan.reliability_cases c
              JOIN solvan.incidents i
                ON (i.organization_id, i.project_id, i.environment_id, i.id)
                 = (c.organization_id, c.project_id, c.environment_id,
                    c.originating_incident_id)
              JOIN solvan.environments e
                ON (e.organization_id, e.project_id, e.id)
                 = (c.organization_id, c.project_id, c.environment_id)
              WHERE c.organization_id = %(organization_id)s
                AND c.project_id = %(project_id)s
                AND c.environment_id = %(environment_id)s
                AND c.id = %(case_id)s
                AND c.state = 'REPAIR_PLANNED'""",
                {**settings.scope.canonical_dict(), "case_id": plan.reliability_case_id},
            )
            owner = cursor.fetchone()
    if owner is None:
        raise WorkspaceConflict("repair case cannot own a workspace in its current state")

    workspace_id = new_identifier("wsp")
    now = datetime.now(UTC)
    provenance = list(plan.evidence_refs) or [plan.repository_snapshot_hash]
    entries: list[dict[str, Any]] = []
    for item in repository_files:
        if set(item) != {"path", "content", "content_hash"}:
            raise ValueError("repository workspace input has an unsupported shape")
        encoded = item["content"].encode("utf-8")
        if sha256_bytes(encoded) != item["content_hash"]:
            raise ValueError("repository workspace input hash does not match its content")
        entries.append(
            {
                "path": item["path"],
                "object_ref": (
                    f"{plan.repository_snapshot_uri}#path={quote(item['path'], safe='')}"
                ),
                "content_hash": item["content_hash"],
                "size_bytes": len(encoded),
                "media_type": "text/plain; charset=utf-8",
                "provenance_refs": provenance,
            }
        )
    for item in guidance_files:
        if set(item) != {"path", "content", "content_hash", "object_ref", "provenance_ref"}:
            raise ValueError("workspace guidance input has an unsupported shape")
        encoded = item["content"].encode("utf-8")
        if sha256_bytes(encoded) != item["content_hash"]:
            raise ValueError("workspace guidance input hash does not match its content")
        entries.append(
            {
                "path": item["path"],
                "object_ref": item["object_ref"],
                "content_hash": item["content_hash"],
                "size_bytes": len(encoded),
                "media_type": "text/markdown; charset=utf-8",
                "provenance_refs": [item["provenance_ref"]],
            }
        )
    manifest = {
        "schema_version": 1,
        "manifest_kind": "INPUT",
        "workspace_id": workspace_id,
        "workspace_generation": 1,
        "checkpoint_sequence": None,
        "parent_manifest_ref": None,
        "parent_manifest_hash": None,
        "classification": str(owner["classification"]),
        "synthetic": settings.environment == "hackathon",
        "entries": entries,
        "created_by": settings.coordinator_principal,
        "created_at": now.isoformat(),
    }
    manifest_receipt = writer.put_json(
        object_name=(
            f"{settings.scope.organization_id}/{settings.scope.project_id}/"
            f"{settings.scope.environment_id}/workspaces/{workspace_id}/input-manifest.json"
        ),
        value=manifest,
    )
    decision_id = new_identifier("pol")
    provider_artifact_digest = canonical_sha256(
        {
            "agent_resource": settings.workspace_agent_resource,
            "agent_revision": settings.workspace_agent_revision,
        }
    )
    eligibility_input = {
        "workspace_id": workspace_id,
        "workspace_generation": 1,
        "task_kind": "REPAIR",
        "provider": "GEMINI_ADK_AGENT_ENGINE",
        "classification": str(owner["classification"]),
        "synthetic": settings.environment == "hackathon",
        "input_manifest_hash": manifest_receipt.content_hash,
        "provider_location": settings.gcp_region,
        "effective_tool_set_hash": tool_hash,
        "effective_network_policy_hash": network_hash,
    }
    eligibility = {
        "schema_version": 1,
        "decision_id": decision_id,
        "policy_kind": "PROVIDER_ELIGIBILITY",
        "policy_version": ELIGIBILITY_POLICY_VERSION,
        **settings.scope.canonical_dict(),
        "workspace_id": workspace_id,
        "workspace_generation": 1,
        "task_kind": "REPAIR",
        "provider": "GEMINI_ADK_AGENT_ENGINE",
        "provider_revision": settings.workspace_agent_revision,
        "implementation_sdk": "google-adk",
        "implementation_sdk_version": ADK_VERSION,
        "implementation_sdk_distribution_hash": ADK_DISTRIBUTION_HASH,
        "hosting_control_plane": "AGENT_RUNTIME",
        "hosting_data_plane": "AGENT_RUNTIME_QUERY_API",
        "provider_service_identity": settings.workspace_agent_principal,
        "provider_artifact_digest": provider_artifact_digest,
        "classification": str(owner["classification"]),
        "synthetic": settings.environment == "hackathon",
        "artifact_manifest_ref": manifest_receipt.uri,
        "artifact_manifest_hash": manifest_receipt.content_hash,
        "synthetic_attestation_ref": None,
        "synthetic_attestation_hash": None,
        "terms_revision": "google-cloud-terms-2026-08-08",
        "required_processing_location": settings.gcp_region,
        "provider_location": settings.gcp_region,
        "effective_tool_set_hash": tool_hash,
        "effective_network_policy_hash": network_hash,
        "input_hash": canonical_sha256(eligibility_input),
        "decision": "ALLOW",
        "reason_codes": ["REGIONAL_ADK_POLICY_MATCH"],
        "decided_by": settings.coordinator_principal,
        "decided_at": now.isoformat(),
    }
    eligibility_receipt = writer.put_json(
        object_name=(
            f"{settings.scope.organization_id}/{settings.scope.project_id}/"
            f"{settings.scope.environment_id}/workspaces/{workspace_id}/eligibility.json"
        ),
        value=eligibility,
    )
    store.record_provider_eligibility(
        scope=settings.scope,
        decision_id=decision_id,
        policy_version=ELIGIBILITY_POLICY_VERSION,
        input_ref=manifest_receipt.uri,
        input_hash=str(eligibility["input_hash"]),
        decision="ALLOW",
        reason_code="REGIONAL_ADK_POLICY_MATCH",
        receipt_ref=eligibility_receipt.uri,
        receipt_hash=eligibility_receipt.content_hash,
    )
    spec = WorkspaceSpec(
        scope=settings.scope,
        workspace_id=workspace_id,
        kind=WorkspaceKind.INCIDENT,
        service_id=str(owner["primary_service_id"]),
        reliability_case_id=plan.reliability_case_id,
        provider=WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE,
        implementation_sdk="google-adk",
        implementation_sdk_version=ADK_VERSION,
        provider_revision=settings.workspace_agent_revision,
        registry_agent_key="workspace-agent",
        provider_agent_resource=settings.workspace_agent_resource,
        provider_service_identity=settings.workspace_agent_principal,
        implementation_sdk_distribution_hash=ADK_DISTRIBUTION_HASH,
        provider_artifact_digest=provider_artifact_digest,
        effective_network_policy_hash=network_hash,
        classification=WorkspaceClassification(str(owner["classification"])),
        synthetic=settings.environment == "hackathon",
        provider_eligibility_decision_id=decision_id,
        artifact_prefix=(
            f"gs://{settings.runtime_bucket}/{settings.scope.organization_id}/"
            f"{settings.scope.project_id}/{settings.scope.environment_id}/"
            f"workspaces/{workspace_id}/"
        ),
        input_manifest_ref=manifest_receipt.uri,
        input_manifest_hash=manifest_receipt.content_hash,
        created_by_principal=str(eligibility["decided_by"]),
    )
    try:
        ref = store.open(spec)
    except WorkspaceConflict as conflict:
        concurrent = store.active_for_case(scope=settings.scope, case_id=plan.reliability_case_id)
        if concurrent is None:
            raise
        if (
            concurrent.provider is not WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE
            or concurrent.provider_revision != settings.workspace_agent_revision
        ):
            raise WorkspaceConflict(
                "concurrent case workspace has a different provider binding"
            ) from conflict
        ref = concurrent
    return PreparedWorkspace(ref, tool_hash, network_hash, effective_tool_set)
