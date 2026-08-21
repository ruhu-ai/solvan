"""Public-synthetic Antigravity workspace preparation and eligibility."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from psycopg import Connection
from psycopg.rows import dict_row

from apps.coordinator.contracts import CoordinatorSettings
from apps.coordinator.workspace_tasks import PreparedWorkspace
from solvan.application import (
    SyntheticAttestationRequest,
    WorkspaceArtifactManifest,
    WorkspaceClassification,
    WorkspaceContractError,
    WorkspaceKind,
    WorkspaceManifestEntry,
    WorkspaceProviderKind,
    WorkspaceSpec,
    WorkspaceTaskInvocation,
    WorkspaceTaskKind,
    sha256_bytes,
)
from solvan.application.repairs import RepairPlanRecord
from solvan.domain import new_identifier
from solvan.persistence import PostgresWorkspaceStore, WorkspaceConflict
from solvan.platform import (
    AntigravityEligibilityEvaluator,
    AntigravityEligibilityInput,
    AntigravityEligibilityPolicy,
    AntigravityProviderConfiguration,
    AntigravityProviderError,
    AntigravityWorkspaceProvider,
    FixtureAttesterClient,
    FixtureAttesterConfiguration,
    FixtureAttesterError,
    GoogleIdentityTokenProvider,
    GoogleKmsPublicKeyReader,
    SyntheticAttestationVerifier,
)
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session

SDK_DISTRIBUTION_HASH = "sha256:f398664b362280037f8ed6df5cd61b996f3d02be1151ff665c6d09c87cc6a992"


def dispatch_antigravity_repair(
    *,
    settings: CoordinatorSettings,
    connection: Connection[Any],
    invocation: WorkspaceTaskInvocation,
    writer: GcsEvidenceWriter,
) -> None:
    """Dispatch one durable request and retain its result for isolated adjudication."""

    config = settings.antigravity
    if config is None:
        raise WorkspaceConflict("Antigravity provider is disabled")
    store = PostgresWorkspaceStore(connection)
    store.mark_dispatched(invocation)

    async def execute() -> Any:
        async with httpx.AsyncClient() as client:
            provider = AntigravityWorkspaceProvider(
                config=AntigravityProviderConfiguration(
                    base_url=config.base_url,
                    audience=config.audience,
                    provider_revision=config.provider_revision,
                    implementation_sdk_distribution_hash=SDK_DISTRIBUTION_HASH,
                    provider_artifact_digest=config.provider_artifact_digest,
                    effective_tool_set_hash=config.effective_tool_set_hash,
                    effective_network_policy_hash=config.effective_network_policy_hash,
                    artifact_bucket=settings.runtime_bucket,
                ),
                client=client,
                token_provider=GoogleIdentityTokenProvider(),
                object_writer=writer,
            )
            return await provider.execute(invocation)

    try:
        result = asyncio.run(execute())
        accepted = store.record_provider_result(invocation=invocation, result=result)
        if not accepted:
            store.record_provider_security_event(
                invocation,
                event_type="WORKSPACE_PROVIDER_RESPONSE_REPLAYED",
                safe_summary="An exact provider response replay was ignored.",
            )
    except (WorkspaceContractError, WorkspaceConflict) as error:
        store.record_provider_security_event(
            invocation,
            event_type="WORKSPACE_PROVIDER_RESPONSE_FENCE_REJECTED",
            safe_summary=(
                f"Provider response failed durable request fencing: {type(error).__name__}"
            ),
        )
        store.fail_task(invocation, error_class=type(error).__name__)
    except AntigravityProviderError as error:
        store.record_provider_security_event(
            invocation,
            event_type="WORKSPACE_PROVIDER_REQUEST_REJECTED",
            safe_summary=(
                f"Private provider authentication or request failed: {type(error).__name__}"
            ),
        )
        store.fail_task(invocation, error_class=type(error).__name__)
    except Exception as error:
        store.fail_task(invocation, error_class=type(error).__name__)


def ensure_antigravity_incident_workspace(
    *,
    settings: CoordinatorSettings,
    connection: Connection[Any],
    plan: RepairPlanRecord,
    repository_files: list[dict[str, str]],
    writer: GcsEvidenceWriter,
) -> PreparedWorkspace:
    """Attest, decide, and open in that order; DENY never reaches the SDK."""

    config = settings.antigravity
    if config is None:
        raise WorkspaceConflict("Antigravity provider is disabled")
    if plan.provider != WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN.value:
        raise WorkspaceConflict("repair plan did not select the Antigravity provider")
    store = PostgresWorkspaceStore(connection)
    with connection.transaction():
        existing = store.active_for_case(scope=settings.scope, case_id=plan.reliability_case_id)
        if existing is not None:
            if (
                existing.provider is not WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN
                or existing.provider_revision != config.provider_revision
            ):
                raise WorkspaceConflict("active case workspace has a different provider binding")
            return PreparedWorkspace(
                existing,
                config.effective_tool_set_hash,
                config.effective_network_policy_hash,
            )
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT i.primary_service_id
                  FROM solvan.reliability_cases c
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (c.organization_id, c.project_id, c.environment_id,
                        c.originating_incident_id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'REPAIR_PLANNED'""",
                {**settings.scope.canonical_dict(), "case_id": plan.reliability_case_id},
            )
            owner = cursor.fetchone()
    if owner is None:
        raise WorkspaceConflict("repair case cannot own a workspace in its current state")
    # This classification covers only the independently attested, materialized
    # fixture manifest. It never inherits the broader case/environment ceiling.
    classification = WorkspaceClassification.PUBLIC
    fixture_prefix = (
        f"gs://{settings.runtime_bucket}/{settings.scope.organization_id}/"
        f"{settings.scope.project_id}/{settings.scope.environment_id}/fixtures/"
        f"{config.fixture_id}/"
    )
    source_allowed = plan.repository_snapshot_uri.startswith(fixture_prefix)
    synthetic = source_allowed and settings.environment == "hackathon"
    workspace_id = new_identifier("wsp")
    now = datetime.now(UTC)
    provenance = (f"fixture:{config.fixture_id}", plan.repository_snapshot_hash)
    entries: list[WorkspaceManifestEntry] = []
    for item in repository_files:
        if set(item) != {"path", "content", "content_hash"}:
            raise ValueError("repository workspace input has an unsupported shape")
        content = item["content"].encode()
        if sha256_bytes(content) != item["content_hash"]:
            raise ValueError("repository workspace input hash does not match its content")
        entries.append(
            WorkspaceManifestEntry(
                path=item["path"],
                object_ref=f"{plan.repository_snapshot_uri}#path={quote(item['path'], safe='')}",
                content_hash=item["content_hash"],
                size_bytes=len(content),
                media_type="text/plain; charset=utf-8",
                provenance_refs=provenance,
            )
        )
    manifest = WorkspaceArtifactManifest(
        manifest_kind="INPUT",
        workspace_id=workspace_id,
        workspace_generation=1,
        classification=classification,
        synthetic=synthetic,
        entries=tuple(entries),
        created_by=_coordinator_principal(settings),
        created_at=now,
    )
    manifest_receipt = writer.put_json(
        object_name=_workspace_object(settings, workspace_id, "input-manifest.json"),
        value=manifest.model_dump(mode="json"),
    )
    attestation = None
    additional_denials: list[str] = []
    if not source_allowed:
        additional_denials.append("FIXTURE_SOURCE_PREFIX_MISMATCH")
    if classification is WorkspaceClassification.PUBLIC and synthetic:
        try:
            with httpx.Client() as client:
                attestation = FixtureAttesterClient(
                    config=FixtureAttesterConfiguration(
                        base_url=config.fixture_attester_url,
                        audience=config.fixture_attester_audience,
                    ),
                    client=client,
                    token_provider=GoogleIdentityTokenProvider(),
                ).attest(
                    SyntheticAttestationRequest(
                        workspace_id=workspace_id,
                        workspace_generation=1,
                        fixture_id=config.fixture_id,
                        artifact_manifest_ref=manifest_receipt.uri,
                        artifact_manifest_hash=manifest_receipt.content_hash,
                    )
                )
        except FixtureAttesterError:
            additional_denials.append("FIXTURE_ATTESTER_UNAVAILABLE")
    session = authorized_session()
    evaluator = AntigravityEligibilityEvaluator(
        SyntheticAttestationVerifier(
            evidence_reader=GcsEvidenceReader(
                allowed_buckets=frozenset({settings.evidence_bucket}), session=session
            ),
            kms_reader=GoogleKmsPublicKeyReader(session),
        )
    )
    decision_id = new_identifier("pol")
    decision = evaluator.evaluate(
        AntigravityEligibilityInput(
            decision_id=decision_id,
            workspace_id=workspace_id,
            workspace_generation=1,
            task_kind=WorkspaceTaskKind.REPAIR,
            artifact_manifest_ref=manifest_receipt.uri,
            artifact_manifest_hash=manifest_receipt.content_hash,
            synthetic_attestation_ref=(
                None if attestation is None else attestation.attestation_ref
            ),
            synthetic_attestation_hash=(
                None if attestation is None else attestation.attestation_hash
            ),
            synthetic_attestation=(
                None if attestation is None else attestation.attestation.model_dump(mode="json")
            ),
            classification=classification,
            synthetic=synthetic,
            provider_location=settings.gcp_region,
            terms_revision=config.terms_revision,
        ),
        policy=_policy(settings, now=now),
        additional_denials=tuple(additional_denials),
    )
    nonpublic_decision = evaluator.evaluate(
        AntigravityEligibilityInput(
            decision_id=new_identifier("pol"),
            workspace_id=workspace_id,
            workspace_generation=1,
            task_kind=WorkspaceTaskKind.REPAIR,
            artifact_manifest_ref=manifest_receipt.uri,
            artifact_manifest_hash=manifest_receipt.content_hash,
            synthetic_attestation_ref=(
                None if attestation is None else attestation.attestation_ref
            ),
            synthetic_attestation_hash=(
                None if attestation is None else attestation.attestation_hash
            ),
            synthetic_attestation=(
                None if attestation is None else attestation.attestation.model_dump(mode="json")
            ),
            classification=WorkspaceClassification.INTERNAL,
            synthetic=synthetic,
            provider_location=settings.gcp_region,
            terms_revision=config.terms_revision,
        ),
        policy=_policy(settings, now=now),
    )
    if (
        nonpublic_decision.decision != "DENY"
        or "CLASSIFICATION_NOT_PUBLIC" not in nonpublic_decision.reason_codes
    ):
        raise WorkspaceConflict("Antigravity non-public negative control did not deny")
    nonpublic_receipt = writer.put_json(
        object_name=_workspace_object(
            settings, workspace_id, "eligibility-nonpublic-negative.json"
        ),
        value=nonpublic_decision.model_dump(mode="json"),
    )
    store.record_provider_eligibility(
        scope=settings.scope,
        decision_id=nonpublic_decision.decision_id,
        policy_version=nonpublic_decision.policy_version,
        input_ref=manifest_receipt.uri,
        input_hash=nonpublic_decision.input_hash,
        decision=nonpublic_decision.decision,
        reason_code=",".join(nonpublic_decision.reason_codes),
        receipt_ref=nonpublic_receipt.uri,
        receipt_hash=nonpublic_receipt.content_hash,
    )
    eligibility_receipt = writer.put_json(
        object_name=_workspace_object(settings, workspace_id, "eligibility.json"),
        value=decision.model_dump(mode="json"),
    )
    store.record_provider_eligibility(
        scope=settings.scope,
        decision_id=decision.decision_id,
        policy_version=decision.policy_version,
        input_ref=manifest_receipt.uri,
        input_hash=decision.input_hash,
        decision=decision.decision,
        reason_code=",".join(decision.reason_codes),
        receipt_ref=eligibility_receipt.uri,
        receipt_hash=eligibility_receipt.content_hash,
    )
    if decision.decision != "ALLOW":
        raise WorkspaceConflict(
            f"Antigravity provider eligibility denied: {','.join(decision.reason_codes)}"
        )
    assert attestation is not None
    ref = store.open(
        WorkspaceSpec(
            scope=settings.scope,
            workspace_id=workspace_id,
            kind=WorkspaceKind.INCIDENT,
            service_id=str(owner["primary_service_id"]),
            reliability_case_id=plan.reliability_case_id,
            provider=WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
            implementation_sdk="google-antigravity",
            implementation_sdk_version="0.1.13",
            provider_revision=config.provider_revision,
            registry_agent_key="antigravity-workspace-provider",
            provider_agent_resource=config.base_url,
            provider_service_identity=config.provider_service_identity,
            implementation_sdk_distribution_hash=SDK_DISTRIBUTION_HASH,
            provider_artifact_digest=config.provider_artifact_digest,
            effective_network_policy_hash=config.effective_network_policy_hash,
            classification=WorkspaceClassification.PUBLIC,
            synthetic=True,
            synthetic_attestation_ref=attestation.attestation_ref,
            synthetic_attestation_hash=attestation.attestation_hash,
            provider_eligibility_decision_id=decision.decision_id,
            artifact_prefix=(
                f"gs://{settings.runtime_bucket}/{_workspace_object(settings, workspace_id, '')}"
            ),
            input_manifest_ref=manifest_receipt.uri,
            input_manifest_hash=manifest_receipt.content_hash,
            created_by_principal=_coordinator_principal(settings),
        )
    )
    return PreparedWorkspace(
        ref, config.effective_tool_set_hash, config.effective_network_policy_hash
    )


def _policy(settings: CoordinatorSettings, *, now: datetime) -> AntigravityEligibilityPolicy:
    config = settings.antigravity
    assert config is not None
    return AntigravityEligibilityPolicy(
        scope=settings.scope,
        release_commit=config.release_commit,
        deployment_id=config.deployment_id,
        terms_revision=config.terms_revision,
        required_location="europe-west1",
        allowed_issuer_principals=frozenset({config.fixture_attester_principal}),
        allowed_kms_key_versions=frozenset({config.fixture_attester_kms_key_version}),
        provider_revision=config.provider_revision,
        provider_service_identity=config.provider_service_identity,
        implementation_sdk_distribution_hash=SDK_DISTRIBUTION_HASH,
        provider_artifact_digest=config.provider_artifact_digest,
        effective_tool_set_hash=config.effective_tool_set_hash,
        effective_network_policy_hash=config.effective_network_policy_hash,
        decided_by=_coordinator_principal(settings),
        now=now,
    )


def _coordinator_principal(settings: CoordinatorSettings) -> str:
    return settings.coordinator_principal


def _workspace_object(settings: CoordinatorSettings, workspace_id: str, object_name: str) -> str:
    return (
        f"{settings.scope.organization_id}/{settings.scope.project_id}/"
        f"{settings.scope.environment_id}/workspaces/{workspace_id}/{object_name}"
    )
