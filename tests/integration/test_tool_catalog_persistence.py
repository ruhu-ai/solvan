"""Governed Tool Catalog contracts against real PostgreSQL 16."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from io import BytesIO
from zipfile import ZipFile

import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.operational_guidance_admin import (
    GuidanceContentInspection,
    operational_guidance_router,
)
from solvan.application.default_tool_catalog import (
    AGENT_PROFILE_KEYS,
    INTERNAL_PROVIDERS,
    TOOL_SEEDS,
    alert_triage_profile,
    catalog_principals,
    catalog_profile,
    catalog_tools,
)
from solvan.application.guidance_evaluation import UnavailableGuidanceEvaluationVerifier
from solvan.application.operational_guidance import (
    GuidanceError,
    GuidanceIncompatibilityDeclaration,
    GuidanceKind,
    GuidanceLifecycle,
    GuidanceRevision,
    GuidanceSourceKind,
    TriggerPolicyRevision,
    VerifiedTriggerEvent,
)
from solvan.application.skills_governance import (
    SkillCompileCommand,
    compile_import,
    export_approved_revision,
)
from solvan.application.skills_interchange_service import SkillImportCommand, SkillImportService
from solvan.application.skills_security import DeterministicModelArmor, SecurityScanReceipt
from solvan.application.skills_selection import PostgresSkillSelector
from solvan.application.tool_catalog import (
    CapabilityProbe,
    CatalogLifecycle,
    CatalogPrincipal,
    EvidenceKind,
    ExecutionRole,
    IdempotencyKind,
    ImplementationKind,
    ModelArmorCoverage,
    NoDataSemantics,
    PermissionClass,
    RegistryKind,
    ToolConnectionBindingKind,
    ToolConnectionRequirement,
    ToolProfileRevision,
    ToolRevision,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence.connection_store import PostgresConnectionStore
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore
from solvan.persistence.skills_interchange_store import PostgresSkillImportRepository
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore
from solvan.persistence.trigger_policy_store import PostgresTriggerPolicyStore
from solvan.platform.evidence_objects import ObjectReceipt

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
CONNECTION_ID = "con_01J4QZK8Q4J8Q6B95KQY4M9R2S"
HASH = f"sha256:{'a' * 64}"
MANIFEST_HASH = f"sha256:{'e' * 64}"
FIXTURE_PROFILE_KEY = "fixture.evidence-observability.v1"
TRIGGER_SNAPSHOT_ID = "pgs_07777777777777777777777777"
TRIGGER_NODE_ID = "pgn_07777777777777777777777777"
TRIGGER_TARGET_HASH = canonical_sha256(
    {
        "snapshot_id": TRIGGER_SNAPSHOT_ID,
        "snapshot_content_hash": HASH,
        "snapshot_version": 777,
        "target_key": "cloud-run/ruhu-api",
        "node_kind": "SERVICE",
        "resource_ref": "projects/solvan-test/locations/europe-west1/services/ruhu-api",
        "external_project_id": "solvan-test",
        "classification": "INTERNAL",
        "provenance_ref": "fixture://trigger-target",
        "attributes": {"region": "europe-west1"},
    }
)


@pytest.fixture
def connection():
    assert DATABASE_URL is not None
    with (
        psycopg.connect(DATABASE_URL) as database,
        database.transaction(force_rollback=True),
    ):
        database.execute(
            """INSERT INTO solvan.organizations(id,display_name)
               VALUES (%s,'Test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id,),
        )
        database.execute(
            """INSERT INTO solvan.projects
                 (organization_id,id,display_name,gcp_project_id)
               VALUES (%s,%s,'Test','solvan-test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        database.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Test','europe-west1','INTERNAL')
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        database.execute(
            """INSERT INTO solvan.tenant_connections
                 (organization_id,project_id,environment_id,id,display_name,kind,
                  provider,credential_posture,residency_region,classification,
                  lifecycle,availability,availability_reason_code,availability_explanation,availability_remediation_kind,availability_receipt_ref,last_probe_at,last_probe_result,created_by_principal)
               VALUES (%s,%s,%s,%s,'Ruhu metrics','GCP_NATIVE',
                       'CLOUD_MONITORING','CUSTOMER_SIDE_NONE','europe-west1',
                       'INTERNAL','ENABLED','READY',NULL,NULL,NULL,'probe://seed',now(),'SUCCEEDED','user:test@example.com')
               ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                CONNECTION_ID,
            ),
        )
        yield database


def _principal() -> CatalogPrincipal:
    return CatalogPrincipal(
        principal_key="evidence-agent",
        display_name="Evidence Agent",
        registry_kind=RegistryKind.AGENT,
        execution_role=ExecutionRole.SPECIALIST,
        model_backed=True,
        manifest_hash=MANIFEST_HASH,
    )


def _tool() -> ToolRevision:
    """A synthetic revision, deliberately not a checked-in catalog key.

    It used to be published as `managed_prometheus_query` with different
    immutable material, and the two concurrency tests below commit it, so any
    later test that published the real catalog collided with a fixture rather
    than with a contract.
    """

    return ToolRevision(
        tool_key="fixture_bounded_metric_read",
        version="1",
        display_name="Fixture bounded metric read",
        description="Execute one registered bounded metric template.",
        use_cases=("Read service telemetry",),
        anti_use_cases=("Execute arbitrary PromQL",),
        owner_department="Reliability Platform",
        permission_class=PermissionClass.READ,
        implementation_kind=ImplementationKind.CONNECTOR,
        allowed_requester_keys=("evidence-agent",),
        required_capabilities=("promql.read",),
        required_connection_providers=("CLOUD_MONITORING",),
        input_schema_ref="schema://managed-prometheus/input/1",
        input_schema_hash=HASH,
        output_schema_ref="schema://managed-prometheus/output/1",
        output_schema_hash=HASH,
        evidence_kind=EvidenceKind.METRICS,
        output_semantics=("bounded time series",),
        supported_retrieval_controls=("registered_template", "bounded_window"),
        no_data_semantics=NoDataSemantics.UNKNOWN,
        failure_taxonomy=("NO_DATA", "PERMISSION_DENIED"),
        supported_data_classes=("INTERNAL",),
        runtime_regions=("europe-west1",),
        gateway_destination="monitoring.googleapis.com",
        registry_resource="registry://managed-prometheus/1",
        model_armor_coverage=ModelArmorCoverage.NOT_APPLICABLE,
        network_policy_hash=HASH,
        timeout_ms=10_000,
        max_input_bytes=4096,
        max_output_bytes=65_536,
        default_call_budget=3,
        idempotency=IdempotencyKind.NOT_APPLICABLE,
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref="approval://tool/1",
        evaluation_ref="evaluation://tool/1",
    )


def _profile() -> ToolProfileRevision:
    return ToolProfileRevision(
        # This fixture is committed by the endpoint/concurrency contracts
        # below.  It must not occupy the immutable key used by the checked-in
        # release catalog that the following integration module publishes.
        profile_key=FIXTURE_PROFILE_KEY,
        version="1",
        purpose="Investigate Ruhu telemetry",
        allowed_agent_key="evidence-agent",
        tool_revisions=("fixture_bounded_metric_read@1",),
        maximum_total_calls=3,
        maximum_parallel_calls=1,
        tool_connection_requirements=(
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="fixture_bounded_metric_read@1",
                binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
            ),
        ),
        data_classification_ceiling="INTERNAL",
        runtime_region="europe-west1",
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref="approval://profile/1",
        evaluation_ref="evaluation://profile/1",
    )


def _trigger_profile() -> ToolProfileRevision:
    return _profile().model_copy(
        update={
            "profile_key": "evidence.ruhu-trigger-observability.v1",
            "tool_connection_requirements": (
                ToolConnectionRequirement(
                    ordinal=1,
                    tool_revision="fixture_bounded_metric_read@1",
                    binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                    provider="CLOUD_MONITORING",
                    capability_key="METRIC_READ",
                    external_project_selector="TARGET_RESOURCE_PROJECT",
                ),
            ),
        }
    )


def test_immutable_tool_profile_and_probe_round_trip(connection) -> None:
    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())
    store.publish_tool(_tool())
    store.publish_profile(scope=SCOPE, profile=_profile())
    loaded = store.load_profile(scope=SCOPE, profile_key=FIXTURE_PROFILE_KEY, version="1")
    assert loaded.profile_material_hash == _profile().profile_material_hash
    assert (
        loaded.tool_connection_requirements[0].binding_kind
        is ToolConnectionBindingKind.COMPUTE_ONLY
    )

    now = datetime(2026, 8, 10, tzinfo=UTC)
    probe_id = store.record_probe(
        scope=SCOPE,
        probe=CapabilityProbe(
            connection_id=CONNECTION_ID,
            tool_revision="fixture_bounded_metric_read@1",
            agent_key="evidence-agent",
            connection_provider="CLOUD_MONITORING",
            capabilities=frozenset({"promql.read"}),
            connection_epoch=1,
            identity_ref="identity://evidence-agent/1",
            registry_resource="registry://managed-prometheus/1",
            gateway_policy_ref="gateway://policy/1",
            network_policy_hash=HASH,
            region="europe-west1",
            classification_ceiling="INTERNAL",
            outcome="PASSED",
            observed_at=now,
            expires_at=now + timedelta(minutes=5),
            receipt_ref="receipt://probe/1",
            receipt_hash=HASH,
        ),
    )
    assert probe_id.startswith("tpr_")
    projection = store.projection(scope=SCOPE)
    assert any(item["tool_key"] == "fixture_bounded_metric_read" for item in projection["tools"])
    assert any(
        item["profile_key"] == FIXTURE_PROFILE_KEY and item["allowed_agent_key"] == "evidence-agent"
        for item in projection["profiles"]
    )
    assert any(
        item["connection_id"] == CONNECTION_ID and item["outcome"] == "PASSED"
        for item in projection["probes"]
    )


def test_revision_key_cannot_be_republished_with_different_material(connection) -> None:
    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())
    store.publish_tool(_tool())
    changed = _tool().model_copy(update={"description": "different immutable meaning"})
    with pytest.raises(RuntimeError, match="different immutable material"):
        store.publish_tool(changed)


def test_identical_revision_republication_keeps_original_governance_refs(connection) -> None:
    store = PostgresToolCatalogStore(connection)
    original = _tool()
    store.register_principal(_principal())
    store.publish_tool(original)

    store.publish_tool(
        original.model_copy(
            update={
                "approval_ref": "approval://tool/later-release",
                "evaluation_ref": "evaluation://tool/later-release",
            }
        )
    )

    persisted = connection.execute(
        """SELECT approval_ref, evaluation_ref, content_hash
             FROM solvan_operability.tool_revisions
            WHERE tool_key=%s AND version=%s""",
        (original.tool_key, original.version),
    ).fetchone()
    assert persisted == (original.approval_ref, original.evaluation_ref, original.content_hash)


def _guidance() -> GuidanceRevision:
    return GuidanceRevision.model_validate(
        {
            "guidance_key": "payments.connection-exhaustion",
            "version": "1",
            "display_name": "Payment connection exhaustion",
            "description": "Gather bounded evidence for exhausted pools.",
            "owner_department": "Payments SRE",
            "discoverable_departments": ("Payments", "Reliability"),
            "guidance_kind": "DIAGNOSTIC_PROCEDURE",
            "applicable_service_kinds": ("CLOUD_RUN",),
            "applicable_incident_classes": ("CONNECTION_EXHAUSTION",),
            "symptom_tags": ("http-503",),
            "purpose": "INCIDENT_INVESTIGATION",
            "classification": "INTERNAL",
            "eligible_regions": ("europe-west1",),
            "allowed_agent_keys": ("evidence-agent",),
            "required_profile_revisions": (f"{FIXTURE_PROFILE_KEY}@1",),
            "steps": (
                {
                    "step_key": "observe-errors",
                    "ordinal": 1,
                    "title": "Observe bounded errors",
                    "objective": "Measure the registered error signature in the incident window.",
                    "step_kind": "OBSERVE",
                    "allowed_tool_revisions": ("fixture_bounded_metric_read@1",),
                    "prerequisite_step_keys": (),
                    "completion_predicate_key": "evidence-kind-present",
                    "completion_predicate_version": "1",
                    "required_evidence_kinds": ("METRICS",),
                    "maximum_tool_requests": 1,
                    "on_blocked": "STOP_INCONCLUSIVE",
                },
            ),
            "content_ref": "gs://guidance/payments/connection-exhaustion/1.json",
            "content_hash": HASH,
            "source_kind": "SOLVAN_AUTHORED",
            "source_ref": "solvan://guidance/payments/connection-exhaustion",
            "author_principal": "user:author@example.com",
            "lifecycle": "DRAFT",
        }
    )


def test_guidance_revision_is_immutable_and_projection_excludes_content_ref(connection) -> None:
    catalog = PostgresToolCatalogStore(connection)
    catalog.register_principal(_principal())
    catalog.publish_tool(_tool())
    catalog.publish_profile(scope=SCOPE, profile=_profile())
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%s,%s,%s,'user:author@example.com','GUIDANCE_AUTHOR','Payments SRE','test'),
                  (%s,%s,%s,'user:evaluator@example.com','GUIDANCE_EVALUATOR',
                   'Payments SRE','test'),
                  (%s,%s,%s,'user:approver@example.com','GUIDANCE_APPROVER',
                   'Payments SRE','test')""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
        ),
    )
    store = PostgresOperationalGuidanceStore(connection)
    revision = _guidance()
    created = store.create_draft(
        scope=SCOPE, revision=revision, decision_request_id="guidance-create-1"
    )
    assert created.lifecycle == "DRAFT"
    ingestion_id = store.record_ingestion(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        content_hash=revision.content_hash,
        accepted=True,
        reason_codes=("STRUCTURE_AND_SECURITY_VALIDATED",),
        armor_verdict_ref="armor:allow:guidance-1",
        principal=revision.author_principal,
        decision_request_id="guidance-ingest-1",
    )
    replayed_ingestion_id = store.record_ingestion(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        content_hash=revision.content_hash,
        accepted=True,
        reason_codes=("STRUCTURE_AND_SECURITY_VALIDATED",),
        armor_verdict_ref="armor:allow:guidance-1",
        principal=revision.author_principal,
        decision_request_id="guidance-ingest-1",
    )
    assert replayed_ingestion_id == ingestion_id
    assert connection.execute(
        """SELECT count(*) FROM solvan_operability.guidance_ingestion_receipts
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key=%s AND guidance_version=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            revision.guidance_key,
            revision.version,
        ),
    ).fetchone() == (1,)
    with pytest.raises(GuidanceError, match="idempotency material mismatch"):
        store.record_ingestion(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            content_hash=revision.content_hash,
            accepted=False,
            reason_codes=("ARMOR_FINDING",),
            armor_verdict_ref=None,
            principal=revision.author_principal,
            decision_request_id="guidance-ingest-1",
        )
    with pytest.raises(GuidanceError, match="role is inactive"):
        store.record_ingestion(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            content_hash=revision.content_hash,
            accepted=True,
            reason_codes=("STRUCTURE_AND_SECURITY_VALIDATED",),
            armor_verdict_ref=None,
            principal="user:evaluator@example.com",
            decision_request_id="guidance-ingest-unauthorized",
        )
    evaluation_id = store.record_evaluation(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        expected_digest=revision.approval_digest,
        principal="user:evaluator@example.com",
        suite_version="guidance-adversarial-v1",
        passed_cases=6,
        failed_cases=0,
        receipt_ref="gs://solvan-evaluations/guidance-1.json",
        receipt_hash=HASH,
        receipt_generation="1",
        corpus_digest=HASH,
        case_set_digest=HASH,
        scorer_name="deterministic-guidance-scorer",
        scorer_version="1",
        model_config_pins={"model": "gemini-test-pinned"},
        repetitions=1,
        pass_thresholds={"pass_rate": 1.0},
        reason_codes=("ADVERSARIAL_SUITE_PASSED",),
        decision_request_id="guidance-eval-1",
    )
    assert evaluation_id.startswith("gev_")
    submitted = store.submit(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        principal=revision.author_principal,
        expected_digest=revision.approval_digest,
        decision_request_id="guidance-submit-1",
    )
    assert submitted.lifecycle == "IN_REVIEW"
    approved = store.approve(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        principal="user:approver@example.com",
        expected_digest=revision.approval_digest,
        evaluation_ref=evaluation_id,
        decision_request_id="guidance-approve-1",
        reason="Reviewed exact evaluation and bounded Tool graph.",
        known_predicates=frozenset({"evidence-kind-present@1"}),
    )
    assert approved.lifecycle == "APPROVED" and approved.decision_id is not None
    replayed_approval = store.approve(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        principal="user:approver@example.com",
        expected_digest=revision.approval_digest,
        evaluation_ref=evaluation_id,
        decision_request_id="guidance-approve-1",
        reason="Reviewed exact evaluation and bounded Tool graph.",
        known_predicates=frozenset({"evidence-kind-present@1"}),
    )
    assert replayed_approval.decision_id == approved.decision_id
    assert not replayed_approval.created
    projection = store.projection(scope=SCOPE)
    assert projection["guidance"][0]["guidance_key"] == revision.guidance_key
    assert "content_ref" not in projection["guidance"][0]
    with pytest.raises(RuntimeError, match="different material"):
        store.create_draft(
            scope=SCOPE,
            revision=revision.model_copy(update={"description": "changed after approval"}),
            decision_request_id="guidance-create-2",
        )


def test_agent_skills_declared_incompatibility_is_the_only_conflict_authority(
    connection,
) -> None:
    catalog = PostgresToolCatalogStore(connection)
    catalog.register_principal(_principal())
    catalog.publish_tool(_tool())
    catalog.publish_profile(scope=SCOPE, profile=_profile())
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%s,%s,%s,'user:author@example.com','GUIDANCE_AUTHOR',
                   'Payments SRE','test')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    store = PostgresOperationalGuidanceStore(connection)
    other = _guidance().model_copy(
        update={
            "guidance_key": "platform.other",
            "display_name": "Platform other procedure",
            "source_ref": "solvan://guidance/platform/other",
        }
    )
    store.create_draft(scope=SCOPE, revision=other, decision_request_id="skill-incompat-target")
    declared = _guidance().model_copy(
        update={
            "guidance_kind": GuidanceKind.SKILL,
            "incompatibilities": (
                GuidanceIncompatibilityDeclaration(
                    guidance_key=other.guidance_key,
                    reason_code="AUTHOR_DECLARED_INCOMPATIBLE",
                ),
            ),
        }
    )
    store.create_draft(scope=SCOPE, revision=declared, decision_request_id="skill-incompat-source")
    narrative_only = _guidance().model_copy(
        update={
            "guidance_key": "payments.narrated-conflict",
            "display_name": "Narrated conflict",
            "description": "A model may say this conflicts with platform.other.",
            "guidance_kind": GuidanceKind.SKILL,
            "source_ref": "solvan://guidance/payments/narrated-conflict",
            "incompatibilities": (),
        }
    )
    store.create_draft(
        scope=SCOPE,
        revision=narrative_only,
        decision_request_id="skill-incompat-narrative",
    )
    rows = connection.execute(
        """SELECT declaring_guidance_key,incompatible_guidance_key,reason_code
             FROM solvan_operability.guidance_incompatibilities
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
            ORDER BY declaring_guidance_key""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    ).fetchall()
    assert rows == [
        (
            declared.guidance_key,
            other.guidance_key,
            "AUTHOR_DECLARED_INCOMPATIBLE",
        )
    ]


def test_non_skill_incompatibility_declaration_is_persisted(connection) -> None:
    catalog = PostgresToolCatalogStore(connection)
    catalog.register_principal(_principal())
    catalog.publish_tool(_tool())
    catalog.publish_profile(scope=SCOPE, profile=_profile())
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%s,%s,%s,'user:author@example.com','GUIDANCE_AUTHOR',
                   'Payments SRE','test')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    store = PostgresOperationalGuidanceStore(connection)
    target = _guidance().model_copy(
        update={
            "guidance_key": "platform.other",
            "display_name": "Platform other procedure",
            "source_ref": "solvan://guidance/platform/other",
        }
    )
    store.create_draft(scope=SCOPE, revision=target, decision_request_id="runbook-incompat-target")
    runbook = _guidance().model_copy(
        update={
            "guidance_key": "payments.runbook-conflict",
            "display_name": "Runbook conflict",
            "guidance_kind": GuidanceKind.RUNBOOK,
            "source_ref": "solvan://guidance/payments/runbook-conflict",
            "incompatibilities": (
                GuidanceIncompatibilityDeclaration(
                    guidance_key=target.guidance_key,
                    reason_code="AUTHOR_DECLARED_INCOMPATIBLE",
                ),
            ),
        }
    )
    store.create_draft(scope=SCOPE, revision=runbook, decision_request_id="runbook-incompat-src")
    rows = connection.execute(
        """SELECT declaring_guidance_key,incompatible_guidance_key,reason_code,reviewable_digest
             FROM solvan_operability.guidance_incompatibilities
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
            ORDER BY declaring_guidance_key""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    ).fetchall()
    assert rows == [
        (
            runbook.guidance_key,
            target.guidance_key,
            "AUTHOR_DECLARED_INCOMPATIBLE",
            runbook.approval_digest,
        )
    ]


class _MemorySkillObjects:
    """Content-addressed object seam used by the Cloud SQL target E2E."""

    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}

    def put_bytes(self, *, object_name: str, content: bytes, content_type: str) -> ObjectReceipt:
        del content_type
        uri = f"gs://skills-test/{object_name}"
        self.items[uri] = content
        return ObjectReceipt(
            uri=uri,
            content_hash=f"sha256:{hashlib.sha256(content).hexdigest()}",
            generation="1",
        )

    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int = 1_048_576) -> bytes:
        content = self.items[uri]
        if len(content) > max_bytes:
            raise ValueError("object exceeds test read bound")
        actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if actual != expected_hash:
            raise ValueError("object hash mismatch")
        return content


def _skill_archive(*, license_identifier: str = "Apache-2.0") -> bytes:
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr(
            "connection-exhaustion/SKILL.md",
            "---\n"
            "name: connection-exhaustion\n"
            "description: Inspect bounded payment connection failures.\n"
            f"license: {license_identifier}\n"
            "---\n\n"
            "Read the registered payment error evidence for this incident.\n",
        )
    return output.getvalue()


def test_agent_skills_cloud_sql_target_e2e_import_approve_select_export(connection) -> None:
    """Exercise the target path against Cloud SQL, not the fixture repository."""

    catalog = PostgresToolCatalogStore(connection)
    catalog.register_principal(_principal())
    catalog.publish_tool(_tool())
    catalog.publish_profile(scope=SCOPE, profile=_profile())
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%s,%s,%s,'user:author@example.com','GUIDANCE_AUTHOR','Payments SRE','test'),
                  (%s,%s,%s,'user:evaluator@example.com','GUIDANCE_EVALUATOR',
                   'Payments SRE','test'),
                  (%s,%s,%s,'user:approver@example.com','GUIDANCE_APPROVER',
                   'Payments SRE','test'),
                  (%s,%s,%s,'user:exporter@example.com','GUIDANCE_EXPORTER',
                   'Payments SRE','test')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id) * 4,
    )
    connection.execute(
        """INSERT INTO solvan_operability.skill_retention_policies
             (organization_id,project_id,environment_id,policy_id,storage_region,retention_days)
           VALUES (%s,%s,%s,'default','europe-west1',30)""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    connection.execute(
        """INSERT INTO solvan_operability.skill_owner_department_slugs
             (organization_id,project_id,environment_id,owner_slug,owner_department,owner_principal)
           VALUES (%s,%s,%s,'payments','Payments SRE','user:author@example.com')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    connection.execute(
        """INSERT INTO solvan_operability.skill_license_policies
             (organization_id,project_id,environment_id,normalized_identifier,
              policy_version,import_allowed,redistribution_allowed,reviewed_by_principal)
           VALUES (%s,%s,%s,'Apache-2.0','test/1',true,true,
                   'user:approver@example.com')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    objects = _MemorySkillObjects()
    repository = PostgresSkillImportRepository(connection, object_writer=objects)
    disallowed_request = SkillImportCommand(
        command_id="skill-e2e-disallowed-license",
        scope=SCOPE,
        purpose="GUIDANCE_IMPORT",
        classification="INTERNAL",
        region="europe-west1",
        source_kind="ARCHIVE",
        source_ref="upload://connection-exhaustion-gpl",
        principal="user:author@example.com",
        authorization_ref="grant://guidance-author/e2e",
        idempotency_key="skill-e2e-gpl-license",
    )
    disallowed = SkillImportService(repository, armor=DeterministicModelArmor()).import_archive(
        disallowed_request,
        _skill_archive(license_identifier="GPL-3.0-only"),
    )
    assert disallowed.decision == "QUARANTINED"
    assert "LICENSE_POLICY_DENIED" in disallowed.reason_codes
    disallowed_state = connection.execute(
        """SELECT license_state,normalized_license_identifier
             FROM solvan_operability.skill_imports
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND attempt_id=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            disallowed.attempt_id,
        ),
    ).fetchone()
    assert disallowed_state == ("REJECTED_BY_POLICY", "GPL-3.0-only")
    with pytest.raises(ValueError, match="LICENSE_POLICY_DENIED"):
        repository.require_compile_context(
            scope=SCOPE,
            import_id=disallowed.attempt_id,
            guidance_key="payments.connection-exhaustion-gpl",
            owner_department="Payments SRE",
            normalized_license_identifier="GPL-3.0-only",
            source_classification=GuidanceSourceKind.IMPORTED,
            provenance_attestation_ref=None,
            provenance_attestation_hash=None,
            contains_third_party_material=False,
        )
    request = SkillImportCommand(
        command_id="skill-e2e-import",
        scope=SCOPE,
        purpose="GUIDANCE_IMPORT",
        classification="INTERNAL",
        region="europe-west1",
        source_kind="ARCHIVE",
        source_ref="upload://connection-exhaustion",
        principal="user:author@example.com",
        authorization_ref="grant://guidance-author/e2e",
        idempotency_key="skill-e2e-idempotency",
    )
    imported = SkillImportService(repository, armor=DeterministicModelArmor()).import_archive(
        request, _skill_archive()
    )
    assert imported.decision == "QUARANTINED"
    assert imported.inspection is not None
    inspection = repository.load_inspection(
        scope=SCOPE, import_id=imported.attempt_id, reader=objects
    )
    command = SkillCompileCommand(
        guidance_key="payments.connection-exhaustion",
        version="1",
        display_name="Payment connection exhaustion",
        description="Gather bounded evidence for exhausted pools.",
        owner_department="Payments SRE",
        discoverable_departments=("Payments", "Reliability"),
        applicable_service_kinds=("CLOUD_RUN",),
        applicable_incident_classes=("CONNECTION_EXHAUSTION",),
        symptom_tags=("http-503",),
        purpose="INCIDENT_INVESTIGATION",
        classification="INTERNAL",
        eligible_regions=("europe-west1",),
        allowed_agent_keys=("evidence-agent",),
        required_profile_revisions=(f"{FIXTURE_PROFILE_KEY}@1",),
        normalized_license_identifier="Apache-2.0",
        author_principal="user:author@example.com",
    )
    revision = compile_import(
        command=command, attempt_id=imported.attempt_id, inspection=inspection
    )
    store = PostgresOperationalGuidanceStore(connection)
    draft = store.create_draft(
        scope=SCOPE, revision=revision, decision_request_id="skill-e2e-draft"
    )
    license_evidence_hash = repository.require_compile_context(
        scope=SCOPE,
        import_id=imported.attempt_id,
        guidance_key=revision.guidance_key,
        owner_department=revision.owner_department,
        normalized_license_identifier="Apache-2.0",
        source_classification=GuidanceSourceKind.IMPORTED,
        provenance_attestation_ref=None,
        provenance_attestation_hash=None,
        contains_third_party_material=False,
    )
    repository.persist_compile_binding(
        scope=SCOPE,
        import_id=imported.attempt_id,
        revision=revision,
        license_evidence_hash=license_evidence_hash,
        provenance_attestation_ref=None,
        provenance_attestation_hash=None,
        contains_third_party_material=False,
    )
    assert draft.lifecycle == "DRAFT"
    store.record_ingestion(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        content_hash=revision.content_hash,
        accepted=True,
        reason_codes=("STRUCTURE_AND_SECURITY_VALIDATED",),
        armor_verdict_ref="armor:e2e:allow",
        principal="user:author@example.com",
        decision_request_id="skill-e2e-ingest",
    )
    evaluation_id = store.record_evaluation(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        expected_digest=revision.approval_digest,
        principal="user:evaluator@example.com",
        suite_version="agent-skills-e2e-v1",
        passed_cases=4,
        failed_cases=0,
        receipt_ref="gs://skills-test/evaluation.json",
        receipt_hash=HASH,
        receipt_generation="1",
        corpus_digest=HASH,
        case_set_digest=HASH,
        scorer_name="deterministic-guidance-scorer",
        scorer_version="1",
        model_config_pins={"model": "gemini-test-pinned"},
        repetitions=1,
        pass_thresholds={"pass_rate": 1.0},
        reason_codes=("ADVERSARIAL_SUITE_PASSED",),
        decision_request_id="skill-e2e-evaluation",
    )
    store.submit(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        principal="user:author@example.com",
        expected_digest=revision.approval_digest,
        decision_request_id="skill-e2e-submit",
    )
    approved = store.approve(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        principal="user:approver@example.com",
        expected_digest=revision.approval_digest,
        evaluation_ref=evaluation_id,
        decision_request_id="skill-e2e-approve",
        reason="Reviewed the exact imported bytes and evaluation receipt.",
        known_predicates=frozenset({"guidance-content-fetched@1"}),
    )
    assert approved.lifecycle == "APPROVED"
    approved_revision = revision.model_copy(
        update={
            "lifecycle": GuidanceLifecycle.APPROVED,
            "evaluation_ref": evaluation_id,
            "approval_ref": approved.decision_id,
            "approved_by_principal": "user:approver@example.com",
            "approved_at": datetime.now(UTC),
        }
    )
    connection.execute(
        """INSERT INTO solvan_operability.skill_reader_grants
             (organization_id,project_id,environment_id,principal,owner_department,
              purpose,region,classification_ceiling,granted_by_principal)
           VALUES (%s,%s,%s,'user:operator@example.com','Payments',
                   'INCIDENT_INVESTIGATION','europe-west1','INTERNAL',
                   'user:approver@example.com')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    selector = PostgresSkillSelector(connection)
    parsed, candidate = selector.resolve_for_principal(
        scope=SCOPE,
        principal="user:operator@example.com",
        command=("/payments/connection-exhaustion /other/skill nested activation remains inert"),
        runtime_region="europe-west1",
    )
    assert candidate.guidance_key == revision.guidance_key
    invocation = selector.record_invocation(
        scope=SCOPE,
        thread_id="thr_skills_e2e",
        answer_message_id="msg_skills_e2e",
        anchor_kind="RECORD",
        anchor_record_type="incident",
        anchor_record_id="inc_skills_e2e",
        parsed=parsed,
        candidate=candidate,
        principal="user:operator@example.com",
        membership_epoch=1,
        policy_epoch=1,
    )
    assert invocation.status == "PENDING_COORDINATOR"
    note_row = connection.execute(
        """SELECT note_text,note_classification,access_mode
             FROM solvan_operability.guidance_operator_notes
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND invocation_request_id=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            invocation.request_id,
        ),
    ).fetchone()
    assert note_row == (
        "/other/skill nested activation remains inert",
        "INTERNAL",
        "SELECTION_READERS",
    )
    analytics_row = connection.execute(
        """SELECT selection_reason,outcome_code,selection_count
             FROM solvan_operability.guidance_selection_analytics
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key=%s AND guidance_version=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            revision.guidance_key,
            revision.version,
        ),
    ).fetchone()
    assert analytics_row == ("OPERATOR_INVOKED", "CANDIDATE_RECORDED", 1)
    store.record_operator_note(
        scope=SCOPE,
        invocation_request_id=invocation.request_id,
        note="/other/skill nested activation remains inert",
        classification="INTERNAL",
        author_principal="user:operator@example.com",
    )
    with pytest.raises(GuidanceError, match="OPERATOR_NOTE_IDEMPOTENCY_MISMATCH"):
        store.record_operator_note(
            scope=SCOPE,
            invocation_request_id=invocation.request_id,
            note="a different note under the same invocation request",
            classification="INTERNAL",
            author_principal="user:operator@example.com",
        )
    assert connection.execute(
        """SELECT note_text FROM solvan_operability.guidance_operator_notes
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND invocation_request_id=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            invocation.request_id,
        ),
    ).fetchone() == ("/other/skill nested activation remains inert",)
    for _delivery in range(2):
        store.record_selection_analytics(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            selection_reason="OPERATOR_INVOKED",
            outcome_code="CANDIDATE_RECORDED",
            delivery_request_id=invocation.request_id,
        )
    with pytest.raises(GuidanceError, match="idempotency material mismatch"):
        store.record_selection_analytics(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            selection_reason="OPERATOR_INVOKED",
            outcome_code="CONFLICT_REFUSED",
            delivery_request_id=invocation.request_id,
        )
    assert connection.execute(
        """SELECT selection_count
             FROM solvan_operability.guidance_selection_analytics
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key=%s AND guidance_version=%s
              AND selection_reason='OPERATOR_INVOKED' AND outcome_code='CANDIDATE_RECORDED'""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            revision.guidance_key,
            revision.version,
        ),
    ).fetchone() == (2,)
    connection.execute(
        """INSERT INTO solvan_operability.guidance_export_destinations
             (organization_id,project_id,environment_id,destination_id,destination_kind,
              binding_ref,region,classification_ceiling)
           VALUES (%s,%s,%s,'local-e2e','GCS','gs://skills-e2e/exports',
                   'europe-west1','INTERNAL')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    export_id = repository.prepare_export(
        scope=SCOPE,
        idempotency_key="skill-e2e-export",
        request_hash="sha256:" + "b" * 64,
        guidance_key=approved_revision.guidance_key,
        guidance_version=approved_revision.version,
        destination_id="local-e2e",
        purpose="GUIDANCE_DISTRIBUTION",
        exporter_principal="user:exporter@example.com",
        authorization_ref="grant://guidance-exporter/e2e",
    )
    assert (
        repository.prepare_export(
            scope=SCOPE,
            idempotency_key="skill-e2e-export",
            request_hash="sha256:" + "b" * 64,
            guidance_key=approved_revision.guidance_key,
            guidance_version=approved_revision.version,
            destination_id="local-e2e",
            purpose="GUIDANCE_DISTRIBUTION",
            exporter_principal="user:exporter@example.com",
            authorization_ref="grant://guidance-exporter/e2e",
        )
        == export_id
    )
    with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
        repository.prepare_export(
            scope=SCOPE,
            idempotency_key="skill-e2e-export",
            request_hash="sha256:" + "c" * 64,
            guidance_key=approved_revision.guidance_key,
            guidance_version=approved_revision.version,
            destination_id="other",
            purpose="GUIDANCE_DISTRIBUTION",
            exporter_principal="user:exporter@example.com",
            authorization_ref="grant://guidance-exporter/e2e",
        )
    bundle, receipt = export_approved_revision(
        revision=approved_revision,
        files=inspection.files,
        destination_id="local-e2e",
        export_id=export_id,
    )
    stored = repository.persist_export(
        scope=SCOPE,
        revision=approved_revision,
        idempotency_key="skill-e2e-export",
        request_hash="sha256:" + "b" * 64,
        destination_id="local-e2e",
        exporter_principal="user:exporter@example.com",
        authorization_ref="grant://guidance-exporter/e2e",
        receipt=receipt,
        stale_acknowledged=False,
        destination_receipt_ref="gs://skills-test/exports/e2e.zip",
        destination_receipt_generation="1",
        destination_kind="GCS",
        destination_binding_ref="gs://skills-e2e/exports",
        scanner_receipts=tuple(
            SecurityScanReceipt(name, "e2e-1", "ALLOWED", (), receipt.bundle_hash)
            for name in ("SECRET_SCANNER", "PII_SCANNER", "MODEL_ARMOR", "TENANT_LICENSE_POLICY")
        ),
        storage_region="europe-west1",
    )
    assert stored.bundle_hash == receipt.bundle_hash
    assert bundle.startswith(b"PK")
    assert repository.find_export(scope=SCOPE, request_hash="sha256:" + "b" * 64) is not None
    export_row = connection.execute(
        """SELECT stale_acknowledged
             FROM solvan_operability.skill_export_receipts
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND attempt_id=%s""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, export_id),
    ).fetchone()
    assert export_row == (False,)

    deprecated = store.deprecate(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version=revision.version,
        principal="user:approver@example.com",
        expected_digest=revision.approval_digest,
        decision_request_id="skill-e2e-deprecate-v1",
    )
    assert deprecated.lifecycle == "DEPRECATED"
    with pytest.raises(ValueError, match="GUIDANCE_NOT_ELIGIBLE"):
        selector.resolve_for_principal(
            scope=SCOPE,
            principal="user:operator@example.com",
            command="/payments/connection-exhaustion",
            runtime_region="europe-west1",
        )

    successor_command = command.model_copy(
        update={
            "version": "2",
            "description": "Gather bounded evidence using the reviewed successor.",
            "supersedes": revision.revision_ref,
        }
    )
    successor = compile_import(
        command=successor_command,
        attempt_id=imported.attempt_id,
        inspection=inspection,
    )
    store.create_draft(
        scope=SCOPE,
        revision=successor,
        decision_request_id="skill-e2e-draft-v2",
    )
    repository.persist_compile_binding(
        scope=SCOPE,
        import_id=imported.attempt_id,
        revision=successor,
        license_evidence_hash=license_evidence_hash,
        provenance_attestation_ref=None,
        provenance_attestation_hash=None,
        contains_third_party_material=False,
    )
    competing = compile_import(
        command=successor_command.model_copy(update={"version": "3"}),
        attempt_id=imported.attempt_id,
        inspection=inspection,
    )
    with pytest.raises(GuidanceError, match="LINEAGE_CONFLICT"):
        store.create_draft(
            scope=SCOPE,
            revision=competing,
            decision_request_id="skill-e2e-competing-v3",
        )
    store.record_ingestion(
        scope=SCOPE,
        guidance_key=successor.guidance_key,
        version=successor.version,
        content_hash=successor.content_hash,
        accepted=True,
        reason_codes=("STRUCTURE_AND_SECURITY_VALIDATED",),
        armor_verdict_ref="armor:e2e:allow-v2",
        principal="user:author@example.com",
        decision_request_id="skill-e2e-ingest-v2",
    )
    successor_evaluation = store.record_evaluation(
        scope=SCOPE,
        guidance_key=successor.guidance_key,
        version=successor.version,
        expected_digest=successor.approval_digest,
        principal="user:evaluator@example.com",
        suite_version="agent-skills-e2e-v1",
        passed_cases=4,
        failed_cases=0,
        receipt_ref="gs://skills-test/evaluation-v2.json",
        receipt_hash=HASH,
        receipt_generation="2",
        corpus_digest=HASH,
        case_set_digest=HASH,
        scorer_name="deterministic-guidance-scorer",
        scorer_version="1",
        model_config_pins={"model": "gemini-test-pinned"},
        repetitions=1,
        pass_thresholds={"pass_rate": 1.0},
        reason_codes=("ADVERSARIAL_SUITE_PASSED",),
        decision_request_id="skill-e2e-evaluation-v2",
    )
    store.submit(
        scope=SCOPE,
        guidance_key=successor.guidance_key,
        version=successor.version,
        principal="user:author@example.com",
        expected_digest=successor.approval_digest,
        decision_request_id="skill-e2e-submit-v2",
    )
    store.approve(
        scope=SCOPE,
        guidance_key=successor.guidance_key,
        version=successor.version,
        principal="user:approver@example.com",
        expected_digest=successor.approval_digest,
        evaluation_ref=successor_evaluation,
        decision_request_id="skill-e2e-approve-v2",
        reason="Reviewed the exact successor and evaluation receipt.",
        known_predicates=frozenset({"guidance-content-fetched@1"}),
    )
    _, selected_successor = selector.resolve_for_principal(
        scope=SCOPE,
        principal="user:operator@example.com",
        command="/payments/connection-exhaustion",
        runtime_region="europe-west1",
    )
    assert selected_successor.version == "2"


def _trigger_policy() -> TriggerPolicyRevision:
    return TriggerPolicyRevision(
        policy_key="ruhu.rollout-investigation",
        version="1",
        owner_department="Reliability Platform",
        trigger_kind="DEPLOYMENT_ROLLOUT",
        source_connection_id=CONNECTION_ID,
        source_connection_epoch=1,
        source_capability_tool_ref="fixture_bounded_metric_read@1",
        source_capability_agent_key="evidence-agent",
        source_capability_identity_ref="identity://evidence-agent/1",
        source_capability_class="METRIC_READ",
        target_selector_ref="selector://ruhu/cloud-run-service@1",
        incident_class="deployment_regression",
        severity="SEV3",
        deduplication_dimension="rollout",
        action_budget=2,
        repeated_action_limit=1,
        investigation_profile_ref="evidence.ruhu-trigger-observability.v1@1",
        delay_ms=0,
        cooldown_ms=0,
        maximum_pending_per_target=3,
        supersession="LATEST_WAITING_PER_TARGET",
        region="europe-west1",
        classification_ceiling="INTERNAL",
        lifecycle="DRAFT",
        author_principal="user:trigger-author@example.com",
    )


def _event(sequence: int) -> VerifiedTriggerEvent:
    return VerifiedTriggerEvent(
        source_event_id=f"rollout-delivery-{sequence}",
        source_sequence=sequence,
        source_event_hash=f"sha256:{sequence:064x}",
        connection_id=CONNECTION_ID,
        connection_epoch=1,
        target_key="cloud-run/ruhu-api",
        target_snapshot_hash=TRIGGER_TARGET_HASH,
        region="europe-west1",
        classification="INTERNAL",
        observed_at=datetime.now(UTC) - timedelta(seconds=5),
    )


def _approved_trigger_store(
    connection,
    *,
    policy: TriggerPolicyRevision | None = None,
    decision_prefix: str = "trigger",
) -> tuple[PostgresTriggerPolicyStore, TriggerPolicyRevision]:
    """Install one exact approved policy and its fresh capability proof."""

    catalog = PostgresToolCatalogStore(connection)
    catalog.register_principal(_principal())
    catalog.publish_tool(_tool())
    catalog.publish_profile(scope=SCOPE, profile=_trigger_profile())
    now = datetime.now(UTC)
    catalog.record_probe(
        scope=SCOPE,
        probe=CapabilityProbe(
            connection_id=CONNECTION_ID,
            tool_revision="fixture_bounded_metric_read@1",
            agent_key="evidence-agent",
            connection_provider="CLOUD_MONITORING",
            capabilities=frozenset({"promql.read"}),
            connection_epoch=1,
            identity_ref="identity://evidence-agent/1",
            registry_resource="registry://managed-prometheus/1",
            gateway_policy_ref="gateway://policy/1",
            network_policy_hash=HASH,
            region="europe-west1",
            classification_ceiling="INTERNAL",
            outcome="PASSED",
            observed_at=now,
            expires_at=now + timedelta(minutes=5),
            receipt_ref="receipt://probe/trigger",
            receipt_hash=HASH,
        ),
    )
    connection.execute(
        """UPDATE solvan.production_graph_snapshots
              SET superseded_at=now()
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND status='APPROVED' AND superseded_at IS NULL
              AND id<>%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            TRIGGER_SNAPSHOT_ID,
        ),
    )
    connection.execute(
        """INSERT INTO solvan.production_graph_snapshots
             (organization_id,project_id,environment_id,id,version,status,
              source_manifest_ref,content_hash,effective_at,approved_by,approved_at)
           VALUES (%s,%s,%s,%s,777,'APPROVED','fixture://trigger-graph',%s,now(),
                   'user:graph-approver@example.com',now())
           ON CONFLICT DO NOTHING""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            TRIGGER_SNAPSHOT_ID,
            HASH,
        ),
    )
    connection.execute(
        """INSERT INTO solvan.production_graph_nodes
             (organization_id,project_id,environment_id,id,snapshot_id,node_key,
              node_kind,resource_ref,external_project_id,classification,
              provenance_ref,attributes_json)
           VALUES (%s,%s,%s,%s,%s,
                   'cloud-run/ruhu-api','SERVICE',
                   'projects/solvan-test/locations/europe-west1/services/ruhu-api',
                   'solvan-test','INTERNAL','fixture://trigger-target',
                   '{"region":"europe-west1"}'::jsonb)
           ON CONFLICT DO NOTHING""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            TRIGGER_NODE_ID,
            TRIGGER_SNAPSHOT_ID,
        ),
    )
    connection.execute(
        """INSERT INTO solvan_onboarding.environment_external_project_bindings
             (organization_id,project_id,environment_id,external_project_id,
              binding_epoch,deciding_principal,decision_ref,is_current)
           VALUES (%s,%s,%s,'solvan-test',1,'user:test@example.com',
                   'fixture://trigger-project-binding',true)
           ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    connection.execute(
        """INSERT INTO solvan_onboarding.connection_external_project_coverage
             (organization_id,project_id,environment_id,connection_id,
              capability_class,external_project_id,connection_epoch,observed_at,
              probe_receipt_ref)
           VALUES (%s,%s,%s,%s,'METRIC_READ','solvan-test',1,now(),
                   'receipt://probe/trigger')
           ON CONFLICT DO NOTHING""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            CONNECTION_ID,
        ),
    )
    store = PostgresTriggerPolicyStore(connection)
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%s,%s,%s,'user:trigger-author@example.com','TRIGGER_POLICY_AUTHOR',
                   'Reliability Platform','test'),
                  (%s,%s,%s,'user:trigger-evaluator@example.com','TRIGGER_POLICY_EVALUATOR',
                   'Reliability Platform','test'),
                  (%s,%s,%s,'user:trigger-approver@example.com','TRIGGER_POLICY_APPROVER',
                   'Reliability Platform','test'),
                  (%s,%s,%s,'user:trigger-activator@example.com','TRIGGER_POLICY_ACTIVATOR',
                   'Reliability Platform','test'),
                  (%s,%s,%s,'user:trigger-lifecycle@example.com',
                   'TRIGGER_POLICY_LIFECYCLE_MANAGER','Reliability Platform','test'),
                  (%s,%s,%s,'user:trigger-replacer@example.com',
                   'TRIGGER_POLICY_ACTIVATOR','Reliability Platform','test'),
                  (%s,%s,%s,'user:trigger-replacer@example.com',
                   'TRIGGER_POLICY_LIFECYCLE_MANAGER','Reliability Platform','test')
           ON CONFLICT DO NOTHING""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
        ),
    )
    policy = policy or _trigger_policy()
    store.create_draft(
        scope=SCOPE,
        policy=policy,
        decision_request_id=f"{decision_prefix}-create-1",
    )
    store.record_evaluation(
        scope=SCOPE,
        policy_key=policy.policy_key,
        version=policy.version,
        expected_digest=policy.policy_hash,
        principal="user:trigger-evaluator@example.com",
        suite_version="trigger-rollout-v1",
        passed_cases=8,
        failed_cases=0,
        receipt_ref="gs://solvan-evaluations/trigger-1.json",
        receipt_hash=HASH,
        reason_codes=("TRIGGER_SUITE_PASSED",),
        decision_request_id=f"{decision_prefix}-eval-1",
    )
    approved = store.approve(
        scope=SCOPE,
        policy_key=policy.policy_key,
        version=policy.version,
        principal="user:trigger-approver@example.com",
        expected_digest=policy.policy_hash,
        reason="Reviewed the exact source, target, delay, and qualification receipt.",
        decision_request_id=f"{decision_prefix}-approve-1",
    )
    assert approved.lifecycle == "APPROVED"
    eligible = store.mark_eligible(
        scope=SCOPE,
        policy_key=policy.policy_key,
        version=policy.version,
        principal="user:trigger-lifecycle@example.com",
        expected_digest=policy.policy_hash,
        decision_request_id=f"{decision_prefix}-eligible-1",
    )
    assert eligible.lifecycle == "ELIGIBLE"
    active = store.activate(
        scope=SCOPE,
        policy_key=policy.policy_key,
        version=policy.version,
        principal="user:trigger-activator@example.com",
        expected_digest=policy.policy_hash,
        expected_prior_head_epoch=0,
        expected_activation_id=None,
        placement_epoch=1,
        decision_request_id=f"{decision_prefix}-activate-1",
    )
    assert active.lifecycle == "ACTIVE"
    return store, policy


def test_trigger_firing_deduplicates_supersedes_and_enqueues_once(connection) -> None:
    store, _ = _approved_trigger_store(connection)
    first_event = _event(1)
    first = store.accept_event(
        scope=SCOPE,
        policy_key="ruhu.rollout-investigation",
        policy_version="1",
        event=first_event,
    )
    duplicate = store.accept_event(
        scope=SCOPE,
        policy_key="ruhu.rollout-investigation",
        policy_version="1",
        event=first_event,
    )
    second = store.accept_event(
        scope=SCOPE,
        policy_key="ruhu.rollout-investigation",
        policy_version="1",
        event=_event(2),
    )
    assert first.status == second.status == "WAITING"
    assert duplicate.firing_id == first.firing_id and not duplicate.created
    claim = store.claim_due(scope=SCOPE, owner="trigger-scheduler", now=datetime.now(UTC))
    assert claim is not None and claim.firing_id == second.firing_id
    enqueue_result = store.enqueue_claim(
        scope=SCOPE,
        claim=claim,
        observed_target_snapshot_hash=_event(2).target_snapshot_hash,
    )
    assert enqueue_result.status == "ENQUEUED"
    assert enqueue_result.inbox_event_id is not None
    assert enqueue_result.inbox_event_id.startswith("evt_")
    statuses = connection.execute(
        """SELECT status,count(*) FROM solvan_operability.trigger_firings
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
            GROUP BY status ORDER BY status""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    ).fetchall()
    assert statuses == [("ENQUEUED", 1), ("SUPERSEDED", 1)]
    assert connection.execute(
        "SELECT count(*) FROM solvan.inbox_events WHERE source='trigger-policy'"
    ).fetchone() == (1,)
    assert (
        PostgresConnectionStore(connection).invalidate_connection(
            scope=SCOPE,
            connection_id=CONNECTION_ID,
            expected_epoch=1,
            revoke=False,
        )
        == 2
    )
    with pytest.raises(RuntimeError, match="connection epoch has changed"):
        store.accept_event(
            scope=SCOPE,
            policy_key="ruhu.rollout-investigation",
            policy_version="1",
            event=_event(3),
        )


def test_trigger_event_replay_requires_exact_material_and_current_capability(connection) -> None:
    store, _ = _approved_trigger_store(connection)
    event = _event(70)
    accepted = store.accept_event(
        scope=SCOPE,
        policy_key="ruhu.rollout-investigation",
        policy_version="1",
        event=event,
    )
    with pytest.raises(RuntimeError, match="reused with changed material"):
        store.accept_event(
            scope=SCOPE,
            policy_key="ruhu.rollout-investigation",
            policy_version="1",
            event=event.model_copy(update={"source_event_hash": f"sha256:{'f' * 64}"}),
        )
    deleted_probe = connection.execute(
        """DELETE FROM solvan_operability.tool_probe_receipts
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND connection_id=%s AND tool_key='fixture_bounded_metric_read'""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            CONNECTION_ID,
        ),
    )
    assert deleted_probe.rowcount == 1
    with pytest.raises(RuntimeError, match="exact capability proof"):
        store.accept_event(
            scope=SCOPE,
            policy_key="ruhu.rollout-investigation",
            policy_version="1",
            event=event,
        )
    PostgresToolCatalogStore(connection).record_probe(
        scope=SCOPE,
        probe=CapabilityProbe(
            connection_id=CONNECTION_ID,
            tool_revision="fixture_bounded_metric_read@1",
            agent_key="evidence-agent",
            connection_provider="CLOUD_MONITORING",
            capabilities=frozenset({"promql.read"}),
            connection_epoch=1,
            identity_ref="identity://unrelated-agent/1",
            registry_resource="registry://managed-prometheus/1",
            gateway_policy_ref="gateway://policy/1",
            network_policy_hash=HASH,
            region="europe-west1",
            classification_ceiling="INTERNAL",
            outcome="PASSED",
            observed_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            receipt_ref="receipt://probe/trigger",
            receipt_hash=HASH,
        ),
    )
    with pytest.raises(RuntimeError, match="exact capability proof"):
        store.accept_event(
            scope=SCOPE,
            policy_key="ruhu.rollout-investigation",
            policy_version="1",
            event=event,
        )
    assert accepted.created


def test_trigger_capability_requires_exact_project_coverage_at_accept_and_enqueue(
    connection,
) -> None:
    store, policy = _approved_trigger_store(connection)
    connection.execute(
        """DELETE FROM solvan_onboarding.connection_external_project_coverage
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND connection_id=%s AND capability_class='METRIC_READ'""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            CONNECTION_ID,
        ),
    )
    with pytest.raises(RuntimeError, match="exact capability proof"):
        store.accept_event(
            scope=SCOPE,
            policy_key=policy.policy_key,
            policy_version=policy.version,
            event=_event(80),
        )

    connection.execute(
        """INSERT INTO solvan_onboarding.connection_external_project_coverage
             (organization_id,project_id,environment_id,connection_id,
              capability_class,external_project_id,connection_epoch,observed_at,
              probe_receipt_ref)
           VALUES (%s,%s,%s,%s,'METRIC_READ','solvan-test',1,now(),
                   'receipt://probe/trigger')""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            CONNECTION_ID,
        ),
    )
    store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(81),
    )
    claim = store.claim_due(scope=SCOPE, owner="trigger-scheduler", now=datetime.now(UTC))
    assert claim is not None
    connection.execute(
        """DELETE FROM solvan_onboarding.connection_external_project_coverage
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND connection_id=%s AND capability_class='METRIC_READ'""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            CONNECTION_ID,
        ),
    )
    blocked = store.enqueue_claim(
        scope=SCOPE,
        claim=claim,
        observed_target_snapshot_hash=TRIGGER_TARGET_HASH,
    )
    assert blocked.status == "BLOCKED"
    assert blocked.decision_reason == "CONNECTION_CAPABILITY_INVALID"


def test_trigger_decision_replay_reauthorizes_and_compares_full_body(connection) -> None:
    store, policy = _approved_trigger_store(connection)
    with pytest.raises(RuntimeError, match="changed material"):
        store.record_evaluation(
            scope=SCOPE,
            policy_key=policy.policy_key,
            version=policy.version,
            expected_digest=policy.policy_hash,
            principal="user:trigger-evaluator@example.com",
            suite_version="trigger-rollout-v1",
            passed_cases=7,
            failed_cases=0,
            receipt_ref="gs://solvan-evaluations/trigger-1.json",
            receipt_hash=HASH,
            reason_codes=("TRIGGER_SUITE_PASSED",),
            decision_request_id="trigger-eval-1",
        )
    with pytest.raises(RuntimeError, match="changed material"):
        store.approve(
            scope=SCOPE,
            policy_key=policy.policy_key,
            version=policy.version,
            principal="user:trigger-approver@example.com",
            expected_digest=policy.policy_hash,
            reason="A different replay body.",
            decision_request_id="trigger-approve-1",
        )
    connection.execute(
        """DELETE FROM solvan_operability.operability_role_bindings
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND principal IN ('user:trigger-evaluator@example.com',
                                'user:trigger-approver@example.com')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    with pytest.raises(RuntimeError, match="role is inactive"):
        store.record_evaluation(
            scope=SCOPE,
            policy_key=policy.policy_key,
            version=policy.version,
            expected_digest=policy.policy_hash,
            principal="user:trigger-evaluator@example.com",
            suite_version="trigger-rollout-v1",
            passed_cases=8,
            failed_cases=0,
            receipt_ref="gs://solvan-evaluations/trigger-1.json",
            receipt_hash=HASH,
            reason_codes=("TRIGGER_SUITE_PASSED",),
            decision_request_id="trigger-eval-1",
        )
    with pytest.raises(RuntimeError, match="role is inactive"):
        store.approve(
            scope=SCOPE,
            policy_key=policy.policy_key,
            version=policy.version,
            principal="user:trigger-approver@example.com",
            expected_digest=policy.policy_hash,
            reason="Reviewed the exact source, target, delay, and qualification receipt.",
            decision_request_id="trigger-approve-1",
        )


def test_expired_trigger_claim_is_reclaimed_and_old_token_is_fenced(connection) -> None:
    store, _ = _approved_trigger_store(connection)
    accepted = store.accept_event(
        scope=SCOPE,
        policy_key="ruhu.rollout-investigation",
        policy_version="1",
        event=_event(10),
    )
    claimed_at = datetime.now(UTC)
    old = store.claim_due(scope=SCOPE, owner="scheduler-old", now=claimed_at, lease_seconds=10)
    assert old is not None and old.firing_id == accepted.firing_id
    time.sleep(10.1)
    replacement = store.claim_due(
        scope=SCOPE,
        owner="scheduler-new",
        now=datetime.now(UTC),
        lease_seconds=60,
    )
    assert replacement is not None and replacement.firing_id == old.firing_id
    assert replacement.claim_token != old.claim_token
    assert connection.execute(
        """SELECT f.claim_owner,f.claim_token,
                  f.claim_owner=w.claim_owner,
                  f.claim_token=w.claim_token,
                  f.claim_expires_at=w.claim_expires_at
             FROM solvan_operability.trigger_firings f
             JOIN solvan_operability.trigger_firing_wakeups w ON
               (w.organization_id,w.project_id,w.environment_id,w.firing_id)=
               (f.organization_id,f.project_id,f.environment_id,f.id)
            WHERE f.id=%s AND w.id=%s""",
        (replacement.firing_id, replacement.wakeup_id),
    ).fetchone() == (
        "scheduler-new",
        replacement.claim_token,
        True,
        True,
        True,
    )
    with pytest.raises(RuntimeError, match="stale or lost"):
        store.enqueue_claim(
            scope=SCOPE,
            claim=old,
            observed_target_snapshot_hash=old.target_snapshot_hash,
        )
    result = store.enqueue_claim(
        scope=SCOPE,
        claim=replacement,
        observed_target_snapshot_hash=replacement.target_snapshot_hash,
    )
    assert result.status == "ENQUEUED"


def test_disabled_policy_after_claim_blocks_enqueue(connection) -> None:
    store, policy = _approved_trigger_store(connection)
    store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(20),
    )
    claim = store.claim_due(scope=SCOPE, owner="scheduler", now=datetime.now(UTC))
    assert claim is not None
    store.disable(
        scope=SCOPE,
        policy_key=policy.policy_key,
        version=policy.version,
        principal="user:trigger-activator@example.com",
        expected_digest=policy.policy_hash,
        expected_head_epoch=1,
        expected_activation_id=claim.activation_id,
        decision_request_id="trigger-disable-after-claim",
    )
    result = store.enqueue_claim(
        scope=SCOPE,
        claim=claim,
        observed_target_snapshot_hash=claim.target_snapshot_hash,
    )
    assert result.status == "BLOCKED"
    assert result.decision_reason == "POLICY_NOT_ACTIVE"
    assert result.inbox_event_id is None


def test_changed_trigger_target_blocks_enqueue(connection) -> None:
    store, policy = _approved_trigger_store(connection)
    store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(30),
    )
    claim = store.claim_due(scope=SCOPE, owner="scheduler", now=datetime.now(UTC))
    assert claim is not None
    result = store.enqueue_claim(
        scope=SCOPE,
        claim=claim,
        observed_target_snapshot_hash=f"sha256:{'f' * 64}",
    )
    assert result.status == "BLOCKED"
    assert result.decision_reason == "TARGET_CHANGED"
    assert result.inbox_event_id is None


def test_cooldown_suppresses_a_new_firing_without_touching_running_work(connection) -> None:
    policy = _trigger_policy().model_copy(update={"cooldown_ms": 60_000})
    store, _ = _approved_trigger_store(connection, policy=policy)
    first = store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(40),
    )
    claim = store.claim_due(scope=SCOPE, owner="scheduler", now=datetime.now(UTC))
    assert claim is not None and claim.firing_id == first.firing_id
    enqueued = store.enqueue_claim(
        scope=SCOPE,
        claim=claim,
        observed_target_snapshot_hash=claim.target_snapshot_hash,
    )
    assert enqueued.status == "ENQUEUED"
    connection.execute(
        """UPDATE solvan_operability.trigger_firings SET status='RUNNING'
             WHERE organization_id=%s AND project_id=%s AND environment_id=%s AND id=%s""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, first.firing_id),
    )
    second = store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(41),
    )
    assert second.status == "SUPPRESSED"
    assert connection.execute(
        "SELECT status FROM solvan_operability.trigger_firings WHERE id=%s",
        (first.firing_id,),
    ).fetchone() == ("RUNNING",)


def test_trigger_firing_sql_guard_owns_transitions_and_field_shapes(connection) -> None:
    store, policy = _approved_trigger_store(connection)
    firing = store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(80),
    )
    for index, illegal_root in enumerate(
        ("CLAIMED", "ENQUEUED", "RUNNING", "COMPLETED", "SUPERSEDED", "BLOCKED"),
        start=1,
    ):
        with (
            pytest.raises(
                psycopg.errors.ObjectNotInPrerequisiteState,
                match="legal root state",
            ),
            connection.transaction(),
        ):
            connection.execute(
                """INSERT INTO solvan_operability.trigger_firings
                   SELECT (jsonb_populate_record(
                     NULL::solvan_operability.trigger_firings,
                     to_jsonb(source_firing) || jsonb_build_object(
                       'id',%(id)s::text,
                       'source_event_id',%(source_event_id)s::text,
                       'status',%(status)s::text
                     )
                   )).* FROM solvan_operability.trigger_firings source_firing
                    WHERE source_firing.id=%(source_firing_id)s""",
                {
                    "id": f"trf_06{'0' * 23}{index}",
                    "source_event_id": f"illegal-root-{index}",
                    "status": illegal_root,
                    "source_firing_id": firing.firing_id,
                },
            )
    with (
        pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="illegal trigger firing status transition",
        ),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings SET status='RUNNING'
                 WHERE id=%s""",
            (firing.firing_id,),
        )
    with (
        pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="state fields are immutable",
        ),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings SET completed_at=now()
                 WHERE id=%s""",
            (firing.firing_id,),
        )

    claim = store.claim_due(scope=SCOPE, owner="state-guard", now=datetime.now(UTC))
    assert claim is not None and claim.firing_id == firing.firing_id
    assert connection.execute(
        """SELECT status,claim_owner,claim_token IS NOT NULL,claim_expires_at IS NOT NULL
             FROM solvan_operability.trigger_firings WHERE id=%s""",
        (firing.firing_id,),
    ).fetchone() == ("CLAIMED", "state-guard", True, True)
    with (
        pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="healthy trigger firing lease cannot be replaced",
        ),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings
                  SET claim_owner='lease-thief',claim_token=gen_random_uuid(),
                      claim_expires_at=claim_expires_at + interval '30 seconds'
                WHERE id=%s""",
            (firing.firing_id,),
        )
    enqueued = store.enqueue_claim(
        scope=SCOPE,
        claim=claim,
        observed_target_snapshot_hash=claim.target_snapshot_hash,
    )
    assert enqueued.status == "ENQUEUED"
    assert connection.execute(
        """SELECT claim_owner,claim_token,claim_expires_at,
                  coordinator_inbox_event_id IS NOT NULL,completed_at
             FROM solvan_operability.trigger_firings WHERE id=%s""",
        (firing.firing_id,),
    ).fetchone() == (None, None, None, True, None)
    with (
        pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="cannot retain a lease tuple|state fields are immutable",
        ),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings SET claim_owner='stale'
                 WHERE id=%s""",
            (firing.firing_id,),
        )
    with (
        pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="inbox result",
        ),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings
                  SET status='RUNNING',coordinator_inbox_event_id=NULL WHERE id=%s""",
            (firing.firing_id,),
        )

    connection.execute(
        "UPDATE solvan_operability.trigger_firings SET status='RUNNING' WHERE id=%s",
        (firing.firing_id,),
    )
    connection.execute(
        """UPDATE solvan_operability.trigger_firings
              SET status='COMPLETED',completed_at=now() WHERE id=%s""",
        (firing.firing_id,),
    )
    with (
        pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="illegal trigger firing status transition",
        ),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings
                  SET status='RUNNING',completed_at=NULL WHERE id=%s""",
            (firing.firing_id,),
        )

    blocked_firing = store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(81),
    )
    blocked_claim = store.claim_due(scope=SCOPE, owner="state-guard", now=datetime.now(UTC))
    assert blocked_claim is not None and blocked_claim.firing_id == blocked_firing.firing_id
    blocked = store.block_claim(
        scope=SCOPE,
        claim=blocked_claim,
        reason="TARGET_STATE_INVALID",
    )
    assert blocked.status == "BLOCKED"
    assert connection.execute(
        """SELECT decision_reason,completed_at IS NOT NULL,claim_token
             FROM solvan_operability.trigger_firings WHERE id=%s""",
        (blocked_firing.firing_id,),
    ).fetchone() == ("TARGET_STATE_INVALID", True, None)


def test_retiring_current_trigger_head_atomically_removes_matching_authority(connection) -> None:
    store, policy = _approved_trigger_store(connection)
    retired = store.retire(
        scope=SCOPE,
        policy_key=policy.policy_key,
        version=policy.version,
        principal="user:trigger-lifecycle@example.com",
        expected_digest=policy.policy_hash,
        expected_lifecycle_epoch=1,
        expected_head_epoch=1,
        expected_activation_id=connection.execute(
            """SELECT activation_id FROM solvan_operability.trigger_policy_current_heads
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND policy_key=%s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                policy.policy_key,
            ),
        ).fetchone()[0],
        decision_request_id="trigger-retire-current-1",
    )
    assert retired.lifecycle == "RETIRED"
    assert connection.execute(
        """SELECT h.is_current,h.activation_kind,l.availability,l.decision_operation
             FROM solvan_operability.trigger_policy_current_heads h
             JOIN solvan_operability.trigger_policy_current_lifecycles l USING
               (organization_id,project_id,environment_id,policy_key)
            WHERE h.organization_id=%s AND h.project_id=%s AND h.environment_id=%s
              AND h.policy_key=%s AND l.policy_version=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            policy.policy_key,
            policy.version,
        ),
    ).fetchone() == (False, "DEACTIVATE", "RETIRED", "RETIRE")
    with pytest.raises(RuntimeError, match="active eligible trigger-policy head"):
        store.accept_event(
            scope=SCOPE,
            policy_key=policy.policy_key,
            policy_version=policy.version,
            event=_event(50),
        )


def test_trigger_authority_tuple_splicing_is_rejected_by_exact_foreign_keys(connection) -> None:
    store, policy = _approved_trigger_store(connection)
    firing = store.accept_event(
        scope=SCOPE,
        policy_key=policy.policy_key,
        policy_version=policy.version,
        event=_event(60),
    )
    with (
        pytest.raises(psycopg.errors.ForeignKeyViolation, match="trigger_policy_current_heads"),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_policy_current_heads
                      SET policy_hash=%s
                    WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                      AND policy_key=%s""",
            (
                f"sha256:{'f' * 64}",
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                policy.policy_key,
            ),
        )
    with (
        pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="frozen material"),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings
                      SET placement_epoch=placement_epoch+1
                    WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                      AND id=%s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                firing.firing_id,
            ),
        )
    with (
        pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="frozen material"),
        connection.transaction(),
    ):
        connection.execute(
            """UPDATE solvan_operability.trigger_firings
                      SET source_event_hash=%s
                    WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                      AND id=%s""",
            (
                f"sha256:{'e' * 64}",
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                firing.firing_id,
            ),
        )


def test_prepared_trigger_replacement_is_exact_atomic_and_single_use(connection) -> None:
    store, current = _approved_trigger_store(connection)
    successor = _trigger_policy().model_copy(update={"version": "2"})
    store.create_draft(
        scope=SCOPE, policy=successor, decision_request_id="trigger-create-successor"
    )
    store.record_evaluation(
        scope=SCOPE,
        policy_key=successor.policy_key,
        version=successor.version,
        expected_digest=successor.policy_hash,
        principal="user:trigger-evaluator@example.com",
        suite_version="trigger-rollout-v1",
        passed_cases=8,
        failed_cases=0,
        receipt_ref="gs://solvan-evaluations/trigger-2.json",
        receipt_hash=HASH,
        reason_codes=("TRIGGER_SUITE_PASSED",),
        decision_request_id="trigger-eval-successor",
    )
    store.approve(
        scope=SCOPE,
        policy_key=successor.policy_key,
        version=successor.version,
        principal="user:trigger-approver@example.com",
        expected_digest=successor.policy_hash,
        reason="Reviewed the exact successor material.",
        decision_request_id="trigger-approve-successor",
    )
    store.mark_eligible(
        scope=SCOPE,
        policy_key=successor.policy_key,
        version=successor.version,
        principal="user:trigger-lifecycle@example.com",
        expected_digest=successor.policy_hash,
        decision_request_id="trigger-eligible-successor",
    )
    activation_id = connection.execute(
        """SELECT activation_id FROM solvan_operability.trigger_policy_current_heads
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND policy_key=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            current.policy_key,
        ),
    ).fetchone()[0]
    prepared = store.prepare_replacement(
        scope=SCOPE,
        retiring_policy_key=current.policy_key,
        retiring_version=current.version,
        retiring_digest=current.policy_hash,
        successor_policy_key=successor.policy_key,
        successor_version=successor.version,
        successor_digest=successor.policy_hash,
        principal="user:trigger-replacer@example.com",
        expected_head_epoch=1,
        expected_activation_id=activation_id,
        expected_lifecycle_epoch=1,
        placement_epoch=1,
        decision_request_id="trigger-prepare-replacement",
    )
    assert prepared.created
    exact_prepare_replay = store.prepare_replacement(
        scope=SCOPE,
        retiring_policy_key=current.policy_key,
        retiring_version=current.version,
        retiring_digest=current.policy_hash,
        successor_policy_key=successor.policy_key,
        successor_version=successor.version,
        successor_digest=successor.policy_hash,
        principal="user:trigger-replacer@example.com",
        expected_head_epoch=1,
        expected_activation_id=activation_id,
        expected_lifecycle_epoch=1,
        placement_epoch=1,
        decision_request_id="trigger-prepare-replacement",
    )
    assert exact_prepare_replay.intent_id == prepared.intent_id
    assert not exact_prepare_replay.created
    with pytest.raises(RuntimeError, match="changed material"):
        store.prepare_replacement(
            scope=SCOPE,
            retiring_policy_key=current.policy_key,
            retiring_version=current.version,
            retiring_digest=current.policy_hash,
            successor_policy_key=successor.policy_key,
            successor_version=successor.version,
            successor_digest=successor.policy_hash,
            principal="user:trigger-replacer@example.com",
            expected_head_epoch=1,
            expected_activation_id=activation_id,
            expected_lifecycle_epoch=1,
            placement_epoch=2,
            decision_request_id="trigger-prepare-replacement",
        )
    with pytest.raises(RuntimeError, match="existing request or material"):
        store.prepare_replacement(
            scope=SCOPE,
            retiring_policy_key=current.policy_key,
            retiring_version=current.version,
            retiring_digest=current.policy_hash,
            successor_policy_key=successor.policy_key,
            successor_version=successor.version,
            successor_digest=successor.policy_hash,
            principal="user:trigger-replacer@example.com",
            expected_head_epoch=1,
            expected_activation_id=activation_id,
            expected_lifecycle_epoch=1,
            placement_epoch=1,
            decision_request_id="trigger-prepare-replacement-new-key",
        )
    stale_fences = (
        (2, activation_id, 1, 1, "head"),
        (1, f"tpa_{'0' * 26}", 1, 1, "activation"),
        (1, activation_id, 2, 1, "lifecycle"),
        (1, activation_id, 1, 2, "placement"),
    )
    for head_epoch, stale_activation, lifecycle_epoch, placement_epoch, label in stale_fences:
        with pytest.raises(RuntimeError, match="authority material is stale"):
            store.prepare_replacement(
                scope=SCOPE,
                retiring_policy_key=current.policy_key,
                retiring_version=current.version,
                retiring_digest=current.policy_hash,
                successor_policy_key=successor.policy_key,
                successor_version=successor.version,
                successor_digest=successor.policy_hash,
                principal="user:trigger-replacer@example.com",
                expected_head_epoch=head_epoch,
                expected_activation_id=stale_activation,
                expected_lifecycle_epoch=lifecycle_epoch,
                placement_epoch=placement_epoch,
                decision_request_id=f"trigger-prepare-replacement-stale-{label}",
            )
    with pytest.raises(RuntimeError, match="independently authorized"):
        store.prepare_replacement(
            scope=SCOPE,
            retiring_policy_key=current.policy_key,
            retiring_version=current.version,
            retiring_digest=current.policy_hash,
            successor_policy_key=successor.policy_key,
            successor_version=successor.version,
            successor_digest=f"sha256:{'f' * 64}",
            principal="user:trigger-replacer@example.com",
            expected_head_epoch=1,
            expected_activation_id=activation_id,
            expected_lifecycle_epoch=1,
            placement_epoch=1,
            decision_request_id="trigger-prepare-replacement-changed-digest",
        )
    active = store.retire_with_prepared_replacement(
        scope=SCOPE,
        replacement_intent_id=prepared.intent_id,
        expected_retiring_policy_key=current.policy_key,
        expected_retiring_version=current.version,
        principal="user:trigger-replacer@example.com",
        expected_compound_request_hash=prepared.compound_request_hash,
        decision_request_id="trigger-consume-replacement",
    )
    assert (active.version, active.lifecycle, active.created) == ("2", "ACTIVE", True)
    replay = store.retire_with_prepared_replacement(
        scope=SCOPE,
        replacement_intent_id=prepared.intent_id,
        expected_retiring_policy_key=current.policy_key,
        expected_retiring_version=current.version,
        principal="user:trigger-replacer@example.com",
        expected_compound_request_hash=prepared.compound_request_hash,
        decision_request_id="trigger-consume-replacement",
    )
    assert (replay.version, replay.lifecycle, replay.created) == ("2", "ACTIVE", False)
    with pytest.raises(RuntimeError, match="independently authorized|role is inactive"):
        store.retire_with_prepared_replacement(
            scope=SCOPE,
            replacement_intent_id=prepared.intent_id,
            expected_retiring_policy_key=current.policy_key,
            expected_retiring_version=current.version,
            principal="user:other-replacer@example.com",
            expected_compound_request_hash=prepared.compound_request_hash,
            decision_request_id="trigger-consume-replacement",
        )
    connection.execute(
        """DELETE FROM solvan_operability.operability_role_bindings
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND principal='user:trigger-replacer@example.com'
              AND role='TRIGGER_POLICY_LIFECYCLE_MANAGER'""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    with pytest.raises(RuntimeError, match="role is inactive"):
        store.retire_with_prepared_replacement(
            scope=SCOPE,
            replacement_intent_id=prepared.intent_id,
            expected_retiring_policy_key=current.policy_key,
            expected_retiring_version=current.version,
            principal="user:trigger-replacer@example.com",
            expected_compound_request_hash=prepared.compound_request_hash,
            decision_request_id="trigger-consume-replacement",
        )
    assert connection.execute(
        """SELECT count(*) FROM solvan_operability.trigger_policy_replacement_consumptions
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND replacement_intent_id=%s""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            prepared.intent_id,
        ),
    ).fetchone() == (1,)


def test_latest_waiting_is_serialized_across_two_database_transactions() -> None:
    """Concurrent out-of-order delivery leaves one latest waiting firing."""

    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as setup:
        setup.execute(
            """INSERT INTO solvan.organizations(id,display_name)
               VALUES (%s,'Concurrency test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id,),
        )
        setup.execute(
            """INSERT INTO solvan.projects
                 (organization_id,id,display_name,gcp_project_id)
               VALUES (%s,%s,'Concurrency test','solvan-test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        setup.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Concurrency test','europe-west1','INTERNAL')
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        setup.execute(
            """INSERT INTO solvan.tenant_connections
                 (organization_id,project_id,environment_id,id,display_name,kind,
                  provider,credential_posture,residency_region,classification,
                  lifecycle,availability,availability_reason_code,
                  availability_explanation,availability_remediation_kind,
                  availability_receipt_ref,last_probe_at,last_probe_result,
                  created_by_principal)
               VALUES (%s,%s,%s,%s,'Concurrency metrics','GCP_NATIVE',
                       'CLOUD_MONITORING','CUSTOMER_SIDE_NONE','europe-west1',
                       'INTERNAL','ENABLED','READY',NULL,NULL,NULL,'probe://concurrency',
                       now(),'SUCCEEDED','user:test@example.com')
               ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                CONNECTION_ID,
            ),
        )
        policy = _trigger_policy().model_copy(
            update={"policy_key": "ruhu.concurrent-rollout-investigation"}
        )
        _approved_trigger_store(setup, policy=policy)
        setup.commit()

    barrier = threading.Barrier(2)

    def accept(sequence: int) -> tuple[int, str]:
        assert DATABASE_URL is not None
        with psycopg.connect(DATABASE_URL) as worker:
            store = PostgresTriggerPolicyStore(worker)
            barrier.wait(timeout=5)
            result = store.accept_event(
                scope=SCOPE,
                policy_key=policy.policy_key,
                policy_version=policy.version,
                event=_event(sequence),
            )
            worker.commit()
            return sequence, result.status

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(accept, (70, 71)))

    assert {sequence for sequence, _status in results} == {70, 71}
    with psycopg.connect(DATABASE_URL) as inspection:
        rows = inspection.execute(
            """SELECT source_sequence,status,decision_reason
                 FROM solvan_operability.trigger_firings
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND policy_key=%s AND policy_version=%s
                ORDER BY source_sequence""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                policy.policy_key,
                policy.version,
            ),
        ).fetchall()
    assert rows[-1] == (71, "WAITING", None)
    assert rows[0] in {
        (70, "SUPERSEDED", "NEWER_SOURCE_SEQUENCE"),
        (70, "SUPPRESSED", "STALE_SOURCE_SEQUENCE"),
    }


def test_prepared_replacement_consumption_is_single_use_across_two_transactions() -> None:
    """Two consumers of one intent produce one replacement and one exact replay."""

    assert DATABASE_URL is not None
    current = _trigger_policy().model_copy(
        update={"policy_key": "ruhu.replacement-race-investigation"}
    )
    successor = current.model_copy(update={"version": "2"})
    with psycopg.connect(DATABASE_URL) as setup:
        setup.execute(
            """INSERT INTO solvan.organizations(id,display_name)
               VALUES (%s,'Replacement race') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id,),
        )
        setup.execute(
            """INSERT INTO solvan.projects
                 (organization_id,id,display_name,gcp_project_id)
               VALUES (%s,%s,'Replacement race','solvan-test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        setup.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Replacement race','europe-west1','INTERNAL')
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        setup.execute(
            """INSERT INTO solvan.tenant_connections
                 (organization_id,project_id,environment_id,id,display_name,kind,
                  provider,credential_posture,residency_region,classification,
                  lifecycle,availability,availability_reason_code,
                  availability_explanation,availability_remediation_kind,
                  availability_receipt_ref,last_probe_at,last_probe_result,
                  created_by_principal)
               VALUES (%s,%s,%s,%s,'Replacement metrics','GCP_NATIVE',
                       'CLOUD_MONITORING','CUSTOMER_SIDE_NONE','europe-west1',
                       'INTERNAL','ENABLED','READY',NULL,NULL,NULL,
                       'probe://replacement-race',now(),'SUCCEEDED',
                       'user:test@example.com') ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                CONNECTION_ID,
            ),
        )
        store, _ = _approved_trigger_store(
            setup, policy=current, decision_prefix="trigger-replacement-race-current"
        )
        store.create_draft(
            scope=SCOPE,
            policy=successor,
            decision_request_id="trigger-replacement-race-successor-create",
        )
        store.record_evaluation(
            scope=SCOPE,
            policy_key=successor.policy_key,
            version=successor.version,
            expected_digest=successor.policy_hash,
            principal="user:trigger-evaluator@example.com",
            suite_version="trigger-rollout-v1",
            passed_cases=8,
            failed_cases=0,
            receipt_ref="gs://solvan-evaluations/trigger-race-2.json",
            receipt_hash=HASH,
            reason_codes=("TRIGGER_SUITE_PASSED",),
            decision_request_id="trigger-replacement-race-successor-eval",
        )
        store.approve(
            scope=SCOPE,
            policy_key=successor.policy_key,
            version=successor.version,
            principal="user:trigger-approver@example.com",
            expected_digest=successor.policy_hash,
            reason="Reviewed the exact replacement-race successor.",
            decision_request_id="trigger-replacement-race-successor-approve",
        )
        store.mark_eligible(
            scope=SCOPE,
            policy_key=successor.policy_key,
            version=successor.version,
            principal="user:trigger-lifecycle@example.com",
            expected_digest=successor.policy_hash,
            decision_request_id="trigger-replacement-race-successor-eligible",
        )
        activation_id = setup.execute(
            """SELECT activation_id
                 FROM solvan_operability.trigger_policy_current_heads
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND policy_key=%s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                current.policy_key,
            ),
        ).fetchone()[0]
        prepared = store.prepare_replacement(
            scope=SCOPE,
            retiring_policy_key=current.policy_key,
            retiring_version=current.version,
            retiring_digest=current.policy_hash,
            successor_policy_key=successor.policy_key,
            successor_version=successor.version,
            successor_digest=successor.policy_hash,
            principal="user:trigger-replacer@example.com",
            expected_head_epoch=1,
            expected_activation_id=activation_id,
            expected_lifecycle_epoch=1,
            placement_epoch=1,
            decision_request_id="trigger-replacement-race-prepare",
        )
        setup.commit()

    barrier = threading.Barrier(2)

    def consume() -> bool:
        assert DATABASE_URL is not None
        with psycopg.connect(DATABASE_URL) as worker:
            barrier.wait(timeout=5)
            result = PostgresTriggerPolicyStore(worker).retire_with_prepared_replacement(
                scope=SCOPE,
                replacement_intent_id=prepared.intent_id,
                expected_retiring_policy_key=current.policy_key,
                expected_retiring_version=current.version,
                principal="user:trigger-replacer@example.com",
                expected_compound_request_hash=prepared.compound_request_hash,
                decision_request_id="trigger-replacement-race-consume",
            )
            return result.created

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: consume(), range(2)))
    assert sorted(outcomes) == [False, True]

    with psycopg.connect(DATABASE_URL) as inspection:
        scope_values = (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
        )
        assert inspection.execute(
            """SELECT policy_version,is_current
                 FROM solvan_operability.trigger_policy_current_heads
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND policy_key=%s""",
            (*scope_values, current.policy_key),
        ).fetchone() == ("2", True)
        assert inspection.execute(
            """SELECT count(*)
                 FROM solvan_operability.trigger_policy_lifecycle_decisions
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND policy_key=%s AND policy_version='1' AND operation='RETIRE'""",
            (*scope_values, current.policy_key),
        ).fetchone() == (1,)
        assert inspection.execute(
            """SELECT count(*)
                 FROM solvan_operability.trigger_policy_replacement_consumptions
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND replacement_intent_id=%s""",
            (*scope_values, prepared.intent_id),
        ).fetchone() == (1,)


def test_canonical_catalog_publishes_against_the_authoritative_schema(connection) -> None:
    """Publish the checked-in catalog exactly as `release_admin.publish_catalog` does.

    Nothing exercised this path against the real DDL, and it could not have
    succeeded: the typed profile model admitted two provider/capability pairs
    the schema's CHECK constraint refuses, so publication raised on the first
    Agent profile that named one. The same drift left four admissible pairs
    unstateable, and the affected connector Tools were published COMPUTE_ONLY —
    external reach with no connection, epoch, or capability receipt to fence
    it. This test is the gate that was missing, not a restatement of the unit
    assertions: only the database can refuse a requirement shape.
    """

    store = PostgresToolCatalogStore(connection)
    for principal in catalog_principals(manifest_hash=MANIFEST_HASH):
        store.register_principal(principal)
    for revision in catalog_tools(
        network_policy_hash=MANIFEST_HASH,
        approval_ref="approval://catalog/1",
        evaluation_ref="evaluation://catalog/1",
    ):
        store.publish_tool(revision)
    for agent_key in AGENT_PROFILE_KEYS:
        store.publish_profile(
            scope=SCOPE,
            profile=catalog_profile(
                agent_key=agent_key,
                approval_ref="approval://catalog/1",
                evaluation_ref="evaluation://catalog/1",
                classification_ceiling="INTERNAL",
            ),
        )
    store.publish_profile(
        scope=SCOPE,
        profile=alert_triage_profile(
            approval_ref="approval://catalog/1",
            evaluation_ref="evaluation://catalog/1",
        ),
    )
    stored = connection.execute(
        """SELECT r.tool_key, r.binding_kind
             FROM solvan_operability.tool_profile_connection_requirements r
            WHERE r.profile_key = ANY(%(profiles)s)""",
        {"profiles": [*AGENT_PROFILE_KEYS.values(), "alert-triage-read-compute-v1"]},
    ).fetchall()
    # Read back what the database actually stored: a COMPUTE_ONLY binding
    # carries no connection, epoch, capability receipt, or external project, so
    # a Tool that reaches an external system must be stored source-bound or not
    # at all. Only a compute Tool or one of Solvan's own services may be
    # compute-only.
    seed_by_key = {seed.key: seed for seed in TOOL_SEEDS}
    assert stored
    for tool_key, binding_kind in stored:
        seed = seed_by_key[tool_key]
        reaches_outward = (
            seed.permission is not PermissionClass.COMPUTE
            and seed.provider not in INTERNAL_PROVIDERS
        )
        assert (binding_kind == "POLICY_SOURCE_CONNECTION") is reaches_outward, tool_key
    loaded = store.load_profile(
        scope=SCOPE, profile_key="evidence.ruhu-observability.v1", version="1"
    )
    assert (
        loaded.profile_material_hash
        == catalog_profile(
            agent_key="evidence-agent",
            approval_ref="approval://catalog/1",
            evaluation_ref="evaluation://catalog/1",
            classification_ceiling="INTERNAL",
        ).profile_material_hash
    )


def _seed_shared_environment(setup: psycopg.Connection) -> None:
    setup.execute(
        """INSERT INTO solvan.organizations(id,display_name)
           VALUES (%s,'Test') ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id,),
    )
    setup.execute(
        """INSERT INTO solvan.projects
             (organization_id,id,display_name,gcp_project_id)
           VALUES (%s,%s,'Test','solvan-test') ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id, SCOPE.project_id),
    )
    setup.execute(
        """INSERT INTO solvan.environments
             (organization_id,project_id,id,display_name,region,classification)
           VALUES (%s,%s,%s,'Test','europe-west1','INTERNAL')
           ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    setup.execute(
        """INSERT INTO solvan.tenant_connections
             (organization_id,project_id,environment_id,id,display_name,kind,
              provider,credential_posture,residency_region,classification,
              lifecycle,availability,availability_reason_code,
              availability_explanation,availability_remediation_kind,
              availability_receipt_ref,last_probe_at,last_probe_result,
              created_by_principal)
           VALUES (%s,%s,%s,%s,'Ruhu metrics','GCP_NATIVE',
                   'CLOUD_MONITORING','CUSTOMER_SIDE_NONE','europe-west1',
                   'INTERNAL','ENABLED','READY',NULL,NULL,NULL,'probe://seed',
                   now(),'SUCCEEDED','user:test@example.com')
           ON CONFLICT DO NOTHING""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            CONNECTION_ID,
        ),
    )
    setup.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%s,%s,%s,'user:author@example.com','GUIDANCE_AUTHOR','Payments SRE','test'),
                  (%s,%s,%s,'user:evaluator@example.com','GUIDANCE_EVALUATOR',
                   'Payments SRE','test'),
                  (%s,%s,%s,'user:approver@example.com','GUIDANCE_APPROVER',
                   'Payments SRE','test')
           ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id) * 3,
    )


def _draft_command_body() -> dict[str, object]:
    return {
        "schema_version": 1,
        "guidance_key": "payments.endpoint-replay",
        "version": "1",
        "display_name": "Endpoint replay procedure",
        "description": "Gather bounded evidence for replayed deliveries.",
        "owner_department": "Payments SRE",
        "discoverable_departments": ["Payments"],
        "guidance_kind": "DIAGNOSTIC_PROCEDURE",
        "applicable_service_kinds": ["CLOUD_RUN"],
        "applicable_incident_classes": ["CONNECTION_EXHAUSTION"],
        "symptom_tags": ["http-503"],
        "purpose": "INCIDENT_INVESTIGATION",
        "classification": "INTERNAL",
        "eligible_regions": ["europe-west1"],
        "allowed_agent_keys": ["evidence-agent"],
        "required_profile_revisions": [f"{FIXTURE_PROFILE_KEY}@1"],
        "steps": [
            {
                "step_key": "observe-errors",
                "ordinal": 1,
                "title": "Observe bounded errors",
                "objective": "Measure the registered error signature in the incident window.",
                "step_kind": "OBSERVE",
                "allowed_tool_revisions": ["fixture_bounded_metric_read@1"],
                "prerequisite_step_keys": [],
                "completion_predicate_key": "evidence-kind-present",
                "completion_predicate_version": "1",
                "required_evidence_kinds": ["METRICS"],
                "maximum_tool_requests": 1,
                "on_blocked": "STOP_INCONCLUSIVE",
            }
        ],
        "content_ref": "gs://guidance/payments/endpoint-replay/1.json",
        "content_hash": HASH,
        "source_kind": "SOLVAN_AUTHORED",
        "source_ref": "solvan://guidance/payments/endpoint-replay",
    }


def test_draft_endpoint_duplicate_delivery_replays_the_ingestion_receipt() -> None:
    """One Idempotency-Key runs create-draft plus ingestion; a retry must replay both."""

    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as setup:
        _seed_shared_environment(setup)
        catalog = PostgresToolCatalogStore(setup)
        catalog.register_principal(_principal())
        catalog.publish_tool(_tool())
        catalog.publish_profile(scope=SCOPE, profile=_profile())
        setup.commit()
    app = FastAPI()
    app.include_router(
        operational_guidance_router(
            principal_provider=lambda token: "user:author@example.com",
            reader_principal_provider=lambda token: "user:author@example.com",
            scope_provider=lambda: SCOPE,
            connect=lambda: psycopg.connect(DATABASE_URL),
            content_inspector=lambda revision: GuidanceContentInspection(
                True, ("STRUCTURE_AND_SECURITY_VALIDATED",), "armor:endpoint:allow"
            ),
            known_predicates=frozenset({"evidence-kind-present@1"}),
            evaluation_verifier=UnavailableGuidanceEvaluationVerifier(),
        )
    )
    with TestClient(app) as client:
        responses = [
            client.post(
                "/api/admin/guidance/drafts",
                json=_draft_command_body(),
                headers={
                    "X-Solvan-Approval-Token": "human-claim",
                    "Idempotency-Key": "endpoint-replay-0001",
                },
            )
            for _attempt in range(2)
        ]
    assert [response.status_code for response in responses] == [200, 200]
    first, second = (response.json() for response in responses)
    assert second["ingestion_id"] == first["ingestion_id"]
    assert (second["guidance_key"], second["version"], second["digest"]) == (
        first["guidance_key"],
        first["version"],
        first["digest"],
    )
    with psycopg.connect(DATABASE_URL) as inspection:
        assert inspection.execute(
            """SELECT count(*) FROM solvan_operability.guidance_ingestion_receipts
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND guidance_key='payments.endpoint-replay' AND guidance_version='1'""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        ).fetchone() == (1,)


def test_concurrent_duplicate_selection_serializes_to_one_typed_result() -> None:
    """Two racing identical selections yield one row and two typed results."""

    assert DATABASE_URL is not None
    incident_id = "inc_77777777777777777777777777"
    run_id = "run_77777777777777777777777777"
    with psycopg.connect(DATABASE_URL) as setup:
        _seed_shared_environment(setup)
        catalog = PostgresToolCatalogStore(setup)
        catalog.register_principal(_principal())
        catalog.publish_tool(_tool())
        profile = _trigger_profile()
        catalog.publish_profile(scope=SCOPE, profile=profile)
        now = datetime.now(UTC)
        probe_id = catalog.record_probe(
            scope=SCOPE,
            probe=CapabilityProbe(
                connection_id=CONNECTION_ID,
                tool_revision="fixture_bounded_metric_read@1",
                agent_key="evidence-agent",
                connection_provider="CLOUD_MONITORING",
                capabilities=frozenset({"promql.read"}),
                connection_epoch=1,
                identity_ref="identity://evidence-agent/1",
                registry_resource="registry://managed-prometheus/1",
                gateway_policy_ref="gateway://policy/1",
                network_policy_hash=HASH,
                region="europe-west1",
                classification_ceiling="INTERNAL",
                outcome="PASSED",
                observed_at=now,
                expires_at=now + timedelta(minutes=5),
                receipt_ref="receipt://probe/selection-race",
                receipt_hash=HASH,
            ),
        )
        setup.execute(
            """INSERT INTO solvan.services
                 (organization_id,project_id,environment_id,id,service_key,
                  display_name,platform_kind,platform_resource,owner_department)
               VALUES (%s,%s,%s,'svc_77777777777777777777777777','payments-api-race',
                       'Payments API','CLOUD_RUN_SERVICE',
                       'projects/test/locations/europe-west1/services/payments-api',
                       'payments') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        setup.execute(
            """UPDATE solvan.production_graph_snapshots
                  SET superseded_at=now()
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND status='APPROVED' AND superseded_at IS NULL
                  AND id<>'pgs_77777777777777777777777777'""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        setup.execute(
            """INSERT INTO solvan.production_graph_snapshots
                 (organization_id,project_id,environment_id,id,version,status,
                  source_manifest_ref,content_hash,effective_at,approved_by,approved_at)
               VALUES (%s,%s,%s,'pgs_77777777777777777777777777',778,'APPROVED',
                       'fixture://selection-race',%s,now(),'owner',now())
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, HASH),
        )
        setup.execute(
            """INSERT INTO solvan.detection_rules
                 (organization_id,project_id,environment_id,id,version,service_id,
                  incident_class,signal_kind,query_json,evaluation_interval_ms,
                  comparator,threshold,sustained_windows,severity,
                  deduplication_dimension,action_budget,repeated_action_limit,status,
                  calibration_receipt_ref,approved_by,approved_at)
               VALUES (%s,%s,%s,'selection-race-http-5xx',1,
                       'svc_77777777777777777777777777','connection_exhaustion',
                       'HTTP_5XX_RATIO','{}',25000,'GT',0.05,2,'SEV2',
                       'http-5xx',2,1,'APPROVED','fixture://calibration','owner',now())
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        setup.execute(
            """INSERT INTO solvan.incidents
                 (organization_id,project_id,environment_id,id,display_id,
                  state_machine_version,state,severity,incident_class,
                  primary_service_id,production_graph_snapshot_id,detected_at,
                  detection_rule_id,detection_rule_version,deduplication_key,
                  action_budget,repeated_action_limit)
               VALUES (%s,%s,%s,%s,'INC-7777','1','INVESTIGATING','SEV2',
                       'connection_exhaustion','svc_77777777777777777777777777',
                       'pgs_77777777777777777777777777',now(),
                       'selection-race-http-5xx',1,'selection-race',2,1)
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, incident_id),
        )
        setup.execute(
            """INSERT INTO solvan.agent_runs
                 (organization_id,project_id,environment_id,id,incident_id,
                  logical_step_key,agent_key,agent_resource,agent_revision,
                  invocation_id,workflow_version,attempt,status,deadline,
                  budget_json,input_ref,input_hash,effective_tool_set_hash)
               VALUES (%s,%s,%s,%s,%s,'incident:selection-race','evidence-agent',
                       'projects/123456789/locations/europe-west1/reasoningEngines/test-v1',
                       'release-1','inv_77777777777777777777777777',1,1,'CREATED',
                       now() + interval '10 minutes','{}',
                       'db://solvan/selection-race',%s,%s)
               ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
                incident_id,
                HASH,
                HASH,
            ),
        )
        setup.execute(
            """INSERT INTO solvan_operability.agent_run_tool_bindings
                 (organization_id,project_id,environment_id,agent_run_id,
                  profile_key,profile_version,profile_material_hash,accepted_tool_count,
                  effective_tool_set_hash,identity_ref,runtime_region,
                  accepted_data_classification,classification_ceiling,
                  policy_head_activation_id,policy_head_epoch,placement_epoch,
                  accepted_step_budget_hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,1,%s,'identity://evidence-agent/1',
                       'europe-west1','INTERNAL','INTERNAL',NULL,0,1,%s)
               ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
                profile.profile_key,
                profile.version,
                profile.profile_material_hash,
                HASH,
                HASH,
            ),
        )
        setup.execute(
            """INSERT INTO solvan_operability.agent_run_accepted_tool_bindings
                 (organization_id,project_id,environment_id,agent_run_id,profile_key,
                  profile_version,ordinal,tool_key,tool_version,binding_kind,provider,
                  capability_key,external_project_selector,connection_id,
                  connection_epoch,capability_receipt_id,capability_receipt_hash,
                  external_project_id)
               VALUES (%s,%s,%s,%s,%s,%s,1,'fixture_bounded_metric_read','1',
                       'POLICY_SOURCE_CONNECTION','CLOUD_MONITORING','METRIC_READ',
                       'TARGET_RESOURCE_PROJECT',%s,1,%s,%s,'solvan-test')
               ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
                profile.profile_key,
                profile.version,
                CONNECTION_ID,
                probe_id,
                HASH,
            ),
        )
        store = PostgresOperationalGuidanceStore(setup)
        revision = _guidance().model_copy(
            update={
                "guidance_key": "payments.concurrent-selection",
                "display_name": "Concurrent selection procedure",
                "required_profile_revisions": (f"{profile.profile_key}@{profile.version}",),
                "source_ref": "solvan://guidance/payments/concurrent-selection",
            }
        )
        store.create_draft(
            scope=SCOPE, revision=revision, decision_request_id="guidance-race-create"
        )
        store.record_ingestion(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            content_hash=revision.content_hash,
            accepted=True,
            reason_codes=("STRUCTURE_AND_SECURITY_VALIDATED",),
            armor_verdict_ref="armor:race:allow",
            principal=revision.author_principal,
            decision_request_id="guidance-race-ingest",
        )
        evaluation_id = store.record_evaluation(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            expected_digest=revision.approval_digest,
            principal="user:evaluator@example.com",
            suite_version="guidance-race-v1",
            passed_cases=4,
            failed_cases=0,
            receipt_ref="gs://solvan-evaluations/guidance-race.json",
            receipt_hash=HASH,
            receipt_generation="1",
            corpus_digest=HASH,
            case_set_digest=HASH,
            scorer_name="deterministic-guidance-scorer",
            scorer_version="1",
            model_config_pins={"model": "gemini-test-pinned"},
            repetitions=1,
            pass_thresholds={"pass_rate": 1.0},
            reason_codes=("ADVERSARIAL_SUITE_PASSED",),
            decision_request_id="guidance-race-eval",
        )
        store.submit(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            principal=revision.author_principal,
            expected_digest=revision.approval_digest,
            decision_request_id="guidance-race-submit",
        )
        store.approve(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version=revision.version,
            principal="user:approver@example.com",
            expected_digest=revision.approval_digest,
            evaluation_ref=evaluation_id,
            decision_request_id="guidance-race-approve",
            reason="Reviewed the exact race fixture and evaluation.",
            known_predicates=frozenset({"evidence-kind-present@1"}),
        )
        setup.commit()

    barrier = threading.Barrier(2)

    def select() -> str:
        assert DATABASE_URL is not None
        with psycopg.connect(DATABASE_URL) as worker:
            store = PostgresOperationalGuidanceStore(worker)
            barrier.wait(timeout=5)
            result = store.select_approved(
                scope=SCOPE,
                agent_run_id=run_id,
                guidance_key="payments.concurrent-selection",
                version="1",
                expected_guidance_hash=_guidance()
                .model_copy(
                    update={
                        "guidance_key": "payments.concurrent-selection",
                        "display_name": "Concurrent selection procedure",
                        "required_profile_revisions": ("evidence.ruhu-trigger-observability.v1@1",),
                        "source_ref": "solvan://guidance/payments/concurrent-selection",
                    }
                )
                .approval_digest,
                runtime_region="europe-west1",
                purpose="INCIDENT_INVESTIGATION",
                data_classification="INTERNAL",
                role="PRIMARY",
                reason="Duplicate delivery of one selection decision.",
            )
            worker.commit()
            return result.selection_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        selection_ids = list(executor.map(lambda _index: select(), range(2)))
    assert selection_ids[0] == selection_ids[1]

    with psycopg.connect(DATABASE_URL) as inspection:
        assert inspection.execute(
            """SELECT count(*) FROM solvan_operability.guidance_selections
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND agent_run_id=%s""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, run_id),
        ).fetchone() == (1,)
        assert inspection.execute(
            """SELECT count(*) FROM solvan_operability.guidance_step_runs
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND selection_id=%s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                selection_ids[0],
            ),
        ).fetchone() == (1,)


# Catalog publication had no test that ran twice against the same database.
# `register_principal` and `publish_tool` were only ever exercised once into a
# clean schema, so the refusal that made `release_admin publish-catalog` fail on
# every release after an agent-manifest edit was invisible: locally it looked
# like "recreate the volume", and against Cloud SQL there is nothing to
# recreate. These cases publish, change the material, and publish again.

_NEXT_MANIFEST_HASH = f"sha256:{'f' * 64}"


def _principal_head(connection, principal_key: str):
    return connection.execute(
        """SELECT version, head_epoch, display_name, manifest_hash
             FROM solvan_operability.catalog_principals WHERE principal_key = %s""",
        (principal_key,),
    ).fetchone()


def test_republishing_an_unchanged_catalog_principal_converges(connection) -> None:
    """An unchanged catalog must publish repeatedly without minting anything."""

    store = PostgresToolCatalogStore(connection)

    first = store.register_principal(_principal())
    second = store.register_principal(_principal())

    assert first == second == 1
    assert _principal_head(connection, "evidence-agent")[:2] == (1, 1)
    assert connection.execute(
        """SELECT count(*) FROM solvan_operability.catalog_principal_revisions
            WHERE principal_key = 'evidence-agent'"""
    ).fetchone() == (1,)


def test_a_changed_agent_manifest_supersedes_rather_than_refusing(connection) -> None:
    """The exact release scenario that could not publish.

    `release_admin.publish_catalog` derives `manifest_hash` from the agent
    manifest file, so this is what every release after a manifest edit does.
    """

    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())

    changed = _principal().model_copy(update={"manifest_hash": _NEXT_MANIFEST_HASH})
    version = store.register_principal(changed)

    assert version == 2
    head = _principal_head(connection, "evidence-agent")
    assert head[0] == 2
    assert head[1] == 2, "the head epoch counts the move"
    assert head[3] == _NEXT_MANIFEST_HASH
    # The superseded revision is retained rather than rewritten.
    assert connection.execute(
        """SELECT manifest_hash FROM solvan_operability.catalog_principal_revisions
            WHERE principal_key = 'evidence-agent' ORDER BY version"""
    ).fetchall() == [(MANIFEST_HASH,), (_NEXT_MANIFEST_HASH,)]


def test_a_head_may_return_to_an_earlier_published_revision(connection) -> None:
    """Rolling a release back is a head move, not a rewrite."""

    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())
    store.register_principal(_principal().model_copy(update={"manifest_hash": _NEXT_MANIFEST_HASH}))

    rolled_back = store.register_principal(_principal())

    assert rolled_back == 1
    head = _principal_head(connection, "evidence-agent")
    assert (head[0], head[3]) == (1, MANIFEST_HASH)
    assert head[1] == 3, "returning to an earlier revision is still a counted move"
    assert connection.execute(
        """SELECT count(*) FROM solvan_operability.catalog_principal_revisions
            WHERE principal_key = 'evidence-agent'"""
    ).fetchone() == (2,), "no third revision is minted for material already published"


def test_a_renamed_tool_definition_supersedes_rather_than_refusing(connection) -> None:
    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())
    store.publish_tool(_tool())

    store.publish_tool(
        _tool().model_copy(update={"display_name": "Renamed bounded metric read", "version": "2"})
    )

    assert connection.execute(
        """SELECT version, head_epoch, display_name
             FROM solvan_operability.tool_definitions
            WHERE tool_key = 'fixture_bounded_metric_read'"""
    ).fetchone() == (2, 2, "Renamed bounded metric read")


def test_catalog_principal_history_is_append_only(connection) -> None:
    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())

    with pytest.raises(psycopg.Error, match="immutable after insert"):
        connection.execute(
            """UPDATE solvan_operability.catalog_principal_revisions
                  SET manifest_hash = %s WHERE principal_key = 'evidence-agent'""",
            (_NEXT_MANIFEST_HASH,),
        )


def test_a_catalog_head_cannot_be_deleted(connection) -> None:
    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())

    with pytest.raises(psycopg.Error, match="current head and cannot be deleted"):
        connection.execute(
            """DELETE FROM solvan_operability.catalog_principals
                WHERE principal_key = 'evidence-agent'"""
        )


def test_a_catalog_head_cannot_move_without_advancing_its_epoch(connection) -> None:
    """A head move is observable or it does not happen."""

    store = PostgresToolCatalogStore(connection)
    store.register_principal(_principal())
    store.register_principal(_principal().model_copy(update={"manifest_hash": _NEXT_MANIFEST_HASH}))

    with pytest.raises(psycopg.Error, match="without advancing its epoch"):
        connection.execute(
            """UPDATE solvan_operability.catalog_principals
                  SET version = 1, display_name = %s, registry_kind = 'AGENT',
                      execution_role = 'SPECIALIST', model_backed = true,
                      manifest_hash = %s
                WHERE principal_key = 'evidence-agent'""",
            ("Evidence Agent", MANIFEST_HASH),
        )
