from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row

from apps.api.console_integration_fixture import integration_fixture
from apps.api.console_projection import live_console_snapshot
from apps.coordinator.contracts import GovernedAgentBinding
from apps.coordinator.security_ingestion import SecurityLogEvent, persist_security_log
from apps.coordinator.tool_binding import PostgresAgentRunBinder
from apps.coordinator.workspace_rehydration import select_rehydration_candidate
from apps.payments_fixture.service import PaymentsFixtureService, PaymentUnavailable
from solvan.application import (
    ActionActuator,
    AgentCompletion,
    AgentResultCoordinator,
    AgentSemanticStatus,
    CanonicalDetectionEvent,
    CaseSchedule,
    CoordinatorAuthority,
    FindingCommit,
    FindingKind,
    IncidentCoordinator,
    InvestigationCoordinator,
    MemoryBankReceipt,
    MemoryCandidateService,
    MemoryPromotionService,
    MemorySearchCandidate,
    PartialRuntimeInvocationReceipt,
    ReliabilityCaseConflict,
    ReliabilityCaseCoordinator,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
    StandingAuthority,
    WorkspaceArtifactDescriptor,
    WorkspaceCheckpointMaterial,
    WorkspaceClassification,
    WorkspaceHypothesisProposal,
    WorkspaceInputMaterial,
    WorkspaceKind,
    WorkspaceProviderKind,
    WorkspaceSpec,
    WorkspaceTaskBudget,
    WorkspaceTaskInvocation,
    WorkspaceTaskKind,
    WorkspaceTaskResult,
    WorkspaceTerminalStatus,
    workspace_repair_budget,
)
from solvan.application.actions import ExecutionAuthorization
from solvan.application.actuator import (
    CustomerAuditRecord,
    MutationCall,
    PredictedEffect,
    Reconciliation,
    ReconciliationResult,
    TargetObservation,
    UndoPlan,
)
from solvan.application.effective_tool_set import (
    EffectiveToolBindingV1,
    EffectiveToolSetV1,
    ToolRevisionRefV1,
    accepted_step_budget_hash,
)
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
    ToolCatalogError,
    ToolConnectionBindingKind,
    ToolConnectionRequirement,
    ToolProfileRevision,
    ToolRevision,
)
from solvan.application.workspace_candidate import CandidateFile, CandidateTree
from solvan.domain import (
    ActionPolicyError,
    ActionType,
    AgentLimit,
    AuthorizedActionMaterial,
    InvestigationPlanProposal,
    InvestigationStepKind,
    MemoryCandidateProposal,
    MemoryCandidateType,
    MemoryConfirmation,
    MemoryGatePolicy,
    MemoryScope,
    PlanValidationPolicy,
    ProposedStep,
    RiskClass,
    Scope,
    StepBudget,
    VerificationResult,
    VerificationVerdict,
    derive_expected_effect,
    freeze_json,
    validate_investigation_plan,
)
from solvan.persistence import (
    AggregateType,
    ClaimLost,
    EvidenceWrite,
    ExecutionReceiptWrite,
    ExecutionResult,
    IncidentOpenRequest,
    PostgresActionStore,
    PostgresApprovalStore,
    PostgresDetectionStore,
    PostgresEvidenceToolStore,
    PostgresInvestigationResultStore,
    PostgresInvestigationStore,
    PostgresMemoryStore,
    PostgresMitigationPlanner,
    PostgresPatchReviewStore,
    PostgresReliabilityCaseStore,
    PostgresRepairStore,
    PostgresRuntimeRunStore,
    PostgresToolCatalogStore,
    PostgresVerificationStore,
    PostgresWorkflowStore,
    PostgresWorkspaceRepairStore,
    PostgresWorkspaceStore,
    ReservationConflict,
    ReservationLost,
    RuntimeRunBudgetExhausted,
    TransitionWrite,
    WorkflowConflict,
    WorkspaceConflict,
)
from solvan.persistence.case_wakeups import WAKEUP_CLAIM_ATTEMPT_BUDGET
from solvan.persistence.claim_sql import (
    INBOX_CLAIM_ATTEMPT_BUDGET,
    OUTBOX_PUBLISH_ATTEMPT_BUDGET,
)
from tools.actuator_crash_fixture import DatabaseFixtureConnector
from tools.bootstrap_database import apply as apply_database_bootstrap
from tools.bootstrap_database import database_role, grant_plan
from tools.seed_demo import CalibrationReceipt, apply_seed, seed_repair_command_authority
from tools.workspace_fixture import (
    REGRESSION_COMMAND_DEFINITION_ID,
    REPOSITORY_BINDING_ID,
    REPRODUCTION_COMMAND_DEFINITION_ID,
)

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    organization_id="org_00000000000000000000000000",
    project_id="prj_00000000000000000000000000",
    environment_id="env_00000000000000000000000000",
)


class _IntegrationFixtureActionGate:
    """The base-schema harness exercises actuation, not target autonomy policy."""

    def check(self, *, scope: Scope, authority: ExecutionAuthorization) -> None:
        assert authority.material.scope == scope


def seed_scope(connection: psycopg.Connection[object]) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO solvan.organizations (id, display_name) VALUES (%s, 'Test')",
            (SCOPE.organization_id,),
        )
        cursor.execute(
            """INSERT INTO solvan.projects
              (organization_id, id, display_name, gcp_project_id)
              VALUES (%s, %s, 'Test', 'solvan-test')""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        cursor.execute(
            """INSERT INTO solvan.environments
              (organization_id, project_id, id, display_name, region, classification)
              VALUES (%s, %s, %s, 'Test', 'europe-west1', 'INTERNAL')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
    connection.commit()


def test_calibrated_demo_seed_builds_executable_policy_atomically() -> None:
    assert DATABASE_URL is not None
    hashes = tuple(f"sha256:{character * 64}" for character in "abcd")
    receipt = CalibrationReceipt.model_validate(
        {
            "schema_version": 1,
            "release_commit": "a" * 40,
            "project_id": "solvan-test",
            "region": "europe-west1",
            "payments_service_name": "solvan-staging-payments",
            "known_good_revision": "solvan-staging-payments-good",
            "fault_revision": "solvan-staging-payments-bad",
            "cloud_sql_database_id": "solvan-test:europe-west1:control",
            "evidence_ref": "gs://solvan-test-evidence/calibration/payments-v1.json",
            "approved_by": "user:owner@example.com",
            "approved_at": datetime(2026, 8, 8, tzinfo=UTC),
            "signals": [
                {
                    "signal_kind": "HTTP_5XX_RATIO",
                    "baseline_max": 0.01,
                    "fault_min": 0.8,
                    "detection_threshold": 0.4,
                    "recovery_threshold": 0.05,
                    "sustained_windows": 2,
                    "sample_hashes": hashes,
                },
                {
                    "signal_kind": "HTTP_P95_LATENCY",
                    "baseline_max": 0.2,
                    "fault_min": 2.0,
                    "detection_threshold": 1.0,
                    "recovery_threshold": 0.3,
                    "sustained_windows": 2,
                    "sample_hashes": hashes,
                },
            ],
        }
    )
    with psycopg.connect(DATABASE_URL) as connection:
        apply_seed(
            connection,
            scope=SCOPE,
            receipt=receipt,
            receipt_hash="sha256:receipt",
            repository_policy={
                "repository_binding_id": REPOSITORY_BINDING_ID,
                "repository_snapshot_uri": "gs://runtime/fixtures/payments/repository.json",
                "repository_snapshot_hash": f"sha256:{'a' * 64}",
                "base_commit_sha": "b" * 40,
                "reproduction_command_definition_id": (REPRODUCTION_COMMAND_DEFINITION_ID),
                "regression_command_definition_id": REGRESSION_COMMAND_DEFINITION_ID,
                "allowed_file_globs": ["app/*.py", "tests/*.py"],
                "artifact_output_uri": "gs://runtime/repairs/",
                "provider": "GEMINI_ADK_AGENT_ENGINE",
            },
        )
        assert connection.execute(
            """SELECT count(*) FROM solvan.detection_rules
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND status = 'APPROVED'""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        ).fetchone() == (2,)
        assert connection.execute(
            """SELECT count(*) FROM solvan.verification_profile_bindings
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND superseded_at IS NULL""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        ).fetchone() == (1,)
        connection.rollback()


@pytest.fixture(scope="module", autouse=True)
def seeded_scope() -> None:
    if DATABASE_URL is None:
        return
    with psycopg.connect(DATABASE_URL) as connection:
        seed_scope(connection)


def test_expired_inbox_claim_is_recovered_and_old_token_is_fenced() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.inbox_events
                  (organization_id, project_id, environment_id, id, source,
                   source_event_id, event_type, payload_ref, payload_hash)
                  VALUES (%s, %s, %s, 'evt_00000000000000000000000000',
                    'monitoring', 'source-1', 'AlertDetected', 'gs://fixture', 'sha256:test')""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
            )
        connection.commit()

        store = PostgresWorkflowStore(connection)
        original = store.claim_inbox(scope=SCOPE, owner="coordinator-a", claim_ttl_ms=10_000)[0]
        connection.commit()

        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.inbox_events SET claim_expires_at = now() - interval '1 second'
                WHERE organization_id = %s AND project_id = %s AND environment_id = %s""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
            )
        connection.commit()

        recovered = store.claim_inbox(scope=SCOPE, owner="coordinator-b", claim_ttl_ms=10_000)[0]
        connection.commit()
        assert recovered.event_id == original.event_id
        assert recovered.claim_token != original.claim_token

        with pytest.raises(ClaimLost):
            store.complete_inbox(
                scope=SCOPE, owner="coordinator-a", claim=original, result_ref="incident:stale"
            )
        connection.rollback()

        store.complete_inbox(
            scope=SCOPE, owner="coordinator-b", claim=recovered, result_ref="incident:created"
        )
        connection.commit()


def test_duplicate_ingress_returns_the_same_durable_event() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        store = PostgresWorkflowStore(connection)
        first = store.ingest_event(
            scope=SCOPE,
            source="detector",
            source_event_id="stable-source-event",
            event_type="MonitoringThresholdBreached",
            payload_ref="gs://fixture/event.json",
            payload_hash="sha256:event",
        )
        connection.commit()
        second = store.ingest_event(
            scope=SCOPE,
            source="detector",
            source_event_id="stable-source-event",
            event_type="MonitoringThresholdBreached",
            payload_ref="gs://fixture/event.json",
            payload_hash="sha256:event",
        )
        connection.commit()

        assert first.event_id == second.event_id
        assert first.disposition.value == "ACCEPTED"
        assert second.disposition.value == "DUPLICATE"


def test_outbox_claim_token_fences_publication() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type, payload_json,
                   idempotency_key)
                  VALUES (%s, %s, %s, 'evt_00000000000000000000000001',
                    'INCIDENT', 'inc_00000000000000000000000000', 1,
                    'incidents', 'IncidentDetected', '{}', 'incident-created-1')""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
            )
        connection.commit()

        store = PostgresWorkflowStore(connection)
        claim = store.claim_outbox(scope=SCOPE, owner="publisher-a", claim_ttl_ms=10_000)[0]
        connection.commit()

        stale = replace(claim, claim_token=uuid4())
        with pytest.raises(ClaimLost):
            store.complete_outbox(scope=SCOPE, owner="publisher-a", claim=stale)
        connection.rollback()

        store.complete_outbox(scope=SCOPE, owner="publisher-a", claim=claim)
        connection.commit()


def test_crash_looping_inbox_event_is_quarantined_after_bounded_claims() -> None:
    assert DATABASE_URL is not None
    poison_id = "evt_00000000000000000000000070"
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            # An old received_at makes the poison event sort first among any
            # leftover claimable events from earlier tests.
            cursor.execute(
                """INSERT INTO solvan.inbox_events
                  (organization_id, project_id, environment_id, id, source,
                   source_event_id, event_type, payload_ref, payload_hash,
                   received_at)
                  VALUES (%s, %s, %s, %s, 'monitoring', 'poison-source-1',
                    'AlertDetected', 'gs://fixture', 'sha256:poison',
                    now() - interval '1 hour')""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, poison_id),
            )
        connection.commit()

        store = PostgresWorkflowStore(connection)
        for attempt in range(INBOX_CLAIM_ATTEMPT_BUDGET):
            claims = store.claim_inbox(
                scope=SCOPE, owner=f"coordinator-{attempt}", claim_ttl_ms=10_000
            )
            connection.commit()
            assert [claim.event_id for claim in claims] == [poison_id]
            # The handler crashes every time; the claim expires unfinished.
            with connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE solvan.inbox_events
                      SET claim_expires_at = now() - interval '1 second'
                      WHERE organization_id = %s AND project_id = %s
                        AND environment_id = %s AND id = %s""",
                    (
                        SCOPE.organization_id,
                        SCOPE.project_id,
                        SCOPE.environment_id,
                        poison_id,
                    ),
                )
            connection.commit()

        # The exhausted budget quarantines the event instead of claiming it again.
        claims = store.claim_inbox(
            scope=SCOPE, owner="coordinator-z", claim_ttl_ms=10_000, batch_size=20
        )
        connection.commit()
        assert poison_id not in [claim.event_id for claim in claims]
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT processing_state, error_class, attempts,
                    processed_at IS NOT NULL, claim_token IS NULL
                  FROM solvan.inbox_events
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, poison_id),
            )
            assert cursor.fetchone() == (
                "FAILED",
                "POISON_EVENT_QUARANTINED",
                INBOX_CLAIM_ATTEMPT_BUDGET,
                True,
                True,
            )


def test_unpublishable_outbox_event_is_quarantined_and_skipped() -> None:
    assert DATABASE_URL is not None
    poison_id = "evt_00000000000000000000000071"
    healthy_id = "evt_00000000000000000000000072"
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            # An old created_at makes the poison row sort first: the claim must
            # skip it for healthy work, not merely reach it last.
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type, payload_json,
                   idempotency_key, publish_attempts, created_at)
                  VALUES (%s, %s, %s, %s, 'INCIDENT',
                    'inc_00000000000000000000000000', 1, 'incidents',
                    'IncidentDetected', '{}', 'poison-outbox-1', %s,
                    now() - interval '1 hour')""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    poison_id,
                    OUTBOX_PUBLISH_ATTEMPT_BUDGET,
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type, payload_json,
                   idempotency_key)
                  VALUES (%s, %s, %s, %s, 'INCIDENT',
                    'inc_00000000000000000000000000', 2, 'incidents',
                    'IncidentDetected', '{}', 'healthy-outbox-1')""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, healthy_id),
            )
        connection.commit()

        # The exhausted row is parked; the claim skips straight to healthy work.
        store = PostgresWorkflowStore(connection)
        claims = store.claim_outbox(
            scope=SCOPE, owner="publisher-a", claim_ttl_ms=10_000, batch_size=20
        )
        connection.commit()
        claimed_ids = [claim.event_id for claim in claims]
        assert poison_id not in claimed_ids
        assert healthy_id in claimed_ids
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT quarantined_at IS NOT NULL, published_at IS NULL,
                    claim_token IS NULL
                  FROM solvan.outbox_events
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, poison_id),
            )
            assert cursor.fetchone() == (True, True, True)

        # Quarantine is durable: nothing ever claims the parked row again, and
        # the healthy row stays fenced behind publisher-a's live claim.
        claims = store.claim_outbox(
            scope=SCOPE, owner="publisher-b", claim_ttl_ms=10_000, batch_size=20
        )
        connection.commit()
        claimed_ids = [claim.event_id for claim in claims]
        assert poison_id not in claimed_ids
        assert healthy_id not in claimed_ids


def seed_incident(connection: psycopg.Connection[object]) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan.services
              (organization_id, project_id, environment_id, id, service_key,
               display_name, platform_kind, platform_resource, owner_department)
              VALUES (%s, %s, %s, 'svc_00000000000000000000000000',
                'payments-api', 'Payments API', 'CLOUD_RUN_SERVICE',
                'projects/test/locations/europe-west1/services/payments-api', 'payments')
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.production_graph_snapshots
              (organization_id, project_id, environment_id, id, version, status,
               source_manifest_ref, content_hash, effective_at, approved_by, approved_at)
              VALUES (%s, %s, %s, 'pgs_00000000000000000000000000', 1,
                'APPROVED', 'fixture://graph', 'sha256:graph', now(), 'owner', now())
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.production_graph_nodes
              (organization_id, project_id, environment_id, id, snapshot_id,
               node_key, node_kind, resource_ref, external_project_id,
               classification, provenance_ref, attributes_json)
              VALUES (%s, %s, %s, 'pgn_00000000000000000000000000',
                'pgs_00000000000000000000000000', 'service:payments-api',
                'SERVICE', 'projects/test/locations/europe-west1/services/payments-api',
                'solvan-test', 'INTERNAL', 'fixture://graph',
                '{"region":"europe-west1"}'::jsonb)
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.detection_rules
              (organization_id, project_id, environment_id, id, version, service_id,
               incident_class, signal_kind, query_json, evaluation_interval_ms,
               comparator, threshold, sustained_windows, severity,
               deduplication_dimension, action_budget, repeated_action_limit, status,
               calibration_receipt_ref, approved_by, approved_at)
              VALUES (%s, %s, %s, 'payments-http-5xx', 1,
                'svc_00000000000000000000000000', 'connection_exhaustion',
                'HTTP_5XX_RATIO', '{}', 25000, 'GT', 0.05, 2, 'SEV2',
                'http-5xx', 2, 1, 'APPROVED',
                'fixture://calibration', 'owner', now())
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.incidents
              (organization_id, project_id, environment_id, id, display_id,
               state_machine_version, state, severity, incident_class,
               primary_service_id, production_graph_snapshot_id, detected_at,
               detection_rule_id, detection_rule_version, deduplication_key,
               action_budget, repeated_action_limit)
              VALUES (%s, %s, %s, 'inc_00000000000000000000000000', 'INC-1000',
                '1', 'DETECTED', 'SEV2', 'connection_exhaustion',
                'svc_00000000000000000000000000',
                'pgs_00000000000000000000000000', now(), 'payments-http-5xx', 1,
                'workflow-test', 2, 1)
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
    connection.commit()


def test_dispatched_runtime_operation_is_recovered_by_fresh_process_without_session_state() -> None:
    assert DATABASE_URL is not None
    incident_id = "inc_22222222222222222222222222"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit)
                  VALUES (%s, %s, %s, %s, 'INC-2222', '1', 'INVESTIGATING',
                    'SEV2', 'connection_exhaustion',
                    'svc_00000000000000000000000000',
                    'pgs_00000000000000000000000000', now(),
                    'payments-http-5xx', 1, 'supervisor-store-test', 2, 1)
                  ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
        connection.commit()
        workflow = PostgresWorkflowStore(connection)
        runs = PostgresRuntimeRunStore(connection)
        with connection.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner="coordinator-supervisor-test",
            )
        assert lease is not None
        with connection.transaction():
            dispatch = runs.reserve_supervisor(
                scope=SCOPE,
                incident_id=incident_id,
                authority=CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version),
                agent_resource=(
                    "projects/123456789/locations/europe-west1/reasoningEngines/supervisor-v1"
                ),
                agent_revision="release-1",
            )
        assert dispatch is not None
        with connection.cursor() as cursor:
            cursor.execute("SELECT status FROM solvan.agent_runs WHERE id = %s", (dispatch.run_id,))
            assert cursor.fetchone() == ("CREATED",)
        with connection.transaction():
            bind_test_agent_run(connection, run_id=dispatch.run_id, agent_key=dispatch.agent_key)
            runs.record_dispatch(
                scope=SCOPE,
                dispatch=dispatch,
                receipt=RuntimeInvocationReceipt(
                    runtime_operation_name=(
                        "projects/123456789/locations/europe-west1/operations/job-1"
                    ),
                    runtime_input_ref="gs://runtime/input.json",
                    runtime_output_ref="gs://runtime/output.json",
                ),
            )
            workflow.release_lease(scope=SCOPE, lease=lease)
        connection.commit()
        # A different database connection represents a replacement coordinator
        # process. It reconstructs the work from Cloud SQL, not process memory or
        # an Agent Runtime Session object.
        with psycopg.connect(DATABASE_URL) as replacement_connection:
            replacement_runs = PostgresRuntimeRunStore(replacement_connection)
            pending = {item.run_id: item for item in replacement_runs.pending(scope=SCOPE)}
        assert pending[dispatch.run_id].agent_resource.endswith("supervisor-v1")
        assert pending[dispatch.run_id].runtime_operation_name.endswith("job-1")


def test_expired_created_runtime_runs_are_fenced_once_by_agent_kind() -> None:
    assert DATABASE_URL is not None
    incident_id = "inc_44444444444444444444444444"
    run_rows = (
        (
            "run_44444444444444444444444440",
            "inv_44444444444444444444444440",
            "incident-supervisor",
            "incident:created-reaper:supervisor",
        ),
        (
            "run_44444444444444444444444441",
            "inv_44444444444444444444444441",
            "execution-agent",
            "incident:created-reaper:execution",
        ),
        (
            "run_44444444444444444444444442",
            "inv_44444444444444444444444442",
            "verification-agent",
            "incident:created-reaper:verification",
        ),
    )
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit)
                  VALUES (%s, %s, %s, %s, 'INC-4444', '1', 'INVESTIGATING',
                    'SEV2', 'connection_exhaustion',
                    'svc_00000000000000000000000000',
                    'pgs_00000000000000000000000000', now(),
                    'payments-http-5xx', 1, 'created-reaper-test', 2, 1)""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
            cursor.executemany(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, incident_id,
                   logical_step_key, agent_key, agent_resource, agent_revision,
                   invocation_id, workflow_version, attempt, status, deadline,
                   budget_json, input_ref, input_hash)
                  VALUES (%s, %s, %s, %s, %s, %s, %s,
                    'projects/123456789/locations/europe-west1/reasoningEngines/test-v1',
                    'release-1', %s, 1, 1, 'CREATED',
                    now() - interval '2 minutes', '{}', %s, %s)""",
                [
                    (
                        SCOPE.organization_id,
                        SCOPE.project_id,
                        SCOPE.environment_id,
                        run_id,
                        incident_id,
                        logical_step_key,
                        agent_key,
                        invocation_id,
                        f"db://solvan/created-reaper/{run_id}",
                        f"sha256:{run_id}",
                    )
                    for run_id, invocation_id, agent_key, logical_step_key in run_rows
                ],
            )
        connection.commit()
        store = PostgresRuntimeRunStore(connection)
        execution_run_id, execution_invocation_id, _, execution_step_key = run_rows[1]
        execution_dispatch = RuntimeDispatch(
            run_id=execution_run_id,
            invocation_id=execution_invocation_id,
            scope=SCOPE,
            incident_id=incident_id,
            plan_id="runtime-recovery",
            plan_version=1,
            step_id="execution-dispatch",
            step_key="execution-dispatch",
            logical_step_key=execution_step_key,
            agent_key="execution-agent",
            agent_resource=("projects/123456789/locations/europe-west1/reasoningEngines/test-v1"),
            agent_revision="release-1",
            scope_ref="scope:action",
            purpose="execute one stored action",
            allowed_tool_names=("actuate_action",),
            workflow_version=1,
            deadline=datetime.now(UTC) - timedelta(minutes=2),
            budget=StepBudget(300_000, 1, 16_000, max_model_calls=1),
            input_ref=f"db://solvan/created-reaper/{execution_run_id}",
            input_hash=f"sha256:{execution_run_id}",
            trace_id="0" * 32,
            span_id="1" * 16,
        )
        with connection.transaction():
            store.record_partial_receipt(
                scope=SCOPE,
                dispatch=execution_dispatch,
                receipt=PartialRuntimeInvocationReceipt(
                    runtime_operation_name=(
                        "projects/123456789/locations/europe-west1/operations/partial"
                    )
                ),
            )
        candidates = {run.run_id: run for run in store.expired_created(scope=SCOPE)}
        assert set(candidates) == {row[0] for row in run_rows}
        for run_id, _invocation_id, agent_key, _logical_step_key in run_rows:
            error_class = (
                "DISPATCH_RECEIPT_INCOMPLETE"
                if agent_key == "execution-agent"
                else "DISPATCH_ACCEPTANCE_UNKNOWN"
            )
            with connection.transaction():
                assert store.expire_created(
                    scope=SCOPE,
                    run=candidates[run_id],
                    error_class=error_class,
                )
            with connection.transaction():
                assert not store.expire_created(
                    scope=SCOPE,
                    run=candidates[run_id],
                    error_class=error_class,
                )
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT agent_key, status, error_class
                  FROM solvan.agent_runs WHERE incident_id = %s
                  ORDER BY agent_key""",
                (incident_id,),
            )
            assert cursor.fetchall() == [
                ("execution-agent", "TIMED_OUT", "DISPATCH_RECEIPT_INCOMPLETE"),
                ("incident-supervisor", "TIMED_OUT", "DISPATCH_ACCEPTANCE_UNKNOWN"),
                ("verification-agent", "TIMED_OUT", "DISPATCH_ACCEPTANCE_UNKNOWN"),
            ]
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, incident_id,
                   logical_step_key, agent_key, agent_resource, agent_revision,
                   invocation_id, workflow_version, attempt, status, deadline,
                   budget_json, input_ref, input_hash)
                  VALUES (%s, %s, %s, 'run_44444444444444444444444443', %s,
                    'incident:created-reaper:supervisor', 'incident-supervisor',
                    'projects/123456789/locations/europe-west1/reasoningEngines/test-v1',
                    'release-1', 'inv_44444444444444444444444443', 1, 2,
                    'CREATED', now() + interval '5 minutes', '{}',
                    'db://solvan/created-reaper/retry', 'sha256:retry')""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
        connection.commit()


def test_supervisor_retry_budget_is_enforced_by_the_durable_attempt_ledger() -> None:
    assert DATABASE_URL is not None
    incident_id = "inc_33333333333333333333333333"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit)
                  VALUES (%s, %s, %s, %s, 'INC-3333', '1', 'INVESTIGATING',
                    'SEV2', 'connection_exhaustion',
                    'svc_00000000000000000000000000',
                    'pgs_00000000000000000000000000', now(),
                    'payments-http-5xx', 1, 'supervisor-budget-test', 2, 1)
                  ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
        connection.commit()
        workflow = PostgresWorkflowStore(connection)
        runs = PostgresRuntimeRunStore(connection)
        with connection.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner="coordinator-supervisor-budget-test",
            )
        assert lease is not None
        authority = CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version)
        resource = "projects/123456789/locations/europe-west1/reasoningEngines/supervisor-v1"
        with connection.transaction():
            first = runs.reserve_supervisor(
                scope=SCOPE,
                incident_id=incident_id,
                authority=authority,
                agent_resource=resource,
                agent_revision="release-1",
            )
            assert first is not None
            runs.fail_created(scope=SCOPE, dispatch=first, error_class="FIRST_FAILURE")
        with connection.transaction():
            second = runs.reserve_supervisor(
                scope=SCOPE,
                incident_id=incident_id,
                authority=authority,
                agent_resource=resource,
                agent_revision="release-1",
            )
            assert second is not None
            runs.fail_created(scope=SCOPE, dispatch=second, error_class="SECOND_FAILURE")
        with pytest.raises(RuntimeRunBudgetExhausted), connection.transaction():
            runs.reserve_supervisor(
                scope=SCOPE,
                incident_id=incident_id,
                authority=authority,
                agent_resource=resource,
                agent_revision="release-1",
            )
        with connection.transaction():
            workflow.release_lease(scope=SCOPE, lease=lease)


def test_detection_streak_is_durable_and_window_idempotent() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        store = PostgresDetectionStore(connection)
        rule = store.load_approved_rules(scope=SCOPE)[0]
        first_end = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
        first = store.record_evaluation(
            scope=SCOPE,
            rule=rule,
            window_start=first_end - timedelta(minutes=1),
            window_end=first_end,
            observed_value=0.10,
            query_receipt_ref="gs://evidence/detection-1.json",
            query_receipt_hash="sha256:detection-1",
        )
        connection.commit()
        second_end = first_end + timedelta(seconds=25)
        second = store.record_evaluation(
            scope=SCOPE,
            rule=rule,
            window_start=second_end - timedelta(minutes=1),
            window_end=second_end,
            observed_value=0.11,
            query_receipt_ref="gs://evidence/detection-2.json",
            query_receipt_hash="sha256:detection-2",
        )
        connection.commit()
        duplicate = store.record_evaluation(
            scope=SCOPE,
            rule=rule,
            window_start=second_end - timedelta(minutes=1),
            window_end=second_end,
            observed_value=0.11,
            query_receipt_ref="gs://evidence/detection-2.json",
            query_receipt_hash="sha256:detection-2",
        )
        connection.commit()
        third_end = second_end + timedelta(seconds=25)
        continuous = store.record_evaluation(
            scope=SCOPE,
            rule=rule,
            window_start=third_end - timedelta(minutes=1),
            window_end=third_end,
            observed_value=0.12,
            query_receipt_ref="gs://evidence/detection-3.json",
            query_receipt_hash="sha256:detection-3",
        )
        connection.commit()

    assert first == (True, False)
    assert second == (True, True)
    assert duplicate == (False, True)
    assert continuous == (True, False)


def test_lease_fences_atomic_projection_transition_and_outbox() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        store = PostgresWorkflowStore(connection)
        lease = store.acquire_lease(
            scope=SCOPE,
            aggregate_type=AggregateType.INCIDENT,
            entity_id="inc_00000000000000000000000000",
            owner="coordinator-a",
        )
        assert lease is not None
        connection.commit()

        assert (
            store.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=lease.entity_id,
                owner="coordinator-b",
            )
            is None
        )
        connection.rollback()

        stale_lease = replace(lease, token=uuid4())
        write = TransitionWrite(
            from_state="DETECTED",
            to_state="TRIAGING",
            transition_key="alert-accepted-1",
            actor_type="COORDINATOR",
            actor_id="coordinator-a",
            reason_code="ALERT_ACCEPTED",
            rationale_summary="Validated detector event",
        )
        with pytest.raises(WorkflowConflict):
            store.commit_transition(scope=SCOPE, lease=stale_lease, transition=write)
        connection.rollback()

        assert store.commit_transition(scope=SCOPE, lease=lease, transition=write) == 2
        connection.commit()

        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT i.state, i.workflow_version,
                  (SELECT count(*) FROM solvan.state_transitions),
                  (SELECT count(*) FROM solvan.outbox_events
                    WHERE aggregate_id = i.id AND topic = 'workflow-transitions')
                FROM solvan.incidents i WHERE i.id = %s""",
                (lease.entity_id,),
            )
            assert cursor.fetchone() == ("TRIAGING", 2, 1, 1)

        store.release_lease(scope=SCOPE, lease=lease)
        connection.commit()


def test_active_detection_deduplicates_and_terminal_detection_recurs() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        store = PostgresWorkflowStore(connection)
        request = IncidentOpenRequest(
            state_machine_version="1",
            severity="SEV2",
            incident_class="connection_exhaustion",
            primary_service_id="svc_00000000000000000000000000",
            production_graph_snapshot_id="pgs_00000000000000000000000000",
            detected_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
            detection_rule_id="payments-http-5xx",
            detection_rule_version=1,
            deduplication_key="payments-http-5xx:payments-api:http-5xx",
            action_budget=2,
            repeated_action_limit=1,
        )
        first = store.open_or_attach_incident(scope=SCOPE, request=request)
        connection.commit()
        attached = store.open_or_attach_incident(scope=SCOPE, request=request)
        connection.commit()

        assert first.disposition.value == "CREATED"
        assert attached.disposition.value == "ATTACHED"
        assert attached.incident_id == first.incident_id

        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.incidents
                  SET state = 'RESOLVED', terminal_reason = 'fixture complete'
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    first.incident_id,
                ),
            )
        connection.commit()

        recurrence = store.open_or_attach_incident(scope=SCOPE, request=request)
        connection.commit()
        assert recurrence.disposition.value == "CREATED"
        assert recurrence.incident_id != first.incident_id
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT recurrence_of FROM solvan.incidents WHERE id = %s",
                (recurrence.incident_id,),
            )
            assert cursor.fetchone() == (first.incident_id,)


def test_twenty_five_simultaneous_incidents_are_not_lost_or_duplicated() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
    barrier = threading.Barrier(25)

    def create(index: int) -> tuple[str, str]:
        request = IncidentOpenRequest(
            state_machine_version="1",
            severity="SEV2",
            incident_class="connection_exhaustion",
            primary_service_id="svc_00000000000000000000000000",
            production_graph_snapshot_id="pgs_00000000000000000000000000",
            detected_at=datetime(2026, 8, 10, 12, index, tzinfo=UTC),
            detection_rule_id="payments-http-5xx",
            detection_rule_version=1,
            deduplication_key=f"load-25:{index}",
            action_budget=2,
            repeated_action_limit=1,
        )
        barrier.wait(timeout=10)
        with psycopg.connect(DATABASE_URL) as participant_connection:
            result = PostgresWorkflowStore(participant_connection).open_or_attach_incident(
                scope=SCOPE, request=request
            )
            participant_connection.commit()
            return result.incident_id, result.disposition.value

    with ThreadPoolExecutor(max_workers=25) as executor:
        results = tuple(executor.map(create, range(25)))
    incident_ids = {incident_id for incident_id, _disposition in results}
    assert len(incident_ids) == 25
    assert {disposition for _incident_id, disposition in results} == {"CREATED"}
    with psycopg.connect(DATABASE_URL) as connection, connection.cursor() as cursor:
        cursor.execute(
            """SELECT count(*), count(DISTINCT display_id), count(DISTINCT deduplication_key)
              FROM solvan.incidents
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND deduplication_key LIKE 'load-25:%%'""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        assert cursor.fetchone() == (25, 25, 25)
        cursor.execute(
            """UPDATE solvan.incidents SET state = 'RESOLVED',
                terminal_reason = 'load contract completed',
                detected_at = '2000-01-01T00:00:00Z'
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND deduplication_key LIKE 'load-25:%%'""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        connection.commit()


def test_coordinator_commits_incident_and_inbox_completion_atomically() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        store = PostgresWorkflowStore(connection)
        ingress = store.ingest_event(
            scope=SCOPE,
            source="detector",
            source_event_id="coordinator-event",
            event_type="MonitoringThresholdBreached",
            payload_ref="gs://fixture/coordinator-event.json",
            payload_hash="sha256:coordinator-event",
        )
        connection.commit()
        claims = store.claim_inbox(
            scope=SCOPE, owner="coordinator-c", claim_ttl_ms=10_000, batch_size=20
        )
        connection.commit()
        claim = next(item for item in claims if item.event_id == ingress.event_id)
        start = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
        result = IncidentCoordinator(store).process_detection(
            scope=SCOPE,
            claim_owner="coordinator-c",
            claim=claim,
            event=CanonicalDetectionEvent(
                rule_id="payments-http-5xx",
                rule_version=1,
                service_id="svc_00000000000000000000000000",
                graph_snapshot_id="pgs_00000000000000000000000000",
                incident_class="connection_exhaustion",
                deduplication_dimension="coordinator",
                window_start=start,
                window_end=start,
                observed_value=0.2,
                severity="SEV2",
                action_budget=2,
                repeated_action_limit=1,
            ),
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT processing_state, result_ref FROM solvan.inbox_events
                  WHERE id = %s""",
                (ingress.event_id,),
            )
            assert cursor.fetchone() == ("COMPLETED", f"incident:{result.incident_id}")


INVESTIGATION_INCIDENT_ID = "inc_00000000000000000000000002"
SUPERVISOR_RUN_ID = "run_00000000000000000000000002"
INVESTIGATION_CONNECTION_ID = "con_01J4QZK8Q4J8Q6B95KQY4M9R2T"
INVESTIGATION_CATALOG_HASH = f"sha256:{'e' * 64}"


def bind_test_agent_run(
    connection: psycopg.Connection[object], *, run_id: str, agent_key: str
) -> str:
    """Install a zero-Tool binding for persistence tests unrelated to Tool policy."""

    role = {
        "incident-supervisor": ExecutionRole.SUPERVISOR,
        "workspace-agent": ExecutionRole.WORKSPACE,
    }.get(agent_key, ExecutionRole.SPECIALIST)
    display_name = {
        "incident-supervisor": "Incident Supervisor Agent",
        "evidence-agent": "Evidence Agent",
        "infrastructure-agent": "Infrastructure Agent",
        "execution-agent": "Execution Agent",
        "verification-agent": "Verification Agent",
        "workspace-agent": "Workspace Agent",
    }[agent_key]
    catalog = PostgresToolCatalogStore(connection)
    catalog.register_principal(
        CatalogPrincipal(
            principal_key=agent_key,
            display_name=display_name,
            registry_kind=RegistryKind.AGENT,
            execution_role=role,
            model_backed=True,
            manifest_hash=INVESTIGATION_CATALOG_HASH,
        )
    )
    profile = ToolProfileRevision(
        profile_key=f"test.runtime.{agent_key}",
        version="1",
        purpose="Exercise a persistence transition with no model-visible Tools.",
        allowed_agent_key=agent_key,
        tool_revisions=(),
        maximum_total_calls=0,
        maximum_parallel_calls=0,
        tool_connection_requirements=(),
        data_classification_ceiling="INTERNAL",
        runtime_region="europe-west1",
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref=f"approval://profile/test/{agent_key}/1",
        evaluation_ref=f"evaluation://profile/test/{agent_key}/1",
    )
    catalog.publish_profile(scope=SCOPE, profile=profile)
    scope_values = (
        SCOPE.organization_id,
        SCOPE.project_id,
        SCOPE.environment_id,
    )
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT effective_tool_set_hash FROM solvan.agent_runs
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND id=%s AND agent_key=%s AND status='CREATED'""",
            (*scope_values, run_id, agent_key),
        )
        row = cursor.fetchone()
        assert row is not None
        effective_hash = row[0] or f"sha256:{'f' * 64}"
        cursor.execute(
            """INSERT INTO solvan_operability.agent_run_tool_bindings
                 (organization_id,project_id,environment_id,agent_run_id,
                  profile_key,profile_version,profile_material_hash,accepted_tool_count,
                  effective_tool_set_hash,identity_ref,runtime_region,
                  accepted_data_classification,classification_ceiling,
                  policy_head_activation_id,
                  policy_head_epoch,placement_epoch,accepted_step_budget_hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,0,%s,%s,'europe-west1',
                       'INTERNAL','INTERNAL',NULL,0,1,%s)
               ON CONFLICT DO NOTHING""",
            (
                *scope_values,
                run_id,
                profile.profile_key,
                profile.version,
                profile.profile_material_hash,
                effective_hash,
                f"identity://{agent_key}/test",
                f"sha256:{'e' * 64}",
            ),
        )
        cursor.execute(
            """UPDATE solvan.agent_runs SET effective_tool_set_hash=%s
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND id=%s AND agent_key=%s AND status='CREATED'
                  AND (effective_tool_set_hash IS NULL OR effective_tool_set_hash=%s)""",
            (
                effective_hash,
                *scope_values,
                run_id,
                agent_key,
                effective_hash,
            ),
        )
        assert cursor.rowcount == 1
    return str(effective_hash)


def seed_investigation_catalog(
    connection: psycopg.Connection[object],
) -> PostgresAgentRunBinder:
    """Build the exact production-shaped binding used by the evidence call test."""

    with connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan.tenant_connections
                 (organization_id,project_id,environment_id,id,display_name,kind,
                  provider,credential_posture,residency_region,classification,
                  lifecycle,availability,availability_reason_code,availability_explanation,availability_remediation_kind,availability_receipt_ref,last_probe_at,last_probe_result,created_by_principal)
               VALUES (%s,%s,%s,%s,'Test Cloud Monitoring','GCP_NATIVE',
                       'CLOUD_MONITORING','CUSTOMER_SIDE_NONE','europe-west1',
                       'INTERNAL','ENABLED','READY',NULL,NULL,NULL,'probe://seed',now(),'SUCCEEDED','test:catalog-seed')
               ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                INVESTIGATION_CONNECTION_ID,
            ),
        )
    catalog = PostgresToolCatalogStore(connection)
    catalog.register_principal(
        CatalogPrincipal(
            principal_key="evidence-agent",
            display_name="Evidence Agent",
            registry_kind=RegistryKind.AGENT,
            execution_role=ExecutionRole.SPECIALIST,
            model_backed=True,
            manifest_hash=INVESTIGATION_CATALOG_HASH,
        )
    )
    catalog.publish_tool(
        ToolRevision(
            tool_key="cloud_monitoring_query",
            version="1",
            display_name="Cloud Monitoring query",
            description="Read one bounded Cloud Monitoring signal.",
            use_cases=("Collect bounded incident telemetry",),
            anti_use_cases=("Execute arbitrary or cross-scope queries",),
            owner_department="Reliability Platform",
            permission_class=PermissionClass.READ,
            implementation_kind=ImplementationKind.CONNECTOR,
            allowed_requester_keys=("evidence-agent",),
            required_capabilities=("monitoring.timeSeries.list",),
            required_connection_providers=("CLOUD_MONITORING",),
            input_schema_ref="schema://cloud-monitoring/input/1",
            input_schema_hash=INVESTIGATION_CATALOG_HASH,
            output_schema_ref="schema://cloud-monitoring/output/1",
            output_schema_hash=INVESTIGATION_CATALOG_HASH,
            evidence_kind=EvidenceKind.METRICS,
            output_semantics=("bounded time series",),
            supported_retrieval_controls=("service_scope", "bounded_window"),
            no_data_semantics=NoDataSemantics.UNKNOWN,
            failure_taxonomy=("NO_DATA", "PERMISSION_DENIED"),
            supported_data_classes=("INTERNAL",),
            runtime_regions=("europe-west1",),
            gateway_destination="monitoring.googleapis.com",
            registry_resource="registry://cloud-monitoring/1",
            model_armor_coverage=ModelArmorCoverage.NOT_APPLICABLE,
            network_policy_hash=INVESTIGATION_CATALOG_HASH,
            timeout_ms=10_000,
            max_input_bytes=4096,
            max_output_bytes=65_536,
            default_call_budget=3,
            idempotency=IdempotencyKind.NOT_APPLICABLE,
            lifecycle=CatalogLifecycle.APPROVED,
            approval_ref="approval://tool/cloud-monitoring/1",
            evaluation_ref="evaluation://tool/cloud-monitoring/1",
        )
    )
    profile = ToolProfileRevision(
        profile_key="evidence.test-observability.v1",
        version="1",
        purpose="Exercise the exact evidence boundary in persistence tests.",
        allowed_agent_key="evidence-agent",
        tool_revisions=("cloud_monitoring_query@1",),
        maximum_total_calls=3,
        maximum_parallel_calls=1,
        tool_connection_requirements=(
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="cloud_monitoring_query@1",
                binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                provider="CLOUD_MONITORING",
                capability_key="METRIC_READ",
                external_project_selector="TARGET_RESOURCE_PROJECT",
            ),
        ),
        data_classification_ceiling="INTERNAL",
        runtime_region="europe-west1",
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref="approval://profile/evidence-test/1",
        evaluation_ref="evaluation://profile/evidence-test/1",
    )
    catalog.publish_profile(scope=SCOPE, profile=profile)
    identity_ref = "identity://evidence-agent/test"
    now = datetime.now(UTC)
    catalog.record_probe(
        scope=SCOPE,
        probe=CapabilityProbe(
            connection_id=INVESTIGATION_CONNECTION_ID,
            tool_revision="cloud_monitoring_query@1",
            agent_key="evidence-agent",
            connection_provider="CLOUD_MONITORING",
            capabilities=frozenset({"monitoring.timeSeries.list"}),
            connection_epoch=1,
            identity_ref=identity_ref,
            registry_resource="registry://cloud-monitoring/1",
            gateway_policy_ref="gateway://policy/cloud-monitoring/1",
            network_policy_hash=INVESTIGATION_CATALOG_HASH,
            region="europe-west1",
            classification_ceiling="INTERNAL",
            outcome="PASSED",
            observed_at=now,
            expires_at=now + timedelta(minutes=5),
            receipt_ref="receipt://probe/cloud-monitoring/test",
            receipt_hash=INVESTIGATION_CATALOG_HASH,
        ),
    )
    with connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan_onboarding.environment_external_project_bindings
                 (organization_id,project_id,environment_id,external_project_id,
                  binding_epoch,deciding_principal,decision_ref,is_current)
               VALUES (%s,%s,%s,'solvan-test',1,'user:test@example.com',
                       'decision://test/environment-project',true)
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan_onboarding.connection_external_project_coverage
                 (organization_id,project_id,environment_id,connection_id,
                  capability_class,external_project_id,connection_epoch,
                  observed_at,probe_receipt_ref)
               VALUES (%s,%s,%s,%s,'METRIC_READ','solvan-test',1,now(),
                       'receipt://probe/cloud-monitoring/test')
               ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                INVESTIGATION_CONNECTION_ID,
            ),
        )
    connection.commit()
    return PostgresAgentRunBinder(
        region="europe-west1",
        bindings={
            "evidence-agent": GovernedAgentBinding(
                profile_key=profile.profile_key,
                profile_version=profile.version,
                identity_ref=identity_ref,
                accepted_tool_ordinals=(1,),
                connection_epochs={INVESTIGATION_CONNECTION_ID: 1},
                gateway_destinations=frozenset({"monitoring.googleapis.com"}),
                data_classification="INTERNAL",
            )
        },
        connection=connection,
    )


def test_run_binding_freezes_an_exact_two_of_four_tool_subset() -> None:
    """A profile is an upper bound; Runtime receives only the accepted subset."""

    assert DATABASE_URL is not None
    run_id = "run_00000000000000000000000012"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_investigation_run(connection)
        catalog = PostgresToolCatalogStore(connection)
        catalog.register_principal(
            CatalogPrincipal(
                principal_key="evidence-agent",
                display_name="Evidence Agent",
                registry_kind=RegistryKind.AGENT,
                execution_role=ExecutionRole.SPECIALIST,
                model_backed=True,
                manifest_hash=INVESTIGATION_CATALOG_HASH,
            )
        )
        tool_refs: list[str] = []
        requirements: list[ToolConnectionRequirement] = []
        for ordinal, tool_key in enumerate(
            ("metric_math", "log_correlation", "trace_summary", "change_lookup"),
            start=1,
        ):
            tool = ToolRevision(
                tool_key=tool_key,
                version="1",
                display_name=tool_key.replace("_", " ").title(),
                description="Perform one deterministic bounded computation.",
                use_cases=("Transform already authorized evidence",),
                anti_use_cases=("Read or mutate an external system",),
                owner_department="Reliability Platform",
                permission_class=PermissionClass.COMPUTE,
                implementation_kind=ImplementationKind.APPLICATION_SERVICE,
                allowed_requester_keys=("evidence-agent",),
                required_capabilities=("deterministic.compute",),
                required_connection_providers=("SOLVAN_INTERNAL",),
                input_schema_ref=f"schema://{tool_key}/input/1",
                input_schema_hash=INVESTIGATION_CATALOG_HASH,
                output_schema_ref=f"schema://{tool_key}/output/1",
                output_schema_hash=INVESTIGATION_CATALOG_HASH,
                evidence_kind=EvidenceKind.NONE,
                output_semantics=("typed deterministic result",),
                supported_retrieval_controls=("deterministic_input",),
                no_data_semantics=NoDataSemantics.NOT_APPLICABLE,
                failure_taxonomy=("INVALID_INPUT",),
                supported_data_classes=("INTERNAL",),
                runtime_regions=("europe-west1",),
                gateway_destination="compute.internal",
                registry_resource=f"registry://{tool_key}/1",
                model_armor_coverage=ModelArmorCoverage.NOT_APPLICABLE,
                network_policy_hash=INVESTIGATION_CATALOG_HASH,
                timeout_ms=1_000,
                max_input_bytes=4_096,
                max_output_bytes=4_096,
                default_call_budget=1,
                idempotency=IdempotencyKind.NOT_APPLICABLE,
                lifecycle=CatalogLifecycle.APPROVED,
                approval_ref=f"approval://tool/{tool_key}/1",
                evaluation_ref=f"evaluation://tool/{tool_key}/1",
            )
            catalog.publish_tool(tool)
            tool_ref = f"{tool_key}@1"
            tool_refs.append(tool_ref)
            requirements.append(
                ToolConnectionRequirement(
                    ordinal=ordinal,
                    tool_revision=tool_ref,
                    binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
                )
            )
        profile = ToolProfileRevision(
            profile_key="evidence.test-narrowed-subset.v1",
            version="1",
            purpose="Prove accepted Tool subsets remain exact at dispatch.",
            allowed_agent_key="evidence-agent",
            tool_revisions=tuple(tool_refs),
            maximum_total_calls=2,
            maximum_parallel_calls=1,
            tool_connection_requirements=tuple(requirements),
            data_classification_ceiling="INTERNAL",
            runtime_region="europe-west1",
            lifecycle=CatalogLifecycle.APPROVED,
            approval_ref="approval://profile/evidence-narrowed/1",
            evaluation_ref="evaluation://profile/evidence-narrowed/1",
        )
        catalog.publish_profile(scope=SCOPE, profile=profile)
        connection.execute(
            """INSERT INTO solvan.agent_runs
              (organization_id,project_id,environment_id,id,incident_id,
               logical_step_key,agent_key,agent_resource,agent_revision,
               invocation_id,workflow_version,attempt,status,deadline,budget_json,
               input_ref,input_hash)
              SELECT %s,%s,%s,%s,%s,'test:narrowed-subset','evidence-agent',
                     'registry://evidence-agent','test-1','inv-narrowed-subset',
                     workflow_version,1,'CREATED',now()+interval '5 minutes',
                     '{"deadline_ms":60000,"max_tool_calls":2,"max_output_bytes":4096,"max_model_calls":1,"max_replans":0}'::jsonb,
                     'fixture://narrowed-subset','sha256:narrowed-subset'
                FROM solvan.incidents
               WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                 AND id=%s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
                INVESTIGATION_INCIDENT_ID,
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                INVESTIGATION_INCIDENT_ID,
            ),
        )
        connection.commit()
        binder = PostgresAgentRunBinder(
            region="europe-west1",
            bindings={
                "evidence-agent": GovernedAgentBinding(
                    profile_key=profile.profile_key,
                    profile_version=profile.version,
                    identity_ref="identity://evidence-agent/narrowed-test",
                    accepted_tool_ordinals=(1, 3),
                    connection_epochs={},
                    gateway_destinations=frozenset({"compute.internal"}),
                    data_classification="INTERNAL",
                )
            },
            connection=connection,
        )
        effective_hash = binder.bind_run(
            scope=SCOPE,
            run_id=run_id,
            agent_key="evidence-agent",
            target_external_project_id=None,
        )
        assert effective_hash.startswith("sha256:")
        frozen_set = catalog.load_bound_effective_tool_set(scope=SCOPE, agent_run_id=run_id)
        assert frozen_set.effective_tool_set_hash == effective_hash
        assert frozen_set.accepted_data_classification == "INTERNAL"
        changed_classification_binder = PostgresAgentRunBinder(
            region="europe-west1",
            bindings={
                "evidence-agent": GovernedAgentBinding(
                    profile_key=profile.profile_key,
                    profile_version=profile.version,
                    identity_ref="identity://evidence-agent/narrowed-test",
                    accepted_tool_ordinals=(1, 3),
                    connection_epochs={},
                    gateway_destinations=frozenset({"compute.internal"}),
                    data_classification="PUBLIC",
                )
            },
            connection=connection,
        )
        with pytest.raises(ToolCatalogError, match="different frozen Tool binding"):
            changed_classification_binder.bind_run(
                scope=SCOPE,
                run_id=run_id,
                agent_key="evidence-agent",
                target_external_project_id=None,
            )
        assert connection.execute(
            """SELECT accepted_tool_count
                 FROM solvan_operability.agent_run_tool_bindings
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND agent_run_id=%s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
            ),
        ).fetchone() == (2,)
        assert connection.execute(
            """SELECT ordinal,tool_key
                 FROM solvan_operability.agent_run_accepted_tool_bindings
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND agent_run_id=%s ORDER BY ordinal""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
            ),
        ).fetchall() == [(1, "metric_math"), (3, "trace_summary")]
        connection.execute(
            """UPDATE solvan.agent_runs SET status='DISPATCHED'
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND id=%s AND status='CREATED'""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
            ),
        )
        connection.commit()
        assert connection.execute(
            """SELECT status FROM solvan.agent_runs
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND id=%s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                run_id,
            ),
        ).fetchone() == ("DISPATCHED",)
        with (
            pytest.raises(
                psycopg.errors.ObjectNotInPrerequisiteState,
                match="agent_run_tool_bindings is immutable after insert",
            ),
            connection.transaction(),
        ):
            connection.execute(
                """UPDATE solvan_operability.agent_run_tool_bindings
                      SET identity_ref='identity://forged'
                    WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                      AND agent_run_id=%s""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    run_id,
                ),
            )
        empty_run_id = "run_00000000000000000000000013"
        connection.execute(
            """INSERT INTO solvan.agent_runs
                 (organization_id,project_id,environment_id,id,incident_id,
                  logical_step_key,agent_key,agent_resource,agent_revision,
                  invocation_id,workflow_version,attempt,status,deadline,budget_json,
                  input_ref,input_hash)
               SELECT organization_id,project_id,environment_id,%s,incident_id,
                      'test:empty-subset','evidence-agent',agent_resource,agent_revision,
                      'inv-empty-subset',workflow_version,1,'CREATED',deadline,budget_json,
                      'fixture://empty-subset','sha256:empty-subset'
                 FROM solvan.agent_runs WHERE id=%s""",
            (empty_run_id, run_id),
        )
        connection.commit()
        empty_binder = PostgresAgentRunBinder(
            region="europe-west1",
            bindings={
                "evidence-agent": GovernedAgentBinding(
                    profile_key=profile.profile_key,
                    profile_version=profile.version,
                    identity_ref="identity://evidence-agent/narrowed-test",
                    accepted_tool_ordinals=(),
                    connection_epochs={},
                    gateway_destinations=frozenset({"compute.internal"}),
                    data_classification="INTERNAL",
                )
            },
            connection=connection,
        )
        with pytest.raises(
            ToolCatalogError,
            match="empty Tool selection requires a tool-less, zero-model, zero-Tool run",
        ):
            empty_binder.bind_run(
                scope=SCOPE,
                run_id=empty_run_id,
                agent_key="evidence-agent",
            )


def seed_investigation_run(
    connection: psycopg.Connection[object],
    *,
    incident_id: str = INVESTIGATION_INCIDENT_ID,
    supervisor_run_id: str = SUPERVISOR_RUN_ID,
    display_id: str = "INC-1002",
    deduplication_key: str = "investigation-plan-test",
) -> None:
    seed_incident(connection)
    with connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan.incidents
              (organization_id, project_id, environment_id, id, display_id,
               state_machine_version, state, severity, incident_class,
               primary_service_id, production_graph_snapshot_id, detected_at,
               detection_rule_id, detection_rule_version, deduplication_key,
               action_budget, repeated_action_limit)
              VALUES (%s, %s, %s, %s, %s, '1', 'INVESTIGATING', 'SEV2',
                'connection_exhaustion', 'svc_00000000000000000000000000',
                'pgs_00000000000000000000000000', now(), 'payments-http-5xx', 1,
                %s, 2, 1)
              ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                incident_id,
                display_id,
                deduplication_key,
            ),
        )
        cursor.execute(
            """INSERT INTO solvan.agent_runs
              (organization_id, project_id, environment_id, id, incident_id,
               logical_step_key, agent_key, agent_resource, agent_revision,
               invocation_id, workflow_version, attempt, status, deadline,
               budget_json, input_ref, input_hash, started_at, completed_at)
              SELECT %s, %s, %s, %s, %s, %s,
                'incident-supervisor',
                'projects/test/locations/europe-west1/reasoningEngines/supervisor-v1',
                'supervisor-20260808-01', %s, workflow_version, 1,
                'SUCCEEDED', now() + interval '5 minutes', '{}', 'fixture://supervisor',
                'sha256:supervisor', now(), now()
              FROM solvan.incidents WHERE organization_id = %s AND project_id = %s
                AND environment_id = %s AND id = %s
              ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                supervisor_run_id,
                incident_id,
                f"incident:{incident_id}:plan:supervisor:1",
                f"inv-{supervisor_run_id}",
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                incident_id,
            ),
        )
    connection.commit()


class InspectingRuntime:
    def __init__(self) -> None:
        self.dispatches: list[RuntimeDispatch] = []

    def invoke(self, dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt:
        assert DATABASE_URL is not None
        with psycopg.connect(DATABASE_URL) as inspection, inspection.cursor() as cursor:
            cursor.execute(
                """SELECT p.status, s.status, r.status
                  FROM solvan.investigation_plans p
                  JOIN solvan.investigation_steps s ON s.plan_id = p.id
                  JOIN solvan.agent_runs r ON r.id = s.current_agent_run_id
                  WHERE p.id = %s AND s.id = %s AND r.id = %s""",
                (dispatch.plan_id, dispatch.step_id, dispatch.run_id),
            )
            assert cursor.fetchone() == ("ACCEPTED", "DISPATCHED", "CREATED")
        self.dispatches.append(dispatch)
        return RuntimeInvocationReceipt(
            runtime_operation_name=f"operations/{dispatch.invocation_id}",
            session_id="session-investigation-1",
        )


class FailOnceRuntime:
    def __init__(self) -> None:
        self.dispatches: list[RuntimeDispatch] = []

    def invoke(self, dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt:
        self.dispatches.append(dispatch)
        if len(self.dispatches) == 1:
            raise TimeoutError("first attempt exhausted")
        return RuntimeInvocationReceipt(
            runtime_operation_name=f"operations/{dispatch.invocation_id}",
            runtime_input_ref="db://solvan/evidence-items/preserved",
            runtime_output_ref="gs://runtime/fallback.json",
        )


def investigation_policy() -> PlanValidationPolicy:
    budget = StepBudget(60_000, 3, 16_000)
    return PlanValidationPolicy(
        agent_limits={
            "evidence-agent": AgentLimit(
                agent_resource=(
                    "projects/test/locations/europe-west1/reasoningEngines/evidence-v1"
                ),
                agent_revision="evidence-20260808-01",
                maximum=budget,
                allowed_scope_refs=frozenset({"scope:payments"}),
                allowed_tool_names=("cloud_monitoring_query",),
            )
        },
        allowed_scope_refs=frozenset({"scope:payments"}),
        maximum_steps=4,
    )


def investigation_proposal(
    *, purpose: str = "inspect bounded telemetry"
) -> InvestigationPlanProposal:
    return InvestigationPlanProposal(
        objective="identify the payments regression",
        completion_condition="required service evidence is available",
        uncertainties=("database saturation may be a symptom",),
        steps=(
            ProposedStep(
                step_key="collect-telemetry",
                kind=InvestigationStepKind.INVOKE_AGENT,
                agent_key="evidence-agent",
                scope_ref="scope:payments",
                purpose=purpose,
                required=True,
                depends_on=(),
                budget=StepBudget(60_000, 3, 16_000),
            ),
        ),
    )


def test_plan_is_committed_before_coordinator_only_runtime_dispatch() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_investigation_run(connection)
        workflow_store = PostgresWorkflowStore(connection)
        lease = workflow_store.acquire_lease(
            scope=SCOPE,
            aggregate_type=AggregateType.INCIDENT,
            entity_id=INVESTIGATION_INCIDENT_ID,
            owner="investigation-coordinator",
        )
        assert lease is not None
        connection.commit()
        authority = CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version)
        runtime = InspectingRuntime()
        coordinator = InvestigationCoordinator(
            PostgresInvestigationStore(connection),
            runtime,
            seed_investigation_catalog(connection),
        )

        accepted = coordinator.accept_supervisor_plan(
            scope=SCOPE,
            incident_id=INVESTIGATION_INCIDENT_ID,
            supervisor_run_id=SUPERVISOR_RUN_ID,
            authority=authority,
            proposal=investigation_proposal(),
            policy=investigation_policy(),
        )
        duplicate = coordinator.accept_supervisor_plan(
            scope=SCOPE,
            incident_id=INVESTIGATION_INCIDENT_ID,
            supervisor_run_id=SUPERVISOR_RUN_ID,
            authority=authority,
            proposal=investigation_proposal(),
            policy=investigation_policy(),
        )
        assert duplicate == accepted
        assert runtime.dispatches == []

        outcomes = coordinator.dispatch_ready_steps(
            scope=SCOPE,
            incident_id=INVESTIGATION_INCIDENT_ID,
            authority=authority,
        )
        assert len(outcomes) == 1
        assert outcomes[0].status.value == "DISPATCHED"
        assert len(runtime.dispatches) == 1
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT p.plan_version, p.content_hash, s.agent_revision,
                    s.status, r.status, r.runtime_operation_name
                  FROM solvan.investigation_plans p
                  JOIN solvan.investigation_steps s ON s.plan_id = p.id
                  JOIN solvan.agent_runs r ON r.id = s.current_agent_run_id
                  WHERE p.id = %s""",
                (accepted.plan_id,),
            )
            row = cursor.fetchone()
        assert row == (
            1,
            accepted.content_hash,
            "evidence-20260808-01",
            "DISPATCHED",
            "DISPATCHED",
            f"operations/{runtime.dispatches[0].invocation_id}",
        )

        evidence_store = PostgresEvidenceToolStore(connection)
        with connection.transaction():
            with pytest.raises(RuntimeError, match="outside the frozen run target"):
                evidence_store.reserve(
                    invocation_id=runtime.dispatches[0].invocation_id,
                    expected_agent_key="evidence-agent",
                    tool_name="cloud_monitoring_query",
                    service_id="svc_11111111111111111111111111",
                    arguments_hash=f"sha256:{'1' * 64}",
                    input_bytes=64,
                    otel_span_id="0000000000000001",
                )
            tool_reservation = evidence_store.reserve(
                invocation_id=runtime.dispatches[0].invocation_id,
                expected_agent_key="evidence-agent",
                tool_name="cloud_monitoring_query",
                service_id="svc_00000000000000000000000000",
                arguments_hash=f"sha256:{'2' * 64}",
                input_bytes=64,
                otel_span_id="0000000000000002",
            )
        now = datetime.now(UTC)
        with connection.transaction():
            evidence_id = evidence_store.complete(
                reservation=tool_reservation,
                write=EvidenceWrite(
                    source_kind="CLOUD_MONITORING",
                    source_resource="projects/test/timeSeries",
                    query_spec={"signal_kind": "HTTP_5XX_RATIO"},
                    window_start=now - timedelta(minutes=1),
                    window_end=now,
                    observed_at=now,
                    content_ref="gs://evidence/metric.json",
                    content_hash=f"sha256:{'3' * 64}",
                    classification="INTERNAL",
                    residency="europe-west1",
                    redaction_manifest_ref="deterministic:none-sensitive-metric-v1",
                    provenance={"request_ids": ["monitoring-request-1"]},
                    freshness_expires_at=now + timedelta(minutes=5),
                ),
                output_bytes=128,
            )
        with connection.transaction():
            duplicate_tool = evidence_store.reserve(
                invocation_id=runtime.dispatches[0].invocation_id,
                expected_agent_key="evidence-agent",
                tool_name="cloud_monitoring_query",
                service_id="svc_00000000000000000000000000",
                arguments_hash=f"sha256:{'2' * 64}",
                input_bytes=64,
                otel_span_id="0000000000000003",
            )
        assert duplicate_tool.existing_evidence_id == evidence_id
        with connection.transaction():
            final_allowed_cached_call = evidence_store.reserve(
                invocation_id=runtime.dispatches[0].invocation_id,
                expected_agent_key="evidence-agent",
                tool_name="cloud_monitoring_query",
                service_id="svc_00000000000000000000000000",
                arguments_hash=f"sha256:{'2' * 64}",
                input_bytes=64,
                otel_span_id="0000000000000004",
            )
        assert final_allowed_cached_call.existing_evidence_id == evidence_id
        with (
            connection.transaction(),
            pytest.raises(RuntimeError, match="tool-call budget is exhausted"),
        ):
            evidence_store.reserve(
                invocation_id=runtime.dispatches[0].invocation_id,
                expected_agent_key="evidence-agent",
                tool_name="cloud_monitoring_query",
                service_id="svc_00000000000000000000000000",
                arguments_hash=f"sha256:{'2' * 64}",
                input_bytes=64,
                otel_span_id="0000000000000005",
            )
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT request_count FROM solvan.tool_calls WHERE id = %s",
                (tool_reservation.call_id,),
            )
            assert cursor.fetchone() == (3,)
        completion = AgentCompletion(
            agent_resource=runtime.dispatches[0].agent_resource,
            agent_revision=runtime.dispatches[0].agent_revision,
            invocation_id=runtime.dispatches[0].invocation_id,
            incident_id=INVESTIGATION_INCIDENT_ID,
            workflow_version=authority.workflow_version,
            input_scope_hash=runtime.dispatches[0].input_hash,
            output_ref="gs://runtime/agent-result.json",
            output_hash="sha256:agent-result",
            output_size_bytes=1_024,
            semantic_status=AgentSemanticStatus.SUCCEEDED,
            summary="5xx ratio increased after connection checkout saturation.",
            evidence_refs=(evidence_id,),
            findings=(
                FindingCommit(
                    finding_key="payments-5xx-elevated",
                    kind=FindingKind.OBSERVATION,
                    statement="The bounded 5xx ratio exceeded the approved threshold.",
                    evidence_refs=(evidence_id,),
                ),
            ),
            completed_at=datetime.now(UTC),
            trace_id=runtime.dispatches[0].trace_id,
        )
        result_coordinator = AgentResultCoordinator(PostgresInvestigationResultStore(connection))
        applied = result_coordinator.complete(
            scope=SCOPE,
            authority=authority,
            completion=completion,
        )
        duplicate_result = result_coordinator.complete(
            scope=SCOPE,
            authority=authority,
            completion=completion,
        )
        assert applied.disposition.value == "APPLIED"
        assert duplicate_result.disposition.value == "DUPLICATE"
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT r.status, s.status, p.status, f.statement,
                    fe.relationship
                  FROM solvan.agent_runs r
                  JOIN solvan.investigation_steps s ON s.current_agent_run_id = r.id
                  JOIN solvan.investigation_plans p ON p.id = s.plan_id
                  JOIN solvan.findings f ON f.agent_run_id = r.id
                  JOIN solvan.finding_evidence fe ON fe.finding_id = f.id
                  WHERE r.id = %s""",
                (runtime.dispatches[0].run_id,),
            )
            result_row = cursor.fetchone()
        assert result_row == (
            "SUCCEEDED",
            "SUCCEEDED",
            "COMPLETED",
            "The bounded 5xx ratio exceeded the approved threshold.",
            "SUPPORTS",
        )
        with connection.transaction():
            workflow_store.release_lease(scope=SCOPE, lease=lease)


@pytest.mark.parametrize(
    ("boundary", "suffix", "expected_provider_calls"),
    [
        ("after-created-before-provider", "20", 0),
        ("after-provider-acceptance", "21", 1),
    ],
)
def test_sigkill_runtime_dispatch_fences_created_attempt_and_provider_call_count(
    boundary: str,
    suffix: str,
    expected_provider_calls: int,
) -> None:
    assert DATABASE_URL is not None
    incident_id = f"inc_000000000000000000000000{suffix}"
    supervisor_id = f"run_000000000000000000000000{suffix}"
    marker = f"runtime-kill-{suffix}"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_investigation_run(
            connection,
            incident_id=incident_id,
            supervisor_run_id=supervisor_id,
            display_id=f"INC-10{suffix}",
            deduplication_key=f"runtime-kill-{suffix}",
        )
        workflow = PostgresWorkflowStore(connection)
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner=f"runtime-kill-coordinator-{suffix}",
            )
        assert lease is not None
        authority = CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version)
        base = investigation_proposal()
        proposal = replace(
            base,
            steps=(replace(base.steps[0], fallback_ref="strategy://read-only-once"),),
        )
        coordinator = InvestigationCoordinator(
            PostgresInvestigationStore(connection),
            InspectingRuntime(),
            seed_investigation_catalog(connection),
        )
        coordinator.accept_supervisor_plan(
            scope=SCOPE,
            incident_id=incident_id,
            supervisor_run_id=supervisor_id,
            authority=authority,
            proposal=proposal,
            policy=investigation_policy(),
        )
        killed = subprocess.run(
            [
                sys.executable,
                "tools/runtime_dispatch_crash_fixture.py",
                "--database-url",
                DATABASE_URL,
                "--organization-id",
                SCOPE.organization_id,
                "--project-id",
                SCOPE.project_id,
                "--environment-id",
                SCOPE.environment_id,
                "--incident-id",
                incident_id,
                "--owner",
                lease.owner,
                "--lease-token",
                str(lease.token),
                "--workflow-version",
                str(lease.workflow_version),
                "--boundary",
                boundary,
                "--marker",
                marker,
            ],
            cwd=os.getcwd(),
            check=False,
        )
        assert killed.returncode == -signal.SIGKILL
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, status FROM solvan.agent_runs
                  WHERE incident_id = %s AND investigation_step_id IS NOT NULL""",
                (incident_id,),
            )
            first_run_id, first_status = cursor.fetchone()
            assert first_status == "CREATED"
            cursor.execute(
                """SELECT count(*) FROM solvan.fixture_admin_actions
                  WHERE idempotency_key = %s""",
                (marker,),
            )
            assert cursor.fetchone() == (expected_provider_calls,)
            cursor.execute(
                """UPDATE solvan.agent_runs SET deadline = now() - interval '2 minutes'
                  WHERE id = %s""",
                (first_run_id,),
            )
        connection.commit()
        store = PostgresInvestigationStore(connection)
        with store.transaction():
            retry = store.reserve_ready_dispatches(
                scope=SCOPE,
                incident_id=incident_id,
                authority=authority,
                batch_size=1,
            )[0]
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT attempt, status FROM solvan.agent_runs
                  WHERE incident_id = %s AND investigation_step_id IS NOT NULL
                  ORDER BY attempt""",
                (incident_id,),
            )
            attempts = cursor.fetchall()
            cursor.execute(
                """SELECT count(*) FROM solvan.fixture_admin_actions
                  WHERE idempotency_key = %s""",
                (marker,),
            )
            provider_calls = cursor.fetchone()[0]
        assert attempts == [(1, "TIMED_OUT"), (2, "CREATED")]
        assert retry.run_id != first_run_id
        assert provider_calls == expected_provider_calls
        with workflow.transaction():
            workflow.release_lease(scope=SCOPE, lease=lease)


def test_new_supervisor_plan_supersedes_and_fences_live_plan_attempts() -> None:
    assert DATABASE_URL is not None
    incident_id = "inc_00000000000000000000000008"
    first_supervisor = "run_00000000000000000000000008"
    second_supervisor = "run_00000000000000000000000009"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit)
                  VALUES (%s, %s, %s, %s, 'INC-1008', '1', 'INVESTIGATING',
                    'SEV2', 'connection_exhaustion',
                    'svc_00000000000000000000000000',
                    'pgs_00000000000000000000000000', now(),
                    'payments-http-5xx', 1, 'plan-supersede-test', 2, 1)
                  ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
            for attempt, run_id in enumerate((first_supervisor, second_supervisor), start=1):
                cursor.execute(
                    """INSERT INTO solvan.agent_runs
                      (organization_id, project_id, environment_id, id, incident_id,
                       logical_step_key, agent_key, agent_resource, agent_revision,
                       invocation_id, workflow_version, attempt, status, deadline,
                       budget_json, input_ref, input_hash, started_at, completed_at)
                      SELECT %s, %s, %s, %s, %s, %s, 'incident-supervisor',
                        'projects/test/locations/europe-west1/reasoningEngines/supervisor-v1',
                        'supervisor-20260808-01', %s, workflow_version, %s,
                        'SUCCEEDED', now() + interval '5 minutes', '{}',
                        'fixture://supervisor', %s, now(), now()
                      FROM solvan.incidents WHERE organization_id = %s
                        AND project_id = %s AND environment_id = %s AND id = %s
                      ON CONFLICT DO NOTHING""",
                    (
                        SCOPE.organization_id,
                        SCOPE.project_id,
                        SCOPE.environment_id,
                        run_id,
                        incident_id,
                        f"incident:plan:supersede:{attempt}",
                        f"inv-supervisor-supersede-{attempt}",
                        attempt,
                        f"sha256:supervisor-{attempt}",
                        SCOPE.organization_id,
                        SCOPE.project_id,
                        SCOPE.environment_id,
                        incident_id,
                    ),
                )
        connection.commit()
        workflow = PostgresWorkflowStore(connection)
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner="plan-supersede-coordinator",
            )
        assert lease is not None
        authority = CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version)
        store = PostgresInvestigationStore(connection)
        coordinator = InvestigationCoordinator(
            store, InspectingRuntime(), seed_investigation_catalog(connection)
        )
        first = coordinator.accept_supervisor_plan(
            scope=SCOPE,
            incident_id=incident_id,
            supervisor_run_id=first_supervisor,
            authority=authority,
            proposal=investigation_proposal(),
            policy=investigation_policy(),
        )
        with store.transaction():
            first_dispatch = store.reserve_ready_dispatches(
                scope=SCOPE,
                incident_id=incident_id,
                authority=authority,
                batch_size=1,
            )[0]
        second = coordinator.accept_supervisor_plan(
            scope=SCOPE,
            incident_id=incident_id,
            supervisor_run_id=second_supervisor,
            authority=authority,
            proposal=investigation_proposal(purpose="replan after contradictory evidence"),
            policy=investigation_policy(),
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, plan_version, status, supersedes_id
                  FROM solvan.investigation_plans WHERE incident_id = %s
                  ORDER BY plan_version""",
                (incident_id,),
            )
            plans = cursor.fetchall()
            cursor.execute(
                """SELECT s.status, r.status, r.error_class
                  FROM solvan.investigation_steps s
                  JOIN solvan.agent_runs r ON r.id = s.current_agent_run_id
                  WHERE s.plan_id = %s""",
                (first.plan_id,),
            )
            stale_attempt = cursor.fetchone()
        assert plans == [
            (first.plan_id, 1, "SUPERSEDED", None),
            (second.plan_id, 2, "ACCEPTED", first.plan_id),
        ]
        assert stale_attempt == ("STALE", "STALE", "PLAN_SUPERSEDED")
        assert first_dispatch.plan_id == first.plan_id
        with workflow.transaction():
            workflow.release_lease(scope=SCOPE, lease=lease)


def test_declared_agent_fallback_is_attempted_once_after_dispatch_failure() -> None:
    assert DATABASE_URL is not None
    incident_id = "inc_00000000000000000000000010"
    supervisor_id = "run_00000000000000000000000010"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit)
                  VALUES (%s, %s, %s, %s, 'INC-1010', '1', 'INVESTIGATING',
                    'SEV2', 'connection_exhaustion',
                    'svc_00000000000000000000000000',
                    'pgs_00000000000000000000000000', now(),
                    'payments-http-5xx', 1, 'fallback-dispatch-test', 2, 1)""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, incident_id,
                   logical_step_key, agent_key, agent_resource, agent_revision,
                   invocation_id, workflow_version, attempt, status, deadline,
                   budget_json, input_ref, input_hash, started_at, completed_at)
                  VALUES (%s, %s, %s, %s, %s, 'incident:fallback:supervisor:1',
                    'incident-supervisor',
                    'projects/test/locations/europe-west1/reasoningEngines/supervisor-v1',
                    'supervisor-20260808-01', 'inv-fallback-supervisor-1', 1, 1,
                    'SUCCEEDED', now() + interval '5 minutes', '{}',
                    'fixture://supervisor', 'sha256:fallback-supervisor', now(), now())""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    supervisor_id,
                    incident_id,
                ),
            )
        connection.commit()
        workflow = PostgresWorkflowStore(connection)
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner="fallback-test-coordinator",
            )
        assert lease is not None
        authority = CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version)
        base = investigation_proposal()
        proposal = replace(
            base,
            steps=(replace(base.steps[0], fallback_ref="strategy://preserve-evidence-once"),),
        )
        runtime = FailOnceRuntime()
        coordinator = InvestigationCoordinator(
            PostgresInvestigationStore(connection),
            runtime,
            seed_investigation_catalog(connection),
        )
        coordinator.accept_supervisor_plan(
            scope=SCOPE,
            incident_id=incident_id,
            supervisor_run_id=supervisor_id,
            authority=authority,
            proposal=proposal,
            policy=investigation_policy(),
        )
        outcomes = coordinator.dispatch_ready_steps(
            scope=SCOPE,
            incident_id=incident_id,
            authority=authority,
        )
        assert [item.status.value for item in outcomes] == ["FAILED"]
        assert len(runtime.dispatches) == 1
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT s.status, s.current_agent_run_id, s.retry_not_before > now()
                  FROM solvan.investigation_steps s
                  JOIN solvan.investigation_plans p ON p.id = s.plan_id
                  WHERE p.incident_id = %s""",
                (incident_id,),
            )
            assert cursor.fetchone() == ("READY", None, True)
            # The production contract requires a durable retry backoff. Advance
            # only this fixture's retry fence rather than weakening that policy
            # or sleeping in the canonical contract lane.
            cursor.execute(
                """UPDATE solvan.investigation_steps s SET retry_not_before = now()
                  FROM solvan.investigation_plans p
                  WHERE p.id = s.plan_id AND p.incident_id = %s""",
                (incident_id,),
            )
        connection.commit()
        outcomes = coordinator.dispatch_ready_steps(
            scope=SCOPE,
            incident_id=incident_id,
            authority=authority,
        )
        assert [item.status.value for item in outcomes] == ["DISPATCHED"]
        assert len(runtime.dispatches) == 2
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT r.attempt, r.status, s.status, s.current_agent_run_id = r.id
                  FROM solvan.agent_runs r
                  JOIN solvan.investigation_steps s ON s.id = r.investigation_step_id
                  WHERE r.incident_id = %s ORDER BY r.attempt""",
                (incident_id,),
            )
            assert cursor.fetchall() == [
                (1, "FAILED", "DISPATCHED", False),
                (2, "DISPATCHED", "DISPATCHED", True),
            ]
        with workflow.transaction():
            workflow.release_lease(scope=SCOPE, lease=lease)


def test_mitigated_incident_opens_one_case_and_due_wakeup_is_fenced() -> None:
    assert DATABASE_URL is not None
    incident_id = "inc_00000000000000000000000003"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit)
                  VALUES (%s, %s, %s, %s, 'INC-1003', '1', 'MITIGATED', 'SEV2',
                    'connection_exhaustion', 'svc_00000000000000000000000000',
                    'pgs_00000000000000000000000000', now(), 'payments-http-5xx', 1,
                    'case-opening-test', 2, 1)""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
        connection.commit()
        workflow_store = PostgresWorkflowStore(connection)
        incident_lease = workflow_store.acquire_lease(
            scope=SCOPE,
            aggregate_type=AggregateType.INCIDENT,
            entity_id=incident_id,
            owner="case-coordinator",
        )
        assert incident_lease is not None
        connection.commit()
        authority = CoordinatorAuthority(
            incident_lease.owner,
            incident_lease.token,
            incident_lease.workflow_version,
        )
        store = PostgresReliabilityCaseStore(connection)
        coordinator = ReliabilityCaseCoordinator(store)
        schedule = CaseSchedule(
            logical_step_key="case:start-rca:1",
            next_action_kind="START_RCA",
            wake_at=datetime.now(UTC) - timedelta(seconds=1),
            reason="mitigation verified; permanent repair remains",
        )
        created = coordinator.open_for_mitigated_incident(
            scope=SCOPE,
            incident_id=incident_id,
            authority=authority,
            schedule=schedule,
        )
        duplicate = coordinator.open_for_mitigated_incident(
            scope=SCOPE,
            incident_id=incident_id,
            authority=authority,
            schedule=schedule,
        )
        assert created.created
        assert not duplicate.created
        assert created.case_id == duplicate.case_id

        claims = store.claim_due_wakeups(
            scope=SCOPE,
            owner="case-coordinator",
            claim_ttl_ms=10_000,
        )
        connection.commit()
        claim = next(item for item in claims if item.wakeup_id == created.wakeup_id)
        extended = store.heartbeat_wakeup(
            scope=SCOPE,
            owner="case-coordinator",
            claim=claim,
            claim_ttl_ms=20_000,
        )
        connection.commit()
        assert extended > claim.claim_expires_at

        case_lease = workflow_store.acquire_lease(
            scope=SCOPE,
            aggregate_type=AggregateType.RELIABILITY_CASE,
            entity_id=created.case_id,
            owner="case-coordinator",
        )
        assert case_lease is not None
        connection.commit()
        outbox_id = store.complete_wakeup(
            scope=SCOPE,
            owner="case-coordinator",
            claim=claim,
        )
        connection.commit()
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT c.state, w.status, w.outbox_event_id, o.event_type
                  FROM solvan.reliability_cases c
                  JOIN solvan.scheduled_wakeups w ON w.case_id = c.id
                  JOIN solvan.outbox_events o ON o.id = w.outbox_event_id
                  WHERE c.id = %s""",
                (created.case_id,),
            )
            assert cursor.fetchone() == (
                "OPEN",
                "COMPLETED",
                outbox_id,
                "ReliabilityCaseWakeupDue",
            )
        with store.transaction():
            to_version, next_wakeup_id = store.commit_progress_transition(
                scope=SCOPE,
                lease=case_lease,
                transition=TransitionWrite(
                    from_state="OPEN",
                    to_state="ROOT_CAUSE_ANALYSIS",
                    transition_key="rca-started-after-wakeup",
                    actor_type="COORDINATOR",
                    actor_id="case-coordinator",
                    reason_code="RCA_STARTED",
                    rationale_summary="Due wakeup resumed the next bounded case step",
                ),
                schedule=CaseSchedule(
                    logical_step_key="case:continue-rca:2",
                    next_action_kind="CONTINUE_RCA",
                    wake_at=datetime.now(UTC) + timedelta(days=1),
                    reason="continue after independent provider attempt",
                ),
            )
        assert to_version == 2
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT c.state, c.workflow_version, c.next_action_kind,
                    w.status, w.wake_at::date > current_date
                  FROM solvan.reliability_cases c
                  JOIN solvan.scheduled_wakeups w ON w.case_id = c.id
                  WHERE c.id = %s AND w.id = %s""",
                (created.case_id, next_wakeup_id),
            )
            assert cursor.fetchone() == (
                "ROOT_CAUSE_ANALYSIS",
                2,
                "CONTINUE_RCA",
                "PENDING",
                True,
            )


@pytest.mark.parametrize(
    ("review_decision", "id_suffix", "display_suffix"),
    [("APPROVE", "04", "1004"), ("CHANGES_REQUESTED", "05", "1005")],
)
def test_exact_repair_plan_workspace_attempt_and_patch_receipt_are_durable(
    review_decision: str, id_suffix: str, display_suffix: str
) -> None:
    assert DATABASE_URL is not None
    incident_id = f"inc_000000000000000000000000{id_suffix}"
    case_id = f"rel_000000000000000000000000{id_suffix}"
    hypothesis_id = f"hyp_000000000000000000000000{id_suffix}"
    repository_node_id = "pgn_00000000000000000000000004"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        scope_values = (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.confirmation_rules
                  (organization_id, project_id, environment_id, id, version,
                   incident_class, required_observations_json,
                   contradiction_policy, status)
                  VALUES (%s, %s, %s, 'repair-confirmation', 1,
                    'connection_exhaustion', '[]', 'ESCALATE', 'DRAFT')
                  ON CONFLICT DO NOTHING""",
                scope_values,
            )
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit, confirmed_root_cause_id)
                  VALUES (%s, %s, %s, %s, %s, '1', 'MITIGATED', 'SEV2',
                    'connection_exhaustion', 'svc_00000000000000000000000000',
                    'pgs_00000000000000000000000000', now(),
                    'payments-http-5xx', 1, %s, 2, 1, %s)""",
                (
                    *scope_values,
                    incident_id,
                    f"INC-{display_suffix}",
                    f"repair-store-test-{id_suffix}",
                    hypothesis_id,
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.hypotheses
                  (organization_id, project_id, environment_id, id, incident_id,
                   statement, normalized_cause_key, revision, status,
                   supporting_evidence_refs, contradicting_evidence_refs,
                   confidence_score, confirmation_rule_id,
                   confirmation_rule_version, confirmed_at)
                  VALUES (%s, %s, %s, %s, %s,
                    'Leaked checkouts exhaust the bounded connection pool.',
                    'payments-connection-leak', 1, 'CONFIRMED',
                    %s, '[]', 0.99,
                    'repair-confirmation', 1, now())""",
                (
                    *scope_values,
                    hypothesis_id,
                    incident_id,
                    psycopg.types.json.Jsonb([f"evd_000000000000000000000000{id_suffix}"]),
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.reliability_cases
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, originating_incident_id,
                   next_action_kind, next_action_at)
                  VALUES (%s, %s, %s, %s, %s, '1',
                    'ROOT_CAUSE_ANALYSIS', %s, 'DEFINE_REPAIR', now())""",
                (*scope_values, case_id, f"REL-{display_suffix}", incident_id),
            )
            cursor.execute(
                """UPDATE solvan.incidents SET reliability_case_id = %s
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (case_id, *scope_values, incident_id),
            )
            repository_policy = {
                "repository_binding_id": REPOSITORY_BINDING_ID,
                "repository_snapshot_uri": "gs://runtime/repositories/payments.json",
                "repository_snapshot_hash": f"sha256:{'a' * 64}",
                "base_commit_sha": "b" * 40,
                "reproduction_command_definition_id": (REPRODUCTION_COMMAND_DEFINITION_ID),
                "regression_command_definition_id": REGRESSION_COMMAND_DEFINITION_ID,
                "allowed_file_globs": ["src/*.py", "tests/*.py"],
                "artifact_output_uri": "gs://runtime/repairs/REL-1004",
                "provider": "GEMINI_ADK_AGENT_ENGINE",
            }
            seed_repair_command_authority(
                cursor,
                scope_values={
                    "organization_id": SCOPE.organization_id,
                    "project_id": SCOPE.project_id,
                    "environment_id": SCOPE.environment_id,
                },
                approved_by="user:repair-store-test@example.com",
                repository_policy=repository_policy,
            )
            cursor.execute(
                """INSERT INTO solvan.production_graph_nodes
                  (organization_id, project_id, environment_id, id, snapshot_id,
                   node_key, node_kind, resource_ref, external_project_id, classification,
                   provenance_ref, attributes_json)
                  VALUES (%s, %s, %s, %s,
                    'pgs_00000000000000000000000000', %s,
                    'REPOSITORY', 'gs://runtime/repositories/payments.json', NULL,
                    'INTERNAL', 'fixture://repository-policy', %s)
                  ON CONFLICT DO NOTHING""",
                (
                    *scope_values,
                    repository_node_id,
                    "payments-repository-test",
                    psycopg.types.json.Jsonb(repository_policy),
                ),
            )
        connection.commit()
        workflow = PostgresWorkflowStore(connection)
        repair_store = PostgresRepairStore(connection)
        runs = PostgresRuntimeRunStore(connection)
        with connection.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.RELIABILITY_CASE,
                entity_id=case_id,
                owner="repair-store-test",
            )
        assert lease is not None
        with connection.transaction():
            plan = repair_store.define_exact_plan(scope=SCOPE, lease=lease)
            duplicate = repair_store.define_exact_plan(scope=SCOPE, lease=lease)
        assert plan.created and not duplicate.created
        assert plan.repair_plan_id == duplicate.repair_plan_id
        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.reliability_cases SET state = 'REPAIR_PLANNED'
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (*scope_values, case_id),
            )
        connection.commit()
        workspace_store = PostgresWorkspaceStore(connection)
        policy_id = f"pol_000000000000000000000000{id_suffix}"
        workspace_id = f"wsp_000000000000000000000000{id_suffix}"
        with connection.transaction():
            workspace_store.record_provider_eligibility(
                scope=SCOPE,
                decision_id=policy_id,
                policy_version="regional-adk-v1",
                input_ref=f"gs://runtime/workspaces/{workspace_id}/eligibility-input.json",
                input_hash=f"sha256:{'1' * 64}",
                decision="ALLOW",
                reason_code="REGIONAL_ADK_POLICY_MATCH",
                receipt_ref=f"gs://runtime/workspaces/{workspace_id}/eligibility.json",
                receipt_hash=f"sha256:{'2' * 64}",
            )
            workspace = workspace_store.open(
                WorkspaceSpec(
                    scope=SCOPE,
                    workspace_id=workspace_id,
                    kind=WorkspaceKind.INCIDENT,
                    service_id="svc_00000000000000000000000000",
                    reliability_case_id=case_id,
                    provider=WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE,
                    implementation_sdk="google-adk",
                    implementation_sdk_version="2.7.1",
                    provider_revision="release-1",
                    registry_agent_key="workspace-agent",
                    provider_agent_resource=(
                        "projects/123456789/locations/europe-west1/reasoningEngines/workspace-v1"
                    ),
                    provider_service_identity=(
                        "serviceAccount:workspace@solvan-test.iam.gserviceaccount.com"
                    ),
                    implementation_sdk_distribution_hash=f"sha256:{'3' * 64}",
                    provider_artifact_digest=f"sha256:{'4' * 64}",
                    effective_network_policy_hash=f"sha256:{'5' * 64}",
                    classification=WorkspaceClassification.INTERNAL,
                    synthetic=False,
                    provider_eligibility_decision_id=policy_id,
                    artifact_prefix=f"gs://runtime/workspaces/{workspace_id}/",
                    input_manifest_ref=(
                        f"gs://runtime/workspaces/{workspace_id}/input-manifest.json"
                    ),
                    input_manifest_hash=f"sha256:{'6' * 64}",
                    created_by_principal=(
                        "serviceAccount:coordinator@solvan-test.iam.gserviceaccount.com"
                    ),
                )
            )
        with connection.transaction():
            command_catalog = PostgresWorkspaceRepairStore(connection).materialize_command_catalog(
                scope=SCOPE,
                repair_plan_id=plan.repair_plan_id,
                repair_plan_version=plan.plan_version,
                repository_node_id=plan.repository_node_id,
                base_tree=CandidateTree(
                    (
                        CandidateFile("src/a.py", "x=1\n"),
                        CandidateFile("tests/test_a.py", "def test_a(): assert True\n"),
                    ),
                    ("src/*.py", "tests/*.py"),
                ),
            )
            tool_refs = tuple(
                ToolRevisionRefV1(tool_key=key, version="1")
                for key in (
                    "workspace.code-repair.read-artifact",
                    "workspace.code-repair.write-candidate-artifact",
                    "workspace.code-repair.run-in-sandbox",
                )
            )
            effective_tool_set = EffectiveToolSetV1(
                profile_material_hash=f"sha256:{'9' * 64}",
                accepted_tools=tool_refs,
                agent_key="workspace-agent",
                agent_revision="release-1",
                scope=SCOPE.canonical_dict(),
                connection_bindings=tuple(
                    EffectiveToolBindingV1(
                        binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
                        tool=tool,
                    )
                    for tool in tool_refs
                ),
                runtime_region="europe-west1",
                accepted_data_classification="INTERNAL",
                classification_ceiling="INTERNAL",
                policy_head_epoch=0,
                placement_epoch=1,
                accepted_step_budget_hash=accepted_step_budget_hash(
                    workspace_repair_budget(synthetic_provider=False)
                ),
            )
            dispatch = runs.reserve_workspace_repair(
                scope=SCOPE,
                lease=lease,
                plan=plan,
                workspace=workspace,
                repository_files=[
                    {
                        "path": "src/a.py",
                        "content": "x=1\n",
                        "content_hash": (
                            "sha256:98752ee28d5484bdc2814fb70adb6a0b2fb31f6a9b8ee7ae81fd2fc9cf300b3b"
                        ),
                    }
                ],
                agent_resource=(
                    "projects/123456789/locations/europe-west1/reasoningEngines/workspace-v1"
                ),
                agent_revision="release-1",
                effective_tool_set_hash=effective_tool_set.effective_tool_set_hash,
                effective_tool_set=effective_tool_set,
                effective_network_policy_hash=f"sha256:{'5' * 64}",
                command_catalog_ids=(
                    command_catalog.reproduction_command_id,
                    command_catalog.regression_command_id,
                ),
                command_catalog_hash=command_catalog.catalog_hash,
            )
        assert dispatch is not None
        assert dispatch.workflow_version == lease.workflow_version + 1
        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.reliability_cases
                  SET state = 'REPAIR_IN_PROGRESS', workflow_version = %s,
                      lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (dispatch.workflow_version, *scope_values, case_id),
            )
        connection.commit()
        with connection.transaction():
            bind_test_agent_run(connection, run_id=dispatch.run_id, agent_key="workspace-agent")
            workspace_store.record_runtime_dispatch(
                dispatch,
                receipt=RuntimeInvocationReceipt(
                    "projects/123456789/locations/europe-west1/operations/workspace-1",
                    runtime_input_ref="gs://runtime/workspace-input.json",
                    runtime_output_ref="gs://runtime/workspace-output.json",
                ),
            )
            current_lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.RELIABILITY_CASE,
                entity_id=case_id,
                owner="repair-store-test",
            )
        assert current_lease is not None
        with connection.transaction():
            material = repair_store.workspace_attempt(
                scope=SCOPE, lease=current_lease, run_id=dispatch.run_id
            )
            artifact_id = repair_store.persist_patch_artifact(
                scope=SCOPE,
                lease=current_lease,
                material=material,
                sandbox_resource=(
                    "projects/123456789/locations/europe-west1/reasoningEngines/"
                    "workspace-v1/sandboxes/test-1"
                ),
                unified_diff_ref="gs://runtime/repair.patch",
                unified_diff_hash=f"sha256:{'d' * 64}",
                changed_paths=("src/a.py",),
                cognition_ref="gs://runtime/cognition.json",
                cognition_hash=f"sha256:{'c' * 64}",
                mechanism="A connection is not returned on the exceptional path.",
                hypotheses=(
                    {
                        "hypothesis_key": "connection-leak",
                        "statement": "The exception path leaks a connection.",
                        "supporting_citations": ["src/a.py:10"],
                        "contradicting_citations": ["src/a.py:30"],
                        "leading": True,
                    },
                    {
                        "hypothesis_key": "pool-capacity",
                        "statement": "Configured capacity is too small.",
                        "supporting_citations": ["config/pool.yaml:2"],
                        "contradicting_citations": ["tests/load.json"],
                        "leading": False,
                    },
                ),
                reproduction_exit_code=1,
                reproduction_output_ref="gs://runtime/reproduction-output.txt",
                reproduction_output_hash=f"sha256:{'b' * 64}",
                test_exit_code=0,
                test_output_ref="gs://runtime/test-output.txt",
                test_output_hash=f"sha256:{'e' * 64}",
                residual_risks=(),
                provider_output_hash=f"sha256:{'f' * 64}",
                provider_boot_hash=f"sha256:{'a' * 64}",
                provider_service_revision="workspace-v1",
            )
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT p.status, r.status, r.output_ref
                  FROM solvan.patch_artifacts p JOIN solvan.agent_runs r
                    ON r.id = p.agent_run_id WHERE p.id = %s""",
                (artifact_id,),
            )
            assert cursor.fetchone() == (
                "TESTS_PASSED",
                "SUCCEEDED",
                "gs://runtime/workspace-output.json",
            )
            cursor.execute(
                """INSERT INTO solvan.actor_role_bindings
                  (organization_id, project_id, environment_id, principal,
                   role, granted_by)
                  VALUES (%s, %s, %s, 'user:reviewer@example.com',
                    'CODE_CHANGE_APPROVER', 'user:admin@example.com') ON CONFLICT DO NOTHING""",
                scope_values,
            )
            cursor.execute(
                """UPDATE solvan.reliability_cases
                  SET state = 'AWAITING_REVIEW', next_action_kind = 'REVIEW_PATCH',
                      next_action_at = now()
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (*scope_values, case_id),
            )
            cursor.execute(
                """INSERT INTO solvan.scheduled_wakeups
                  (organization_id, project_id, environment_id, id, case_id,
                   logical_step_key, wake_at, reason)
                  VALUES (%s, %s, %s, %s, %s,
                        %s, now(), 'review exact patch')""",
                (
                    *scope_values,
                    f"wak_000000000000000000000000{id_suffix}",
                    case_id,
                    f"case:repair-review-test-{id_suffix}",
                ),
            )
        connection.commit()
        reviews = PostgresPatchReviewStore(connection)
        with connection.transaction():
            review_material = reviews.review(scope=SCOPE, patch_artifact_id=artifact_id)
            review = reviews.decide(
                scope=SCOPE,
                patch_artifact_id=artifact_id,
                reviewer_principal="user:reviewer@example.com",
                expected_patch_digest=review_material.patch_digest,
                decision=review_decision,
                reason="Exact patch and sandbox test receipt reviewed.",
                decision_request_id=f"patch-review-integration-{id_suffix}",
            )
            duplicate_review = reviews.decide(
                scope=SCOPE,
                patch_artifact_id=artifact_id,
                reviewer_principal="user:reviewer@example.com",
                expected_patch_digest=review_material.patch_digest,
                decision=review_decision,
                reason="Exact patch and sandbox test receipt reviewed.",
                decision_request_id=f"patch-review-integration-{id_suffix}",
            )
        assert review.created and not duplicate_review.created
        with connection.transaction():
            decision = reviews.decision_for_apply(
                scope=SCOPE, lease=current_lease, review_id=review.review_id
            )
            reviews.mark_applied(scope=SCOPE, lease=current_lease, review_id=review.review_id)
            case_store = PostgresReliabilityCaseStore(connection)
            case_store.complete_active_wakeup_for_transition(scope=SCOPE, lease=current_lease)
            case_store.commit_progress_transition(
                scope=SCOPE,
                lease=current_lease,
                transition=TransitionWrite(
                    from_state="AWAITING_REVIEW",
                    to_state=(
                        "READY_FOR_CANARY" if review_decision == "APPROVE" else "REPAIR_IN_PROGRESS"
                    ),
                    transition_key=f"{review_decision}:{review.review_id}",
                    actor_type="HUMAN",
                    actor_id=decision.reviewer_principal,
                    reason_code=f"AUTHENTICATED_{review_decision}",
                    rationale_summary="Exact digest-bound patch review applied.",
                ),
                schedule=CaseSchedule(
                    logical_step_key=f"case:review-continuation-{id_suffix}",
                    next_action_kind=(
                        "PREPARE_CANARY" if review_decision == "APPROVE" else "REPLAN_REPAIR"
                    ),
                    wake_at=datetime.now(UTC),
                    reason="prepare exact canary",
                ),
            )
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT c.state, r.applied_at IS NOT NULL
                  FROM solvan.reliability_cases c JOIN solvan.patch_reviews r
                    ON r.reliability_case_id = c.id
                  WHERE c.id = %s AND r.id = %s""",
                (case_id, review.review_id),
            )
            assert cursor.fetchone() == (
                "READY_FOR_CANARY" if review_decision == "APPROVE" else "REPAIR_IN_PROGRESS",
                True,
            )
        if review_decision == "CHANGES_REQUESTED":
            with connection.transaction():
                workflow.release_lease(scope=SCOPE, lease=current_lease)
                replan_lease = workflow.acquire_lease(
                    scope=SCOPE,
                    aggregate_type=AggregateType.RELIABILITY_CASE,
                    entity_id=case_id,
                    owner="repair-store-replan-test",
                )
            assert replan_lease is not None
            with connection.transaction():
                successor = repair_store.replan_after_requested_changes(
                    scope=SCOPE, lease=replan_lease
                )
            assert successor.plan_version == 2
            assert successor.created
            assert f"db://solvan/patch-reviews/{review.review_id}" in successor.evidence_refs
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT plan_version, status, supersedes_id
                      FROM solvan.repair_plans WHERE reliability_case_id = %s
                      ORDER BY plan_version""",
                    (case_id,),
                )
                assert cursor.fetchall() == [
                    (1, "SUPERSEDED", None),
                    (2, "ACTIVE", plan.repair_plan_id),
                ]


def seed_actions(connection: psycopg.Connection[object]) -> None:
    seed_incident(connection)
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT workflow_version, evidence_version FROM solvan.incidents
              WHERE id = 'inc_00000000000000000000000000'"""
        )
        incident_versions = cursor.fetchone()
        assert incident_versions is not None
        workflow_version, evidence_version = incident_versions
        cursor.execute(
            """INSERT INTO solvan.verification_profiles
              (organization_id, project_id, environment_id, id, version, status,
               owner, warmup_ms, observation_ms, required_signals_json,
               guardrails_json, inconclusive_policy, content_hash, approved_by,
               approved_at)
              VALUES (%s, %s, %s, 'payments-recovery', 1, 'APPROVED', 'payments',
                1000, 60000, '[]', '[]', 'ESCALATE', 'sha256:profile', 'owner', now())
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.policy_decisions
              (organization_id, project_id, environment_id, id, policy_kind,
               policy_version, input_hash, decision, reason_code)
              VALUES (%s, %s, %s, 'pol_00000000000000000000000000',
                'ACTION', 'policy-v1', 'sha256:input', 'REQUIRE_APPROVAL', 'HIGH_RISK')
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        for suffix, display in (("00", "ACT-1000"), ("01", "ACT-1001")):
            action_id = f"act_000000000000000000000000{suffix}"
            payload = freeze_json(
                {
                    "service_name": "projects/demo/locations/europe-west1/services/payments-api",
                    "known_good_revision": "revision-v0",
                    "percent": 100,
                }
            )
            expected_effect = derive_expected_effect(
                action_type=ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK,
                target_key="org/project/env/cloud-run/payments-api/deployment",
                expected_target_version="revision-v1",
                payload=payload,
            )
            cursor.execute(
                """INSERT INTO solvan.actions
                  (organization_id, project_id, environment_id, id, display_id,
                   incident_id, workflow_version, evidence_version, action_type,
                   normalized_signature, target_key, expected_target_version,
                   expected_target_epoch, payload_json, payload_digest,
                   expected_effect_json, expected_effect_hash, risk_class,
                   reversible, rollback_plan_json, verification_profile_id,
                   verification_profile_version, policy_decision_id,
                   proposer_principal, requires_approval, status, idempotency_key, expires_at)
                  VALUES (%s, %s, %s, %s, %s,
                    'inc_00000000000000000000000000', %s, %s,
                    'CLOUD_RUN_TRAFFIC_ROLLBACK', 'sha256:signature',
                    'org/project/env/cloud-run/payments-api/deployment', 'revision-v1',
                    0, %s, 'sha256:payload', %s, %s, 'HIGH', true, '{}',
                    'payments-recovery', 1, 'pol_00000000000000000000000000',
                    'user:proposer@example.com', true, 'AUTHORIZED', %s,
                    '2026-09-01 00:00:00+00')
                  ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    action_id,
                    display,
                    workflow_version,
                    evidence_version,
                    psycopg.types.json.Jsonb(dict(payload)),
                    psycopg.types.json.Jsonb(expected_effect.descriptor_object()),
                    expected_effect.content_hash,
                    f"action-idempotency-{suffix}",
                ),
            )
            material = AuthorizedActionMaterial(
                action_id=action_id,
                scope=SCOPE,
                owner_entity_id="inc_00000000000000000000000000",
                workflow_version=workflow_version,
                evidence_version=evidence_version,
                action_type=ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK,
                target_key="org/project/env/cloud-run/payments-api/deployment",
                expected_target_version="revision-v1",
                expected_target_epoch=0,
                payload=payload,
                expected_effect=expected_effect.descriptor,
                expected_effect_hash=expected_effect.content_hash,
                risk_class=RiskClass.HIGH,
                reversible=True,
                rollback_plan=freeze_json({}),
                policy_version="policy-v1",
                verification_profile_id="payments-recovery",
                verification_profile_version=1,
                expires_at=datetime(2026, 9, 1, tzinfo=UTC),
            )
            cursor.execute(
                """INSERT INTO solvan.approvals
                  (organization_id, project_id, environment_id, id, action_id,
                   sequence_no, action_digest, target_key, expected_target_version,
                   expected_target_epoch, evidence_version, policy_version,
                   approver_principal, decision, reason, decided_at, expires_at)
                  VALUES (%s, %s, %s, %s, %s, 1, %s,
                    'org/project/env/cloud-run/payments-api/deployment', 'revision-v1',
                    0, %s, 'policy-v1', 'user:approver@example.com', 'APPROVE',
                    'Fixture approval', '2026-08-08 00:00:00+00',
                    '2026-08-31 00:00:00+00')
                  ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    f"apr_000000000000000000000000{suffix}",
                    action_id,
                    material.approval_digest(),
                    evidence_version,
                ),
            )
        cursor.execute(
            """INSERT INTO solvan.actor_role_bindings
              (organization_id, project_id, environment_id, principal, role, granted_by)
              VALUES (%s, %s, %s, 'user:approver@example.com', 'APPROVER', 'admin')
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.target_epochs
              (organization_id, project_id, environment_id, target_key, epoch,
               last_observed_version)
              VALUES (%s, %s, %s,
                'org/project/env/cloud-run/payments-api/deployment', 0, 'revision-v1')
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
    connection.commit()


def execution_receipt(
    *, action_id: str, attempt: int, result: ExecutionResult, version: str | None
) -> ExecutionReceiptWrite:
    now = datetime.now(UTC) - timedelta(seconds=1)
    return ExecutionReceiptWrite(
        action_id=action_id,
        attempt=attempt,
        connector_request_id="connector-request-1",
        idempotency_key=f"receipt-{action_id}-{attempt}",
        before_state_ref="gs://receipt/before",
        after_state_ref=None if result is ExecutionResult.AMBIGUOUS else "gs://receipt/after",
        observed_target_version=version,
        started_at=now,
        connector_returned_at=now,
        reconciled_at=None if result is ExecutionResult.AMBIGUOUS else now,
        result=result,
        error_class="TIMEOUT" if result is ExecutionResult.AMBIGUOUS else None,
        actor_identity="spiffe://solvan/actuator",
        trace_id="trace-action-1",
    )


def test_target_reservation_serializes_and_ambiguity_stays_exclusive() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_actions(connection)
        store = PostgresActionStore(connection)
        first_action = "act_00000000000000000000000000"
        second_action = "act_00000000000000000000000001"
        reservation = store.acquire_reservation(
            scope=SCOPE,
            action_id=first_action,
            owner_identity="spiffe://solvan/actuator",
            ttl_ms=10_000,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.incidents SET evidence_version = evidence_version + 1
                  WHERE id = 'inc_00000000000000000000000000'"""
            )
        connection.commit()
        with pytest.raises(ActionPolicyError, match="evidence_version_stale"):
            store.authorize_for_execution(scope=SCOPE, reservation=reservation)
        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.incidents SET evidence_version = evidence_version - 1
                  WHERE id = 'inc_00000000000000000000000000'"""
            )
        connection.commit()
        authority = store.authorize_for_execution(scope=SCOPE, reservation=reservation)
        assert authority.material.action_id == first_action

        stale = replace(reservation, lease_token=uuid4())
        with pytest.raises(ReservationLost):
            store.heartbeat(scope=SCOPE, reservation=stale, ttl_ms=10_000)
        connection.rollback()
        store.heartbeat(scope=SCOPE, reservation=reservation, ttl_ms=10_000)
        connection.commit()

        store.record_execution(
            scope=SCOPE,
            reservation=reservation,
            receipt=execution_receipt(
                action_id=first_action,
                attempt=1,
                result=ExecutionResult.AMBIGUOUS,
                version=None,
            ),
        )
        with pytest.raises(ReservationConflict, match="epoch changed"):
            store.acquire_reservation(
                scope=SCOPE,
                action_id=second_action,
                owner_identity="spiffe://solvan/actuator",
                ttl_ms=10_000,
            )
        with connection.cursor() as cursor:
            cursor.execute("SELECT status FROM solvan.actions WHERE id = %s", (second_action,))
            assert cursor.fetchone() == ("INVALIDATED",)

        with pytest.raises(ValueError, match="exactly one mutation attempt"):
            store.record_execution(
                scope=SCOPE,
                reservation=reservation,
                receipt=execution_receipt(
                    action_id=first_action,
                    attempt=2,
                    result=ExecutionResult.SUCCEEDED,
                    version="revision-v2",
                ),
            )
        with pytest.raises(ReservationConflict, match="not authorized|epoch changed"):
            store.acquire_reservation(
                scope=SCOPE,
                action_id=second_action,
                owner_identity="spiffe://solvan/actuator",
                ttl_ms=10_000,
            )


def test_dry_run_mismatch_is_durable_and_never_mutates() -> None:
    assert DATABASE_URL is not None

    class Clock:
        def now(self) -> datetime:
            return datetime.now(UTC)

    class MismatchingConnector:
        mutate_calls = 0

        def observe(self, _material: object) -> TargetObservation:
            return TargetObservation("payments://pool/before", "pool-generation-7")

        def dry_run(
            self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
        ) -> PredictedEffect:
            return PredictedEffect.from_object(
                {
                    "profile": "hostile-weaker-profile.v1",
                    "schema_version": 1,
                    "target_key": material.target_key,
                },
                connector_revision="integration-mismatch.v1",
            )

        def mutate(self, *_args: object, **_kwargs: object) -> object:
            self.mutate_calls += 1
            raise AssertionError("mutation must be unreachable after dry-run mismatch")

        def reconcile(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("reconciliation must be unreachable before mutation")

    with psycopg.connect(DATABASE_URL) as connection:
        mismatch_action_id = "act_00000000000000000000000003"
        seed_preauthorized_action(
            connection,
            action_id=mismatch_action_id,
            display_id="ACT-1003",
            idempotency_key="pool-action-idempotency-mismatch",
            target_key="org/project/env/payments-admin/payments-api/mismatch-pool",
        )
        connector = MismatchingConnector()

        class UnreachableAudit:
            def write(self, **_kwargs: object) -> str:
                raise AssertionError("audit is unreachable after dry-run mismatch")

        actuator = ActionActuator(
            store=PostgresActionStore(connection),
            connector=connector,  # type: ignore[arg-type]
            customer_audit=UnreachableAudit(),
            clock=Clock(),
            actuator_id="atr_00000000000000000000000000",
            actor_identity="spiffe://solvan/actuator",
            reservation_ttl_ms=10_000,
            pre_mutation_gate=_IntegrationFixtureActionGate(),
        )

        with pytest.raises(ActionPolicyError, match="dry_run_effect_mismatch"):
            actuator.execute(
                scope=SCOPE,
                action_id=mismatch_action_id,
                trace_id="trace-dry-run-mismatch",
            )

        assert connector.mutate_calls == 0
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT a.status, r.release_reason,
                    (SELECT count(*) FROM solvan.execution_receipts e
                     WHERE e.action_id = a.id)
                  FROM solvan.actions a
                  JOIN solvan.target_reservations r ON r.action_id = a.id
                  WHERE a.id = %s""",
                (mismatch_action_id,),
            )
            assert cursor.fetchone() == ("DRY_RUN_MISMATCH", "DRY_RUN_MISMATCH", 0)


def seed_preauthorized_action(
    connection: psycopg.Connection[object],
    *,
    action_id: str = "act_00000000000000000000000002",
    display_id: str = "ACT-1002",
    idempotency_key: str = "pool-action-idempotency",
    target_key: str = "org/project/env/payments-admin/payments-api/connection-pool",
) -> None:
    seed_actions(connection)
    with connection.cursor() as cursor:
        cursor.execute(
            """UPDATE solvan.incidents SET action_attempt_count = 0,
                cooldown_until = NULL, last_action_signature = NULL
              WHERE organization_id = %s AND project_id = %s
                AND environment_id = %s
                AND id = 'inc_00000000000000000000000000'""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.policy_decisions
              (organization_id, project_id, environment_id, id, policy_kind,
               policy_version, input_hash, decision, reason_code)
              VALUES (%s, %s, %s, 'pol_00000000000000000000000001',
                'ACTION', 'policy-v1', 'sha256:pool-input', 'ALLOW',
                'STANDING_AUTHORITY') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.standing_preauthorizations
              (organization_id, project_id, environment_id, id, version,
               action_type, service_id, incident_class, maximum_risk_class,
               payload_constraints_json, maximum_attempts, cooldown_ms,
               valid_from, valid_until, status, approved_by, approved_at)
              VALUES (%s, %s, %s, 'payments-pool-recycle-v1', 1,
                'PAYMENTS_POOL_RECYCLE', 'svc_00000000000000000000000000',
                'connection_exhaustion', 'MEDIUM',
                '{"admin_operation":"RECYCLE_DB_POOL","drain_timeout_ms":5000}',
                1, 600000, '2026-08-01 00:00:00+00', '2026-08-31 00:00:00+00',
                'APPROVED', 'user:policy-owner@example.com',
                '2026-08-01 00:00:00+00') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """SELECT workflow_version, evidence_version FROM solvan.incidents
              WHERE id = 'inc_00000000000000000000000000'"""
        )
        versions = cursor.fetchone()
        assert versions is not None
        pool_payload = freeze_json({"admin_operation": "RECYCLE_DB_POOL", "drain_timeout_ms": 5000})
        pool_effect = derive_expected_effect(
            action_type=ActionType.PAYMENTS_POOL_RECYCLE,
            target_key=target_key,
            expected_target_version="pool-generation-7",
            payload=pool_payload,
        )
        cursor.execute(
            """INSERT INTO solvan.actions
              (organization_id, project_id, environment_id, id, display_id,
               incident_id, workflow_version, evidence_version, action_type,
               normalized_signature, target_key, expected_target_version,
               expected_target_epoch, payload_json, payload_digest,
               expected_effect_json, expected_effect_hash, risk_class,
               reversible, rollback_plan_json, verification_profile_id,
               verification_profile_version, policy_decision_id,
               proposer_principal, standing_preauthorization_id,
               standing_preauthorization_version, requires_approval, status,
               idempotency_key, expires_at)
              VALUES (%s, %s, %s, %s, %s,
                'inc_00000000000000000000000000', %s, %s,
                'PAYMENTS_POOL_RECYCLE', 'sha256:pool-signature',
                %s, 'pool-generation-7', 0,
                '{"admin_operation":"RECYCLE_DB_POOL","drain_timeout_ms":5000}',
                'sha256:pool-payload', %s, %s, 'MEDIUM', true, '{}',
                'payments-recovery', 1, 'pol_00000000000000000000000001',
                'agent:supervisor', 'payments-pool-recycle-v1', 1,
                false, 'AUTHORIZED', %s,
                '2026-09-01 00:00:00+00') ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                action_id,
                display_id,
                versions[0],
                versions[1],
                target_key,
                psycopg.types.json.Jsonb(pool_effect.descriptor_object()),
                pool_effect.content_hash,
                idempotency_key,
            ),
        )
        cursor.execute(
            """INSERT INTO solvan.target_epochs
              (organization_id, project_id, environment_id, target_key, epoch,
               last_observed_version)
              VALUES (%s, %s, %s, %s, 0, 'pool-generation-7')
              ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                target_key,
            ),
        )
    connection.commit()


def seed_active_actuator(connection: psycopg.Connection[object]) -> str:
    actuator_id = "atr_00000000000000000000000000"
    with connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan.tenant_connections
              (organization_id, project_id, environment_id, id, display_name,
               kind, provider, credential_posture, residency_region,
               classification, lifecycle, availability, availability_reason_code,
               availability_explanation, availability_remediation_kind,
               availability_receipt_ref, last_probe_at, last_probe_result,
               created_by_principal)
              VALUES (%s, %s, %s, 'con_00000000000000000000000000',
                'contract actuator', 'COLLECTOR', 'SOLVAN_ACTUATOR',
                'CUSTOMER_SIDE_NONE', 'europe-west1', 'INTERNAL', 'ENABLED', 'READY',
                NULL, NULL, NULL, 'probe://seed',
                now(), 'SUCCEEDED', 'user:admin@example.com')
              ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        cursor.execute(
            """INSERT INTO solvan.actuator_registrations
              (organization_id, project_id, environment_id, id, connection_id,
               host_kind, production_eligible, principal_email,
               expected_audience, posture, image_digest, actuator_version,
               policy_hash, policy_source_ref, customer_audit_sink_ref,
               status, registered_by_principal)
              VALUES (%s, %s, %s, %s, 'con_00000000000000000000000000',
                'CLOUD_RUN', true, 'actuator@customer.example',
                'https://actuator.customer.example', 'REMEDIATE', %s, 'v1',
                %s, 'gs://customer-policy/v1',
                'projects/solvan-test/logs/solvan-audit', 'ACTIVE',
                'user:admin@example.com') ON CONFLICT DO NOTHING""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                actuator_id,
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
            ),
        )
    connection.commit()
    return actuator_id


def test_actuator_dispatch_intent_effect_and_dual_audit_settle_once() -> None:
    assert DATABASE_URL is not None

    class Clock:
        def now(self) -> datetime:
            return datetime.now(UTC)

    class Connector:
        mutate_calls = 0

        def observe(self, _material: object) -> TargetObservation:
            return TargetObservation("payments://pool/before", "pool-generation-7")

        def dry_run(
            self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
        ) -> PredictedEffect:
            return PredictedEffect(material.expected_effect, "contract-connector.v1")

        def derive_undo(
            self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
        ) -> UndoPlan:
            return UndoPlan.from_object(
                {
                    "before_state_ref": before_state.state_ref,
                    "profile": "contract-compensation.v1",
                    "target_key": material.target_key,
                }
            )

        def mutate(
            self, _material: AuthorizedActionMaterial, *, idempotency_key: str
        ) -> MutationCall:
            assert idempotency_key == "pool-action-idempotency-durable"
            self.mutate_calls += 1
            return MutationCall("connector-request-durable", datetime.now(UTC))

        def reconcile(
            self, _material: AuthorizedActionMaterial, *, idempotency_key: str
        ) -> Reconciliation:
            assert idempotency_key == "pool-action-idempotency-durable"
            return Reconciliation(
                ReconciliationResult.EFFECT_CONFIRMED,
                TargetObservation("payments://pool/after", "pool-generation-8"),
                datetime.now(UTC),
            )

    class Audit:
        def __init__(self) -> None:
            self.writes: list[CustomerAuditRecord] = []

        def write(self, *, sink_ref: str, record: CustomerAuditRecord) -> str:
            assert sink_ref == "projects/solvan-test/logs/solvan-audit"
            self.writes.append(record)
            return f"{sink_ref}#{record.content_hash}"

    action_id = "act_00000000000000000000000004"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_preauthorized_action(
            connection,
            action_id=action_id,
            display_id="ACT-1004",
            idempotency_key="pool-action-idempotency-durable",
            target_key="org/project/env/payments-admin/payments-api/durable-pool",
        )
        actuator_id = seed_active_actuator(connection)
        connector = Connector()
        result = ActionActuator(
            store=PostgresActionStore(connection),
            connector=connector,
            customer_audit=Audit(),
            clock=Clock(),
            actuator_id=actuator_id,
            actor_identity="spiffe://solvan/actuator",
            reservation_ttl_ms=10_000,
            pre_mutation_gate=_IntegrationFixtureActionGate(),
        ).execute(scope=SCOPE, action_id=action_id, trace_id="1" * 32)

        assert result.result is ExecutionResult.SUCCEEDED
        assert connector.mutate_calls == 1
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT d.status, d.mutation_started_at IS NOT NULL,
                    e.execution_receipt_id, e.customer_audit_written,
                    e.undo_derived_from,
                    (SELECT count(*) FROM solvan.execution_receipts x
                     WHERE x.action_id = d.action_id)
                  FROM solvan.actuator_dispatches d
                  JOIN solvan.actuator_effect_receipts e ON e.dispatch_id = d.id
                  WHERE d.action_id = %s""",
                (action_id,),
            )
            assert cursor.fetchone() == (
                "EXECUTED",
                True,
                result.receipt_id,
                True,
                "OBSERVED_PRE_STATE",
                1,
            )


def test_sigkill_after_effect_recovers_reconcile_only_with_two_workers() -> None:
    assert DATABASE_URL is not None
    action_id = "act_00000000000000000000000005"
    idempotency_key = "pool-action-idempotency-process-kill"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_preauthorized_action(
            connection,
            action_id=action_id,
            display_id="ACT-1005",
            idempotency_key=idempotency_key,
            target_key="org/project/env/payments-admin/payments-api/process-kill-pool",
        )
        actuator_id = seed_active_actuator(connection)
        with connection.transaction():
            connection.execute(
                "DELETE FROM solvan.fixture_admin_actions WHERE action_id = %s",
                (action_id,),
            )
            connection.execute(
                """UPDATE solvan.fixture_runtime_state SET state_value = 7,
                    updated_at = now() WHERE state_key = 'pool_generation'"""
            )

    killed = subprocess.run(
        [
            sys.executable,
            "tools/actuator_crash_fixture.py",
            "--database-url",
            DATABASE_URL,
            "--organization-id",
            SCOPE.organization_id,
            "--project-id",
            SCOPE.project_id,
            "--environment-id",
            SCOPE.environment_id,
            "--action-id",
            action_id,
            "--actuator-id",
            actuator_id,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert killed.returncode == -signal.SIGKILL

    with psycopg.connect(DATABASE_URL) as connection, connection.transaction():
        row = connection.execute(
            """SELECT d.status,
                (SELECT count(*) FROM solvan.fixture_admin_actions f
                 WHERE f.action_id = d.action_id),
                (SELECT count(*) FROM solvan.execution_receipts r
                 WHERE r.action_id = d.action_id),
                e.execution_receipt_id
              FROM solvan.actuator_dispatches d
              JOIN solvan.actuator_effect_receipts e ON e.dispatch_id = d.id
              WHERE d.action_id = %s""",
            (action_id,),
        ).fetchone()
        assert row == ("MUTATION_ISSUED", 1, 0, None)
        connection.execute(
            """UPDATE solvan.actuator_dispatches
              SET dispatched_at = now() - interval '20 seconds',
                  lease_expires_at = now() - interval '1 second'
              WHERE action_id = %s""",
            (action_id,),
        )

    class Clock:
        def now(self) -> datetime:
            return datetime.now(UTC)

    class Audit:
        def __init__(self) -> None:
            self.records: list[CustomerAuditRecord] = []
            self._lock = threading.Lock()

        def write(self, *, sink_ref: str, record: CustomerAuditRecord) -> str:
            with self._lock:
                self.records.append(record)
            return f"{sink_ref}#{record.content_hash}"

    audit = Audit()
    barrier = threading.Barrier(2)
    connectors: list[DatabaseFixtureConnector] = []

    def recover() -> tuple[str, ExecutionResult | None]:
        connector = DatabaseFixtureConnector(DATABASE_URL)
        connectors.append(connector)
        barrier.wait(timeout=10)
        try:
            with psycopg.connect(DATABASE_URL) as connection:
                result = ActionActuator(
                    store=PostgresActionStore(connection),
                    connector=connector,
                    customer_audit=audit,
                    clock=Clock(),
                    actuator_id=actuator_id,
                    actor_identity="spiffe://solvan/recovery-worker",
                    reservation_ttl_ms=10_000,
                    pre_mutation_gate=_IntegrationFixtureActionGate(),
                ).execute(scope=SCOPE, action_id=action_id, trace_id="e" * 32)
            return ("SUCCEEDED", result.result)
        except (ReservationConflict, ReservationLost):
            return ("FENCED", None)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: recover(), range(2)))

    assert sorted(outcome[0] for outcome in outcomes) == ["FENCED", "SUCCEEDED"]
    assert sum(connector.mutate_calls for connector in connectors) == 0
    assert len(audit.records) == 1
    with psycopg.connect(DATABASE_URL) as connection:
        final = connection.execute(
            """SELECT d.status, e.customer_audit_written,
                (SELECT count(*) FROM solvan.fixture_admin_actions f
                 WHERE f.action_id = d.action_id),
                (SELECT count(*) FROM solvan.execution_receipts r
                 WHERE r.action_id = d.action_id)
              FROM solvan.actuator_dispatches d
              JOIN solvan.actuator_effect_receipts e ON e.dispatch_id = d.id
              WHERE d.action_id = %s""",
            (action_id,),
        ).fetchone()
    assert final == ("EXECUTED", True, 1, 1)
    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute(
            """UPDATE solvan.fixture_runtime_state SET state_value = 1,
                updated_at = now() WHERE state_key = 'pool_generation'"""
        )
        connection.commit()


def test_autonomous_action_requires_exact_standing_preauthorization() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_preauthorized_action(connection)
        store = PostgresActionStore(connection)
        reservation = store.acquire_reservation(
            scope=SCOPE,
            action_id="act_00000000000000000000000002",
            owner_identity="spiffe://solvan/actuator",
            ttl_ms=10_000,
        )
        authority = store.authorize_for_execution(scope=SCOPE, reservation=reservation)
        assert isinstance(authority, StandingAuthority)
        assert authority.authority.preauthorization_id == "payments-pool-recycle-v1"
        store.release_before_mutation(
            scope=SCOPE,
            reservation=reservation,
            reason="PRECONDITION_FAILED",
        )


def test_completed_investigation_deterministically_authorizes_pool_recycle() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_investigation_run(connection)
        target_key = (
            f"{SCOPE.organization_id}/{SCOPE.project_id}/{SCOPE.environment_id}/"
            "payments-admin/payments-api/connection-pool"
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.investigation_plans
                  (organization_id, project_id, environment_id, id, incident_id,
                   plan_version, objective, completion_condition, content_hash,
                   status, created_by_agent_run_id)
                  VALUES (%s, %s, %s, 'ipl_00000000000000000000000009', %s, 1,
                    'Collect typed saturation evidence', 'Required observations exist',
                    'sha256:planner-plan', 'COMPLETED', %s)
                  ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    INVESTIGATION_INCIDENT_ID,
                    SUPERVISOR_RUN_ID,
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.confirmation_rules
                  (organization_id, project_id, environment_id, id, version,
                   incident_class, required_observations_json,
                   contradiction_policy, status, approved_by, approved_at)
                  VALUES (%s, %s, %s, 'connection-pool-exhaustion-v1', 1,
                    'connection_exhaustion', %s, 'ESCALATE', 'APPROVED',
                    'user:policy-owner@example.com', now()) ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    psycopg.types.json.Jsonb(
                        {
                            "normalized_cause_key": "payments-connection-pool-exhaustion",
                            "statement": (
                                "Payments failures are caused by exhausted database "
                                "connections in the defective revision."
                            ),
                            "all_required": [
                                {
                                    "source_kind": "CLOUD_MONITORING",
                                    "tool_name": "cloud_monitoring_query",
                                    "argument_equals": {"signal_kind": "HTTP_5XX_RATIO"},
                                },
                                {
                                    "source_kind": "CLOUD_LOGGING",
                                    "tool_name": "cloud_logging_query",
                                    "argument_equals": {"signature_key": "connection-exhaustion"},
                                },
                            ],
                        }
                    ),
                ),
            )
            for evidence_id, source_kind, tool_name, arguments in (
                (
                    "evd_00000000000000000000000008",
                    "CLOUD_MONITORING",
                    "cloud_monitoring_query",
                    {"signal_kind": "HTTP_5XX_RATIO"},
                ),
                (
                    "evd_00000000000000000000000009",
                    "CLOUD_LOGGING",
                    "cloud_logging_query",
                    {"signature_key": "connection-exhaustion"},
                ),
            ):
                cursor.execute(
                    """INSERT INTO solvan.evidence_items
                      (organization_id, project_id, environment_id, id, incident_id,
                       source_kind, source_resource, query_spec_json, window_start,
                       window_end, observed_at, content_ref, content_hash,
                       classification, residency, redaction_manifest_ref,
                       provenance_json, freshness_expires_at,
                       created_by_agent_run_id)
                      VALUES (%s, %s, %s, %s, %s, %s, 'fixture://provider', %s,
                        now() - interval '1 minute', now(), now(), %s, %s,
                        'INTERNAL', 'europe-west1', 'fixture:redacted', '{}',
                        now() + interval '5 minutes', %s) ON CONFLICT DO NOTHING""",
                    (
                        SCOPE.organization_id,
                        SCOPE.project_id,
                        SCOPE.environment_id,
                        evidence_id,
                        INVESTIGATION_INCIDENT_ID,
                        source_kind,
                        psycopg.types.json.Jsonb({"tool_name": tool_name, "arguments": arguments}),
                        f"gs://evidence/{evidence_id}.json",
                        f"sha256:{evidence_id}",
                        SUPERVISOR_RUN_ID,
                    ),
                )
            cursor.execute(
                """UPDATE solvan.incidents SET evidence_version = 2
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    INVESTIGATION_INCIDENT_ID,
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.standing_preauthorizations
                  (organization_id, project_id, environment_id, id, version,
                   action_type, service_id, incident_class, maximum_risk_class,
                   payload_constraints_json, maximum_attempts, cooldown_ms,
                   valid_from, valid_until, status, approved_by, approved_at)
                  VALUES (%s, %s, %s, 'payments-pool-recycle-v1', 1,
                    'PAYMENTS_POOL_RECYCLE', 'svc_00000000000000000000000000',
                    'connection_exhaustion', 'MEDIUM',
                    '{"admin_operation":"RECYCLE_DB_POOL","drain_timeout_ms":5000}',
                    1, 600000, now() - interval '1 day', now() + interval '1 day',
                    'APPROVED', 'user:policy-owner@example.com', now())
                  ON CONFLICT DO NOTHING""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
            )
            cursor.execute(
                """INSERT INTO solvan.verification_profiles
                  (organization_id, project_id, environment_id, id, version, status,
                   owner, warmup_ms, observation_ms, required_signals_json,
                   guardrails_json, inconclusive_policy, content_hash, approved_by,
                   approved_at)
                  VALUES (%s, %s, %s, 'planner-payments-recovery', 1, 'APPROVED',
                    'payments', 0, 1,
                    '[{"signal_key":"http_5xx_ratio",'
                    '"provider_signal_kind":"HTTP_5XX_RATIO",'
                    '"comparator":"LTE","threshold":0.05,"sustained_samples":2}]',
                    '{"synthetic_payment":{"amount_minor":100,"required":true}}',
                    'ESCALATE',
                    'sha256:planner-profile', 'owner', now()) ON CONFLICT DO NOTHING""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
            )
            cursor.execute(
                """INSERT INTO solvan.verification_profile_bindings
                  (organization_id, project_id, environment_id,
                   production_graph_snapshot_id, service_id, incident_class,
                   profile_id, profile_version, effective_at, policy_owner)
                  VALUES (%s, %s, %s, 'pgs_00000000000000000000000000',
                    'svc_00000000000000000000000000', 'connection_exhaustion',
                    'planner-payments-recovery', 1, now() - interval '1 minute',
                    'payments') ON CONFLICT DO NOTHING""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
            )
            cursor.execute(
                """INSERT INTO solvan.target_epochs
                  (organization_id, project_id, environment_id, target_key, epoch,
                   last_observed_version)
                  VALUES (%s, %s, %s, %s, 0, 'pool-generation-7')
                  ON CONFLICT DO NOTHING""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    target_key,
                ),
            )
        connection.commit()

        workflow = PostgresWorkflowStore(connection)
        planner = PostgresMitigationPlanner(connection)
        with connection.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=INVESTIGATION_INCIDENT_ID,
                owner="deterministic-mitigation-test",
            )
        assert lease is not None
        with connection.transaction():
            result = planner.plan_preauthorized_pool_recycle(
                scope=SCOPE,
                lease=lease,
                actor_id="coordinator:deterministic-mitigation-policy",
            )
            assert result is not None
            workflow.release_lease(scope=SCOPE, lease=lease)
        assert result.workflow_version == lease.workflow_version + 3
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT i.state, i.workflow_version, i.evidence_version,
                    i.confirmed_root_cause_id, h.status, a.status,
                    a.workflow_version, a.evidence_version, a.requires_approval,
                    p.decision, a.target_key
                  FROM solvan.incidents i
                  JOIN solvan.hypotheses h ON h.id = i.confirmed_root_cause_id
                  JOIN solvan.actions a ON a.incident_id = i.id
                  JOIN solvan.policy_decisions p ON p.id = a.policy_decision_id
                  WHERE i.id = %s AND a.id = %s""",
                (INVESTIGATION_INCIDENT_ID, result.action_id),
            )
            row = cursor.fetchone()
        assert row == (
            "MITIGATING",
            result.workflow_version,
            2,
            result.hypothesis_id,
            "CONFIRMED",
            "AUTHORIZED",
            result.workflow_version,
            2,
            False,
            "ALLOW",
            target_key,
        )

        runtime_store = PostgresRuntimeRunStore(connection)
        with connection.transaction():
            execution_lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=INVESTIGATION_INCIDENT_ID,
                owner="execution-dispatch-test",
            )
        assert execution_lease is not None
        with connection.transaction():
            execution_dispatch = runtime_store.reserve_execution(
                scope=SCOPE,
                action_id=result.action_id,
                authority=CoordinatorAuthority(
                    execution_lease.owner,
                    execution_lease.token,
                    execution_lease.workflow_version,
                ),
                agent_resource=(
                    "projects/test/locations/europe-west1/reasoningEngines/execution-v1"
                ),
                agent_revision="execution-20260808-01",
            )
        assert execution_dispatch is not None
        with connection.transaction():
            bind_test_agent_run(
                connection,
                run_id=execution_dispatch.run_id,
                agent_key=execution_dispatch.agent_key,
            )
            runtime_store.record_dispatch(
                scope=SCOPE,
                dispatch=execution_dispatch,
                receipt=RuntimeInvocationReceipt(
                    runtime_operation_name=(
                        "projects/test/locations/europe-west1/operations/execution-1"
                    ),
                    runtime_input_ref="gs://runtime/execution-input.json",
                    runtime_output_ref="gs://runtime/execution-output.json",
                ),
            )
            workflow.release_lease(scope=SCOPE, lease=execution_lease)

        action_store = PostgresActionStore(connection)
        with connection.transaction():
            with pytest.raises(ActionPolicyError, match="not_bound"):
                action_store.require_execution_invocation(
                    scope=SCOPE,
                    invocation_id=execution_dispatch.invocation_id,
                    action_id="act_00000000000000000000000000",
                )
            action_store.require_execution_invocation(
                scope=SCOPE,
                invocation_id=execution_dispatch.invocation_id,
                action_id=result.action_id,
            )
        reservation = action_store.acquire_reservation(
            scope=SCOPE,
            action_id=result.action_id,
            owner_identity="spiffe://solvan/actuator",
            ttl_ms=10_000,
        )
        authority = action_store.authorize_for_execution(scope=SCOPE, reservation=reservation)
        assert isinstance(authority, StandingAuthority)
        assert authority.execution.workflow_version == result.workflow_version
        receipt_id = action_store.record_execution(
            scope=SCOPE,
            reservation=reservation,
            receipt=execution_receipt(
                action_id=result.action_id,
                attempt=1,
                result=ExecutionResult.SUCCEEDED,
                version="pool-generation-8",
            ),
        )
        pending = next(
            item
            for item in runtime_store.pending(scope=SCOPE)
            if item.run_id == execution_dispatch.run_id
        )
        outcome = runtime_store.execution_outcome(scope=SCOPE, run=pending)
        assert outcome.receipt_id == receipt_id
        assert outcome.receipt_result == "SUCCEEDED"
        with connection.transaction():
            runtime_store.complete_execution(
                scope=SCOPE,
                run=pending,
                output_hash="sha256:execution-agent-output",
                outcome=outcome,
            )
            verification_lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=INVESTIGATION_INCIDENT_ID,
                owner="execution-receipt-test",
            )
            assert verification_lease is not None
            workflow.commit_transition(
                scope=SCOPE,
                lease=verification_lease,
                transition=TransitionWrite(
                    from_state="MITIGATING",
                    to_state="VERIFYING_MITIGATION",
                    transition_key=f"MUTATION_RECONCILED:{result.action_id}:{receipt_id}",
                    actor_type="AGENT",
                    actor_id="execution-agent",
                    reason_code="CONCLUSIVE_EXECUTION_RECEIPT",
                    rationale_summary="Durable receipt proves the bounded effect.",
                ),
            )
            workflow.release_lease(scope=SCOPE, lease=verification_lease)
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT state, action_attempt_count, cooldown_until IS NOT NULL
                  FROM solvan.incidents WHERE id = %s""",
                (INVESTIGATION_INCIDENT_ID,),
            )
            final_incident = cursor.fetchone()
        assert final_incident == ("VERIFYING_MITIGATION", 1, True)

        with connection.transaction():
            verification_lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=INVESTIGATION_INCIDENT_ID,
                owner="verification-dispatch-test",
            )
        assert verification_lease is not None
        with connection.transaction():
            verification_dispatch = runtime_store.reserve_verification(
                scope=SCOPE,
                action_id=result.action_id,
                authority=CoordinatorAuthority(
                    verification_lease.owner,
                    verification_lease.token,
                    verification_lease.workflow_version,
                ),
                agent_resource=(
                    "projects/test/locations/europe-west1/reasoningEngines/verification-v1"
                ),
                agent_revision="verification-20260808-01",
            )
        assert verification_dispatch is not None
        with connection.transaction():
            bind_test_agent_run(
                connection,
                run_id=verification_dispatch.run_id,
                agent_key=verification_dispatch.agent_key,
            )
            runtime_store.record_dispatch(
                scope=SCOPE,
                dispatch=verification_dispatch,
                receipt=RuntimeInvocationReceipt(
                    runtime_operation_name=(
                        "projects/test/locations/europe-west1/operations/verification-1"
                    ),
                    runtime_input_ref="gs://runtime/verification-input.json",
                    runtime_output_ref="gs://runtime/verification-output.json",
                ),
            )
            workflow.release_lease(scope=SCOPE, lease=verification_lease)
        verification_store = PostgresVerificationStore(connection)
        with connection.transaction():
            task = verification_store.reserve(
                scope=SCOPE,
                invocation_id=verification_dispatch.invocation_id,
                action_id=result.action_id,
            )
        now = datetime.now(UTC)
        with connection.transaction():
            verification_id = verification_store.complete(
                task=task,
                window_start=now - timedelta(minutes=1),
                window_end=now,
                signal_results=[
                    {
                        "signal_key": "http_5xx_ratio",
                        "observed_at": now.isoformat(),
                        "value": 0.0,
                    }
                ],
                synthetic_receipt_ref="gs://runtime/verification/receipt.json",
                result=VerificationResult(
                    VerificationVerdict.VERIFIED,
                    ("ALL_REQUIRED_SIGNALS_PASSED",),
                ),
            )
        verification_pending = next(
            item
            for item in runtime_store.pending(scope=SCOPE)
            if item.run_id == verification_dispatch.run_id
        )
        assert verification_store.result_for_run(
            scope=SCOPE,
            run_id=verification_pending.run_id,
            action_id=result.action_id,
        ) == (verification_id, "VERIFIED")
        with connection.transaction():
            runtime_store.complete_verification(
                scope=SCOPE,
                run=verification_pending,
                verification_id=verification_id,
                output_hash="sha256:verification-agent-output",
            )
            mitigated_lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=INVESTIGATION_INCIDENT_ID,
                owner="verification-result-test",
            )
            assert mitigated_lease is not None
            workflow.commit_transition(
                scope=SCOPE,
                lease=mitigated_lease,
                transition=TransitionWrite(
                    from_state="VERIFYING_MITIGATION",
                    to_state="MITIGATED",
                    transition_key=(f"VERIFICATION_PASSED:{result.action_id}:{verification_id}"),
                    actor_type="AGENT",
                    actor_id="verification-agent",
                    reason_code="EXACT_BOUND_PROFILE_PASSED",
                    rationale_summary="Independent verification passed.",
                ),
            )
            workflow.release_lease(scope=SCOPE, lease=mitigated_lease)
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT state, evidence_version FROM solvan.incidents WHERE id = %s""",
                (INVESTIGATION_INCIDENT_ID,),
            )
            verified_incident = cursor.fetchone()
        assert verified_incident == ("MITIGATED", 3)


def test_failed_pool_verification_proposes_exact_approval_bound_rollback() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        seed_preauthorized_action(connection)
        incident_id = "inc_00000000000000000000000000"
        pool_action_id = "act_00000000000000000000000002"
        verification_id = "ver_00000000000000000000000009"
        scope_values = (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
        )
        deployment_target = (
            f"{SCOPE.organization_id}/{SCOPE.project_id}/{SCOPE.environment_id}/"
            "cloud-run/payments-api/deployment"
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.incidents SET state = 'VERIFYING_MITIGATION',
                    workflow_version = 8, evidence_version = 4,
                    action_attempt_count = 1
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (*scope_values, incident_id),
            )
            cursor.execute(
                """UPDATE solvan.actions SET status = 'SUCCEEDED',
                    workflow_version = 8, evidence_version = 3
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s AND id = %s""",
                (*scope_values, pool_action_id),
            )
            cursor.execute(
                """INSERT INTO solvan.verification_profile_bindings
                  (organization_id, project_id, environment_id,
                   production_graph_snapshot_id, service_id, incident_class,
                   profile_id, profile_version, effective_at, policy_owner)
                      VALUES (%s, %s, %s, 'pgs_00000000000000000000000000',
                        'svc_00000000000000000000000000', 'connection_exhaustion',
                        'payments-recovery', 1, now() - interval '1 minute', 'payments')
                      ON CONFLICT DO NOTHING""",
                scope_values,
            )
            cursor.execute(
                """INSERT INTO solvan.verification_runs
                  (organization_id, project_id, environment_id, id, purpose,
                   incident_id, action_id, profile_id, profile_version,
                   resolved_binding_ref, window_start, window_end,
                   signal_results_json, synthetic_receipt_ref, verdict,
                   rationale_codes, completed_at)
                  VALUES (%s, %s, %s, %s, 'MITIGATION_ACTION', %s, %s,
                    'payments-recovery', 1, 'binding:fixture',
                    now() - interval '1 minute', now(), '[]',
                    'gs://runtime/failed-synthetic.json', 'FAILED',
                    '["SYNTHETIC_FAILED"]', now())""",
                (
                    *scope_values,
                    verification_id,
                    incident_id,
                    pool_action_id,
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.production_graph_nodes
                  (organization_id, project_id, environment_id, id, snapshot_id,
                   node_key, node_kind, resource_ref, external_project_id, classification,
                   provenance_ref, attributes_json)
                  VALUES (%s, %s, %s, 'pgn_00000000000000000000000009',
                    'pgs_00000000000000000000000000', 'payments-deployment',
                    'DEPLOYMENT',
                    'projects/test/locations/europe-west1/services/payments-api', 'solvan-test',
                    'INTERNAL', 'fixture://deployment-policy', %s)""",
                (
                    *scope_values,
                    psycopg.types.json.Jsonb(
                        {
                            "service_id": "svc_00000000000000000000000000",
                            "active_revision": "payments-api-v2-8-1",
                            "known_good_revision": "payments-api-v2-8-0",
                            "target_key": deployment_target,
                        }
                    ),
                ),
            )
            cursor.execute(
                """INSERT INTO solvan.target_epochs
                  (organization_id, project_id, environment_id, target_key,
                   epoch, last_observed_version)
                  VALUES (%s, %s, %s, %s, 0, 'payments-api-v2-8-1')""",
                (*scope_values, deployment_target),
            )
        connection.commit()

        workflow = PostgresWorkflowStore(connection)
        with connection.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner="rollback-planner-test",
            )
        assert lease is not None
        with connection.transaction():
            result = PostgresMitigationPlanner(connection).plan_approval_bound_rollback(
                scope=SCOPE,
                lease=lease,
                failed_action_id=pool_action_id,
                verification_id=verification_id,
                actor_id="coordinator:rollback-policy",
            )
            workflow.release_lease(scope=SCOPE, lease=lease)
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT i.state, i.workflow_version, a.action_type, a.status,
                    a.requires_approval, a.workflow_version, a.evidence_version,
                    a.expected_target_version, a.payload_json,
                    p.decision
                  FROM solvan.incidents i
                  JOIN solvan.actions a ON a.incident_id = i.id
                  JOIN solvan.policy_decisions p ON p.id = a.policy_decision_id
                  WHERE i.id = %s AND a.id = %s""",
                (incident_id, result.action_id),
            )
            row = cursor.fetchone()
        assert row == (
            "AWAITING_APPROVAL",
            10,
            "CLOUD_RUN_TRAFFIC_ROLLBACK",
            "AWAITING_APPROVAL",
            True,
            11,
            4,
            "payments-api-v2-8-1",
            {
                "percent": 100,
                "service_name": ("projects/test/locations/europe-west1/services/payments-api"),
                "known_good_revision": "payments-api-v2-8-0",
            },
            "REQUIRE_APPROVAL",
        )
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.*, p.policy_version FROM solvan.actions a
                  JOIN solvan.policy_decisions p ON p.id = a.policy_decision_id
                  WHERE a.id = %s""",
                (result.action_id,),
            )
            action = cursor.fetchone()
            assert action is not None
            cursor.execute(
                """INSERT INTO solvan.actor_role_bindings
                  (organization_id, project_id, environment_id, principal, role,
                   granted_by)
                  VALUES (%s, %s, %s, 'user:rollback-approver@example.com',
                    'APPROVER', 'user:admin@example.com') ON CONFLICT DO NOTHING""",
                scope_values,
            )
        connection.commit()
        approval_material = AuthorizedActionMaterial(
            action_id=result.action_id,
            scope=SCOPE,
            owner_entity_id=incident_id,
            workflow_version=int(action["workflow_version"]),
            evidence_version=int(action["evidence_version"]),
            action_type=ActionType(action["action_type"]),
            target_key=str(action["target_key"]),
            expected_target_version=str(action["expected_target_version"]),
            expected_target_epoch=int(action["expected_target_epoch"]),
            payload=freeze_json(dict(action["payload_json"])),
            expected_effect=freeze_json(dict(action["expected_effect_json"])),
            expected_effect_hash=str(action["expected_effect_hash"]),
            risk_class=RiskClass(action["risk_class"]),
            reversible=bool(action["reversible"]),
            rollback_plan=freeze_json(dict(action["rollback_plan_json"])),
            policy_version=str(action["policy_version"]),
            verification_profile_id=str(action["verification_profile_id"]),
            verification_profile_version=int(action["verification_profile_version"]),
            expires_at=action["expires_at"],
        )
        with connection.transaction():
            approval_lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner="approval-api-test",
            )
        assert approval_lease is not None
        with connection.transaction():
            approval = PostgresApprovalStore(connection).approve(
                scope=SCOPE,
                lease=approval_lease,
                action_id=result.action_id,
                approver_principal="user:rollback-approver@example.com",
                expected_action_digest=approval_material.approval_digest(),
                decision_request_id="approval-request-rollback-1",
                reason="Exact rollback is required after partial recovery.",
            )
            workflow.release_lease(scope=SCOPE, lease=approval_lease)
        assert approval.created
        assert approval.workflow_version == 11
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT i.state, i.workflow_version, a.status,
                    ap.action_digest = %s
                  FROM solvan.incidents i
                  JOIN solvan.actions a ON a.incident_id = i.id
                  JOIN solvan.approvals ap ON ap.action_id = a.id
                  WHERE i.id = %s AND a.id = %s""",
                (approval_material.approval_digest(), incident_id, result.action_id),
            )
            assert cursor.fetchone() == ("MITIGATING", 11, "AUTHORIZED", True)
        with connection.transaction():
            snapshot = live_console_snapshot(connection, scope=SCOPE)
        projected = next(
            item for item in snapshot["incidents"] if item["machine_id"] == incident_id
        )
        projected_action = next(
            item for item in projected["actions"] if item["id"] == result.action_id
        )
        assert snapshot["data_status"] == "LIVE_CLOUD_SQL_PROJECTION"
        assert projected["state"] == "MITIGATING"
        assert projected_action["status"] == "AUTHORIZED"
        assert projected_action["digest"] == approval_material.approval_digest()
        assert projected_action["expected_effect_hash"] == approval_material.expected_effect_hash
        assert projected_action["expected_effect"] == str(dict(action["expected_effect_json"]))
        # The grant is a durable wake-up, not only a projection change: the
        # transition appends one outbox event the publisher pushes back to the
        # coordinator, so approval never waits on a polling cadence alone.
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT topic, aggregate_id FROM solvan.outbox_events
                  WHERE organization_id = %s AND project_id = %s
                    AND environment_id = %s
                    AND event_type LIKE 'APPROVAL_GRANTED:%%'
                    AND aggregate_id = %s""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    incident_id,
                ),
            )
            assert cursor.fetchall() == [("workflow-transitions", incident_id)]


def test_bad_payments_revision_really_exhausts_and_recycles_postgres_pool() -> None:
    assert DATABASE_URL is not None
    fixture = PaymentsFixtureService(
        database_url=DATABASE_URL,
        revision="v2.8.1",
        checkout_timeout_seconds=0.01,
    )
    try:
        fixture.initialize_schema()
        for index in range(4):
            result = fixture.create_synthetic_payment(
                idempotency_key=f"leak-{index}",
                payment_id=f"payment-{index}",
                amount_minor=100,
            )
            assert result.revision == "v2.8.1"
        assert fixture.leaked_connection_count == 4
        with pytest.raises(PaymentUnavailable, match="exhausted"):
            fixture.create_synthetic_payment(
                idempotency_key="exhausted",
                payment_id="payment-exhausted",
                amount_minor=100,
            )

        recycled = fixture.recycle_pool(
            action_id="act_00000000000000000000000002",
            idempotency_key="pool-recycle-fixture",
            expected_generation=fixture.pool_generation,
            request_id="pool-request-1",
        )
        duplicate = fixture.recycle_pool(
            action_id="act_00000000000000000000000002",
            idempotency_key="pool-recycle-fixture",
            expected_generation=recycled.before_generation,
            request_id="ignored-request",
        )
        assert recycled.after_generation == "pool-generation-2"
        assert duplicate.request_id == "pool-request-1"
        assert duplicate.duplicate is True
        assert fixture.leaked_connection_count == 0

        fixture.create_synthetic_payment(
            idempotency_key="post-recycle",
            payment_id="payment-post-recycle",
            amount_minor=100,
        )
        assert fixture.leaked_connection_count == 1
    finally:
        fixture.close()


def test_database_row_policy_denies_cross_scope_reads_for_workload_role() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute("DROP ROLE IF EXISTS solvan_scope_probe")
        connection.execute("CREATE ROLE solvan_scope_probe NOLOGIN")
        connection.execute("GRANT USAGE ON SCHEMA solvan TO solvan_scope_probe")
        connection.execute("GRANT SELECT ON solvan.services TO solvan_scope_probe")
        connection.execute(
            "GRANT EXECUTE ON FUNCTION solvan.scope_permitted(name, text, text, text) "
            "TO solvan_scope_probe"
        )
        connection.execute(
            """INSERT INTO solvan.database_scope_bindings
              (database_role, organization_id, project_id, environment_id)
              VALUES ('solvan_scope_probe', %s, %s, %s)""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        connection.commit()
        try:
            connection.execute("SET ROLE solvan_scope_probe")
            connection.execute(
                "SELECT set_config('solvan.organization_id', %s, false)",
                (SCOPE.organization_id,),
            )
            connection.execute(
                "SELECT set_config('solvan.project_id', %s, false)",
                (SCOPE.project_id,),
            )
            connection.execute(
                "SELECT set_config('solvan.environment_id', %s, false)",
                (SCOPE.environment_id,),
            )
            assert connection.execute("SELECT count(*) FROM solvan.services").fetchone() == (1,)

            connection.execute(
                "SELECT set_config('solvan.environment_id', %s, false)",
                ("env_11111111111111111111111111",),
            )
            assert connection.execute("SELECT count(*) FROM solvan.services").fetchone() == (1,)
        finally:
            connection.execute("RESET ROLE")
            connection.execute(
                "DELETE FROM solvan.database_scope_bindings "
                "WHERE database_role = 'solvan_scope_probe'"
            )
            connection.execute("DROP OWNED BY solvan_scope_probe")
            connection.execute("DROP ROLE solvan_scope_probe")
            connection.commit()


def test_database_bootstrap_applies_least_privilege_workload_grants() -> None:
    assert DATABASE_URL is not None
    deployment_project_id = "solvan-test"
    roles = [
        database_role(workload=grant.workload, deployment_project_id=deployment_project_id)
        for grant in grant_plan()
    ]
    with psycopg.connect(DATABASE_URL) as connection:
        for role in roles:
            connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
        connection.commit()
        try:
            apply_database_bootstrap(
                connection=connection,
                scope=SCOPE,
                deployment_project_id=deployment_project_id,
                rebuild_local_target_schemas=True,
            )
            connection.commit()
            payments = database_role(
                workload="payments", deployment_project_id=deployment_project_id
            )
            publisher = database_role(
                workload="publisher", deployment_project_id=deployment_project_id
            )
            assert connection.execute(
                "SELECT has_table_privilege(%s, 'solvan.fixture_payments', 'SELECT')",
                (payments,),
            ).fetchone() == (True,)
            assert connection.execute(
                "SELECT has_table_privilege(%s, 'solvan.incidents', 'SELECT')",
                (payments,),
            ).fetchone() == (False,)
            assert connection.execute(
                "SELECT has_table_privilege(%s, 'solvan.outbox_events', 'UPDATE')",
                (publisher,),
            ).fetchone() == (True,)
        finally:
            connection.execute(
                "DELETE FROM solvan.database_scope_bindings WHERE database_role = ANY(%s)",
                (roles,),
            )
            for role in roles:
                connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                connection.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
            connection.commit()


class FakeMemoryBank:
    def __init__(self) -> None:
        self.calls = 0

    def upsert_exact(self, *, exact_scope: MemoryScope, fact_text: str) -> MemoryBankReceipt:
        self.calls += 1
        return MemoryBankReceipt(
            "projects/solvan-test/locations/europe-west1/reasoningEngines/"
            "supervisor/memories/memory-1",
            "2026-08-08T12:00:00Z",
            exact_scope,
            fact_text,
        )

    def retrieve_exact(self, *, exact_scope: MemoryScope) -> tuple[()]:
        del exact_scope
        return ()


def test_memory_candidate_promotes_once_and_retry_returns_durable_receipt() -> None:
    assert DATABASE_URL is not None
    memory_now = datetime(2026, 8, 8, 12, tzinfo=UTC)
    exact_scope = MemoryScope(SCOPE, "incident-investigation", "INTERNAL", "europe-west1")
    candidate = MemoryCandidateProposal(
        candidate_type=MemoryCandidateType.ROOT_CAUSE,
        exact_scope=exact_scope,
        fact_text="Connection pool exhaustion caused the payment errors.",
        source_refs=("hyp_00000000000000000000000000",),
        source_hashes=("a" * 64,),
        confirmation=MemoryConfirmation.CONFIRMED,
        verification_ref=None,
        classification="INTERNAL",
        residency="europe-west1",
        redaction_manifest_ref="redaction:manifest-1",
        armor_verdict_ref="armor:allow:verdict-1",
        provenance=(("confirmation_rule", "root-cause-v1"),),
        policy_version="memory-v1",
        created_by_principal="supervisor@solvan.example",
        expires_at=memory_now + timedelta(days=30),
    )
    policy = MemoryGatePolicy("memory-v1", frozenset({"INTERNAL"}), frozenset({"europe-west1"}))
    with psycopg.connect(DATABASE_URL) as connection:
        store = PostgresMemoryStore(connection, scope=SCOPE)
        stored = MemoryCandidateService(store).evaluate_and_store(
            proposal=candidate, policy=policy, now=memory_now
        )
        assert stored.candidate_id in store.promotable_candidate_ids()
        bank = FakeMemoryBank()
        service = MemoryPromotionService(store, bank)
        first = service.promote(
            candidate_id=stored.candidate_id,
            promoter_identity="promotion-service@solvan.example",
            now=memory_now,
        )
        second = service.promote(
            candidate_id=stored.candidate_id,
            promoter_identity="promotion-service@solvan.example",
            now=memory_now,
        )
        assert first == second
        assert bank.calls == 1
        matching = MemorySearchCandidate(
            first.memory_resource,
            candidate.fact_text,
            exact_scope,
            first.memory_revision,
            0.12,
        )
        hints = store.revalidate_search_hits(
            exact_scope=exact_scope,
            candidates=(matching,),
            now=memory_now,
        )
        assert len(hints) == 1
        assert hints[0].source_refs == candidate.source_refs
        stale = replace(matching, memory_revision="stale-revision")
        unknown = replace(matching, memory_resource=f"{first.memory_resource}-unknown")
        assert (
            store.revalidate_search_hits(
                exact_scope=exact_scope,
                candidates=(stale, unknown),
                now=memory_now,
            )
            == ()
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT status,
                    (SELECT count(*) FROM solvan.memory_promotions
                     WHERE candidate_id = %s)
                  FROM solvan.memory_candidates WHERE id = %s""",
                (stored.candidate_id, stored.candidate_id),
            )
            assert cursor.fetchone() == ("PROMOTED", 1)
        assert stored.candidate_id not in store.promotable_candidate_ids()


def test_security_log_projection_is_durable_and_idempotent() -> None:
    assert DATABASE_URL is not None
    payload_hash = f"sha256:{uuid4().hex}"
    event = SecurityLogEvent(
        source_message_id=f"message-{uuid4()}",
        event_type="AGENT_GATEWAY_IAP_DENIED",
        control="AGENT_GATEWAY",
        severity="HIGH",
        actor_principal="agent-runtime@example.iam",
        destination_ref="projects/solvan-test/locations/europe-west1/services/actuator",
        safe_summary="AGENT_GATEWAY control observation; outcome=DENIED",
        payload_hash=payload_hash,
        policy_ref="iap.webServiceVersions.accessViaIAP",
        trace_id="0123456789abcdef0123456789abcdef",
        occurred_at=datetime(2026, 8, 8, 12, tzinfo=UTC),
    )
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.transaction():
            assert persist_security_log(connection, scope=SCOPE, event=event) is True
        with connection.transaction():
            assert persist_security_log(connection, scope=SCOPE, event=event) is False
        count = connection.execute(
            """SELECT count(*) FROM solvan.security_events
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND payload_hash = %s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                payload_hash,
            ),
        ).fetchone()
        assert count == (1,)
        audit_count = connection.execute(
            """SELECT count(*) FROM solvan.audit_events
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND stream_type = 'SECURITY_EVENT' AND payload_hash = %s""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                payload_hash,
            ),
        ).fetchone()
        assert audit_count == (1,)


def test_workspace_lifecycle_fences_policy_request_completion_and_rehydration() -> None:
    assert DATABASE_URL is not None
    policy_id = "pol_66666666666666666666666666"
    workspace_id = "wsp_66666666666666666666666666"
    content = "def leak():\n    return connection\n"
    content_hash = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_incident(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.policy_decisions
                  (organization_id, project_id, environment_id, id, policy_kind,
                   policy_version, input_ref, input_hash, decision, reason_code,
                   receipt_ref, receipt_hash)
                  VALUES (%s, %s, %s, %s, 'PROVIDER_ELIGIBILITY', 'v1',
                    'gs://runtime/eligibility/input.json', %s, 'ALLOW',
                    'PUBLIC_SYNTHETIC_ATTESTED',
                    'gs://runtime/eligibility/receipt.json', %s)""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    policy_id,
                    f"sha256:{'1' * 64}",
                    f"sha256:{'2' * 64}",
                ),
            )
        connection.commit()
        store = PostgresWorkspaceStore(connection)
        spec = WorkspaceSpec(
            scope=SCOPE,
            workspace_id=workspace_id,
            kind=WorkspaceKind.SERVICE,
            service_id="svc_00000000000000000000000000",
            provider=WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
            implementation_sdk="google-antigravity",
            implementation_sdk_version="0.1.13",
            provider_revision="antigravity-workspace-20260808-01",
            registry_agent_key="antigravity-workspace-provider",
            provider_agent_resource="https://antigravity.example.run.app",
            provider_service_identity="serviceAccount:antigravity@solvan-test.iam.gserviceaccount.com",
            implementation_sdk_distribution_hash=f"sha256:{'3' * 64}",
            provider_artifact_digest=f"sha256:{'4' * 64}",
            effective_network_policy_hash=f"sha256:{'5' * 64}",
            classification=WorkspaceClassification.PUBLIC,
            synthetic=True,
            synthetic_attestation_ref="gs://runtime/attestations/synthetic.json",
            synthetic_attestation_hash=f"sha256:{'6' * 64}",
            provider_eligibility_decision_id=policy_id,
            artifact_prefix=f"gs://runtime/workspaces/{workspace_id}/",
            input_manifest_ref=f"gs://runtime/workspaces/{workspace_id}/input.json",
            input_manifest_hash=f"sha256:{'7' * 64}",
            created_by_principal="serviceAccount:coordinator@solvan-test.iam.gserviceaccount.com",
        )
        ref = store.open(spec)
        assert store.open(spec) == ref

        materialized = WorkspaceInputMaterial(
            path="repository/app.py",
            content=content,
            content_hash=content_hash,
            media_type="text/x-python",
        )
        invocation = WorkspaceTaskInvocation.build(
            schema_version=1,
            request_id="req_11111111111111111111111111",
            run_id="run_22222222222222222222222222",
            invocation_id="inv_33333333333333333333333333",
            logical_step_key=f"workspace:{workspace_id}:repair:1",
            attempt=1,
            scope=SCOPE,
            workspace_id=workspace_id,
            workspace_generation=1,
            task_kind=WorkspaceTaskKind.REPAIR,
            provider=WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
            provider_resource="https://antigravity.example.run.app",
            provider_revision=spec.provider_revision,
            implementation_sdk_distribution_hash=(spec.implementation_sdk_distribution_hash),
            provider_artifact_digest=spec.provider_artifact_digest,
            workflow_version=1,
            deadline=datetime.now(UTC) + timedelta(minutes=5),
            budget=WorkspaceTaskBudget(
                max_runtime_seconds=120,
                max_model_calls=3,
                max_tool_calls=2,
                max_input_bytes=10_000,
                max_output_bytes=100_000,
            ),
            input_manifest_ref=spec.input_manifest_ref,
            input_manifest_hash=spec.input_manifest_hash,
            effective_tool_set_hash=f"sha256:{'8' * 64}",
            effective_network_policy_hash=spec.effective_network_policy_hash,
            allowed_tool_names=(
                "read_workspace_artifact",
                "write_candidate_artifact",
            ),
            input_artifacts=(
                WorkspaceArtifactDescriptor(
                    artifact_handle="wah_" + "1" * 32,
                    path=materialized.path,
                    object_ref="gs://runtime/workspaces/input/app.py",
                    content_hash=materialized.content_hash,
                    size_bytes=len(content.encode()),
                    media_type=materialized.media_type,
                    provenance_refs=("synthetic-fixture-v1",),
                ),
            ),
            input_materials=(materialized,),
            objective="Repair the deterministic synthetic leak.",
            task_parameters={
                "base_commit_sha": "c" * 40,
                "reproduction_command": "pytest -q tests/test_app.py",
                "test_command": "pytest -q tests/test_app.py",
                "allowed_file_globs": ["*.py", "tests/*.py"],
            },
            trace_id="9" * 32,
            span_id="a" * 16,
        )
        store.create_task(invocation)
        store.create_task(invocation)
        with connection.transaction():
            bind_test_agent_run(connection, run_id=invocation.run_id, agent_key="workspace-agent")
        store.mark_dispatched(invocation)
        result = WorkspaceTaskResult.build(
            schema_version=1,
            request_id=invocation.request_id,
            request_hash=invocation.request_hash,
            run_id=invocation.run_id,
            invocation_id=invocation.invocation_id,
            workspace_id=invocation.workspace_id,
            workspace_generation=invocation.workspace_generation,
            task_kind=invocation.task_kind,
            provider=invocation.provider,
            provider_revision=invocation.provider_revision,
            provider_service_revision="antigravity-workspace-00001-x7p",
            provider_boot_hash=f"sha256:{'b' * 64}",
            implementation_sdk="google-antigravity",
            implementation_sdk_version="0.1.13",
            implementation_sdk_distribution_hash=(invocation.implementation_sdk_distribution_hash),
            provider_artifact_digest=invocation.provider_artifact_digest,
            input_manifest_hash=invocation.input_manifest_hash,
            effective_tool_set_hash=invocation.effective_tool_set_hash,
            effective_network_policy_hash=invocation.effective_network_policy_hash,
            budget=invocation.budget,
            terminal_status=WorkspaceTerminalStatus.SUCCEEDED,
            summary="Produced a bounded repair candidate.",
            mechanism="The synthetic handler retained its connection.",
            base_commit_sha="c" * 40,
            unified_diff="diff --git a/app.py b/app.py\n",
            reproduction_command="pytest -q tests/test_app.py",
            test_command="pytest -q tests/test_app.py",
            hypotheses=(
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
            artifacts=(),
            tool_receipts=(),
            citations=("repository/app.py:1",),
            residual_risks=(),
            output_ref=f"gs://runtime/workspaces/{workspace_id}/result.json",
            completed_at=datetime.now(UTC),
            trace_id=invocation.trace_id,
            span_id=invocation.span_id,
        )
        assert store.record_provider_result(invocation=invocation, result=result) is True
        assert store.record_provider_result(invocation=invocation, result=result) is False
        pending_results = store.pending_antigravity_results(scope=SCOPE)
        assert len(pending_results) == 1
        store.assert_pending_result_matches(pending_results[0], result)
        store.complete_task(invocation=invocation, result=result)

        checkpoint_material = WorkspaceCheckpointMaterial(
            provider_request_hash=invocation.request_hash,
            provider_receipt_ref=result.output_ref,
            provider_receipt_hash=result.output_hash,
            provider_boot_hash=result.provider_boot_hash,
            provider_service_revision=result.provider_service_revision,
            artifact_manifest_ref=f"gs://runtime/workspaces/{workspace_id}/checkpoint.json",
            artifact_manifest_hash=f"sha256:{'d' * 64}",
            effective_tool_set_hash=invocation.effective_tool_set_hash,
            effective_network_policy_hash=invocation.effective_network_policy_hash,
            created_by_principal=spec.created_by_principal,
        )
        initial_lineage = store.next_manifest_lineage(ref)
        assert initial_lineage.sequence_no == 1
        assert initial_lineage.parent_manifest_ref == spec.input_manifest_ref
        assert initial_lineage.parent_manifest_hash == spec.input_manifest_hash
        checkpoint = store.checkpoint(ref, checkpoint_material, hibernate=True)
        with (
            pytest.raises(psycopg.errors.CheckViolation),
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                """INSERT INTO solvan.workspace_checkpoints
                      (organization_id, project_id, environment_id, id, workspace_id,
                       workspace_generation, sequence_no, event_kind,
                       parent_checkpoint_id, provider, implementation_sdk,
                       implementation_sdk_version,
                       implementation_sdk_distribution_hash, provider_artifact_digest,
                       provider_revision, provider_request_hash, provider_receipt_ref,
                       provider_receipt_hash, provider_boot_hash,
                       provider_service_revision, input_manifest_ref,
                       input_manifest_hash, artifact_manifest_ref,
                       artifact_manifest_hash, effective_tool_set_hash,
                       effective_network_policy_hash, created_by_principal)
                      SELECT organization_id, project_id, environment_id,
                       'wck_77777777777777777777777777', workspace_id,
                       workspace_generation, sequence_no + 1, 'REHYDRATION', id,
                       provider, implementation_sdk, implementation_sdk_version,
                       implementation_sdk_distribution_hash, %s, provider_revision,
                       provider_request_hash, provider_receipt_ref,
                       provider_receipt_hash, %s, %s, input_manifest_ref,
                       input_manifest_hash, artifact_manifest_ref,
                       artifact_manifest_hash, effective_tool_set_hash,
                       effective_network_policy_hash, created_by_principal
                      FROM solvan.workspace_checkpoints
                      WHERE organization_id = %s AND project_id = %s
                        AND environment_id = %s AND id = %s""",
                (
                    f"sha256:{'0' * 64}",
                    f"sha256:{'e' * 64}",
                    "antigravity-workspace-00002-drift",
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    checkpoint.checkpoint_id,
                ),
            )
        assert (
            store.latest_checkpoint(store.load(scope=SCOPE, workspace_id=workspace_id))
            == checkpoint
        )
        candidate = select_rehydration_candidate(scope=SCOPE, connection=connection)
        assert candidate.workspace_id == workspace_id
        assert candidate.checkpoint_id == checkpoint.checkpoint_id
        assert candidate.reconciliation_pending is False
        next_lineage = store.next_manifest_lineage(ref)
        assert next_lineage.sequence_no == 2
        assert next_lineage.parent_manifest_ref == checkpoint_material.artifact_manifest_ref
        assert next_lineage.parent_manifest_hash == checkpoint_material.artifact_manifest_hash
        assert store.load(scope=SCOPE, workspace_id=workspace_id).status.value == "HIBERNATED"
        resumed = store.resume(
            checkpoint,
            checkpoint_material.model_copy(
                update={
                    "provider_boot_hash": f"sha256:{'e' * 64}",
                    "provider_service_revision": "antigravity-workspace-00002-z9q",
                }
            ),
        )
        assert resumed.status.value == "OPEN"
        reconciliation = select_rehydration_candidate(scope=SCOPE, connection=connection)
        assert reconciliation.workspace_id == workspace_id
        assert reconciliation.checkpoint_id == checkpoint.checkpoint_id
        assert reconciliation.provider_service_revision == checkpoint.provider_service_revision
        assert reconciliation.reconciliation_pending is True
        rows = connection.execute(
            """SELECT event_kind, provider_boot_hash, provider_receipt_ref
              FROM solvan.workspace_checkpoints
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND workspace_id = %s ORDER BY sequence_no""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                workspace_id,
            ),
        ).fetchall()
        assert rows == [
            ("CHECKPOINT", f"sha256:{'b' * 64}", result.output_ref),
            ("REHYDRATION", f"sha256:{'e' * 64}", result.output_ref),
        ]

        deny_policy_id = "pol_55555555555555555555555555"
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.policy_decisions
                  (organization_id, project_id, environment_id, id, policy_kind,
                   policy_version, input_ref, input_hash, decision, reason_code,
                   receipt_ref, receipt_hash)
                  VALUES (%s, %s, %s, %s, 'PROVIDER_ELIGIBILITY', 'v1',
                    'gs://runtime/eligibility/deny-input.json', %s, 'DENY',
                    'CLASSIFICATION_NOT_ALLOWED',
                    'gs://runtime/eligibility/deny-receipt.json', %s)""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    deny_policy_id,
                    f"sha256:{'f' * 64}",
                    f"sha256:{'0' * 64}",
                ),
            )
        connection.commit()
        denied_spec = spec.model_copy(
            update={
                "workspace_id": "wsp_55555555555555555555555555",
                "provider_eligibility_decision_id": deny_policy_id,
            }
        )
        with pytest.raises(WorkspaceConflict, match="ALLOW"):
            store.open(denied_spec)


def test_a_committed_plan_is_re_dispatchable_after_a_crash_before_dispatch() -> None:
    """A fresh READY step carries no backoff, and used to be invisible forever."""

    assert DATABASE_URL is not None
    incident_id = "inc_00000000000000000000009001"
    supervisor_id = "run_00000000000000000000009001"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_investigation_run(
            connection,
            incident_id=incident_id,
            supervisor_run_id=supervisor_id,
            display_id="INC-9001",
            deduplication_key="stranded-ready-step",
        )
        workflow = PostgresWorkflowStore(connection)
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=SCOPE,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner="stranded-ready-coordinator",
            )
        assert lease is not None
        store = PostgresInvestigationStore(connection)
        # The tick commits the accepted plan and then dies before dispatching
        # it. Nothing has reserved a run, and no fallback backoff exists.
        with store.transaction():
            store.persist_accepted_plan(
                scope=SCOPE,
                incident_id=incident_id,
                supervisor_run_id=supervisor_id,
                authority=CoordinatorAuthority(lease.owner, lease.token, lease.workflow_version),
                plan=validate_investigation_plan(investigation_proposal(), investigation_policy()),
            )
        with workflow.transaction():
            workflow.release_lease(scope=SCOPE, lease=lease)
        connection.commit()
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT s.status, s.current_agent_run_id, s.retry_not_before
                  FROM solvan.investigation_steps s
                  JOIN solvan.investigation_plans p ON p.id = s.plan_id
                  WHERE p.incident_id = %s""",
                (incident_id,),
            )
            assert cursor.fetchall() == [("READY", None, None)]
        with store.transaction():
            assert incident_id in store.incidents_with_dispatchable_steps(scope=SCOPE, limit=50)
        # A replacement process reconstructs the work from Cloud SQL alone and
        # reserves exactly one attempt for the stranded step.
        with psycopg.connect(DATABASE_URL) as replacement:
            replacement_workflow = PostgresWorkflowStore(replacement)
            with replacement_workflow.transaction():
                recovered = replacement_workflow.acquire_lease(
                    scope=SCOPE,
                    aggregate_type=AggregateType.INCIDENT,
                    entity_id=incident_id,
                    owner="replacement-coordinator",
                )
            assert recovered is not None
            replacement_store = PostgresInvestigationStore(replacement)
            with replacement_store.transaction():
                dispatches = replacement_store.reserve_ready_dispatches(
                    scope=SCOPE,
                    incident_id=incident_id,
                    authority=CoordinatorAuthority(
                        recovered.owner, recovered.token, recovered.workflow_version
                    ),
                    batch_size=4,
                )
            assert len(dispatches) == 1
            # Reservation is the only writer, so a second sweep adds no run.
            with replacement_store.transaction():
                assert (
                    replacement_store.reserve_ready_dispatches(
                        scope=SCOPE,
                        incident_id=incident_id,
                        authority=CoordinatorAuthority(
                            recovered.owner, recovered.token, recovered.workflow_version
                        ),
                        batch_size=4,
                    )
                    == dispatches
                )
            with replacement_workflow.transaction():
                replacement_workflow.release_lease(scope=SCOPE, lease=recovered)
            replacement.commit()
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT count(*) FROM solvan.agent_runs
                  WHERE incident_id = %s AND investigation_step_id IS NOT NULL""",
                (incident_id,),
            )
            assert cursor.fetchone() == (1,)


def test_a_stranded_infrastructure_attempt_is_reaped_and_its_step_recovers() -> None:
    """The reaper used to omit this agent kind, stalling the incident forever."""

    assert DATABASE_URL is not None
    incident_id = "inc_00000000000000000000009002"
    supervisor_id = "run_00000000000000000000009002"
    plan_id = "ipl_00000000000000000000009002"
    step_id = "ist_00000000000000000000009002"
    run_id = "run_00000000000000000000009012"
    with psycopg.connect(DATABASE_URL) as connection:
        seed_investigation_run(
            connection,
            incident_id=incident_id,
            supervisor_run_id=supervisor_id,
            display_id="INC-9002",
            deduplication_key="stranded-infrastructure-step",
        )
        scope_values = (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.investigation_plans
                  (organization_id, project_id, environment_id, id, incident_id,
                   plan_version, objective, completion_condition, uncertainties_json,
                   content_hash, status, created_by_agent_run_id)
                  VALUES (%s, %s, %s, %s, %s, 1, 'inspect the change surface',
                    'revision metadata is available', '[]', %s, 'ACCEPTED', %s)""",
                (*scope_values, plan_id, incident_id, f"sha256:{'9' * 64}", supervisor_id),
            )
            cursor.execute(
                """INSERT INTO solvan.investigation_steps
                  (organization_id, project_id, environment_id, id, plan_id, step_key,
                   ordinal, kind, agent_key, agent_resource, agent_revision, scope_ref,
                   purpose, required, depends_on_json, budget_json,
                   allowed_tool_names_json, status, fallback_ref)
                  VALUES (%s, %s, %s, %s, %s, 'inspect-revisions', 1, 'INVOKE_AGENT',
                    'infrastructure-agent',
                    'projects/test/locations/europe-west1/reasoningEngines/infra-v1',
                    'infra-20260808-01', 'scope:payments', 'read revision metadata',
                    true, '[]', %s, '[]', 'READY', 'strategy://read-only-once')""",
                (
                    *scope_values,
                    step_id,
                    plan_id,
                    psycopg.types.json.Jsonb(
                        {
                            "deadline_ms": 60_000,
                            "max_tool_calls": 3,
                            "max_output_bytes": 16_000,
                            "max_model_calls": 1,
                            "max_replans": 0,
                        }
                    ),
                ),
            )
            # The tick reserved the attempt and died before the Runtime receipt.
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, incident_id,
                   investigation_step_id, logical_step_key, agent_key, agent_resource,
                   agent_revision, invocation_id, workflow_version, attempt, status,
                   deadline, budget_json, input_ref, input_hash)
                  VALUES (%s, %s, %s, %s, %s, %s,
                    'incident:9002:investigation:1:inspect-revisions',
                    'infrastructure-agent',
                    'projects/test/locations/europe-west1/reasoningEngines/infra-v1',
                    'infra-20260808-01', 'inv_00000000000000000000009012', 1, 1,
                    'CREATED', now() - interval '2 minutes', '{}',
                    'db://solvan/investigation-steps/ist_9002', %s)""",
                (*scope_values, run_id, incident_id, step_id, f"sha256:{'a' * 64}"),
            )
            cursor.execute(
                """UPDATE solvan.investigation_steps SET status = 'DISPATCHED',
                    current_agent_run_id = %s, started_at = now() WHERE id = %s""",
                (run_id, step_id),
            )
        connection.commit()

        runs = PostgresRuntimeRunStore(connection)
        investigations = PostgresInvestigationStore(connection)
        # Neither queue can see the attempt: pending() needs DISPATCHED/RUNNING,
        # and the step already carries current_agent_run_id.
        with connection.transaction():
            assert run_id not in {item.run_id for item in runs.pending(scope=SCOPE)}
        with investigations.transaction():
            assert incident_id not in investigations.incidents_with_dispatchable_steps(
                scope=SCOPE, limit=50
            )

        candidates = {item.run_id: item for item in runs.expired_created(scope=SCOPE)}
        assert run_id in candidates
        with connection.transaction():
            assert runs.expire_created(
                scope=SCOPE,
                run=candidates[run_id],
                error_class="DISPATCH_ACCEPTANCE_UNKNOWN",
            )
        with connection.cursor() as cursor:
            cursor.execute("SELECT status FROM solvan.agent_runs WHERE id = %s", (run_id,))
            assert cursor.fetchone() == ("TIMED_OUT",)
            cursor.execute(
                """SELECT status, current_agent_run_id, result_ref,
                    retry_not_before IS NOT NULL
                  FROM solvan.investigation_steps WHERE id = %s""",
                (step_id,),
            )
            assert cursor.fetchone() == (
                "READY",
                None,
                "runtime-error:DISPATCH_ACCEPTANCE_UNKNOWN",
                True,
            )
        with connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.investigation_steps
                  SET retry_not_before = now() - interval '1 second' WHERE id = %s""",
                (step_id,),
            )
        connection.commit()
        with investigations.transaction():
            assert incident_id in investigations.incidents_with_dispatchable_steps(
                scope=SCOPE, limit=50
            )


def test_a_refunded_inbox_claim_never_walks_a_valid_event_into_quarantine() -> None:
    assert DATABASE_URL is not None
    event_id = "evt_00000000000000000000009003"
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.inbox_events
                  (organization_id, project_id, environment_id, id, source,
                   source_event_id, event_type, payload_ref, payload_hash, received_at)
                  VALUES (%s, %s, %s, %s, 'outbox', 'contended-source-1',
                    'IncidentDetected', 'gs://fixture/contended.json', 'sha256:test',
                    now() - interval '1 hour')""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, event_id),
            )
        connection.commit()
        store = PostgresWorkflowStore(connection)
        # Sustained lease contention outlasts the bounded budget by a wide
        # margin and still leaves the command claimable.
        for _ in range(INBOX_CLAIM_ATTEMPT_BUDGET * 2):
            claimed = store.claim_inbox(scope=SCOPE, owner="coordinator-a", claim_ttl_ms=10_000)
            assert [item.event_id for item in claimed] == [event_id]
            store.release_inbox(
                scope=SCOPE, owner="coordinator-a", claim=claimed[0], refund_attempt=True
            )
            connection.commit()
        assert connection.execute(
            "SELECT attempts, processing_state FROM solvan.inbox_events WHERE id = %s",
            (event_id,),
        ).fetchone() == (0, "PENDING")

        # Genuine poison keeps every attempt it spends and is parked durably.
        for _ in range(INBOX_CLAIM_ATTEMPT_BUDGET):
            claimed = store.claim_inbox(scope=SCOPE, owner="coordinator-a", claim_ttl_ms=10_000)
            assert [item.event_id for item in claimed] == [event_id]
            connection.commit()
            with connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE solvan.inbox_events
                      SET claim_expires_at = now() - interval '1 second' WHERE id = %s""",
                    (event_id,),
                )
            connection.commit()
        # This test shares a real target schema with other cases, so a separate
        # valid event may remain claimable. The poison fence must nevertheless
        # park this exact event before any later claim selection.
        subsequent = store.claim_inbox(scope=SCOPE, owner="coordinator-a", claim_ttl_ms=10_000)
        if subsequent:
            store.release_inbox(
                scope=SCOPE, owner="coordinator-a", claim=subsequent[0], refund_attempt=True
            )
        connection.commit()
        assert connection.execute(
            "SELECT processing_state, error_class FROM solvan.inbox_events WHERE id = %s",
            (event_id,),
        ).fetchone() == ("FAILED", "POISON_EVENT_QUARANTINED")
        connection.rollback()


def seed_wakeup_case(
    connection: psycopg.Connection[object], *, case_id: str, incident_id: str, display: str
) -> None:
    scope_values = (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id)
    seed_incident(connection)
    with connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan.incidents
              (organization_id, project_id, environment_id, id, display_id,
               state_machine_version, state, severity, incident_class,
               primary_service_id, production_graph_snapshot_id, detected_at,
               detection_rule_id, detection_rule_version, deduplication_key,
               action_budget, repeated_action_limit)
              VALUES (%s, %s, %s, %s, %s, '1', 'MITIGATED', 'SEV2',
                'connection_exhaustion', 'svc_00000000000000000000000000',
                'pgs_00000000000000000000000000', now(), 'payments-http-5xx', 1,
                %s, 2, 1)
              ON CONFLICT DO NOTHING""",
            (*scope_values, incident_id, f"INC-{display}", f"wakeup-budget-{display}"),
        )
        cursor.execute(
            """INSERT INTO solvan.reliability_cases
              (organization_id, project_id, environment_id, id, display_id,
               state_machine_version, state, originating_incident_id,
               next_action_kind, next_action_at)
              VALUES (%s, %s, %s, %s, %s, '1', 'REPAIR_PLANNED', %s,
                'START_REPAIR', now())""",
            (*scope_values, case_id, f"REL-{display}", incident_id),
        )
    connection.commit()


def test_a_case_wakeup_that_keeps_poisoning_its_tick_is_quarantined() -> None:
    assert DATABASE_URL is not None
    case_id = "rel_00000000000000000000009004"
    wakeup_id = "wak_00000000000000000000009004"
    scope_values = (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id)
    with psycopg.connect(DATABASE_URL) as connection:
        seed_wakeup_case(
            connection,
            case_id=case_id,
            incident_id="inc_00000000000000000000009004",
            display="9004",
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.scheduled_wakeups
                  (organization_id, project_id, environment_id, id, case_id,
                   logical_step_key, wake_at, reason)
                  VALUES (%s, %s, %s, %s, %s, 'case:9004:start-repair:3',
                    now() - interval '1 minute', 'Start the exact repair attempt.')""",
                (*scope_values, wakeup_id, case_id),
            )
        connection.commit()
        store = PostgresReliabilityCaseStore(connection)

        # Every claim dies on the same permanent fault and lapses.
        for _ in range(WAKEUP_CLAIM_ATTEMPT_BUDGET):
            with store.transaction():
                claims = store.claim_due_wakeups(
                    scope=SCOPE, owner="coordinator-a", claim_ttl_ms=10_000, batch_size=50
                )
            assert wakeup_id in {item.wakeup_id for item in claims}
            with connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE solvan.scheduled_wakeups
                      SET claim_expires_at = now() - interval '1 second' WHERE id = %s""",
                    (wakeup_id,),
                )
            connection.commit()
        with store.transaction():
            exhausted = store.claim_due_wakeups(
                scope=SCOPE, owner="coordinator-a", claim_ttl_ms=10_000, batch_size=50
            )
        assert wakeup_id not in {item.wakeup_id for item in exhausted}
        assert connection.execute(
            """SELECT status, quarantined_at IS NOT NULL
              FROM solvan.scheduled_wakeups WHERE id = %s""",
            (wakeup_id,),
        ).fetchone() == ("QUARANTINED", True)
        # The quarantined row releases the one-active-step slot, so the case can
        # still be given a new, reviewed continuation.
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.scheduled_wakeups
                  (organization_id, project_id, environment_id, id, case_id,
                   logical_step_key, wake_at, reason)
                  VALUES (%s, %s, %s, 'wak_00000000000000000000009014', %s,
                    'case:9004:start-repair:3', now(), 'Reviewed continuation.')""",
                (*scope_values, case_id),
            )
            assert cursor.rowcount == 1
        connection.rollback()


def test_a_contended_case_wakeup_is_refunded_and_stays_claimable() -> None:
    assert DATABASE_URL is not None
    case_id = "rel_00000000000000000000009005"
    wakeup_id = "wak_00000000000000000000009005"
    scope_values = (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id)
    with psycopg.connect(DATABASE_URL) as connection:
        seed_wakeup_case(
            connection,
            case_id=case_id,
            incident_id="inc_00000000000000000000009005",
            display="9005",
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.scheduled_wakeups
                  (organization_id, project_id, environment_id, id, case_id,
                   logical_step_key, wake_at, reason)
                  VALUES (%s, %s, %s, %s, %s, 'case:9005:start-repair:3',
                    now() - interval '1 minute', 'Start the exact repair attempt.')""",
                (*scope_values, wakeup_id, case_id),
            )
        connection.commit()
        store = PostgresReliabilityCaseStore(connection)
        for _ in range(WAKEUP_CLAIM_ATTEMPT_BUDGET * 2):
            with store.transaction():
                claims = store.claim_due_wakeups(
                    scope=SCOPE, owner="coordinator-a", claim_ttl_ms=10_000, batch_size=50
                )
            mine = [item for item in claims if item.wakeup_id == wakeup_id]
            assert len(mine) == 1
            with store.transaction():
                store.release_claimed_wakeup(
                    scope=SCOPE, owner="coordinator-a", claim=mine[0], refund_attempt=True
                )
        assert connection.execute(
            "SELECT attempts, status FROM solvan.scheduled_wakeups WHERE id = %s",
            (wakeup_id,),
        ).fetchone() == (0, "PENDING")
        # A refund is still token-fenced: a stale owner cannot rewind the budget.
        with store.transaction():
            claims = store.claim_due_wakeups(
                scope=SCOPE, owner="coordinator-b", claim_ttl_ms=10_000, batch_size=50
            )
        taken = [item for item in claims if item.wakeup_id == wakeup_id]
        assert len(taken) == 1
        with pytest.raises(ReliabilityCaseConflict), store.transaction():
            store.release_claimed_wakeup(
                scope=SCOPE, owner="coordinator-a", claim=taken[0], refund_attempt=True
            )
        connection.rollback()


def test_live_integration_projection_carries_every_key_the_console_reads() -> None:
    """Shape parity between the live projection and the local fixture.

    The console renders one Integrations component against either source. When
    the live projection silently omitted `providers`, the route threw during
    render on real data while every fixture-backed test passed, so the failure
    was only observable by opening the page against a database.
    """

    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection, connection.transaction():
        live = live_console_snapshot(connection, scope=SCOPE)["integration"]

    assert set(live) == set(integration_fixture())
    # Absence is the failure mode being guarded, so an empty catalog is not a
    # passing shape: the console offers no onboarding at all without it.
    assert live["providers"]
    assert live["providers"] == integration_fixture()["providers"]
