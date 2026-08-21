"""Alert Triage Phase-1 durability against PostgreSQL 16."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from solvan.application.alert_policy_products import AlertPolicyTemplateV1
from solvan.application.alert_triage import (
    AlertIngressError,
    VerifiedPushIdentity,
    canonicalize_cloud_monitoring_push,
)
from solvan.application.default_tool_catalog import (
    alert_triage_profile,
    catalog_principals,
    catalog_tools,
)
from solvan.domain import Scope
from solvan.persistence.alert_triage import AlertTriageRepository, SourceRegistration
from solvan.persistence.alert_triage_types import SourceQualificationDelivery
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")
SCOPE = Scope(
    "org_00000000000000000000000002",
    "prj_00000000000000000000000002",
    "env_00000000000000000000000002",
)
CONNECTION_ID = "con_00000000000000000000000002"
IDENTITY = VerifiedPushIdentity(
    issuer="https://accounts.google.com",
    subject="123",
    email="push@metrics-scope.iam.gserviceaccount.com",
    audience="https://alerts.example/internal",
)
SCOPE_TUPLE = (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id)


@pytest.fixture
def connection():
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as database, database.transaction(force_rollback=True):
        database.execute(
            "INSERT INTO solvan.organizations VALUES (%s,'Alert test',now())",
            (SCOPE.organization_id,),
        )
        database.execute(
            """INSERT INTO solvan.projects
                 (organization_id,id,display_name,gcp_project_id)
               VALUES (%s,%s,'Alert test','alert-test')""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        database.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Alert test','europe-west1','INTERNAL')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        database.execute(
            """INSERT INTO solvan_scale.cell_eligibility_profiles
                 (eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
                  allowed_provider_launch_stages,encryption_profile_hash,
                  support_access_allowed,allowed_recovery_regions,approved_ref)
               VALUES (%s,ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],%s,
                       false,ARRAY['europe-west1'],'ref_alert_test')""",
            ("sha256:" + "1" * 64, "sha256:" + "2" * 64),
        )
        database.execute(
            """INSERT INTO solvan_scale.cells
                 (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
                  capacity_profile_hash,data_policy_hash,eligibility_profile_hash,
                  deployment_manifest_hash)
               VALUES ('cell_alert_test','OSS_SINGLE_TENANT','europe-west1','alert-test',
                       'READY',1,%s,%s,%s,%s)""",
            (
                "sha256:" + "3" * 64,
                "sha256:" + "4" * 64,
                "sha256:" + "1" * 64,
                "sha256:" + "5" * 64,
            ),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_eligibility_requirements
                 (organization_id,requirement_hash,allowed_classifications,
                  allowed_residency_regions,allowed_provider_launch_stages,
                  encryption_profile_hash,support_access_allowed,
                  allowed_recovery_regions,approved_ref)
               VALUES (%s,%s,ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
                       %s,false,ARRAY['europe-west1'],'ref_alert_tenant')""",
            (SCOPE.organization_id, "sha256:" + "6" * 64, "sha256:" + "2" * 64),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_placements
                 (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
                  home_region,classification_ceiling,eligibility_requirement_hash,
                  policy_hash,encryption_profile_hash,activated_at)
               VALUES (%s,1,'cell_alert_test','ACTIVE',true,'OSS_SINGLE_TENANT',
                       'europe-west1','INTERNAL',%s,%s,%s,now())""",
            (
                SCOPE.organization_id,
                "sha256:" + "6" * 64,
                "sha256:" + "7" * 64,
                "sha256:" + "2" * 64,
            ),
        )
        database.execute(
            """INSERT INTO solvan.tenant_connections
                 (organization_id,project_id,environment_id,id,display_name,kind,provider,
                  credential_posture,residency_region,classification,
                  connection_epoch,lifecycle,availability,availability_reason_code,
                  availability_explanation,availability_remediation_kind,
                  availability_receipt_ref,last_probe_at,last_probe_result,last_success_at,
                  created_by_principal)
               VALUES (%s,%s,%s,%s,'Alerts','GCP_NATIVE','CLOUD_MONITORING',
                       'CUSTOMER_SIDE_NONE','europe-west1','INTERNAL',1,'ENABLED','READY',
                       NULL,NULL,NULL,'probe://alert-test',now(),'SUCCEEDED',now(),'admin')""",
            (*SCOPE_TUPLE, CONNECTION_ID),
        )
        database.execute(
            """INSERT INTO solvan_onboarding.environment_external_project_bindings
                 (organization_id,project_id,environment_id,external_project_id,binding_epoch,
                  deciding_principal,decision_ref)
               VALUES (%s,%s,%s,'payments-prod',1,'admin','ref_project_binding')""",
            SCOPE_TUPLE,
        )
        database.execute(
            """INSERT INTO solvan_onboarding.connection_external_project_coverage
                 (organization_id,project_id,environment_id,connection_id,capability_class,
                  external_project_id,connection_epoch,observed_at,probe_receipt_ref)
               VALUES (%s,%s,%s,%s,'METRIC_READ','payments-prod',1,now(),
                       'probe://metrics-read')""",
            (*SCOPE_TUPLE, CONNECTION_ID),
        )
        yield database


def _push(*, message_id: str, state: str, ended_at: str | None = None) -> bytes:
    incident = {
        "incident_id": "incident-42",
        "state": state,
        "started_at": "2026-08-13T12:00:00Z",
        "scoping_project_id": "metrics-scope",
        "resource": {
            "type": "cloud_run_revision",
            "labels": {"project_id": "payments-prod", "service_name": "payments-api"},
        },
        "policy_name": "payments-errors",
        "condition_name": "http-5xx",
        "severity": "critical",
    }
    if ended_at is not None:
        incident["ended_at"] = ended_at
    data = base64.b64encode(json.dumps({"version": "1.2", "incident": incident}).encode())
    return json.dumps(
        {
            "message": {
                "messageId": message_id,
                "publishTime": "2026-08-13T12:00:05Z",
                "data": data.decode(),
            },
            "subscription": "projects/metrics-scope/subscriptions/solvan-alerts",
        }
    ).encode()


def _source(repository: AlertTriageRepository) -> str:
    source_id = repository.register_cloud_monitoring_source(
        scope=SCOPE,
        registration=SourceRegistration(
            connection_id=CONNECTION_ID,
            connection_epoch=1,
            scoping_project_id="metrics-scope",
            topic_name="projects/metrics-scope/topics/alerts",
            topic_binding_receipt_ref="ref_topic_binding",
            subscription_name="projects/metrics-scope/subscriptions/solvan-alerts",
            push_principal="push@metrics-scope.iam.gserviceaccount.com",
            oidc_audience="https://alerts.example/internal",
            source_material_hash="sha256:" + "8" * 64,
            configuration_digest="sha256:" + "7" * 64,
            pubsub_token_minting_receipt_ref="receipt://pubsub-token-minting/1",
            classification="INTERNAL",
            retention_policy_revision="retention/alert-v1",
        ),
        actor_principal="connection-lifecycle",
        idempotency_key="source-registration-0001",
        request_hash="sha256:" + "9" * 64,
    )
    binding = repository.source_binding(
        scope=SCOPE, connection_id=CONNECTION_ID, require_qualified=False
    )
    repository.qualify_source_binding(
        scope=SCOPE,
        delivery=SourceQualificationDelivery(
            source_binding_id=binding.source_binding_id,
            source_binding_epoch=binding.binding_epoch,
            pubsub_message_id="qualification-message-1",
            subscription_name=binding.subscription_name,
            authenticated_push_principal="serviceAccount:push@metrics-scope.iam.gserviceaccount.com",
            oidc_audience=binding.oidc_audience,
            envelope_hash="sha256:" + "6" * 64,
            configuration_digest="sha256:" + "7" * 64,
        ),
    )
    return source_id


def test_ingress_is_idempotent_and_projects_close_dominantly(connection) -> None:
    repository = AlertTriageRepository(connection)
    source_id = _source(repository)
    binding = repository.source_binding(scope=SCOPE, connection_id=CONNECTION_ID)
    assert binding.source_identity_id == source_id

    opened = repository.record_committed_delivery(
        binding=binding,
        identity=IDENTITY,
        alert=canonicalize_cloud_monitoring_push(_push(message_id="message-open", state="open")),
    )
    duplicate = repository.record_committed_delivery(
        binding=binding,
        identity=IDENTITY,
        alert=canonicalize_cloud_monitoring_push(_push(message_id="message-open", state="open")),
    )
    closed = repository.record_committed_delivery(
        binding=binding,
        identity=IDENTITY,
        alert=canonicalize_cloud_monitoring_push(
            _push(
                message_id="message-closed",
                state="closed",
                ended_at="2026-08-13T12:04:00Z",
            )
        ),
    )

    assert opened.created is True
    assert duplicate.created is False
    assert duplicate.delivery_id == opened.delivery_id
    assert duplicate.semantic_event_id == opened.semantic_event_id
    assert closed.provider_generation_id == opened.provider_generation_id
    assert opened.provider_generation_id is not None
    projection = repository.project_provider_generation(
        scope=SCOPE,
        provider_generation_id=opened.provider_generation_id,
    )
    replay = repository.project_provider_generation(
        scope=SCOPE,
        provider_generation_id=opened.provider_generation_id,
    )
    assert projection.outcome == "UNMATCHED"
    assert projection.episode_id is None
    assert projection.created is True
    assert replay == type(replay)(
        provider_generation_id=opened.provider_generation_id,
        outcome="UNMATCHED",
        episode_id=None,
        selected_policy_key=None,
        created=False,
    )
    counts = connection.execute(
        """SELECT
             (SELECT count(*) FROM solvan_alerts.alert_ingress_deliveries),
             (SELECT count(*) FROM solvan_alerts.alert_ingress_receive_attempts),
             (SELECT count(*) FROM solvan_alerts.alert_events),
             (SELECT count(*) FROM solvan_alerts.alert_provider_generations),
             (SELECT count(*) FROM solvan_alerts.alert_provider_generation_occurrences),
             (SELECT count(*) FROM solvan_alerts.alert_generation_outcomes),
             (SELECT count(*) FROM solvan_alerts.alert_episodes),
             (SELECT provider_state_projection FROM solvan_alerts.alert_provider_generations)"""
    ).fetchone()
    assert counts == (2, 3, 2, 1, 2, 1, 0, "CLOSED")


def test_wrong_monitored_project_fails_before_semantic_admission(connection) -> None:
    repository = AlertTriageRepository(connection)
    _source(repository)
    binding = repository.source_binding(scope=SCOPE, connection_id=CONNECTION_ID)
    body = _push(message_id="wrong-project", state="open").replace(
        b"payments-prod", b"attacker-prod"
    )
    # Replacing bytes does not alter the base64 payload, so build a decoded
    # variant explicitly to exercise the authorization boundary.
    outer = json.loads(body)
    payload = json.loads(base64.b64decode(outer["message"]["data"]))
    payload["incident"]["resource"]["labels"]["project_id"] = "attacker-prod"
    outer["message"]["data"] = base64.b64encode(json.dumps(payload).encode()).decode()
    with pytest.raises(AlertIngressError, match="MONITORED_PROJECT_NOT_AUTHORIZED"):
        repository.record_committed_delivery(
            binding=binding,
            identity=IDENTITY,
            alert=canonicalize_cloud_monitoring_push(json.dumps(outer).encode()),
        )
    assert connection.execute("SELECT count(*) FROM solvan_alerts.alert_events").fetchone() == (0,)


def test_policy_template_is_immutable_and_never_creates_policy_authority(connection) -> None:
    repository = AlertTriageRepository(connection)
    policy_count_before = connection.execute(
        "SELECT count(*) FROM solvan_operability.trigger_policy_revisions"
    ).fetchone()
    template = AlertPolicyTemplateV1.model_validate(
        {
            "template_key": "cloud-run-http-errors",
            "version": "1",
            "publisher_ref": "solvan:first-party",
            "policy_skeleton": {"mode": "POLICY_ESCALATED", "threshold": "${error_ratio}"},
            "calibration_slots": ["error_ratio", "window_ms", "connection_id"],
            "example_values": {"error_ratio": 0.02, "window_ms": 300_000},
            "compatibility": "cloud-monitoring/1.2",
        }
    )
    assert repository.register_alert_policy_template(
        scope=SCOPE,
        template=template,
        classification="INTERNAL",
        retention_policy_revision="retention/alert-policy-template-v1",
    )
    assert not repository.register_alert_policy_template(
        scope=SCOPE,
        template=template,
        classification="INTERNAL",
        retention_policy_revision="retention/alert-policy-template-v1",
    )
    projection = repository.list_alert_policy_templates(scope=SCOPE)
    assert projection["rows"][0]["creates"] == "DRAFT_ONLY"
    assert projection["rows"][0]["example_values_label"] == "EXAMPLE — NOT A DEFAULT"
    assert (
        connection.execute(
            "SELECT count(*) FROM solvan_operability.trigger_policy_revisions"
        ).fetchone()
        == policy_count_before
    )


# The Fleet Alert-policy projections had no database-lane coverage at all: every
# console test ran against the local development fixture, so the deployed
# queries were never parsed by PostgreSQL. One of them selected a table that was
# not in its FROM clause and two columns that do not exist, and shipped.

ALERT_MATERIAL_HASH = "sha256:" + "a" * 64
POLICY_HASH = "sha256:" + "b" * 64
CATALOG_HASH = "sha256:" + "c" * 64
POLICY_KEY = "payments-http-errors"
POLICY_VERSION = "4"
EVALUATION_ID = "tev_01K2M7Y8F90H6J1K3M5N7P9QRS"
APPROVAL_ID = "tap_01K2M7Y8F90H6J1K3M5N7P9QRS"
LIFECYCLE_PRINCIPAL = "user:policy-lifecycle@example.com"


def _seed_alert_policy(connection, *, mark_eligible: bool = True) -> None:
    """Install one approved Alert policy on its exact bound source connection."""

    catalog = PostgresToolCatalogStore(connection)
    for principal in catalog_principals(manifest_hash=CATALOG_HASH):
        catalog.register_principal(principal)
    for revision in catalog_tools(
        network_policy_hash=CATALOG_HASH,
        approval_ref="approval://catalog/1",
        evaluation_ref="evaluation://catalog/1",
    ):
        catalog.publish_tool(revision)
    catalog.publish_profile(
        scope=SCOPE,
        profile=alert_triage_profile(
            approval_ref="approval://catalog/1",
            evaluation_ref="evaluation://catalog/1",
        ),
    )
    connection.execute(
        """INSERT INTO solvan_operability.trigger_policy_revisions
             (organization_id,project_id,environment_id,policy_key,version,
              owner_department,trigger_kind,source_connection_id,source_connection_epoch,
              source_tool_key,source_tool_version,source_agent_key,source_identity_ref,
              source_capability_class,target_selector_ref,incident_class,severity,
              deduplication_dimension,action_budget,repeated_action_limit,
              profile_key,profile_version,delay_ms,cooldown_ms,maximum_pending_per_target,
              supersession,region,classification_ceiling,lifecycle,author_principal,
              policy_hash)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(policy_key)s,
                   %(version)s,'Reliability Platform','ALERT_OPENED',%(connection_id)s,1,
                   'cloud_monitoring_query','1','evidence-agent',
                   'identity://evidence-agent/1','METRIC_READ',%(selector)s,
                   'payment_errors','SEV2','target',2,1,
                   'alert-triage-read-compute-v1','1',0,0,3,'LATEST_WAITING_PER_TARGET',
                   'europe-west1','INTERNAL','DRAFT',%(author)s,%(policy_hash)s)""",
        {
            **SCOPE.canonical_dict(),
            "policy_key": POLICY_KEY,
            "version": POLICY_VERSION,
            "connection_id": CONNECTION_ID,
            "selector": f"selector://alert-policy/{ALERT_MATERIAL_HASH.removeprefix('sha256:')}@1",
            "author": "user:policy-author@example.com",
            "policy_hash": POLICY_HASH,
        },
    )
    connection.execute(
        """INSERT INTO solvan_alerts.alert_policy_revisions
             (organization_id,project_id,environment_id,policy_key,policy_version,
              policy_hash,alert_material_hash,source_kind,selector_json,target_mapping_json,
              severity_mapping_json,mode,triage_profile_ref,incident_profile_ref,
              triage_budget_json,incident_admission_budget_json,episode_horizon_ms,
              classification,retention_policy_revision)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(policy_key)s,
                   %(version)s,%(policy_hash)s,%(material)s,'CLOUD_MONITORING',
                   '{}'::jsonb,'{}'::jsonb,'{}'::jsonb,'TRIAGE',
                   'alert-triage-read-compute-v1@1','incident-read-v1@1',
                   '{}'::jsonb,'{}'::jsonb,3600000,'INTERNAL','retention/alert-policy-v1')""",
        {
            **SCOPE.canonical_dict(),
            "policy_key": POLICY_KEY,
            "version": POLICY_VERSION,
            "policy_hash": POLICY_HASH,
            "material": ALERT_MATERIAL_HASH,
        },
    )
    # Evaluation and approval reference the revision, and the revision then
    # carries their identifiers, so the seed walks the same order the authoring
    # service does rather than asserting an approved row into existence.
    connection.execute(
        """INSERT INTO solvan_operability.trigger_policy_evaluations
             (organization_id,project_id,environment_id,id,policy_key,policy_version,
              policy_hash,suite_version,decision,passed_cases,failed_cases,
              receipt_ref,receipt_hash,evaluator_principal,reason_codes_json)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(evaluation_id)s,
                   %(policy_key)s,%(version)s,%(policy_hash)s,'alert-suite@1','PASS',6,0,
                   'receipt://alert-policy-evaluation/4',%(receipt_hash)s,
                   %(evaluator)s,'["SUITE_PASSED"]'::jsonb)""",
        {
            **SCOPE.canonical_dict(),
            "evaluation_id": EVALUATION_ID,
            "policy_key": POLICY_KEY,
            "version": POLICY_VERSION,
            "policy_hash": POLICY_HASH,
            "receipt_hash": "sha256:" + "e" * 64,
            "evaluator": "user:policy-evaluator@example.com",
        },
    )
    connection.execute(
        """INSERT INTO solvan_operability.trigger_policy_approvals
             (organization_id,project_id,environment_id,id,policy_key,policy_version,
              policy_hash,evaluation_ref,approver_principal,decision,reason,
              decision_request_id)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(approval_id)s,
                   %(policy_key)s,%(version)s,%(policy_hash)s,%(evaluation_id)s,
                   %(approver)s,'APPROVE','Independently reviewed.',
                   'alert-policy-approval-1')""",
        {
            **SCOPE.canonical_dict(),
            "approval_id": APPROVAL_ID,
            "evaluation_id": EVALUATION_ID,
            "policy_key": POLICY_KEY,
            "version": POLICY_VERSION,
            "policy_hash": POLICY_HASH,
            "approver": "user:policy-approver@example.com",
        },
    )
    connection.execute(
        """UPDATE solvan_operability.trigger_policy_revisions
              SET lifecycle='APPROVED',evaluation_ref=%(evaluation_id)s,
                  approval_ref=%(approval_id)s,approved_by_principal=%(approver)s,
                  approved_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND policy_key=%(policy_key)s
              AND version=%(version)s""",
        {
            **SCOPE.canonical_dict(),
            "evaluation_id": EVALUATION_ID,
            "approval_id": APPROVAL_ID,
            "policy_key": POLICY_KEY,
            "version": POLICY_VERSION,
            "approver": "user:policy-approver@example.com",
        },
    )
    if not mark_eligible:
        return
    # The database refuses to let the author or the approver mark their own
    # policy eligible, so eligibility is decided by a third bound principal.
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(principal)s,
                   'TRIGGER_POLICY_LIFECYCLE_MANAGER','Reliability Platform','user:seed')""",
        {**SCOPE.canonical_dict(), "principal": LIFECYCLE_PRINCIPAL},
    )
    connection.execute(
        """INSERT INTO solvan_operability.trigger_policy_lifecycle_decisions
             (organization_id,project_id,environment_id,id,policy_key,policy_version,
              policy_hash,lifecycle_epoch,expected_prior_lifecycle_epoch,operation,
              actor_principal,idempotency_key,request_hash,reason_code)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                   'tpl_01K2M7Y8F90H6J1K3M5N7P9QRS',%(policy_key)s,%(version)s,
                   %(policy_hash)s,1,0,'MARK_ELIGIBLE',%(principal)s,
                   'alert-policy-eligible-1',%(request_hash)s,'INDEPENDENTLY_APPROVED')""",
        {
            **SCOPE.canonical_dict(),
            "policy_key": POLICY_KEY,
            "version": POLICY_VERSION,
            "policy_hash": POLICY_HASH,
            "principal": LIFECYCLE_PRINCIPAL,
            "request_hash": "sha256:" + "d" * 64,
        },
    )
    connection.execute(
        """INSERT INTO solvan_operability.trigger_policy_current_lifecycles
             (organization_id,project_id,environment_id,policy_key,policy_version,
              policy_hash,lifecycle_epoch,availability,decision_id,decision_operation)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(policy_key)s,
                   %(version)s,%(policy_hash)s,1,'ELIGIBLE',
                   'tpl_01K2M7Y8F90H6J1K3M5N7P9QRS','MARK_ELIGIBLE')""",
        {
            **SCOPE.canonical_dict(),
            "policy_key": POLICY_KEY,
            "version": POLICY_VERSION,
            "policy_hash": POLICY_HASH,
        },
    )


def _seed_quota(connection, *, version: int, concurrent: int, active: int, bind: bool) -> None:
    now = datetime.now(UTC)
    connection.execute(
        """INSERT INTO solvan_scale.tenant_quota_policy_revisions
             (organization_id,version,policy_hash,effective_at,approval_ref)
           VALUES (%s,%s,%s,%s,%s)""",
        (
            SCOPE.organization_id,
            version,
            f"sha256:{version:064x}",
            now - timedelta(minutes=1),
            f"ref_quota_{version}",
        ),
    )
    connection.execute(
        """INSERT INTO solvan_scale.tenant_quota_limits
             (organization_id,policy_version,resource_kind,window_seconds,
              sustained_limit,burst_limit,maximum_concurrent,exhaustion_behavior)
           VALUES (%s,%s,'MODEL_REQUEST',60,10,10,%s,'WAIT')""",
        (SCOPE.organization_id, version, concurrent),
    )
    connection.execute(
        """INSERT INTO solvan_scale.tenant_quota_counters
             (organization_id,policy_version,resource_kind,token_nanounits,
              active_reservations,refill_at,counter_epoch)
           VALUES (%s,%s,'MODEL_REQUEST',10000000000,%s,%s,1)""",
        (SCOPE.organization_id, version, active, now),
    )
    if bind:
        connection.execute(
            """INSERT INTO solvan_scale.tenant_quota_policy_bindings
                 (organization_id,binding_epoch,decision,policy_version,decision_ref)
               VALUES (%s,%s,'ACTIVATE',%s,%s)""",
            (SCOPE.organization_id, version, version, f"ref_bind_{version}"),
        )


def test_alert_policy_projections_execute_against_the_contract_schema(connection) -> None:
    """Every Fleet Alert-policy read must survive PostgreSQL parse and planning.

    This is the gate the shipped defect walked through: the console suite runs
    entirely on the development fixture, so a query naming a table absent from
    its own FROM clause raised only in a deployment. An empty tenant is enough —
    PostgreSQL resolves every relation and column before it looks for rows.
    """

    repository = AlertTriageRepository(connection)

    policies = repository.list_alert_policies(scope=SCOPE)
    capacity = repository.get_alert_capacity(scope=SCOPE)
    templates = repository.list_alert_policy_templates(scope=SCOPE)
    recommendations = repository.list_alert_policy_recommendations(scope=SCOPE)
    missing = repository.get_alert_policy_revision(scope=SCOPE, policy_key="absent", version="1")

    assert policies == {"schema_version": 1, "rows": []}
    assert templates["rows"] == recommendations["rows"] == []
    assert missing is None
    assert capacity["status"] == "UNAVAILABLE"


def test_alert_policy_row_carries_its_exact_source_binding_and_approval(connection) -> None:
    """Specification 21 §10.5 requires source health and approval on the list itself."""

    _seed_quota(connection, version=1, concurrent=4, active=0, bind=True)
    _seed_alert_policy(connection)
    repository = AlertTriageRepository(connection)

    row = repository.list_alert_policies(scope=SCOPE)["rows"][0]

    assert row["policy_key"] == POLICY_KEY
    assert row["version"] == POLICY_VERSION
    assert row["mode"] == "TRIAGE"
    assert row["lifecycle"] == "APPROVED"
    assert row["availability"] == "ELIGIBLE"
    assert row["connection_id"] == CONNECTION_ID
    assert row["connection_health"] == "READY"
    assert row["connection_binding_current"] is True
    assert row["approved_by_principal"] == "user:policy-approver@example.com"
    assert row["approved_by_principal"] != row["author_principal"]
    assert row["approval_ref"] == APPROVAL_ID
    assert row["evaluation_ref"] == EVALUATION_ID
    assert row["current_capacity"] == "AVAILABLE"


def test_alert_policy_source_health_follows_the_bound_connection_epoch(connection) -> None:
    """A re-issued connection leaves the policy bound to a superseded epoch.

    Reporting the current connection's health against a stale binding would tell
    an operator a policy can admit when the admission path fences it out.
    """

    _seed_alert_policy(connection)
    connection.execute(
        """UPDATE solvan.tenant_connections
              SET connection_epoch=2,availability='DEGRADED',
                  availability_reason_code='PROBE_FAILED',
                  availability_explanation='the newest probe did not succeed',
                  availability_remediation_kind='RETRY_PROBE'
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s AND id=%s""",
        (*SCOPE_TUPLE, CONNECTION_ID),
    )

    row = AlertTriageRepository(connection).list_alert_policies(scope=SCOPE)["rows"][0]

    assert row["connection_epoch"] == 1
    assert row["connection_binding_current"] is False
    assert row["connection_health"] == "DEGRADED"
    assert row["connection_reason_code"] == "PROBE_FAILED"


def test_alert_policy_revision_detail_projects_its_bound_connection(connection) -> None:
    _seed_alert_policy(connection)

    detail = AlertTriageRepository(connection).get_alert_policy_revision(
        scope=SCOPE, policy_key=POLICY_KEY, version=POLICY_VERSION
    )

    assert detail is not None
    assert detail["policy"]["mode"] == "TRIAGE"
    assert detail["policy"]["approved_by_principal"] == "user:policy-approver@example.com"
    assert detail["connections"] == [
        {
            "connection_id": CONNECTION_ID,
            "connection_epoch": 1,
            "health": "READY",
            "reason_code": None,
            "lifecycle": "ENABLED",
            "binding_current": True,
            "last_probe_at": detail["connections"][0]["last_probe_at"],
            "last_probe_result": "SUCCEEDED",
        }
    ]
    assert "connection_health" not in detail["policy"]


def test_alert_capacity_reads_only_the_currently_bound_quota_policy(connection) -> None:
    """Superseded quota revisions must not contribute headroom.

    Summing every version reported a ceiling no reservation path would honour:
    two revisions of a four-request limit read as eight, so an exhausted tenant
    was shown as available.
    """

    _seed_quota(connection, version=1, concurrent=4, active=4, bind=True)
    _seed_quota(connection, version=2, concurrent=4, active=1, bind=True)

    capacity = AlertTriageRepository(connection).get_alert_capacity(scope=SCOPE)

    assert capacity["limit"] == 4
    assert capacity["active_reservations"] == 1
    assert capacity["status"] == "AVAILABLE"
    assert capacity["reason_code"] is None


def test_alert_capacity_reports_exhaustion_at_the_bound_ceiling(connection) -> None:
    _seed_quota(connection, version=1, concurrent=4, active=4, bind=True)

    capacity = AlertTriageRepository(connection).get_alert_capacity(scope=SCOPE)

    assert capacity["status"] == "EXHAUSTED"
    assert capacity["reason_code"] == "MODEL_REQUEST_CONCURRENCY_EXHAUSTED"


def test_alert_capacity_refuses_when_the_bound_quota_policy_is_revoked(connection) -> None:
    """A revoked policy leaves no ceiling to report, not a zero one."""

    _seed_quota(connection, version=1, concurrent=4, active=0, bind=True)
    connection.execute(
        """INSERT INTO solvan_scale.tenant_quota_policy_bindings
             (organization_id,binding_epoch,decision,policy_version,decision_ref)
           VALUES (%s,2,'REVOKE',NULL,'ref_revoke')""",
        (SCOPE.organization_id,),
    )

    capacity = AlertTriageRepository(connection).get_alert_capacity(scope=SCOPE)

    assert capacity["status"] == "UNAVAILABLE"
    assert capacity["reason_code"] == "QUOTA_POLICY_UNAVAILABLE"
    assert capacity["limit"] == 0
