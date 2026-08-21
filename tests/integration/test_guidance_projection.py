"""The console guidance projection shows current state, never history.

Every key used to project every revision, so the Skills catalog rendered
each pack once per superseded version — dozens of DEPRECATED rows that read
as duplicated, deprecated skills. The projection now returns each key's
approved head plus any in-flight draft; superseded revisions stay durable
and queryable, just not in the catalog.
"""

from __future__ import annotations

import os
from typing import Any

import psycopg
import pytest

from solvan.domain import Scope
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
HASH = "sha256:" + "c" * 64


def _seed(connection: psycopg.Connection[Any]) -> None:
    connection.execute(
        "INSERT INTO solvan.organizations(id,display_name) VALUES (%s,'T') ON CONFLICT DO NOTHING",
        (SCOPE.organization_id,),
    )
    connection.execute(
        "INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id) "
        "VALUES (%s,%s,'T','solvan-test') ON CONFLICT DO NOTHING",
        (SCOPE.organization_id, SCOPE.project_id),
    )
    connection.execute(
        "INSERT INTO solvan.environments(organization_id,project_id,id,display_name,region,"
        "classification) VALUES (%s,%s,%s,'T','europe-west1','INTERNAL') ON CONFLICT DO NOTHING",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    for key, name in (("payments.pool-check", "Pool check"), ("payments.draft-flow", "Draft flow")):
        connection.execute(
            """INSERT INTO solvan_operability.guidance_definitions
                 (organization_id,project_id,environment_id,guidance_key,display_name,
                  owner_department)
               VALUES (%s,%s,%s,%s,%s,'Payments SRE')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, key, name),
        )
    connection.execute(
        """INSERT INTO solvan_operability.tool_profile_revisions
             (schema_version,canonicalization_version,profile_key,version,purpose,
              allowed_agent_key,maximum_total_calls,maximum_parallel_calls,
              maximum_read_window_ms,maximum_aggregate_evidence_bytes,
              data_classification_ceiling,runtime_region,lifecycle,profile_material_hash)
           VALUES (2,1,'evidence.core','1','projection test','evidence-agent',3,1,60000,
                   1048576,'INTERNAL','europe-west1','DRAFT',%s)""",
        (HASH,),
    )
    for version, lifecycle, supersedes in ((1, "DEPRECATED", None), (2, "DRAFT", "1")):
        connection.execute(
            """INSERT INTO solvan_operability.guidance_revisions
                 (organization_id,project_id,environment_id,guidance_key,version,description,
                  discoverable_departments_json,guidance_kind,applicable_service_kinds_json,
                  applicable_incident_classes_json,symptom_tags_json,purpose,classification,
                  eligible_regions_json,content_ref,content_hash,revision_hash,source_kind,
                  source_ref,author_principal,supersedes_version,lifecycle)
               VALUES (%s,%s,%s,'payments.pool-check',%s,'pool diagnosis','["Payments SRE"]',
                       'RUNBOOK','["CLOUD_RUN"]','["CONNECTION_EXHAUSTION"]','["http-503"]',
                       'INCIDENT_INVESTIGATION','INTERNAL','["europe-west1"]','gs://g/body',%s,
                       %s,'SOLVAN_AUTHORED','repo://g','user:author@example.com',%s,%s)""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                str(version),
                HASH,
                HASH,
                supersedes,
                lifecycle,
            ),
        )
    scope_dict = SCOPE.canonical_dict()
    connection.execute(
        """INSERT INTO solvan_operability.guidance_evaluations
             (organization_id,project_id,environment_id,id,guidance_key,guidance_version,
              revision_digest,suite_version,decision,passed_cases,failed_cases,receipt_ref,
              receipt_hash,receipt_generation,corpus_digest,case_set_digest,scorer_name,
              scorer_version,model_config_pins_json,repetitions,pass_thresholds_json,
              evaluator_principal,reason_codes_json)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                   'gev_00000000000000000000000001','payments.pool-check','2',%(sha)s,
                   'suite@v1','PASS',3,0,'gs://eval/1',%(sha2)s,'1',%(sha2)s,%(sha2)s,
                   'release-gate','1','{"gate":"merge"}',1,'{"pass_rate":1.0}',
                   'user:evaluator@example.com','["ALL_CASES_PASS"]')""",
        {**scope_dict, "sha": HASH, "sha2": HASH},
    )
    connection.execute(
        """INSERT INTO solvan_operability.guidance_approvals
             (organization_id,project_id,environment_id,id,guidance_key,guidance_version,
              revision_digest,evaluation_ref,approver_principal,decision,reason,
              decision_request_id)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                   'gap_00000000000000000000000001','payments.pool-check','2',%(sha)s,
                   'gev_00000000000000000000000001','user:approver@example.com','APPROVE',
                   'reviewed','projection-test-approval')""",
        {**scope_dict, "sha": HASH},
    )
    connection.execute(
        """UPDATE solvan_operability.guidance_revisions
              SET lifecycle='APPROVED',
                  evaluation_ref='gev_00000000000000000000000001',
                  approval_ref='gap_00000000000000000000000001',
                  approved_digest=%(sha)s,
                  approved_by_principal='user:approver@example.com',
                  approved_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s
              AND guidance_key='payments.pool-check' AND version='2'""",
        {**scope_dict, "sha": HASH},
    )
    for version in ("1", "2"):
        connection.execute(
            """INSERT INTO solvan_operability.guidance_revision_agents
                 (organization_id,project_id,environment_id,guidance_key,guidance_version,
                  agent_key)
               VALUES (%s,%s,%s,'payments.pool-check',%s,'evidence-agent')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, version),
        )
        connection.execute(
            """INSERT INTO solvan_operability.guidance_revision_profiles
                 (organization_id,project_id,environment_id,guidance_key,guidance_version,
                  profile_key,profile_version)
               VALUES (%s,%s,%s,'payments.pool-check',%s,'evidence.core','1')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, version),
        )
    connection.execute(
        """INSERT INTO solvan_operability.guidance_current_heads
             (organization_id,project_id,environment_id,guidance_key,approved_version,head_epoch)
           VALUES (%s,%s,%s,'payments.pool-check','2',2)""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    connection.execute(
        """INSERT INTO solvan_operability.guidance_revisions
             (organization_id,project_id,environment_id,guidance_key,version,description,
              discoverable_departments_json,guidance_kind,applicable_service_kinds_json,
              applicable_incident_classes_json,symptom_tags_json,purpose,classification,
              eligible_regions_json,content_ref,content_hash,revision_hash,source_kind,
              source_ref,author_principal,lifecycle)
           VALUES (%s,%s,%s,'payments.draft-flow','1','draft in flight','["Payments SRE"]',
                   'RUNBOOK','["CLOUD_RUN"]','["CONNECTION_EXHAUSTION"]','["http-503"]',
                   'INCIDENT_INVESTIGATION','INTERNAL','["europe-west1"]','gs://g/draft',%s,
                   %s,'SOLVAN_AUTHORED','repo://g','user:author@example.com','IN_REVIEW')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, HASH, HASH),
    )
    for table, extra in (
        ("guidance_revision_agents", "'evidence-agent'"),
        ("guidance_revision_profiles", "'evidence.core','1'"),
    ):
        connection.execute(
            f"""INSERT INTO solvan_operability.{table}
                 (organization_id,project_id,environment_id,guidance_key,guidance_version,
                  {"agent_key" if table.endswith("agents") else "profile_key,profile_version"})
               VALUES (%s,%s,%s,'payments.draft-flow','1',{extra})""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )


def test_the_projection_returns_heads_and_in_flight_drafts_never_history() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection, connection.transaction(force_rollback=True):
        _seed(connection)
        rows = PostgresOperationalGuidanceStore(connection).projection(scope=SCOPE)["guidance"]

    projected = {(row["guidance_key"], row["version"], row["lifecycle"]) for row in rows}
    assert ("payments.pool-check", "2", "APPROVED") in projected
    assert ("payments.draft-flow", "1", "IN_REVIEW") in projected
    assert not any(
        version == "1" and lifecycle == "DEPRECATED" for _, version, lifecycle in projected
    )
