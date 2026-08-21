"""Code-repair completion predicates against real PostgreSQL 16.

Governing records: specification 23 §5, specification 17 §4.2/§10.

The release loader approves the code-repair pack's steps, so every predicate
those steps name must be honestly evaluable over durable records — an
unimplemented predicate verdicts ERROR forever, and an infereed one fabricates
meaning. These cases seed the real repair chain and prove each predicate reads
exactly the record it is named for, plus the §10 rule that an idempotent
replay re-checks the caller's current role binding.
"""

from __future__ import annotations

import os
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.operational_guidance import GuidanceError
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
HASH = "sha256:" + "a" * 64
RUN_ID = new_identifier("run")
PLAN_ID = new_identifier("rep")
CASE_ID = new_identifier("rel")
INCIDENT_ID = new_identifier("inc")


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
    connection.execute(
        """INSERT INTO solvan.production_graph_snapshots
             (organization_id,project_id,environment_id,id,version,status,
              source_manifest_ref,content_hash,effective_at)
           VALUES (%s,%s,%s,'pgs_00000000000000000000009901',9001,'DRAFT',
                   'fixture://graph',%s,now())""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, HASH),
    )
    connection.execute(
        """INSERT INTO solvan.production_graph_nodes
             (organization_id,project_id,environment_id,id,snapshot_id,node_key,node_kind,
              resource_ref,external_project_id,classification,provenance_ref,attributes_json)
           VALUES (%s,%s,%s,'pgn_00000000000000000000009901','pgs_00000000000000000000009901',
                   'payments-api','SERVICE','run/payments-api','ruhu-dev','INTERNAL',
                   'fixture://node','{}'),
                  (%s,%s,%s,'pgn_00000000000000000000009902','pgs_00000000000000000000009901',
                   'repo','REPOSITORY','github/repo',NULL,'INTERNAL','fixture://node','{}')
           ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id) * 2,
    )
    connection.execute(
        """INSERT INTO solvan.services
             (organization_id,project_id,environment_id,id,service_key,display_name,
              platform_kind,platform_resource,owner_department)
           VALUES (%s,%s,%s,'svc_00000000000000000000009901','predicate-test-service',
                   'predicate-test-service','CLOUD_RUN_SERVICE','run/predicate-test-service',
                   'Payments SRE')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    connection.execute(
        """INSERT INTO solvan.detection_rules
             (organization_id,project_id,environment_id,id,version,service_id,
              incident_class,signal_kind,query_json,evaluation_interval_ms,
              comparator,threshold,sustained_windows,severity,
              deduplication_dimension,action_budget,repeated_action_limit,status,
              calibration_receipt_ref,approved_by,approved_at)
           VALUES (%s,%s,%s,'predicate-rule-1',1,'svc_00000000000000000000009901',
                   'connection_exhaustion','HTTP_5XX_RATIO','{}',25000,'GT',0.05,2,'SEV2',
                   'http-5xx',2,1,'APPROVED','fixture://calibration','owner',now())""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
    )
    connection.execute(
        """INSERT INTO solvan.incidents
             (organization_id,project_id,environment_id,id,display_id,state_machine_version,
              state,severity,incident_class,primary_service_id,production_graph_snapshot_id,
              detected_at,detection_rule_id,detection_rule_version,deduplication_key,
              action_budget,repeated_action_limit)
           VALUES (%s,%s,%s,%s,'INC-9777','1','INVESTIGATING','SEV2','connection_exhaustion',
                   'svc_00000000000000000000009901','pgs_00000000000000000000009901',now(),
                   'predicate-rule-1',1,'dedup-9777',2,1)""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, INCIDENT_ID),
    )
    connection.execute(
        """INSERT INTO solvan.reliability_cases
             (organization_id,project_id,environment_id,id,display_id,state_machine_version,
              state,originating_incident_id)
           VALUES (%s,%s,%s,%s,'REL-9777','1','REPAIR_IN_PROGRESS',%s)""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, CASE_ID, INCIDENT_ID),
    )
    connection.execute(
        """INSERT INTO solvan.github_repositories
             (organization_id,project_id,environment_id,id,installation_id,owner,name,
              default_branch,api_base_url,classification,credential_secret_ref,
               webhook_secret_ref,policy_hash,allowed_operations_json,status,
               last_probe_at,last_probe_result,created_by_principal)
           VALUES (%s,%s,%s,'ghr_00000000000000000000009901',1,'solvan','payments',
                   'main','https://api.github.com','INTERNAL',
                   'projects/p/secrets/cred/versions/1','projects/p/secrets/hook/versions/1',
                   %s,'["PR_CREATE"]','ACTIVE',now(),'SUCCEEDED','user:test@example.com')""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, HASH),
    )
    connection.execute(
        """INSERT INTO solvan.repair_plans
             (organization_id,project_id,environment_id,id,reliability_case_id,plan_version,
              repository_node_id,repository_snapshot_uri,repository_snapshot_hash,
              base_commit_sha,reproduction_command,allowed_file_globs_json,test_command,
              artifact_output_uri,confirmed_root_cause_id,evidence_refs_json,provider,
              content_hash,status)
           VALUES (%s,%s,%s,%s,%s,1,'pgn_00000000000000000000009902','gs://snap/1',%s,
                   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','pytest -x','["src/**"]','pytest',
                   'gs://artifacts/1','hyp-1','["db://solvan/evidence-items/e1"]',
                   'GEMINI_ADK_AGENT_ENGINE',%s,'ACTIVE')""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            PLAN_ID,
            CASE_ID,
            HASH,
            HASH,
        ),
    )
    connection.execute(
        """INSERT INTO solvan.agent_runs
             (organization_id,project_id,environment_id,id,reliability_case_id,repair_plan_id,
              repair_plan_version,logical_step_key,agent_key,agent_resource,agent_revision,
              invocation_id,workflow_version,attempt,status,deadline,budget_json,input_ref,
              input_hash)
           VALUES (%s,%s,%s,%s,%s,%s,1,'repair-attempt-1','workspace-agent',
                   'agents/workspace-agent','1','inv-9001',1,1,'RUNNING',
                   now()+interval '1 hour','{}','gs://input/1',%s)""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            RUN_ID,
            CASE_ID,
            PLAN_ID,
            HASH,
        ),
    )


def _predicates(
    connection: psycopg.Connection[Any], predicate_ref: str
) -> tuple[str, tuple[str, ...], str | None]:
    store = PostgresOperationalGuidanceStore(connection)
    with connection.cursor(row_factory=dict_row) as cursor:
        return store._evaluate_registered_predicate(
            cursor=cursor,
            scope=SCOPE,
            predicate_ref=predicate_ref,
            selection_id="sel-9001",
            agent_run_id=RUN_ID,
            required_evidence_kinds=("ARTIFACT",),
        )


def test_every_approved_code_repair_predicate_reads_its_named_record() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection, connection.transaction(force_rollback=True):
        _seed(connection)
        # Nothing recorded yet: every predicate refuses with its closed code.
        assert _predicates(connection, "repair-input-manifest-valid@1") == (
            "NOT_SATISFIED",
            (f"db://solvan/agent-runs/{RUN_ID}",),
            "REPAIR_INPUT_MANIFEST_NOT_BOUND",
        )
        assert _predicates(connection, "repair-evidence-cited@1")[2] == "REPAIR_EVIDENCE_NOT_CITED"
        assert _predicates(connection, "exploratory-baseline-recorded@1")[2] == (
            "EXPLORATORY_BASELINE_NOT_RECORDED"
        )
        assert _predicates(connection, "candidate-generation-recorded@1")[2] == (
            "CANDIDATE_GENERATION_NOT_RECORDED"
        )
        assert _predicates(connection, "exploratory-regression-recorded@1")[2] == (
            "EXPLORATORY_REGRESSION_NOT_RECORDED"
        )
        assert _predicates(connection, "patch-proposal-complete@1")[2] == (
            "PATCH_PROPOSAL_NOT_COMPLETE"
        )
        assert _predicates(connection, "ci-failure-classified@1")[0] == "ERROR"

        set_id = new_identifier("rgs")
        connection.execute(
            """INSERT INTO solvan_delivery.repair_plan_guidance_selection_sets
                 (organization_id,project_id,environment_id,id,repair_plan_id,repair_plan_version,
                  selection_set_hash,status)
               VALUES (%s,%s,%s,%s,%s,1,%s,'PENDING_BIND')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, set_id, PLAN_ID, HASH),
        )
        connection.execute(
            """UPDATE solvan_delivery.repair_plan_guidance_selection_sets
                  SET status='BOUND',bound_agent_run_id=%(run)s,bound_at=now()
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(id)s""",
            {
                "run": RUN_ID,
                "id": set_id,
                **SCOPE.canonical_dict(),
            },
        )
        for ordinal, kind in ((1, "REPRODUCTION"), (2, "REGRESSION")):
            definition_id = new_identifier("rcd")
            catalog_id = new_identifier("rcc")
            declared_inputs = [{"path": "src/payments/api.py", "kind": "FILE"}]
            declared_inputs_hash = canonical_sha256(declared_inputs)
            resolved_inputs = [{"path": "src/payments/api.py", "hash": HASH}]
            resolved_inputs_hash = canonical_sha256(resolved_inputs)
            connection.execute(
                """INSERT INTO solvan_delivery.repair_plan_command_definitions
                     (organization_id,project_id,environment_id,id,repository_binding_id,
                      command_hash,command_kind,argv_json,working_directory,declared_inputs_hash,
                      declared_outputs_hash,timeout_ms,cpu_millis,memory_mib,output_byte_limit,
                      network_mode,catalog_hash,lifecycle,approved_ref,declared_inputs_json,
                      declared_outputs_json)
                   VALUES (%s,%s,%s,%s,'ghr_00000000000000000000009901',%s,%s,'["pytest"]','.',
                           %s,%s,60000,500,256,4096,'NONE',%s,'APPROVED','ref-1',%s,'[]')""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    definition_id,
                    f"sha256:{'b' * 63}{ordinal}",
                    kind,
                    declared_inputs_hash,
                    HASH,
                    HASH,
                    Jsonb(declared_inputs),
                ),
            )
            connection.execute(
                """INSERT INTO solvan_delivery.repair_plan_command_catalogs
                     (organization_id,project_id,environment_id,id,repair_plan_id,
                      repair_plan_version,command_ordinal,command_definition_id,command_hash,
                      base_tree_hash,argv_json,working_directory,declared_inputs_hash,timeout_ms,
                      cpu_millis,memory_mib,output_byte_limit,network_mode,status,catalog_hash,
                      resolved_inputs_json,resolved_inputs_hash)
                   VALUES (%s,%s,%s,%s,%s,1,%s,%s,%s,%s,'["pytest"]','.',%s,60000,500,256,4096,
                           'NONE','RESOLVED',%s,%s,%s)""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    catalog_id,
                    PLAN_ID,
                    ordinal,
                    definition_id,
                    f"sha256:{'b' * 63}{ordinal}",
                    HASH,
                    declared_inputs_hash,
                    HASH,
                    Jsonb(resolved_inputs),
                    resolved_inputs_hash,
                ),
            )
        verdict = _predicates(connection, "repair-input-manifest-valid@1")
        assert verdict[0] == "SATISFIED"
        assert any("guidance-selection-sets" in ref for ref in verdict[1])

        connection.execute(
            """INSERT INTO solvan.evidence_items
                 (organization_id,project_id,environment_id,id,incident_id,source_kind,
                  source_resource,query_spec_json,window_start,window_end,observed_at,
                  content_ref,content_hash,classification,residency,redaction_manifest_ref,
                  provenance_json,freshness_expires_at)
               VALUES (%s,%s,%s,'evd_00000000000000000000009901',%s,'CLOUD_LOGGING',
                       'run/payments-api','{}',now()-interval '5 minutes',now(),now(),
                       'gs://evidence/1',%s,'INTERNAL','EU','gs://redaction/1','{}',
                       now()+interval '1 day')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, INCIDENT_ID, HASH),
        )
        # The run anchors on the case; the citation is the originating incident's evidence.
        assert _predicates(connection, "repair-evidence-cited@1")[0] == "SATISFIED"

        generation_id = new_identifier("wcg")
        connection.execute(
            """INSERT INTO solvan_delivery.workspace_candidate_generations
                 (organization_id,project_id,environment_id,id,repair_plan_id,repair_plan_version,
                  agent_run_id,generation_ordinal,base_tree_hash,changed_paths_hash,
                  candidate_tree_hash,candidate_manifest_ref,candidate_manifest_hash,
                  aggregate_bytes,file_count,input_hash)
               VALUES (%s,%s,%s,%s,%s,1,%s,1,%s,%s,%s,'gs://manifest/1',%s,10,1,%s)""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                generation_id,
                PLAN_ID,
                RUN_ID,
                HASH,
                HASH,
                HASH,
                HASH,
                HASH,
            ),
        )
        assert _predicates(connection, "candidate-generation-recorded@1")[0] == "SATISFIED"

        for predicate, ordinal, reason in (
            ("exploratory-baseline-recorded@1", 1, None),
            ("exploratory-regression-recorded@1", 2, None),
        ):
            catalog_row = connection.execute(
                """SELECT id FROM solvan_delivery.repair_plan_command_catalogs
                    WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                      AND repair_plan_id=%s AND command_ordinal=%s""",
                (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, PLAN_ID, ordinal),
            ).fetchone()
            connection.execute(
                """INSERT INTO solvan_delivery.exploratory_sandbox_receipts
                     (organization_id,project_id,environment_id,id,agent_run_id,
                      candidate_generation_id,command_catalog_id,command_hash,sandbox_image_hash,
                      request_hash,exit_code,stdout_ref,stdout_hash,stderr_ref,stderr_hash,
                      output_bytes,trust_class,started_at,completed_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,'gs://stdout/1',%s,'gs://stderr/1',%s,
                           0,'EXPERIMENTAL',now(),now())""",
                (
                    SCOPE.organization_id,
                    SCOPE.project_id,
                    SCOPE.environment_id,
                    new_identifier("esr"),
                    RUN_ID,
                    generation_id,
                    catalog_row[0],
                    f"sha256:{'b' * 63}{ordinal}",
                    HASH,
                    HASH,
                    HASH,
                    HASH,
                ),
            )
            assert _predicates(connection, predicate)[0] == "SATISFIED", reason

        connection.execute(
            """INSERT INTO solvan.patch_artifacts
                 (organization_id,project_id,environment_id,id,reliability_case_id,repair_plan_id,
                  repair_plan_version,agent_run_id,sandbox_resource,base_commit_sha,
                  unified_diff_ref,unified_diff_hash,changed_paths_json,cognition_ref,
                  cognition_hash,mechanism,hypotheses_json,reproduction_command,
                  reproduction_exit_code,reproduction_output_ref,reproduction_output_hash,
                  test_command,test_exit_code,test_output_ref,test_output_hash,
                  residual_risks_json,provider,status)
               VALUES (%s,%s,%s,%s,%s,%s,1,%s,'sandbox/1',
                   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','gs://diff/1',%s,'["src/a.py"]',
                   'gs://cognition/1',%s,'connection pool exhausts under retry storm',
                   '["h1","h2"]','pytest -x',1,'gs://repro/1',%s,'pytest',0,'gs://test/1',%s,
                   '[]','GEMINI_ADK_AGENT_ENGINE','TESTS_PASSED')""",
            (
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                new_identifier("pat"),
                CASE_ID,
                PLAN_ID,
                RUN_ID,
                HASH,
                HASH,
                HASH,
                HASH,
            ),
        )
        assert _predicates(connection, "patch-proposal-complete@1")[0] == "SATISFIED"


def test_an_approval_replay_rechecks_the_current_role_binding() -> None:
    """§10: a revoked approver role means the prior result is not returned."""

    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as connection, connection.transaction(force_rollback=True):
        _seed(connection)
        store = PostgresOperationalGuidanceStore(connection)
        department = "Payments SRE"
        connection.execute(
            """INSERT INTO solvan_operability.operability_role_bindings
                 (organization_id,project_id,environment_id,principal,role,department,granted_by)
               VALUES (%s,%s,%s,'user:predicate-approver@example.com','GUIDANCE_APPROVER',%s,
                       'test')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, department),
        )
        connection.execute(
            """INSERT INTO solvan_operability.guidance_definitions
                 (organization_id,project_id,environment_id,guidance_key,display_name,
                  owner_department)
               VALUES (%s,%s,%s,'payments.replay-check','Replay check',%s)""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, department),
        )
        with pytest.raises(GuidanceError, match="guidance is not awaiting review"):
            store.approve(
                scope=SCOPE,
                guidance_key="payments.replay-check",
                version="1",
                principal="user:predicate-approver@example.com",
                expected_digest=HASH,
                evaluation_ref="gev_00000000000000000000000001",
                decision_request_id="replay-role-check-0001",
                reason="reviewed",
                known_predicates=frozenset(),
            )
        # The refusal above recorded nothing; simulate the replay probe directly:
        # with the role revoked, even the department resolution refuses.
        connection.execute(
            """UPDATE solvan_operability.operability_role_bindings
                  SET granted_at=now()-interval '1 hour',expires_at=now()-interval '1 second'
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND principal='user:predicate-approver@example.com'""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        with pytest.raises(GuidanceError, match="role is inactive"):
            store.approve(
                scope=SCOPE,
                guidance_key="payments.replay-check",
                version="1",
                principal="user:predicate-approver@example.com",
                expected_digest=HASH,
                evaluation_ref="gev_00000000000000000000000001",
                decision_request_id="replay-role-check-0001",
                reason="reviewed",
                known_predicates=frozenset(),
            )
