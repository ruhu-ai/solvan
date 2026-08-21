"""Initialize the worktree-local PostgreSQL schema without cloud IAM grants."""

from __future__ import annotations

import argparse
import os
import pathlib
from datetime import UTC, datetime, timedelta
from typing import cast

import psycopg

from tools.bootstrap_database import (
    expected_alert_tables,
    expected_liaison_tables,
    expected_operability_tables,
    transactional_schema_sql,
)
from tools.console_demo_seed import seed_console_demo_records
from tools.target_schema_migrations import apply_target_migrations

_LOCAL_ORGANIZATION_ID = "org_00000000000000000000000000"
_LOCAL_PROJECT_ID = "prj_00000000000000000000000000"
_LOCAL_ENVIRONMENT_ID = "env_00000000000000000000000000"
_LOCAL_CELL_ID = "cell_local_europe_west1"


def _seed_local_operator_invitations(connection: psycopg.Connection[object]) -> int:
    """Invite the configured development identities, so a first sign-in is admitted.

    Sign-in requires a membership: a verified account at an admitted domain is
    eligible, and only an explicit grant lets it in. Locally that grant has to
    exist before anyone signs in, or every developer meets a correct refusal.

    An invitation rather than a membership, because the actor does not exist
    until someone signs in as that identity — and because it exercises the
    redemption path a real onboarding uses instead of a shortcut around it.
    """

    from solvan.domain.identifiers import new_identifier

    declared = os.environ.get("SOLVAN_DEV_IDENTITIES", "")
    identities = [item.strip().lower() for item in declared.split(",") if "@" in item]
    # The founding administrator is invited here too, and this is not belt and
    # braces — it is the only thing that admits them locally.
    #
    # `claim_founding_administrator` grants ADMIN only while the environment has
    # no administrator at all, which is what stops it being a way back in after a
    # removal. Locally an administrator always exists by the time a person signs
    # in with Google: the browser suite signs in as a fixture identity and
    # redeems its ADMIN invitation. So the founding path is correctly closed, and
    # without an invitation the real account meets "verified but holds no
    # access" — which is the product working exactly as designed, and useless.
    #
    # An invitation rather than a special case, because it is the same door
    # every other person comes through.
    founding = os.environ.get("SOLVAN_FOUNDING_ADMINISTRATOR", "").strip().lower()
    if "@" in founding and founding not in identities:
        identities.append(founding)
    if not identities:
        return 0
    now = datetime.now(UTC)
    # A local inviter, so `granted_by` names somebody rather than the invitee.
    inviter = new_identifier("act")
    connection.execute(
        "INSERT INTO solvan_identity.actors(actor_id,status,created_at) "
        "VALUES (%s,'ACTIVE',%s) ON CONFLICT DO NOTHING",
        (inviter, now),
    )
    seeded = 0
    for email in identities:
        domain = email.split("@", 1)[1]
        # Every development identity is an administrator: a local harness exists
        # to exercise the flows, and withholding a role would only hide them.
        for role in ("OPERATOR", "APPROVER", "ADMIN"):
            connection.execute(
                """INSERT INTO solvan_identity.actor_invitations
                     (id,organization_id,project_id,environment_id,email,admitted_domain,
                      role,invited_by_actor_id,created_at,expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT DO NOTHING""",
                (
                    new_identifier("inv"),
                    _LOCAL_ORGANIZATION_ID,
                    _LOCAL_PROJECT_ID,
                    _LOCAL_ENVIRONMENT_ID,
                    email,
                    domain,
                    role,
                    inviter,
                    now,
                    now + timedelta(days=365),
                ),
            )
            seeded += 1
    return seeded


def _seed_local_incident_anchor(connection: psycopg.Connection[object]) -> None:
    """Bind the visible local incident fixture to an authoritative workflow row.

    The console projection is deliberately synthetic, but the conversational
    Steer boundary still revalidates against Cloud-SQL-shaped workflow state.
    Seeding that state here keeps local development honest: production code
    continues to refuse a projected record that has no durable anchor.
    """

    scope = (_LOCAL_ORGANIZATION_ID, _LOCAL_PROJECT_ID, _LOCAL_ENVIRONMENT_ID)
    connection.execute(
        """INSERT INTO solvan.organizations (id, display_name)
           VALUES (%s, 'Solvan local development organization')
           ON CONFLICT DO NOTHING""",
        (scope[0],),
    )
    connection.execute(
        """INSERT INTO solvan.projects
             (organization_id,id,display_name,gcp_project_id)
           VALUES (%s,%s,'Solvan local development project','local-development')
           ON CONFLICT DO NOTHING""",
        scope[:2],
    )
    connection.execute(
        """INSERT INTO solvan.environments
             (organization_id,project_id,id,display_name,region,classification)
           VALUES (%s,%s,%s,'Local development','europe-west1','INTERNAL')
           ON CONFLICT DO NOTHING""",
        scope,
    )
    connection.execute(
        """INSERT INTO solvan.services
             (organization_id,project_id,environment_id,id,service_key,display_name,
              platform_kind,platform_resource,owner_department)
           VALUES (%s,%s,%s,'svc_00000000000000000000000000','payments-api',
             'Payments API','CLOUD_RUN_SERVICE',
             'projects/local-development/locations/europe-west1/services/payments-api',
             'payments')
           ON CONFLICT DO NOTHING""",
        scope,
    )
    connection.execute(
        """INSERT INTO solvan.production_graph_snapshots
             (organization_id,project_id,environment_id,id,version,status,
              source_manifest_ref,content_hash,effective_at,approved_by,approved_at)
           VALUES (%s,%s,%s,'pgs_00000000000000000000000000',1,'APPROVED',
             'fixture://local-development/production-graph','sha256:local-development-graph',
             now(),'local-development-owner',now())
           ON CONFLICT DO NOTHING""",
        scope,
    )
    connection.execute(
        """INSERT INTO solvan.detection_rules
             (organization_id,project_id,environment_id,id,version,service_id,
              incident_class,signal_kind,query_json,evaluation_interval_ms,comparator,
              threshold,sustained_windows,severity,deduplication_dimension,
              action_budget,repeated_action_limit,status,calibration_receipt_ref,
              approved_by,approved_at)
           VALUES (%s,%s,%s,'payments-http-5xx',1,
             'svc_00000000000000000000000000','connection_exhaustion',
             'HTTP_5XX_RATIO','{}',25000,'GT',0.05,2,'SEV2','http-5xx',2,1,
             'APPROVED','fixture://local-development/calibration',
             'local-development-owner',now())
           ON CONFLICT DO NOTHING""",
        scope,
    )
    connection.execute(
        """INSERT INTO solvan.incidents
             (organization_id,project_id,environment_id,id,display_id,
              state_machine_version,state,severity,incident_class,primary_service_id,
              production_graph_snapshot_id,detected_at,detection_rule_id,
              detection_rule_version,deduplication_key,action_budget,
              repeated_action_limit)
           VALUES (%s,%s,%s,'inc_11111111111111111111111111','INC-1042','1',
             'INVESTIGATING','SEV2','connection_exhaustion',
             'svc_00000000000000000000000000',
             'pgs_00000000000000000000000000',now(),'payments-http-5xx',1,
             'liaison-local-development',2,1)
           ON CONFLICT DO NOTHING""",
        scope,
    )


#: Local development refs. They name themselves so nothing downstream can mistake
#: a bootstrap write for an evaluation or approval receipt.
_LOCAL_APPROVAL_REF = "local-development://no-approval-authority"
_LOCAL_EVALUATION_REF = "local-development://no-evaluation-authority"
_LOCAL_NETWORK_POLICY_HASH = "sha256:" + "0" * 64


def _publish_local_catalog(connection: psycopg.Connection[object]) -> tuple[int, int, int]:
    """Publish the checked-in governed catalog into the local development database.

    This is the same material and the same store `tools/release_admin.py`
    publishes in a deployment: principals from
    `specs/artifacts/agent-manifests.yaml`, Tool revisions from
    `TOOL_SEEDS`, and one bounded profile per canonical Agent. Nothing here is
    a second catalog; only the approval, evaluation, and network-policy refs
    differ, and those name themselves as local so no reader can mistake them
    for release evidence.

    No capability probe is written. A probe receipt asserts that an exact
    capability was reached through a bound connection under a real identity,
    which has not happened here, so every published Tool projects as
    unavailable with the honest reason. That refusal is the point: it is what
    the console should show until a connection is bound and probed.
    """

    import yaml

    from solvan.application.default_tool_catalog import (
        AGENT_PROFILE_KEYS,
        catalog_profile,
        catalog_tools,
    )
    from solvan.application.tool_catalog import CatalogPrincipal, ExecutionRole, RegistryKind
    from solvan.application.workspace_hashing import canonical_sha256
    from solvan.domain import Scope
    from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore

    scope = Scope(_LOCAL_ORGANIZATION_ID, _LOCAL_PROJECT_ID, _LOCAL_ENVIRONMENT_ID)
    root = pathlib.Path(__file__).resolve().parents[1]
    manifest = yaml.safe_load(
        (root / "specs/artifacts/agent-manifests.yaml").read_text(encoding="utf-8")
    )
    entries = [
        *manifest.get("agents", []),
        *manifest.get("optional_agents", []),
        *manifest.get("deterministic_services", []),
    ]
    store = PostgresToolCatalogStore(connection)
    for entry in entries:
        # Agents key on `agent_key`; the deterministic service keys on
        # `service_key` and carries no execution role.
        key = str(entry.get("agent_key") or entry["service_key"])
        kind = RegistryKind(str(entry.get("registry_kind", "AGENT")))
        store.register_principal(
            CatalogPrincipal(
                principal_key=key,
                display_name=str(entry["display_name"])[:120],
                registry_kind=kind,
                execution_role=ExecutionRole(str(entry.get("execution_role", "SERVICE"))),
                model_backed=kind is RegistryKind.AGENT,
                manifest_hash=canonical_sha256(entry),
            )
        )
    tools = catalog_tools(
        network_policy_hash=_LOCAL_NETWORK_POLICY_HASH,
        approval_ref=_LOCAL_APPROVAL_REF,
        evaluation_ref=_LOCAL_EVALUATION_REF,
    )
    for tool in tools:
        store.publish_tool(tool)
    for agent_key in AGENT_PROFILE_KEYS:
        store.publish_profile(
            scope=scope,
            profile=catalog_profile(
                agent_key=agent_key,
                approval_ref=_LOCAL_APPROVAL_REF,
                evaluation_ref=_LOCAL_EVALUATION_REF,
                classification_ceiling="INTERNAL",
            ),
        )
    return len(entries), len(tools), len(AGENT_PROFILE_KEYS)


def _seed_first_party_guidance(connection: psycopg.Connection[object]) -> int:
    """Publish the repository's first-party skill packs as built-in guidance.

    Per specification 18 §11 the packs are built-in product guidance: the
    loader publishes them through the ordinary lifecycle with the release
    principals and the pinned commit's merge-gate receipt, registers those
    principals' role bindings itself, and converges an existing lineage by
    supersession rather than deletion. The commit is resolved explicitly and
    the loader refuses to run without one, so a placeholder can never enter
    decision identifiers or evidence. This local development database carries no
    production authority.
    """

    from solvan.domain import Scope
    from tools.load_first_party_skill_packs import load, release_commit

    scope = Scope(_LOCAL_ORGANIZATION_ID, _LOCAL_PROJECT_ID, _LOCAL_ENVIRONMENT_ID)
    return len(load(connection, scope=scope, commit=release_commit()))


def _seed_local_imported_guidance(connection: psycopg.Connection[object]) -> int:
    """Seed one imported skill mid-quarantine so the local UI shows the journey.

    Built-in packs arrive approved by the release; nothing in a fresh local
    database exercises the imported path. This seeds exactly one third-party
    revision as an ordinary submitted draft (IN_REVIEW): visible, unavailable,
    and awaiting evaluation plus independent approval — the state the demo and
    the browser suite assert. Local development only; no production authority.
    """

    from solvan.application.operational_guidance import (
        BlockedBehavior,
        GuidanceKind,
        GuidanceLifecycle,
        GuidanceRevision,
        GuidanceSourceKind,
        GuidanceStepKind,
        GuidanceStepRevision,
    )
    from solvan.application.workspace_hashing import canonical_sha256
    from solvan.domain import Scope
    from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore

    scope = Scope(_LOCAL_ORGANIZATION_ID, _LOCAL_PROJECT_ID, _LOCAL_ENVIRONMENT_ID)
    author = "user:payments-sre@example.com"
    key = "payments.connection-exhaustion"
    existing = connection.execute(
        """SELECT 1 FROM solvan_operability.guidance_revisions
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key=%s AND version='1'""",
        (scope.organization_id, scope.project_id, scope.environment_id, key),
    ).fetchone()
    if existing is not None:
        return 0
    profile = cast(
        "tuple[str, str] | None",
        connection.execute(
            """SELECT profile_key, version FROM solvan_operability.tool_profile_revisions
                WHERE allowed_agent_key='evidence-agent' AND lifecycle='APPROVED'
                ORDER BY profile_key, version LIMIT 1"""
        ).fetchone(),
    )
    if profile is None:
        return 0
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id, project_id, environment_id, principal, role,
              department, granted_by)
           VALUES (%s,%s,%s,%s,'GUIDANCE_AUTHOR','payments','local-development-bootstrap')
           ON CONFLICT (organization_id, project_id, environment_id, principal, role,
                        department)
           DO UPDATE SET expires_at = NULL, granted_by = EXCLUDED.granted_by""",
        (scope.organization_id, scope.project_id, scope.environment_id, author),
    )
    body = (
        "A bounded diagnostic sequence for connection-pool exhaustion; "
        "it grants no action authority."
    )
    revision = GuidanceRevision(
        guidance_key=key,
        version="1",
        display_name="Payment connection exhaustion",
        description=body,
        owner_department="payments",
        discoverable_departments=("payments",),
        guidance_kind=GuidanceKind.DIAGNOSTIC_PROCEDURE,
        lifecycle=GuidanceLifecycle.DRAFT,
        applicable_service_kinds=("payments-api",),
        applicable_incident_classes=("CONNECTION_EXHAUSTION",),
        symptom_tags=("payments",),
        purpose="INCIDENT_INVESTIGATION",
        classification="INTERNAL",
        eligible_regions=("europe-west1",),
        allowed_agent_keys=("evidence-agent",),
        required_profile_revisions=(f"{profile[0]}@{profile[1]}",),
        steps=(
            GuidanceStepRevision(
                step_key="read-pack",
                ordinal=1,
                title="Read the quarantined checklist",
                objective=body[:900],
                step_kind=GuidanceStepKind.CHECKPOINT,
                allowed_tool_revisions=(),
                prerequisite_step_keys=(),
                completion_predicate_key="guidance-content-fetched",
                completion_predicate_version="1",
                required_evidence_kinds=("GUIDANCE_FETCH_RECEIPT",),
                maximum_tool_requests=0,
                on_blocked=BlockedBehavior.CONTINUE,
            ),
        ),
        content_ref="quarantine://acme-platform/sre-skills/payments/connection-exhaustion",
        content_hash=canonical_sha256({"body": body}),
        source_kind=GuidanceSourceKind.IMPORTED,
        source_ref="github.com/acme-platform/sre-skills · payments/connection-exhaustion",
        source_license="Apache-2.0",
        author_principal=author,
    )
    store = PostgresOperationalGuidanceStore(connection)
    draft = store.create_draft(
        scope=scope, revision=revision, decision_request_id=f"local-import:{key}"
    )
    store.submit(
        scope=scope,
        guidance_key=key,
        version="1",
        principal=author,
        expected_digest=draft.digest,
        decision_request_id=f"local-import-submit:{key}",
    )
    return 1


def _seed_local_governance_evidence(connection: psycopg.Connection[object]) -> None:
    """Seed the Fleet governance tabs: memory, security, audit, and run rows.

    A fresh local database left Memory and Security rendering an empty panel
    and the Agents run ledger with nothing to show, so the surfaces the
    browser suite asserts were untestable locally. These are synthetic local
    development fixtures anchored to the seeded incident; every value is
    deliberately obviously local and the database carries no production
    authority. Fixed IDs and ON CONFLICT keep the seed idempotent.
    """

    scope = (_LOCAL_ORGANIZATION_ID, _LOCAL_PROJECT_ID, _LOCAL_ENVIRONMENT_ID)
    incident = "inc_11111111111111111111111111"
    memory_rows = [
        ("PENDING", "ROOT_CAUSE", "CONFIRMED", "AUTOMATIC", 1),
        ("QUARANTINED", "PATTERN", "UNCONFIRMED", "HUMAN", 2),
        ("REJECTED", "MITIGATION_OUTCOME", "CONTRADICTED", "HUMAN", 3),
        ("PROMOTED", "RUNBOOK_FACT", "VERIFIED", "AUTOMATIC", 4),
    ]
    for status, kind, decision, review, index in memory_rows:
        connection.execute(
            """INSERT INTO solvan.memory_candidates
                 (organization_id,project_id,environment_id,id,scope_json,purpose,
                  candidate_type,fact_text,content_hash,source_refs,source_hashes,
                  confirmation_status,verification_ref,classification,residency,
                  redaction_manifest_ref,armor_verdict_ref,provenance_json,
                  policy_version,review_requirement,status,created_by_principal,
                  expires_at)
               VALUES (%s,%s,%s,%s,
                  '{"service":"payments-api","purpose":"INCIDENT_INVESTIGATION"}',
                  'INCIDENT_INVESTIGATION',%s,
                  'Local development fixture: synthetic candidate for the console.',
                  %s,'["local://evidence/1"]','["sha256:local"]',%s,NULL,'INTERNAL',
                  'europe-west1','local://redaction/1','local://armor/1',
                  '{"seed":"local-development"}','local-1',%s,%s,
                  'coordinator@local-development',now() + interval '30 days')
               ON CONFLICT DO NOTHING""",
            (
                *scope,
                f"memc_01DEVSEEDMEM{index:014d}",
                kind,
                "sha256:" + str(index) * 64,
                decision,
                review,
                status,
            ),
        )
    security_rows = [
        (
            "MODEL_ARMOR",
            "HIGH",
            "PROMPT_CONTENT_BLOCKED",
            "evidence-agent",
            "model-context",
            incident,
        ),
        (
            "AGENT_GATEWAY",
            "WARNING",
            "DESTINATION_DENIED",
            "infrastructure-agent",
            "external.example",
            None,
        ),
        ("MEMORY_GATE", "INFO", "CANDIDATE_QUARANTINED", "coordinator", "memory-bank", None),
    ]
    for index, (control, severity, event, actor, destination, event_incident) in enumerate(
        security_rows, start=1
    ):
        connection.execute(
            """INSERT INTO solvan.security_events
                 (organization_id,project_id,environment_id,id,event_type,control,
                  severity,actor_principal,destination_ref,incident_id,safe_summary,
                  payload_hash,policy_ref,trace_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                  'Local development fixture: a control refused and recorded it.',
                  %s,'policy://local-development',%s)
               ON CONFLICT DO NOTHING""",
            (
                *scope,
                f"sec_01DEVSEEDSEC{index:014d}",
                event,
                control,
                severity,
                actor,
                destination,
                event_incident,
                "sha256:" + str(index) * 64,
                f"{index:032x}",
            ),
        )
    run_rows = [
        ("incident-supervisor", "plan-investigation", "SUCCEEDED", None, 1),
        ("evidence-agent", "collect-evidence", "SUCCEEDED", None, 2),
        ("infrastructure-agent", "resource-metadata", "FAILED", "TOOL_TIMEOUT", 3),
    ]
    for agent_key, step, run_status, error_class, index in run_rows:
        connection.execute(
            """INSERT INTO solvan.agent_runs
                 (organization_id,project_id,environment_id,id,incident_id,
                  logical_step_key,agent_key,agent_resource,agent_revision,
                  invocation_id,workflow_version,attempt,status,deadline,
                  budget_json,input_ref,input_hash,error_class,started_at,
                  completed_at,trace_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'1',%s,1,1,%s,
                  now() + interval '1 hour','{"model_requests":4,"tool_calls":12}',
                  'local://inputs/seed',%s,%s,
                  now() - interval '25 minutes',now() - interval '24 minutes',%s)
               ON CONFLICT DO NOTHING""",
            (
                *scope,
                f"run_01DEVSEEDRVN{index:014d}",
                incident,
                f"seed-{step}",
                agent_key,
                f"projects/local-development/locations/europe-west1/agents/{agent_key}",
                f"invk_01DEVSEEDRVN{index:014d}",
                run_status,
                "sha256:" + str(index) * 64,
                error_class,
                f"{index:032x}",
            ),
        )
    audit_rows = [
        ("INCIDENT", incident, "INCIDENT_OPENED", 1),
        ("MEMORY_CANDIDATE", "memc_01DEVSEEDMEM00000000000002", "MEMORY_CANDIDATE_QUARANTINED", 2),
    ]
    for stream_type, stream_id, event, index in audit_rows:
        connection.execute(
            """INSERT INTO solvan.audit_events
                 (organization_id,project_id,environment_id,id,stream_type,stream_id,
                  event_type,actor_principal,decision_ref,payload_hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,'coordinator@local-development',NULL,%s)
               ON CONFLICT (organization_id,project_id,environment_id,id) DO NOTHING""",
            (
                *scope,
                f"aud_01DEVSEEDAVD{index:014d}",
                stream_type,
                stream_id,
                event,
                "sha256:" + str(index) * 64,
            ),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--rebuild-local-target-schemas", action="store_true")
    args = parser.parse_args()
    with psycopg.connect(args.database_url) as connection, connection.transaction():
        exists = connection.execute(
            "SELECT to_regclass('solvan.organizations') IS NOT NULL"
        ).fetchone()
        if exists != (True,):
            connection.execute(transactional_schema_sql())
        count = connection.execute(
            """SELECT count(*) FROM information_schema.tables
              WHERE table_schema = 'solvan' AND table_type = 'BASE TABLE'"""
        ).fetchone()
        if count != (61,):
            raise RuntimeError(
                "local schema is stale: expected 61 tables; preserve or explicitly "
                "replace the worktree-local PostgreSQL volume before continuing"
            )
        # Target schemas share the persistent migration ledger. Destructive
        # recovery is available only when the caller explicitly identifies this
        # database as a disposable local development database. No deployment
        # bootstrap passes the flag, so it can never drop a production schema.
        apply_target_migrations(
            connection,
            rebuild_local=args.rebuild_local_target_schemas,
        )
        _seed_local_incident_anchor(connection)
        invitations = _seed_local_operator_invitations(connection)
        demo_records = seed_console_demo_records(
            connection,
            scope=(
                _LOCAL_ORGANIZATION_ID,
                _LOCAL_PROJECT_ID,
                _LOCAL_ENVIRONMENT_ID,
            ),
        )
        catalog_principals, catalog_tool_count, catalog_profiles = _publish_local_catalog(
            connection
        )
        guidance_drafts = _seed_first_party_guidance(connection)
        guidance_drafts += _seed_local_imported_guidance(connection)
        _seed_local_governance_evidence(connection)
        connection.execute(
            """INSERT INTO solvan_scale.cell_eligibility_profiles (
                  eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
                  allowed_provider_launch_stages,encryption_profile_hash,
                  support_access_allowed,allowed_recovery_regions,approved_ref)
               VALUES (%s,ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY['europe-west1'],
                  ARRAY['GA'],%s,false,ARRAY['europe-west1'],'ref_local_development')
               ON CONFLICT (eligibility_profile_hash) DO NOTHING""",
            ("sha256:" + "6" * 64, "sha256:" + "7" * 64),
        )
        connection.execute(
            """INSERT INTO solvan_scale.cells (
                  cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
                  capacity_profile_hash,data_policy_hash,eligibility_profile_hash,
                  deployment_manifest_hash)
               VALUES (%s,'OSS_SINGLE_TENANT','europe-west1','local-development','READY',1,
                  %s,%s,%s,%s) ON CONFLICT (cell_id) DO NOTHING""",
            (
                _LOCAL_CELL_ID,
                "sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
                "sha256:" + "6" * 64,
                "sha256:" + "3" * 64,
            ),
        )
        connection.execute(
            """INSERT INTO solvan_scale.tenant_eligibility_requirements (
                  organization_id,requirement_hash,allowed_classifications,
                  allowed_residency_regions,allowed_provider_launch_stages,
                  encryption_profile_hash,support_access_allowed,
                  allowed_recovery_regions,approved_ref)
               VALUES (%s,%s,ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],
                  ARRAY['europe-west1'],ARRAY['GA'],%s,false,
                  ARRAY['europe-west1'],'ref_local_tenant_development')
               ON CONFLICT (organization_id,requirement_hash) DO NOTHING""",
            (
                _LOCAL_ORGANIZATION_ID,
                "sha256:" + "8" * 64,
                "sha256:" + "7" * 64,
            ),
        )
        connection.execute(
            """INSERT INTO solvan_scale.tenant_placements (
                  organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
                  home_region,classification_ceiling,eligibility_requirement_hash,
                  policy_hash,encryption_profile_hash,activated_at)
               SELECT %s,1,%s,'ACTIVE',true,'OSS_SINGLE_TENANT','europe-west1',
                  'CONFIDENTIAL',%s,%s,%s,now()
                WHERE NOT EXISTS (SELECT 1 FROM solvan_scale.tenant_placements
                    WHERE organization_id=%s AND is_current)""",
            (
                _LOCAL_ORGANIZATION_ID,
                _LOCAL_CELL_ID,
                "sha256:" + "8" * 64,
                "sha256:" + "4" * 64,
                "sha256:" + "7" * 64,
                _LOCAL_ORGANIZATION_ID,
            ),
        )
        expected = expected_liaison_tables()
        current = connection.execute(
            """SELECT count(*) FROM information_schema.tables
              WHERE table_schema = 'solvan_liaison' AND table_type = 'BASE TABLE'"""
        ).fetchone()
        present = 0 if current is None else int(current[0])
        if present != expected:
            raise RuntimeError(f"local liaison schema drift: expected {expected}, found {present}")
        operability_expected = expected_operability_tables()
        operability_current = connection.execute(
            """SELECT count(*) FROM information_schema.tables
              WHERE table_schema = 'solvan_operability' AND table_type = 'BASE TABLE'"""
        ).fetchone()
        operability_present = 0 if operability_current is None else int(operability_current[0])
        if operability_present != operability_expected:
            raise RuntimeError(
                "local operability schema drift: "
                f"expected {operability_expected}, found {operability_present}"
            )
        alert_expected = expected_alert_tables()
        alert_current = connection.execute(
            """SELECT count(*) FROM information_schema.tables
              WHERE table_schema = 'solvan_alerts' AND table_type = 'BASE TABLE'"""
        ).fetchone()
        alert_present = 0 if alert_current is None else int(alert_current[0])
        if alert_present != alert_expected:
            raise RuntimeError(
                f"local Alert Triage schema drift: expected {alert_expected}, found {alert_present}"
            )
        scale_current = connection.execute(
            """SELECT count(*) FROM information_schema.tables
              WHERE table_schema = 'solvan_scale' AND table_type = 'BASE TABLE'"""
        ).fetchone()
        scale_present = 0 if scale_current is None else int(scale_current[0])
        if scale_present != 28:
            raise RuntimeError(f"local SaaS-scale schema drift: expected 28, found {scale_present}")
    print("Local PostgreSQL schema is ready (61 tables; no cloud authority).")
    note = " (explicit local rebuild allowed)" if args.rebuild_local_target_schemas else ""
    print(f"Target conversational schema ready ({present} tables; not release DDL){note}.")
    print(
        "Target governed-operability schema ready "
        f"({operability_present} tables; not release DDL){note}."
    )
    print(
        f"Governed catalog published ({catalog_principals} principals, "
        f"{catalog_tool_count} Tool revisions, {catalog_profiles} profiles; no capability "
        "probe, so every Tool projects as unavailable until a connection is bound). "
        f"First-party skill packs converged as built-in guidance ({guidance_drafts} new "
        "revisions, including the quarantined imported draft)."
    )
    if invitations:
        print(
            f"Development sign-in invitations seeded ({invitations}); "
            "first sign-in redeems one and is admitted."
        )

    print(f"Demonstration investigation records seeded ({demo_records}; no cloud authority).")
    print(f"Target Alert Triage schema ready ({alert_present} tables; not release DDL){note}.")
    print(f"Target SaaS-scale schema ready ({scale_present} tables; not release DDL){note}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
