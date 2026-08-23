"""Forward-only, checksum-bound lifecycle for target product schemas."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from psycopg import Connection, sql

ROOT = Path(__file__).resolve().parents[1]


class TargetMigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TargetMigration:
    schema_name: str
    version: int
    name: str
    source: Path
    anchor_table: str

    @property
    def checksum(self) -> str:
        return f"sha256:{hashlib.sha256(self.source.read_bytes()).hexdigest()}"


MIGRATIONS = (
    TargetMigration(
        "solvan_scale",
        1,
        "saas_scale_and_isolation_baseline",
        ROOT / "specs" / "artifacts" / "saas-scale-schema.target.sql",
        "cells",
    ),
    TargetMigration(
        "solvan_onboarding",
        1,
        "external_estate_scope_baseline",
        ROOT / "specs" / "artifacts" / "connection-scope-schema.target.sql",
        "connection_external_resource_scopes",
    ),
    TargetMigration(
        "solvan_onboarding",
        2,
        "explicit_workload_region_authorization",
        ROOT / "specs" / "artifacts" / "connection-scope-schema.target.v2.sql",
        "connection_external_resource_scopes",
    ),
    TargetMigration(
        "solvan_onboarding",
        3,
        "connection_bound_polling_detection",
        ROOT / "specs" / "artifacts" / "connection-scope-schema.target.v3.sql",
        "connection_external_resource_scopes",
    ),
    TargetMigration(
        "solvan_onboarding",
        4,
        "per_region_binding_epoch_key",
        ROOT / "specs" / "artifacts" / "connection-scope-schema.target.v4.sql",
        "connection_external_resource_scopes",
    ),
    TargetMigration(
        "solvan_liaison",
        1,
        "conversational_surface_baseline",
        ROOT / "specs" / "artifacts" / "liaison-schema.target.sql",
        "liaison_threads",
    ),
    TargetMigration(
        "solvan_liaison",
        2,
        "alert_episode_record_anchor",
        ROOT / "specs" / "artifacts" / "liaison-schema.target.v2.sql",
        "liaison_threads",
    ),
    TargetMigration(
        "solvan_liaison",
        3,
        "guidance_reference_turn_intent",
        ROOT / "specs" / "artifacts" / "liaison-schema.target.v3.sql",
        "liaison_threads",
    ),
    TargetMigration(
        "solvan_liaison",
        4,
        "durable_steer_grant_nonce",
        ROOT / "specs" / "artifacts" / "liaison-schema.target.v4.sql",
        "liaison_threads",
    ),
    TargetMigration(
        "solvan_graph",
        1,
        "production_graph_baseline",
        ROOT / "specs" / "artifacts" / "production-graph-schema.target.sql",
        "graph_scope_bindings",
    ),
    TargetMigration(
        "solvan_quality",
        1,
        "outcome_quality_and_earned_autonomy_baseline",
        ROOT / "specs" / "artifacts" / "outcome-quality-schema.target.sql",
        "quality_scope_bindings",
    ),
    TargetMigration(
        "solvan_operability",
        1,
        "governed_operability_baseline",
        ROOT / "specs" / "artifacts" / "operability-schema.target.sql",
        "tool_definitions",
    ),
    TargetMigration(
        "solvan_operability",
        2,
        "governed_operability_force_rls",
        ROOT / "specs" / "artifacts" / "operability-schema.target.v2.sql",
        "tool_definitions",
    ),
    TargetMigration(
        "solvan_operability",
        3,
        "agent_skills_interchange",
        ROOT / "specs" / "artifacts" / "operability-schema.target.v3.sql",
        "tool_definitions",
    ),
    TargetMigration(
        "solvan_operability",
        4,
        "relay_observability_source_pairs",
        ROOT / "specs" / "artifacts" / "operability-schema.target.v4.sql",
        "tool_definitions",
    ),
    TargetMigration(
        "solvan_operability",
        5,
        "zero_read_window_for_local_compute_profiles",
        ROOT / "specs" / "artifacts" / "operability-schema.target.v5.sql",
        "tool_definitions",
    ),
    TargetMigration(
        "solvan_operability",
        6,
        "versioned_catalog_principals_and_tool_definitions",
        ROOT / "specs" / "artifacts" / "operability-schema.target.v6.sql",
        "tool_definitions",
    ),
    TargetMigration(
        "solvan_alerts",
        1,
        "alert_triage_phase_one",
        ROOT / "specs" / "artifacts" / "alert-triage-schema.target.sql",
        "alert_ingress_deliveries",
    ),
    TargetMigration(
        "solvan_alerts",
        2,
        "alert_triage_phase_two",
        ROOT / "specs" / "artifacts" / "alert-triage-schema.target.v2.sql",
        "alert_ingress_deliveries",
    ),
    TargetMigration(
        "solvan_alerts",
        3,
        "alert_triage_operator_product",
        ROOT / "specs" / "artifacts" / "alert-triage-schema.target.v3.sql",
        "alert_ingress_deliveries",
    ),
    TargetMigration(
        "solvan_alerts",
        4,
        "alert_triage_evidence_anchor",
        ROOT / "specs" / "artifacts" / "alert-triage-schema.target.v4.sql",
        "alert_ingress_deliveries",
    ),
    TargetMigration(
        "solvan_alerts",
        5,
        "alert_policy_product_surfaces",
        ROOT / "specs" / "artifacts" / "alert-triage-schema.target.v5.sql",
        "alert_ingress_deliveries",
    ),
    TargetMigration(
        "solvan_alerts",
        6,
        "direct_gcp_pilot_identity_and_qualification",
        ROOT / "specs" / "artifacts" / "alert-triage-schema.target.v6.sql",
        "alert_ingress_deliveries",
    ),
    TargetMigration(
        "solvan_alerts",
        7,
        "direct_gcp_pilot_singleton_qualification_issuance",
        ROOT / "specs" / "artifacts" / "alert-triage-schema.target.v7.sql",
        "alert_ingress_deliveries",
    ),
    TargetMigration(
        "solvan_relay",
        1,
        "solvant_relay_baseline",
        ROOT / "specs" / "artifacts" / "relay-schema.target.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_relay",
        2,
        "relay_runtime_proof_key_reference",
        ROOT / "specs" / "artifacts" / "relay-schema.target.v2.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_relay",
        3,
        "relay_image_attestation_digest",
        ROOT / "specs" / "artifacts" / "relay-schema.target.v3.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_relay",
        4,
        "relay_cloud_monitoring_only",
        ROOT / "specs" / "artifacts" / "relay-schema.target.v4.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_relay",
        5,
        "relay_customer_deployment_profiles",
        ROOT / "specs" / "artifacts" / "relay-schema.target.v5.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_relay",
        6,
        "relay_customer_qualification_receipts",
        ROOT / "specs" / "artifacts" / "relay-schema.target.v6.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_relay",
        7,
        "relay_qualified_observability_adapters",
        ROOT / "specs" / "artifacts" / "relay-schema.target.v7.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_relay",
        8,
        "relay_qualification_adapter_evidence",
        ROOT / "specs" / "artifacts" / "relay-schema.target.v8.sql",
        "relay_enrollments",
    ),
    TargetMigration(
        "solvan_delivery",
        1,
        "governed_code_change_release_and_workspace_repair_baseline",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        2,
        "workspace_tool_call_ordinals",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v2.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        3,
        "repair_command_declared_input_resolution",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v3.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        4,
        "github_reviewer_link_lifecycle_closure",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v4.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        5,
        "governed_code_delivery_profiles",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v5.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        6,
        "provider_qualified_code_change_creation",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v6.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        7,
        "production_decision_session_and_idempotency",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v7.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        8,
        "immutable_github_observation_authority",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v8.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        9,
        "signed_release_candidate_and_exact_target_authority",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v9.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        10,
        "durable_release_target_observation_authority",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v10.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        11,
        "delivery_profile_exact_release_target_binding",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v11.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        12,
        "release_candidate_signed_envelope_authority",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v12.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        13,
        "deployment_controller_owned_rollout_start",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v13.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        14,
        "independent_release_verifier_authority",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v14.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        15,
        "verifier_owned_precanary_health_baseline",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v15.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        16,
        "controller_owned_rollout_finalization",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v16.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        17,
        "failed_verification_and_rollback_binding",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v17.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        18,
        "independent_rollback_verification",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v18.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_delivery",
        19,
        "terminal_rollout_ambiguity_recovery",
        ROOT / "specs" / "artifacts" / "code-change-release-schema.target.v19.sql",
        "code_change_requests",
    ),
    TargetMigration(
        "solvan_identity",
        1,
        "operator_identity_session_and_step_up",
        ROOT / "specs" / "artifacts" / "operator-identity-schema.target.sql",
        "actors",
    ),
    TargetMigration(
        "solvan_identity",
        2,
        "replayable_pkce_verifier",
        ROOT / "specs" / "artifacts" / "operator-identity-schema.target.v2.sql",
        "actors",
    ),
    TargetMigration(
        "solvan_identity",
        3,
        "email_sign_in_alongside_google",
        ROOT / "specs" / "artifacts" / "operator-identity-schema.target.v3.sql",
        "actors",
    ),
    TargetMigration(
        "solvan_identity",
        4,
        "transaction_bound_operator_presence",
        ROOT / "specs" / "artifacts" / "operator-identity-schema.target.v4.sql",
        "actors",
    ),
    TargetMigration(
        "solvan_conversation",
        1,
        "governed_github_conversation",
        ROOT / "specs" / "artifacts" / "github-conversation-schema.target.sql",
        "github_conversation_actions",
    ),
    TargetMigration(
        "solvan_conversation",
        2,
        "continuous_installation_intent",
        ROOT / "specs" / "artifacts" / "github-conversation-schema.target.v2.sql",
        "github_conversation_actions",
    ),
    TargetMigration(
        "solvan_conversation",
        3,
        "install_intent_spent_on_claim",
        ROOT / "specs" / "artifacts" / "github-conversation-schema.target.v3.sql",
        "github_conversation_actions",
    ),
)


def _transactional_sql(path: Path) -> str:
    value = path.read_text(encoding="utf-8")
    if "\nBEGIN;\n" not in value or not value.rstrip().endswith("COMMIT;"):
        raise TargetMigrationError(f"target migration source {path.name} has no exact wrapper")
    return value.replace("\nBEGIN;\n", "\n", 1).rstrip().removesuffix("COMMIT;").rstrip()


def _ensure_ledger(connection: Connection[Any]) -> None:
    connection.execute("CREATE SCHEMA IF NOT EXISTS solvan_migrations")
    connection.execute("REVOKE ALL ON SCHEMA solvan_migrations FROM PUBLIC")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS solvan_migrations.target_schema_versions (
             schema_name text NOT NULL,
             version integer NOT NULL CHECK (version > 0),
             migration_name text NOT NULL,
             checksum text NOT NULL CHECK (checksum ~ '^sha256:[0-9a-f]{64}$'),
             applied_at timestamptz NOT NULL DEFAULT now(),
             PRIMARY KEY (schema_name, version),
             UNIQUE (schema_name, migration_name)
           )"""
    )
    connection.execute("REVOKE ALL ON TABLE solvan_migrations.target_schema_versions FROM PUBLIC")


def apply_target_migrations(
    connection: Connection[Any],
    *,
    rebuild_local: bool = False,
) -> None:
    """Apply ordered migrations, refusing unversioned or rewritten history.

    `rebuild_local` drops and rebuilds a target schema. It is destructive and is
    passed only by the worktree-local bootstrap, whose database is disposable
    development data. A deployment bootstrap never passes it, so a real estate
    fails closed on unknown history rather than losing a schema.
    """

    _ensure_ledger(connection)
    schema_names = tuple(dict.fromkeys(item.schema_name for item in MIGRATIONS))
    for schema_name in schema_names:
        migrations = tuple(item for item in MIGRATIONS if item.schema_name == schema_name)
        if tuple(item.version for item in migrations) != tuple(range(1, len(migrations) + 1)):
            raise TargetMigrationError(
                f"{schema_name} migrations must be contiguous from version 1"
            )
        baseline = migrations[0]
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"solvan-target-migration:{schema_name}",),
        )
        anchor_exists = connection.execute(
            "SELECT to_regclass(%s) IS NOT NULL",
            (f"{schema_name}.{baseline.anchor_table}",),
        ).fetchone() == (True,)
        applied = connection.execute(
            """SELECT version,migration_name,checksum
                 FROM solvan_migrations.target_schema_versions
                WHERE schema_name=%s ORDER BY version""",
            (schema_name,),
        ).fetchall()
        if anchor_exists and not applied:
            if not rebuild_local:
                raise TargetMigrationError(
                    f"{schema_name} exists without migration history; refusing adoption"
                )
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema_name))
            )
            anchor_exists = False
        expected_prefix = [
            (item.version, item.name, item.checksum) for item in migrations[: len(applied)]
        ]
        if list(applied) != expected_prefix:
            if not rebuild_local:
                raise TargetMigrationError(
                    f"{schema_name} migration history was rewritten or is unknown"
                )
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema_name))
            )
            connection.execute(
                "DELETE FROM solvan_migrations.target_schema_versions WHERE schema_name=%s",
                (schema_name,),
            )
            anchor_exists = False
            applied = []
        if not anchor_exists and applied:
            raise TargetMigrationError(f"{schema_name} history exists but its schema is absent")
        for migration in migrations[len(applied) :]:
            if migration.version == 1:
                if anchor_exists:
                    raise TargetMigrationError(f"{schema_name} baseline cannot run over a schema")
            elif not anchor_exists:
                raise TargetMigrationError(f"{schema_name} delta cannot run without its baseline")
            connection.execute(_transactional_sql(migration.source))
            anchor_exists = True
            connection.execute(
                """INSERT INTO solvan_migrations.target_schema_versions
                     (schema_name,version,migration_name,checksum)
                   VALUES (%s,%s,%s,%s)""",
                (schema_name, migration.version, migration.name, migration.checksum),
            )


def target_migration_status(connection: Connection[Any]) -> dict[str, tuple[int, str]]:
    _ensure_ledger(connection)
    rows = connection.execute(
        """SELECT schema_name,max(version),max(checksum)
             FROM solvan_migrations.target_schema_versions GROUP BY schema_name"""
    ).fetchall()
    return {str(row[0]): (int(row[1]), str(row[2])) for row in rows}
