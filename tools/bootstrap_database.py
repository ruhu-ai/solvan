"""Initialize the authoritative schema and exact workload database grants.

Dry-run is the default. Applying requires a short-lived, administrator-owned
connection URL supplied out of band; the URL is never printed or persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg import Connection, sql

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier
from tools.target_schema_migrations import apply_target_migrations

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "specs" / "artifacts" / "schema.sql"
#: The conversational surface is a target contract, kept out of the release DDL
#: above. It is loaded into its own `solvan_liaison` schema so the feature can
#: run locally without any chance of being counted as release surface.
LIAISON_SCHEMA = ROOT / "specs" / "artifacts" / "liaison-schema.target.sql"
#: Target governed operability remains a separate schema and release claim,
#: even when deployed alongside Solvan for product qualification.
OPERABILITY_SCHEMA = ROOT / "specs" / "artifacts" / "operability-schema.target.sql"

CORE_TABLES = frozenset(
    {
        "organizations",
        "projects",
        "environments",
        "actor_role_bindings",
        "display_sequences",
        "services",
        "service_dependencies",
        "production_graph_snapshots",
        "production_graph_nodes",
        "production_graph_edges",
        "detection_rules",
        "detection_evaluations",
        "confirmation_rules",
        "reliability_cases",
        "incidents",
        "case_incidents",
        "state_transitions",
        "inbox_events",
        "outbox_events",
        "scheduled_wakeups",
        "agent_runs",
        "repair_plans",
        "patch_artifacts",
        "patch_reviews",
        "investigation_plans",
        "investigation_steps",
        "evidence_items",
        "tool_calls",
        "findings",
        "finding_evidence",
        "hypotheses",
        "policy_decisions",
        "standing_preauthorizations",
        "actions",
        "approvals",
        "target_epochs",
        "target_reservations",
        "execution_receipts",
        "verification_profiles",
        "verification_profile_bindings",
        "verification_runs",
        "memory_candidates",
        "memory_promotions",
        "security_events",
        "audit_events",
    }
)

LIAISON_TABLES = frozenset(
    {
        "scope_event_sequences",
        "liaison_record_directory",
        "liaison_scope_events",
        "liaison_record_edges",
        "liaison_threads",
        "liaison_thread_participants",
        "liaison_access_requests",
        "liaison_thread_read_cursors",
        "liaison_messages",
        "liaison_message_parts",
        "liaison_part_access",
        "liaison_part_audience_principals",
        "liaison_stream_events",
        "liaison_compaction_sources",
        "liaison_attachments",
        "liaison_channel_bindings",
        "liaison_enrollment_challenges",
        "liaison_parked_requests",
        "liaison_subscriptions",
        "liaison_channel_threads",
        "liaison_inbound_events",
        "liaison_deliveries",
        "liaison_subscription_scans",
        "liaison_turns",
        "liaison_context_compiler_revisions",
        "liaison_context_compiler_bindings",
        "liaison_turn_input_manifests",
        "liaison_grant_receipts",
        "liaison_manifest_sources",
        "liaison_operation_ledger",
        "liaison_purge_jobs",
        "liaison_policy_epochs",
        "liaison_budget_counters",
    }
)
LIAISON_IMMUTABLE_CONFIGURATION = frozenset(
    {"liaison_context_compiler_revisions", "liaison_context_compiler_bindings"}
)
LIAISON_RUNTIME_INSERT_TABLES = LIAISON_TABLES - LIAISON_IMMUTABLE_CONFIGURATION

OPERABILITY_TABLES = frozenset(
    {
        "operability_role_bindings",
        "operability_audit_events",
        "catalog_principals",
        "catalog_principal_revisions",
        "tool_definitions",
        "tool_definition_revisions",
        "tool_revisions",
        "tool_revision_requesters",
        "tool_profile_revisions",
        "tool_profile_connection_requirements",
        "tool_profile_members",
        "tool_probe_receipts",
        "agent_run_tool_bindings",
        "agent_run_accepted_tool_bindings",
        "tool_call_receipts",
        "guidance_definitions",
        "guidance_revisions",
        "guidance_revision_agents",
        "guidance_revision_profiles",
        "guidance_steps",
        "guidance_step_tools",
        "guidance_ingestion_receipts",
        "guidance_evaluations",
        "guidance_approvals",
        "guidance_selections",
        "guidance_step_runs",
        "guidance_step_tool_calls",
        "skill_owner_department_slugs",
        "skill_reader_grants",
        "skill_license_policies",
        "guidance_current_heads",
        "skill_import_attempts",
        "skill_imports",
        "skill_import_files",
        "skill_validation_receipts",
        "skill_retention_policies",
        "skill_refresh_ledgers",
        "skill_refresh_attempts",
        "skill_upstream_change_notices",
        "guidance_incompatibilities",
        "guidance_skill_bindings",
        "guidance_invocation_requests",
        "guidance_invocation_conflicts",
        "guidance_operator_notes",
        "guidance_selection_analytics",
        "guidance_export_destinations",
        "skill_export_attempts",
        "skill_export_receipts",
        "skill_retention_controls",
        "skill_deletion_receipts",
        "trigger_policy_revisions",
        "trigger_policy_evaluations",
        "trigger_policy_approvals",
        "trigger_policy_activations",
        "trigger_policy_current_heads",
        "trigger_policy_lifecycle_decisions",
        "trigger_policy_current_lifecycles",
        "trigger_policy_replacement_intents",
        "trigger_firings",
        "trigger_firing_wakeups",
        "trigger_firing_suppressions",
    }
)

ONBOARDING_TABLES = frozenset(
    {
        "connection_external_resource_scopes",
        "environment_external_project_bindings",
        "connection_external_project_coverage",
        "evidence_resource_attribution",
        "detection_rule_connection_bindings",
    }
)

RELAY_TABLES = frozenset(
    {
        "relay_signing_key_revisions",
        "relay_transition_rules",
        "relay_image_attestations",
        "relay_policy_key_revisions",
        "relay_runtime_proof_key_revisions",
        "relay_deployment_profiles",
        "relay_qualification_receipts",
        "relay_enrollments",
        "relay_readiness_challenges",
        "relay_runtime_policy_proofs",
        "relay_readiness_receipts",
        "relay_source_bindings",
        "relay_enrollment_transitions",
        "collection_jobs",
        "collection_job_transitions",
        "relay_attempts",
        "relay_upload_grants",
        "relay_receipts",
        "relay_evidence_acceptances",
        "relay_retention_controls",
    }
)

# Governed code repair and code-change/release delivery is a separately
# qualified product surface.  These relations remain outside the release
# schema, but its runtime identities still receive Cloud SQL IAM roles and
# exact scope bindings so qualification cannot accidentally run as an owner or
# an unscoped administrator.
DELIVERY_TABLES = frozenset(
    {
        "code_delivery_profiles",
        "code_change_qualification_intents",
        "code_change_qualification_receipts",
        "patch_adjudication_receipts",
        "repair_plan_command_definitions",
        "repair_plan_command_catalogs",
        "repair_plan_guidance_selection_sets",
        "repair_plan_guidance_selections",
        "workspace_candidate_generations",
        "exploratory_sandbox_receipts",
        "code_change_requests",
        "code_change_transitions",
        "code_change_decisions",
        "code_change_decision_challenges",
        "github_oauth_client_profiles",
        "github_reviewer_bindings",
        "github_reviewer_binding_events",
        "github_identity_link_transactions",
        "code_change_operations",
        "code_change_github_observations",
        "private_command_dispatches",
        "release_candidates",
        "release_signer_keys",
        "release_verifier_keys",
        "release_health_baselines",
        "release_target_profiles",
        "release_target_observations",
        "release_target_reservations",
        "deployment_rollouts",
        "deployment_rollout_operations",
        "release_verification_receipts",
        "release_rollback_verification_receipts",
    }
)


@dataclass(frozen=True, slots=True)
class WorkloadGrant:
    workload: str
    select: frozenset[str]
    insert: frozenset[str] = frozenset()
    update: frozenset[str] = frozenset()
    delete: frozenset[str] = frozenset()
    sequence_usage: bool = False


def grant_plan() -> tuple[WorkloadGrant, ...]:
    coordinator_write = CORE_TABLES.difference(
        {"organizations", "projects", "environments", "memory_promotions", "audit_events"}
    )
    return (
        WorkloadGrant(
            "api",
            CORE_TABLES,
            insert=frozenset(
                {"approvals", "patch_reviews", "state_transitions", "outbox_events", "inbox_events"}
            ),
            update=frozenset({"actions", "incidents"}),
        ),
        WorkloadGrant(
            "coordinator",
            CORE_TABLES,
            insert=coordinator_write,
            update=coordinator_write,
            delete=frozenset({"scheduled_wakeups"}),
            sequence_usage=True,
        ),
        WorkloadGrant(
            "detector",
            frozenset(
                {
                    "services",
                    "production_graph_snapshots",
                    "detection_rules",
                    "detection_evaluations",
                    "inbox_events",
                }
            ),
            insert=frozenset({"detection_evaluations", "inbox_events"}),
        ),
        WorkloadGrant(
            "evidence",
            frozenset(
                {
                    "agent_runs",
                    "projects",
                    "investigation_steps",
                    "incidents",
                    "services",
                    "production_graph_snapshots",
                    "production_graph_nodes",
                    "production_graph_edges",
                    "evidence_items",
                    "tool_calls",
                }
            ),
            insert=frozenset({"evidence_items", "tool_calls"}),
            update=frozenset({"tool_calls"}),
        ),
        WorkloadGrant(
            "actuator",
            frozenset(
                {
                    "actor_role_bindings",
                    "actions",
                    "approvals",
                    "incidents",
                    "reliability_cases",
                    "policy_decisions",
                    "standing_preauthorizations",
                    "target_epochs",
                    "target_reservations",
                    "execution_receipts",
                    "outbox_events",
                }
            ),
            insert=frozenset({"target_reservations", "execution_receipts", "outbox_events"}),
            update=frozenset(
                {
                    "actions",
                    "incidents",
                    "reliability_cases",
                    "target_epochs",
                    "target_reservations",
                }
            ),
        ),
        WorkloadGrant(
            "payments",
            frozenset({"fixture_payments", "fixture_admin_actions", "fixture_runtime_state"}),
            insert=frozenset({"fixture_payments", "fixture_admin_actions"}),
            update=frozenset({"fixture_runtime_state"}),
        ),
        WorkloadGrant(
            "publisher",
            frozenset({"outbox_events"}),
            update=frozenset({"outbox_events"}),
        ),
        WorkloadGrant(
            "verifier",
            frozenset(
                {
                    "agent_runs",
                    "actions",
                    "incidents",
                    "services",
                    "projects",
                    "verification_profiles",
                    "verification_profile_bindings",
                    "execution_receipts",
                    "verification_runs",
                }
            ),
            insert=frozenset({"verification_runs"}),
            update=frozenset({"agent_runs", "incidents"}),
        ),
        WorkloadGrant(
            "probe",
            CORE_TABLES
            | frozenset(
                {
                    # The deployment probe is a read-only qualification
                    # principal. It needs visibility of the complete release
                    # table inventory (including dormant workspace, GitHub,
                    # tenant-connection, and actuator receipt tables) so its
                    # schema and RLS checks cannot be fooled by privilege-
                    # filtered catalog views.
                    "github_repositories",
                    "github_webhook_events",
                    "github_pull_requests",
                    "github_check_runs",
                    "github_operations",
                    "workspaces",
                    "workspace_checkpoints",
                    "tenant_connections",
                    "connection_capabilities",
                    "actuator_registrations",
                    "actuator_dispatches",
                    "actuator_effect_receipts",
                    "database_scope_bindings",
                    "fixture_payments",
                    "fixture_admin_actions",
                    "fixture_runtime_state",
                }
            ),
        ),
        WorkloadGrant(
            "injector",
            frozenset(
                {
                    "actions",
                    "agent_runs",
                    "actor_role_bindings",
                    "approvals",
                    "display_sequences",
                    "execution_receipts",
                    "evidence_items",
                    "finding_evidence",
                    "findings",
                    "incidents",
                    "inbox_events",
                    "investigation_plans",
                    "investigation_steps",
                    "memory_candidates",
                    "memory_promotions",
                    "policy_decisions",
                    "production_graph_nodes",
                    "projects",
                    "reliability_cases",
                    "services",
                    "target_epochs",
                    "target_reservations",
                    "tool_calls",
                }
            ),
            insert=frozenset(
                {
                    "actions",
                    "agent_runs",
                    "actor_role_bindings",
                    "approvals",
                    "display_sequences",
                    "execution_receipts",
                    "evidence_items",
                    "finding_evidence",
                    "findings",
                    "incidents",
                    "inbox_events",
                    "investigation_plans",
                    "investigation_steps",
                    "memory_candidates",
                    "policy_decisions",
                    "security_events",
                    "target_reservations",
                    "tool_calls",
                    "outbox_events",
                }
            ),
            update=frozenset(
                {
                    "actions",
                    "agent_runs",
                    "actor_role_bindings",
                    "display_sequences",
                    "incidents",
                    "investigation_plans",
                    "investigation_steps",
                    "target_epochs",
                    "target_reservations",
                    "tool_calls",
                }
            ),
        ),
        WorkloadGrant(
            "oracle",
            CORE_TABLES
            | frozenset({"fixture_payments", "fixture_admin_actions", "fixture_runtime_state"}),
        ),
        WorkloadGrant(
            "memory",
            frozenset({"memory_candidates", "memory_promotions"}),
            insert=frozenset({"memory_promotions"}),
            update=frozenset({"memory_candidates"}),
        ),
        WorkloadGrant(
            "github_provider",
            frozenset(
                {
                    "github_repositories",
                    "github_webhook_events",
                    "github_pull_requests",
                    "github_check_runs",
                    "github_operations",
                    "patch_artifacts",
                    "patch_reviews",
                    "repair_plans",
                }
            ),
            insert=frozenset(
                {
                    "github_webhook_events",
                    "github_pull_requests",
                    "github_check_runs",
                    "github_operations",
                }
            ),
            update=frozenset(
                {
                    "github_repositories",
                    "github_webhook_events",
                    "github_pull_requests",
                    "github_operations",
                }
            ),
        ),
        WorkloadGrant(
            "slack_liaison",
            CORE_TABLES,
            insert=frozenset({"audit_events"}),
        ),
        WorkloadGrant("mcp_facade", CORE_TABLES, insert=frozenset({"audit_events"})),
        WorkloadGrant("discord_liaison", CORE_TABLES, insert=frozenset({"audit_events"})),
        WorkloadGrant("email_liaison", CORE_TABLES, insert=frozenset({"audit_events"})),
        WorkloadGrant(
            "liaison_maintenance",
            frozenset({"audit_events"}),
            insert=frozenset({"audit_events"}),
        ),
        WorkloadGrant(
            "trigger_scheduler",
            frozenset(
                {
                    "production_graph_snapshots",
                    "production_graph_nodes",
                    "services",
                    "tenant_connections",
                    "inbox_events",
                }
            ),
            insert=frozenset({"inbox_events"}),
        ),
        # Target Relay services need a Cloud SQL IAM role and exact scope
        # binding, but no direct release-schema DML. Successful evidence
        # settlement is available only through relay_commit_success_v1.
        WorkloadGrant("relay_control", frozenset()),
        WorkloadGrant("relay_maintenance", frozenset()),
        # These services have no release-schema permission by virtue of
        # existing.  The empty base grants merely create their IAM database
        # roles and bind them to an exact tenant scope; the target delivery
        # grants below are the only authority they receive.
        WorkloadGrant("workspace_adapter", frozenset({"agent_runs", "repair_plans"})),
        WorkloadGrant(
            "github_identity_broker",
            frozenset({"actor_role_bindings", "github_repositories", "audit_events"}),
            insert=frozenset({"audit_events"}),
        ),
        WorkloadGrant("deployment_controller", frozenset()),
        WorkloadGrant("release_verifier", frozenset()),
    )


def liaison_grant_plan() -> tuple[WorkloadGrant, ...]:
    """Exact target conversational privileges; no Agent service receives them."""

    return (
        WorkloadGrant(
            "api",
            LIAISON_TABLES,
            insert=LIAISON_RUNTIME_INSERT_TABLES,
            update=frozenset(
                {
                    "scope_event_sequences",
                    "liaison_threads",
                    "liaison_messages",
                    "liaison_attachments",
                    "liaison_parked_requests",
                    "liaison_deliveries",
                    "liaison_turns",
                    "liaison_operation_ledger",
                    "liaison_purge_jobs",
                    "liaison_policy_epochs",
                    "liaison_budget_counters",
                }
            ),
            delete=frozenset(
                {
                    "liaison_message_parts",
                    "liaison_part_access",
                    "liaison_part_audience_principals",
                }
            ),
        ),
        WorkloadGrant(
            "slack_liaison",
            LIAISON_TABLES,
            insert=LIAISON_RUNTIME_INSERT_TABLES,
            update=frozenset(
                {
                    "scope_event_sequences",
                    "liaison_threads",
                    "liaison_messages",
                    "liaison_channel_bindings",
                    "liaison_enrollment_challenges",
                    "liaison_subscriptions",
                    "liaison_inbound_events",
                    "liaison_deliveries",
                    "liaison_turns",
                    "liaison_operation_ledger",
                    "liaison_policy_epochs",
                    "liaison_budget_counters",
                }
            ),
        ),
        WorkloadGrant(
            "mcp_facade",
            LIAISON_TABLES,
            insert=frozenset(
                {
                    "scope_event_sequences",
                    "liaison_record_directory",
                    "liaison_scope_events",
                    "liaison_record_edges",
                    "liaison_threads",
                    "liaison_thread_participants",
                    "liaison_messages",
                    "liaison_stream_events",
                    "liaison_message_parts",
                    "liaison_part_access",
                    "liaison_part_audience_principals",
                    "liaison_turns",
                    "liaison_grant_receipts",
                    "liaison_operation_ledger",
                    "liaison_policy_epochs",
                    "liaison_budget_counters",
                    "liaison_channel_bindings",
                    "liaison_enrollment_challenges",
                }
            ),
            update=frozenset(
                {
                    "scope_event_sequences",
                    "liaison_threads",
                    "liaison_messages",
                    "liaison_turns",
                    "liaison_operation_ledger",
                    "liaison_policy_epochs",
                    "liaison_budget_counters",
                    "liaison_channel_bindings",
                    "liaison_enrollment_challenges",
                }
            ),
        ),
        *(
            WorkloadGrant(
                workload,
                LIAISON_TABLES,
                insert=LIAISON_RUNTIME_INSERT_TABLES,
                update=frozenset(
                    {
                        "scope_event_sequences",
                        "liaison_threads",
                        "liaison_messages",
                        "liaison_channel_bindings",
                        "liaison_enrollment_challenges",
                        "liaison_inbound_events",
                        "liaison_deliveries",
                        "liaison_turns",
                        "liaison_operation_ledger",
                        "liaison_policy_epochs",
                        "liaison_budget_counters",
                    }
                ),
            )
            for workload in ("discord_liaison", "email_liaison")
        ),
        WorkloadGrant(
            "liaison_maintenance",
            LIAISON_TABLES,
            insert=frozenset(
                {
                    "liaison_messages",
                    "liaison_message_parts",
                    "liaison_compaction_sources",
                    "liaison_part_access",
                    "liaison_part_audience_principals",
                    "liaison_purge_jobs",
                    "liaison_grant_receipts",
                }
            ),
            update=frozenset(
                {"liaison_threads", "liaison_messages", "liaison_turns", "liaison_purge_jobs"}
            ),
            delete=frozenset(
                {
                    "liaison_message_parts",
                    "liaison_part_access",
                    "liaison_part_audience_principals",
                }
            ),
        ),
        WorkloadGrant("probe", LIAISON_TABLES),
    )


def operability_grant_plan() -> tuple[WorkloadGrant, ...]:
    """Exact target catalog, guidance, and trigger privileges by typed service."""

    trigger_tables = frozenset(
        {"trigger_firings", "trigger_firing_wakeups", "trigger_firing_suppressions"}
    )
    catalog_read = frozenset(
        {
            "catalog_principals",
            "tool_definitions",
            "tool_revisions",
            "tool_revision_requesters",
            "tool_profile_revisions",
            "tool_profile_connection_requirements",
            "tool_profile_members",
            "tool_probe_receipts",
            "agent_run_tool_bindings",
        }
    )
    return (
        WorkloadGrant(
            "api",
            OPERABILITY_TABLES,
            insert=OPERABILITY_TABLES.difference(
                {
                    "agent_run_tool_bindings",
                    "guidance_step_runs",
                    "operability_role_bindings",
                }
            ),
            update=frozenset(
                {
                    "guidance_revisions",
                    "trigger_policy_revisions",
                    "trigger_firings",
                    "trigger_firing_wakeups",
                }
            ),
        ),
        WorkloadGrant(
            "coordinator",
            OPERABILITY_TABLES,
            insert=frozenset(
                {
                    "agent_run_tool_bindings",
                    "guidance_selections",
                    "guidance_step_runs",
                }
            )
            | trigger_tables,
            update=frozenset({"guidance_step_runs", "trigger_firings", "trigger_firing_wakeups"}),
        ),
        WorkloadGrant(
            "detector",
            catalog_read | frozenset({"trigger_policy_revisions"}) | trigger_tables,
            insert=trigger_tables,
            update=frozenset({"trigger_firings", "trigger_firing_wakeups"}),
        ),
        WorkloadGrant(
            "trigger_scheduler",
            catalog_read | frozenset({"trigger_policy_revisions"}) | trigger_tables,
            insert=trigger_tables,
            update=frozenset({"trigger_firings", "trigger_firing_wakeups"}),
        ),
        WorkloadGrant(
            "evidence",
            catalog_read | frozenset({"tool_call_receipts"}),
            insert=frozenset({"tool_call_receipts"}),
            update=frozenset({"tool_call_receipts"}),
        ),
        WorkloadGrant("probe", OPERABILITY_TABLES),
    )


def onboarding_grant_plan() -> tuple[WorkloadGrant, ...]:
    """Exact estate-scope authority; model-backed Agents receive no SQL role."""

    authority_tables = frozenset(
        {
            "connection_external_resource_scopes",
            "environment_external_project_bindings",
            "connection_external_project_coverage",
            "detection_rule_connection_bindings",
        }
    )
    resolved_read_tables = frozenset(
        {
            "environment_external_project_bindings",
            "connection_external_project_coverage",
        }
    )
    return (
        WorkloadGrant(
            "api",
            ONBOARDING_TABLES,
            insert=authority_tables,
            update=authority_tables,
        ),
        WorkloadGrant("coordinator", resolved_read_tables),
        WorkloadGrant("detector", frozenset({"detection_rule_connection_bindings"})),
        WorkloadGrant(
            "evidence",
            resolved_read_tables | frozenset({"evidence_resource_attribution"}),
            insert=frozenset({"evidence_resource_attribution"}),
        ),
        WorkloadGrant("verifier", resolved_read_tables),
        WorkloadGrant("probe", ONBOARDING_TABLES),
    )


def relay_grant_plan() -> tuple[WorkloadGrant, ...]:
    """Exact target Relay privileges; customer Relay and Agents have no SQL role."""

    administrative = frozenset(
        {
            "relay_policy_key_revisions",
            "relay_runtime_proof_key_revisions",
            "relay_enrollments",
            "relay_source_bindings",
            "relay_enrollment_transitions",
        }
    )

    coordinator_write = frozenset({"collection_jobs", "collection_job_transitions"})
    control_write = frozenset(
        {
            "relay_readiness_challenges",
            "relay_runtime_policy_proofs",
            "relay_readiness_receipts",
            "relay_enrollment_transitions",
            "collection_job_transitions",
            "relay_attempts",
            "relay_upload_grants",
            "relay_receipts",
            "relay_evidence_acceptances",
        }
    )
    return (
        WorkloadGrant(
            "api",
            RELAY_TABLES,
            insert=administrative,
            update=frozenset({"relay_enrollments", "relay_source_bindings"}),
        ),
        WorkloadGrant(
            "coordinator",
            RELAY_TABLES,
            insert=coordinator_write,
            update=frozenset({"collection_jobs"}),
        ),
        WorkloadGrant(
            "relay_control",
            RELAY_TABLES,
            insert=control_write,
            update=frozenset(
                {
                    "relay_readiness_challenges",
                    "relay_enrollments",
                    "collection_jobs",
                    "relay_attempts",
                    "relay_upload_grants",
                }
            ),
        ),
        WorkloadGrant(
            "relay_maintenance",
            frozenset(
                {
                    "relay_enrollments",
                    "collection_jobs",
                    "relay_attempts",
                    "relay_upload_grants",
                    "relay_receipts",
                    "relay_retention_controls",
                }
            ),
            insert=frozenset({"relay_retention_controls"}),
            update=frozenset({"collection_jobs", "relay_retention_controls"}),
        ),
        WorkloadGrant("probe", RELAY_TABLES),
    )


CONVERSATION_TABLES = frozenset(
    {
        "github_conversation_participants",
        "github_conversation_threads",
        "github_conversation_actions",
        "github_installation_intents",
    }
)


def conversation_grant_plan() -> tuple[WorkloadGrant, ...]:
    """Exact authority over the GitHub conversation surface.

    The split between the two writers is the point. The provider is driven by
    inbound webhook traffic, so it may record who asked and what thread they
    asked on — but it may not create an action, because an action is something
    Solvan proposes to say and only the approval path authors one. The API may
    create and decide an action but may not move it to published, because
    publication is the provider observing GitHub accept it.
    """

    return (
        WorkloadGrant(
            "api",
            CONVERSATION_TABLES,
            insert=frozenset({"github_conversation_actions"}),
            update=frozenset({"github_conversation_participants", "github_conversation_actions"}),
        ),
        WorkloadGrant(
            "github_provider",
            CONVERSATION_TABLES,
            insert=frozenset({"github_conversation_participants", "github_conversation_threads"}),
            update=CONVERSATION_TABLES,
        ),
        WorkloadGrant(
            "coordinator",
            CONVERSATION_TABLES,
            update=frozenset({"github_conversation_actions"}),
        ),
        WorkloadGrant("probe", CONVERSATION_TABLES),
    )


def delivery_grant_plan() -> tuple[WorkloadGrant, ...]:
    """Exact Code Repair/Change/Release authority by deterministic service.

    Model providers, channels, the Action Actuator, and the existing generic
    verifier receive no delivery-schema grant. Runtime handlers must still
    reload the particular durable command and enforce its material, caller,
    deadline, and idempotency fences.
    """

    coordinator_read = DELIVERY_TABLES.difference({"github_oauth_client_profiles"})
    return (
        WorkloadGrant(
            "api",
            frozenset(
                {
                    "repair_plan_command_definitions",
                    "code_delivery_profiles",
                    "code_change_requests",
                    "code_change_transitions",
                    "code_change_decisions",
                    "code_change_decision_challenges",
                    "code_change_operations",
                    "code_change_github_observations",
                    "release_candidates",
                    "release_signer_keys",
                    "release_verifier_keys",
                    "release_target_profiles",
                    "release_target_observations",
                    "release_health_baselines",
                    "deployment_rollouts",
                    "release_verification_receipts",
                    "release_rollback_verification_receipts",
                }
            ),
            insert=frozenset(
                {
                    "repair_plan_command_definitions",
                    "code_delivery_profiles",
                    "code_change_decisions",
                    "code_change_decision_challenges",
                    "release_signer_keys",
                    "release_verifier_keys",
                    "release_target_profiles",
                }
            ),
            update=frozenset(
                {
                    "repair_plan_command_definitions",
                    "code_delivery_profiles",
                    "code_change_decision_challenges",
                    "release_signer_keys",
                    "release_verifier_keys",
                    "release_target_profiles",
                }
            ),
        ),
        WorkloadGrant(
            "coordinator",
            coordinator_read,
            insert=frozenset(
                {
                    "repair_plan_command_catalogs",
                    "repair_plan_guidance_selection_sets",
                    "repair_plan_guidance_selections",
                    "code_change_qualification_intents",
                    "patch_adjudication_receipts",
                    "code_change_requests",
                    "code_change_transitions",
                    "code_change_decisions",
                    "code_change_operations",
                    "private_command_dispatches",
                    "release_candidates",
                }
            ),
            update=frozenset(
                {
                    "repair_plan_guidance_selection_sets",
                    "code_change_operations",
                    "private_command_dispatches",
                }
            ),
        ),
        WorkloadGrant(
            "workspace_adapter",
            frozenset(
                {
                    "repair_plan_command_definitions",
                    "repair_plan_command_catalogs",
                    "repair_plan_guidance_selection_sets",
                    "repair_plan_guidance_selections",
                    "workspace_candidate_generations",
                    "exploratory_sandbox_receipts",
                    "private_command_dispatches",
                }
            ),
            insert=frozenset({"workspace_candidate_generations", "exploratory_sandbox_receipts"}),
            update=frozenset({"private_command_dispatches"}),
        ),
        WorkloadGrant(
            "github_provider",
            frozenset(
                {
                    "code_delivery_profiles",
                    "code_change_qualification_intents",
                    "code_change_qualification_receipts",
                    "patch_adjudication_receipts",
                    "workspace_candidate_generations",
                    "code_change_requests",
                    "code_change_transitions",
                    "code_change_decisions",
                    "github_reviewer_bindings",
                    "github_reviewer_binding_events",
                    "code_change_operations",
                    "private_command_dispatches",
                    "code_change_github_observations",
                }
            ),
            insert=frozenset(
                {
                    "code_change_qualification_receipts",
                    "code_change_transitions",
                    "code_change_operations",
                    "code_change_github_observations",
                }
            ),
            update=frozenset({"code_change_operations", "private_command_dispatches"}),
        ),
        WorkloadGrant(
            "github_identity_broker",
            frozenset(
                {
                    "github_oauth_client_profiles",
                    "code_delivery_profiles",
                    "github_reviewer_bindings",
                    "github_reviewer_binding_events",
                    "github_identity_link_transactions",
                    "private_command_dispatches",
                }
            ),
            insert=frozenset(
                {
                    "github_reviewer_bindings",
                    "github_reviewer_binding_events",
                    "github_identity_link_transactions",
                }
            ),
            update=frozenset(
                {
                    "github_identity_link_transactions",
                    "private_command_dispatches",
                }
            ),
        ),
        WorkloadGrant(
            "deployment_controller",
            frozenset(
                {
                    "code_change_requests",
                    "code_change_transitions",
                    "code_change_decisions",
                    "release_candidates",
                    "release_signer_keys",
                    "release_verifier_keys",
                    "release_target_profiles",
                    "release_target_observations",
                    "release_health_baselines",
                    "release_target_reservations",
                    "deployment_rollouts",
                    "deployment_rollout_operations",
                    "release_verification_receipts",
                    "release_rollback_verification_receipts",
                    "private_command_dispatches",
                }
            ),
            insert=frozenset(
                {
                    "code_change_transitions",
                    "release_target_observations",
                    "release_target_reservations",
                    "deployment_rollouts",
                    "deployment_rollout_operations",
                }
            ),
            update=frozenset(
                {
                    "release_target_reservations",
                    "deployment_rollouts",
                    "deployment_rollout_operations",
                    "private_command_dispatches",
                }
            ),
        ),
        WorkloadGrant(
            "release_verifier",
            frozenset(
                {
                    "code_delivery_profiles",
                    "code_change_requests",
                    "release_candidates",
                    "release_target_profiles",
                    "release_verifier_keys",
                    "release_health_baselines",
                    "deployment_rollouts",
                    "release_target_observations",
                    "release_verification_receipts",
                    "release_rollback_verification_receipts",
                    "private_command_dispatches",
                }
            ),
            insert=frozenset(
                {
                    "release_health_baselines",
                    "release_verification_receipts",
                    "release_rollback_verification_receipts",
                }
            ),
            update=frozenset({"private_command_dispatches"}),
        ),
        WorkloadGrant("probe", DELIVERY_TABLES),
    )


def database_role(*, workload: str, deployment_project_id: str) -> str:
    if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", deployment_project_id) is None:
        raise ValueError("GCP project ID is invalid")
    # Terraform derives provider-valid service-account IDs by replacing the
    # internal registry key's underscores with hyphens. Cloud SQL IAM database
    # roles therefore use the same canonical spelling.
    return f"solvan-{workload.replace('_', '-')}@{deployment_project_id}.iam"


def bind_bootstrap_role(connection: Connection[Any], *, scope: Scope) -> str | None:
    """Give the migration owner its exact scope only for this transaction.

    Target schemas enable FORCE RLS before their bootstrap rows are inserted.
    Cloud SQL's postgres administrator does not bypass that policy, so the
    migration needs the same immutable scope predicate as every workload. The
    caller removes a newly created binding before commit; a pre-existing exact
    binding is preserved, while a conflicting binding refuses.
    """

    current = connection.execute("SELECT current_user").fetchone()
    if current is None or not isinstance(current[0], str) or not current[0]:
        raise RuntimeError("database migration role is unavailable")
    role = current[0]
    existing = connection.execute(
        """SELECT organization_id,project_id,environment_id
             FROM solvan.database_scope_bindings WHERE database_role=%s""",
        (role,),
    ).fetchone()
    exact_scope = (scope.organization_id, scope.project_id, scope.environment_id)
    if existing is not None:
        if existing != exact_scope:
            raise RuntimeError("database migration role has a conflicting scope binding")
        return None
    connection.execute(
        """INSERT INTO solvan.database_scope_bindings
             (database_role,organization_id,project_id,environment_id)
           VALUES (%s,%s,%s,%s)""",
        (role, *exact_scope),
    )
    return role


def transactional_schema_sql() -> str:
    """Return the authoritative DDL without its standalone transaction wrapper."""

    value = SCHEMA.read_text(encoding="utf-8")
    if "\nBEGIN;\n" not in value or not value.rstrip().endswith("COMMIT;"):
        raise RuntimeError("authoritative schema transaction wrapper is malformed")
    value = value.replace("\nBEGIN;\n", "\n", 1)
    return value.rstrip().removesuffix("COMMIT;").rstrip()


def transactional_liaison_schema_sql() -> str:
    """Return the target conversational DDL without its transaction wrapper."""

    value = LIAISON_SCHEMA.read_text(encoding="utf-8")
    if "\nBEGIN;\n" not in value or not value.rstrip().endswith("COMMIT;"):
        raise RuntimeError("target conversational schema transaction wrapper is malformed")
    value = value.replace("\nBEGIN;\n", "\n", 1)
    return value.rstrip().removesuffix("COMMIT;").rstrip()


def expected_liaison_tables() -> int:
    """How many tables the target conversational schema declares."""

    return LIAISON_SCHEMA.read_text(encoding="utf-8").count("\nCREATE TABLE ")


def transactional_operability_schema_sql() -> str:
    """Return governed-operability target DDL without its transaction wrapper."""

    value = OPERABILITY_SCHEMA.read_text(encoding="utf-8")
    if "\nBEGIN;\n" not in value or not value.rstrip().endswith("COMMIT;"):
        raise RuntimeError("target operability schema transaction wrapper is malformed")
    value = value.replace("\nBEGIN;\n", "\n", 1)
    return value.rstrip().removesuffix("COMMIT;").rstrip()


def expected_operability_tables() -> int:
    """How many tables the governed-operability target schema declares."""

    sources = sorted((ROOT / "specs" / "artifacts").glob("operability-schema.target*.sql"))
    return sum(source.read_text(encoding="utf-8").count("CREATE TABLE ") for source in sources)


def expected_alert_tables() -> int:
    """How many tables the ordered Alert Triage target migrations declare."""

    sources = sorted((ROOT / "specs" / "artifacts").glob("alert-triage-schema.target*.sql"))
    return sum(source.read_text(encoding="utf-8").count("CREATE TABLE ") for source in sources)


def _grant_tables(
    connection: Connection[Any],
    *,
    role: str,
    privilege: str,
    tables: frozenset[str],
    schema: str = "solvan",
) -> None:
    if not tables:
        return
    table_list = sql.SQL(", ").join(
        sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(table))
        for table in sorted(tables)
    )
    connection.execute(
        sql.SQL("GRANT {} ON TABLE {} TO {}").format(
            sql.SQL(privilege), table_list, sql.Identifier(role)
        )
    )


def apply(
    *,
    connection: Connection[Any],
    scope: Scope,
    deployment_project_id: str,
    region: str = "europe-west1",
    rebuild_local_target_schemas: bool = False,
    github_oauth_client_id: str | None = None,
    github_oauth_client_secret_ref: str | None = None,
    github_oauth_callback_uri: str | None = None,
) -> None:
    schema_exists = connection.execute(
        "SELECT to_regclass('solvan.organizations') IS NOT NULL"
    ).fetchone()
    if schema_exists != (True,):
        connection.execute(transactional_schema_sql())
    table_count = connection.execute(
        """SELECT count(*) FROM information_schema.tables
          WHERE table_schema = 'solvan' AND table_type = 'BASE TABLE'"""
    ).fetchone()
    if table_count != (61,):
        raise RuntimeError(f"authoritative schema drift: expected 61 tables, found {table_count}")

    # Re-apply the non-negotiable database boundary on every bootstrap. This
    # is idempotent and also hardens databases created before the FORCE clause
    # was added to schema.sql; no migration may leave a scoped table owned by
    # a bypass-capable role without forced RLS.
    connection.execute(
        """DO $scope_force$
        DECLARE scoped_table record;
        BEGIN
          FOR scoped_table IN
            SELECT table_name
              FROM information_schema.columns
             WHERE table_schema = 'solvan'
               AND column_name IN ('organization_id','project_id','environment_id')
               AND table_name <> 'database_scope_bindings'
             GROUP BY table_name
            HAVING count(DISTINCT column_name) = 3
          LOOP
            EXECUTE format('ALTER TABLE solvan.%I ENABLE ROW LEVEL SECURITY',
                           scoped_table.table_name);
            EXECUTE format('ALTER TABLE solvan.%I FORCE ROW LEVEL SECURITY',
                           scoped_table.table_name);
          END LOOP;
        END
        $scope_force$;"""
    )

    apply_target_migrations(connection, rebuild_local=rebuild_local_target_schemas)
    for schema_name, expected in (
        (
            "solvan_scale",
            28,
        ),
        (
            "solvan_liaison",
            expected_liaison_tables(),
        ),
        (
            "solvan_operability",
            expected_operability_tables(),
        ),
        (
            "solvan_alerts",
            expected_alert_tables(),
        ),
        (
            "solvan_onboarding",
            len(ONBOARDING_TABLES),
        ),
        (
            "solvan_relay",
            len(RELAY_TABLES),
        ),
        (
            "solvan_delivery",
            len(DELIVERY_TABLES),
        ),
    ):
        target_count = connection.execute(
            """SELECT count(*) FROM information_schema.tables
                 WHERE table_schema = %s AND table_type = 'BASE TABLE'""",
            (schema_name,),
        ).fetchone()
        if target_count != (expected,):
            raise RuntimeError(
                f"{schema_name} target schema drift: expected {expected} tables, "
                f"found {target_count}"
            )

    connection.execute(
        """INSERT INTO solvan.organizations (id, display_name)
          VALUES (%s, 'Solvan competition organization') ON CONFLICT DO NOTHING""",
        (scope.organization_id,),
    )
    # `projects.gcp_project_id` is the tenancy column specification 13 §4.3
    # removes at promotion of the connection-scope delta. It is seeded from the
    # deployment project only because a single-project development deployment
    # happens to run Solvan inside the estate it watches. That coincidence is
    # not a contract: nothing may read this column expecting the deployment
    # project, and nothing may read `deployment_project_id` expecting a
    # customer's estate.
    connection.execute(
        """INSERT INTO solvan.projects
          (organization_id, id, display_name, gcp_project_id)
          VALUES (%s, %s, 'Solvan competition project', %s) ON CONFLICT DO NOTHING""",
        (scope.organization_id, scope.project_id, deployment_project_id),
    )
    connection.execute(
        """INSERT INTO solvan.environments
          (organization_id, project_id, id, display_name, region, classification)
          VALUES (%s, %s, %s, 'Hackathon', %s, 'CONFIDENTIAL')
          ON CONFLICT DO NOTHING""",
        (scope.organization_id, scope.project_id, scope.environment_id, region),
    )
    resolved_scope = connection.execute(
        """SELECT p.gcp_project_id, e.region
          FROM solvan.projects p JOIN solvan.environments e
            ON e.organization_id = p.organization_id AND e.project_id = p.id
          WHERE e.organization_id = %s AND e.project_id = %s AND e.id = %s""",
        (scope.organization_id, scope.project_id, scope.environment_id),
    ).fetchone()
    if resolved_scope != (deployment_project_id, region):
        raise RuntimeError("existing tenant scope conflicts with deployment project or region")

    temporary_bootstrap_role = bind_bootstrap_role(connection, scope=scope)

    oauth_values = (
        github_oauth_client_id,
        github_oauth_client_secret_ref,
        github_oauth_callback_uri,
    )
    if any(value is not None for value in oauth_values):
        if not all(isinstance(value, str) and value for value in oauth_values):
            raise RuntimeError("GitHub OAuth profile configuration must be complete")
        assert github_oauth_client_id is not None
        assert github_oauth_client_secret_ref is not None
        assert github_oauth_callback_uri is not None
        material = {
            "provider_kind": "GITHUB_APP_USER_TO_SERVER",
            "github_app_client_id": github_oauth_client_id,
            "client_secret_ref": github_oauth_client_secret_ref,
            "authorization_endpoint": "https://github.com/login/oauth/authorize",
            "token_endpoint": "https://github.com/login/oauth/access_token",
            "api_base_url": "https://api.github.com",
            "callback_uri": github_oauth_callback_uri,
            "protocol_version": "github-app-user-to-server-v1",
            "token_expiration_required": True,
        }
        configuration_hash = canonical_sha256(material)
        active = connection.execute(
            """SELECT configuration_hash FROM solvan_delivery.github_oauth_client_profiles
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND status='ACTIVE' FOR UPDATE""",
            (scope.organization_id, scope.project_id, scope.environment_id),
        ).fetchone()
        if active != (configuration_hash,):
            connection.execute(
                """UPDATE solvan_delivery.github_oauth_client_profiles
                      SET status='REVOKED',revoked_at=now()
                    WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                      AND status='ACTIVE'""",
                (scope.organization_id, scope.project_id, scope.environment_id),
            )
            connection.execute(
                """INSERT INTO solvan_delivery.github_oauth_client_profiles
                     (organization_id,project_id,environment_id,id,provider_kind,
                      github_app_client_id,client_secret_ref,authorization_endpoint,
                      token_endpoint,api_base_url,callback_uri,protocol_version,
                      token_expiration_required,configuration_hash,status,activated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true,%s,'ACTIVE',now())""",
                (
                    scope.organization_id,
                    scope.project_id,
                    scope.environment_id,
                    new_identifier("gop"),
                    material["provider_kind"],
                    material["github_app_client_id"],
                    material["client_secret_ref"],
                    material["authorization_endpoint"],
                    material["token_endpoint"],
                    material["api_base_url"],
                    material["callback_uri"],
                    material["protocol_version"],
                    configuration_hash,
                ),
            )

    cell_id = f"cell_{region.replace('-', '_')}"
    eligibility_profile_hash = (
        "sha256:"
        + hashlib.sha256(f"{deployment_project_id}:{region}:eligibility".encode()).hexdigest()
    )
    connection.execute(
        """INSERT INTO solvan_scale.cell_eligibility_profiles (
              eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
              allowed_provider_launch_stages,encryption_profile_hash,
              support_access_allowed,allowed_recovery_regions,approved_ref)
           VALUES (%s,ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY[%s],ARRAY['GA'],
              %s,false,ARRAY[%s],'ref_local_bootstrap')
           ON CONFLICT (eligibility_profile_hash) DO NOTHING""",
        (eligibility_profile_hash, region, "sha256:" + "5" * 64, region),
    )
    connection.execute(
        """INSERT INTO solvan_scale.cells (
              cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
              capacity_profile_hash,data_policy_hash,eligibility_profile_hash,
              deployment_manifest_hash)
           VALUES (%s,'OSS_SINGLE_TENANT',%s,%s,'READY',1,%s,%s,%s,%s)
           ON CONFLICT (cell_id) DO NOTHING""",
        (
            cell_id,
            region,
            deployment_project_id,
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
            eligibility_profile_hash,
            "sha256:" + hashlib.sha256(f"{deployment_project_id}:{region}".encode()).hexdigest(),
        ),
    )
    tenant_requirement_hash = (
        "sha256:"
        + hashlib.sha256(
            f"{scope.organization_id}:{region}:tenant-eligibility".encode()
        ).hexdigest()
    )
    connection.execute(
        """INSERT INTO solvan_scale.tenant_eligibility_requirements (
              organization_id,requirement_hash,allowed_classifications,
              allowed_residency_regions,allowed_provider_launch_stages,
              encryption_profile_hash,support_access_allowed,
              allowed_recovery_regions,approved_ref)
           VALUES (%s,%s,ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY[%s],
              ARRAY['GA'],%s,false,ARRAY[%s],'ref_local_tenant_bootstrap')
           ON CONFLICT (organization_id,requirement_hash) DO NOTHING""",
        (
            scope.organization_id,
            tenant_requirement_hash,
            region,
            "sha256:" + "5" * 64,
            region,
        ),
    )
    connection.execute(
        """INSERT INTO solvan_scale.tenant_placements (
              organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
              home_region,classification_ceiling,eligibility_requirement_hash,
              policy_hash,encryption_profile_hash,activated_at)
           SELECT %s,1,%s,'ACTIVE',true,'OSS_SINGLE_TENANT',%s,'CONFIDENTIAL',%s,%s,%s,now()
            WHERE NOT EXISTS (SELECT 1 FROM solvan_scale.tenant_placements
                WHERE organization_id=%s AND is_current)""",
        (
            scope.organization_id,
            cell_id,
            region,
            tenant_requirement_hash,
            "sha256:" + "3" * 64,
            "sha256:" + "5" * 64,
            scope.organization_id,
        ),
    )

    connection.execute("REVOKE ALL ON SCHEMA solvan FROM PUBLIC")
    connection.execute("REVOKE ALL ON ALL TABLES IN SCHEMA solvan FROM PUBLIC")
    connection.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA solvan FROM PUBLIC")
    connection.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA solvan FROM PUBLIC")
    for target_schema in (
        "solvan_scale",
        "solvan_onboarding",
        "solvan_liaison",
        "solvan_graph",
        "solvan_quality",
        "solvan_operability",
        "solvan_relay",
        "solvan_delivery",
        "solvan_conversation",
    ):
        connection.execute(
            sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(target_schema))
        )
        connection.execute(
            sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM PUBLIC").format(
                sql.Identifier(target_schema)
            )
        )
        connection.execute(
            sql.SQL("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {} FROM PUBLIC").format(
                sql.Identifier(target_schema)
            )
        )
    current_database = connection.execute("SELECT current_database()").fetchone()
    if current_database is None or not isinstance(current_database[0], str):
        raise RuntimeError("database name is unavailable")

    for grant in grant_plan():
        role = database_role(workload=grant.workload, deployment_project_id=deployment_project_id)
        role_exists = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", (role,)
        ).fetchone()
        if role_exists != (True,):
            raise RuntimeError(f"Cloud SQL IAM database role is missing: {role}")
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(current_database[0]), sql.Identifier(role)
            )
        )
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA solvan TO {}").format(sql.Identifier(role))
        )
        connection.execute(
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION solvan.scope_permitted(name, text, text, text) TO {}"
            ).format(sql.Identifier(role))
        )
        _grant_tables(connection, role=role, privilege="SELECT", tables=grant.select)
        _grant_tables(connection, role=role, privilege="INSERT", tables=grant.insert)
        _grant_tables(connection, role=role, privilege="UPDATE", tables=grant.update)
        _grant_tables(connection, role=role, privilege="DELETE", tables=grant.delete)
        if grant.sequence_usage:
            connection.execute(
                sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA solvan TO {}").format(
                    sql.Identifier(role)
                )
            )
        connection.execute(
            """INSERT INTO solvan.database_scope_bindings
              (database_role, organization_id, project_id, environment_id)
              VALUES (%s, %s, %s, %s)
              ON CONFLICT (database_role) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                project_id = EXCLUDED.project_id,
                environment_id = EXCLUDED.environment_id""",
            (role, scope.organization_id, scope.project_id, scope.environment_id),
        )

    for target_schema, target_grants in (
        ("solvan_liaison", liaison_grant_plan()),
        ("solvan_operability", operability_grant_plan()),
        ("solvan_onboarding", onboarding_grant_plan()),
        ("solvan_relay", relay_grant_plan()),
        ("solvan_delivery", delivery_grant_plan()),
        ("solvan_conversation", conversation_grant_plan()),
    ):
        for grant in target_grants:
            role = database_role(
                workload=grant.workload, deployment_project_id=deployment_project_id
            )
            connection.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(target_schema), sql.Identifier(role)
                )
            )
            _grant_tables(
                connection,
                role=role,
                privilege="SELECT",
                tables=grant.select,
                schema=target_schema,
            )
            _grant_tables(
                connection,
                role=role,
                privilege="INSERT",
                tables=grant.insert,
                schema=target_schema,
            )
            _grant_tables(
                connection,
                role=role,
                privilege="UPDATE",
                tables=grant.update,
                schema=target_schema,
            )
            _grant_tables(
                connection,
                role=role,
                privilege="DELETE",
                tables=grant.delete,
                schema=target_schema,
            )

    relay_control_role = database_role(
        workload="relay_control", deployment_project_id=deployment_project_id
    )
    connection.execute(
        sql.SQL(
            "GRANT EXECUTE ON FUNCTION solvan_relay.relay_commit_success_v1("
            "solvan_relay.relay_receipts,solvan.evidence_items,"
            "solvan_relay.relay_evidence_acceptances,"
            "solvan_relay.collection_job_transitions,solvan.outbox_events) TO {}"
        ).format(sql.Identifier(relay_control_role))
    )

    # The context compiler resolves placement as read-only authority before it
    # writes a manifest. No conversational workload may alter placement.
    for workload in {item.workload for item in liaison_grant_plan()}:
        role = database_role(workload=workload, deployment_project_id=deployment_project_id)
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA solvan_scale TO {}").format(sql.Identifier(role))
        )
        connection.execute(
            sql.SQL(
                "GRANT SELECT ON TABLE solvan_scale.cells, solvan_scale.tenant_placements TO {}"
            ).format(sql.Identifier(role))
        )

    persistent_roles = {
        database_role(workload=item.workload, deployment_project_id=deployment_project_id)
        for item in grant_plan()
    }
    if temporary_bootstrap_role is not None and temporary_bootstrap_role not in persistent_roles:
        connection.execute(
            "DELETE FROM solvan.database_scope_bindings WHERE database_role=%s",
            (temporary_bootstrap_role,),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment-project-id", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--region", default="europe-west1")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    scope = Scope(args.organization_id, args.project_id, args.environment_id)
    roles = [
        database_role(workload=item.workload, deployment_project_id=args.deployment_project_id)
        for item in grant_plan()
    ]
    if not args.apply:
        print("PLAN_ONLY: initialize schema and bind exact scope to roles:")
        for role in roles:
            print(f"- {role}")
        return 0
    database_url = os.environ.get("SOLVAN_MIGRATION_DATABASE_URL")
    if not database_url:
        raise RuntimeError("SOLVAN_MIGRATION_DATABASE_URL is required with --apply")
    with psycopg.connect(database_url) as connection, connection.transaction():
        apply(
            connection=connection,
            scope=scope,
            deployment_project_id=args.deployment_project_id,
            region=args.region,
        )
    print("APPLIED_UNVERIFIED: schema and grants committed; run platform preflight next")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
