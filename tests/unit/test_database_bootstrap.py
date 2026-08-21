import pytest

from solvan.domain import Scope
from tools.bootstrap_database import (
    CORE_TABLES,
    DELIVERY_TABLES,
    LIAISON_TABLES,
    ONBOARDING_TABLES,
    OPERABILITY_TABLES,
    RELAY_TABLES,
    bind_bootstrap_role,
    database_role,
    delivery_grant_plan,
    expected_alert_tables,
    expected_operability_tables,
    grant_plan,
    liaison_grant_plan,
    onboarding_grant_plan,
    operability_grant_plan,
    relay_grant_plan,
    transactional_operability_schema_sql,
    transactional_schema_sql,
)


class _Result:
    def __init__(self, row: tuple[str, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[str, ...] | None:
        return self._row


class _BootstrapConnection:
    def __init__(self, *, existing: tuple[str, ...] | None = None) -> None:
        self.existing = existing
        self.calls: list[tuple[object, object]] = []

    def execute(self, query: object, params: object = None) -> _Result:
        self.calls.append((query, params))
        value = str(query)
        if value == "SELECT current_user":
            return _Result(("postgres",))
        if value.startswith("SELECT organization_id"):
            return _Result(self.existing)
        return _Result(None)


def test_bootstrap_role_gets_an_exact_temporary_scope_binding() -> None:
    connection = _BootstrapConnection()
    scope = Scope(
        "org_11111111111111111111111111",
        "prj_11111111111111111111111111",
        "env_11111111111111111111111111",
    )

    assert bind_bootstrap_role(connection, scope=scope) == "postgres"  # type: ignore[arg-type]
    assert connection.calls[-1][1] == (
        "postgres",
        scope.organization_id,
        scope.project_id,
        scope.environment_id,
    )


def test_bootstrap_role_preserves_exact_binding_and_refuses_conflict() -> None:
    scope = Scope(
        "org_11111111111111111111111111",
        "prj_11111111111111111111111111",
        "env_11111111111111111111111111",
    )
    exact = (scope.organization_id, scope.project_id, scope.environment_id)
    assert (
        bind_bootstrap_role(  # type: ignore[arg-type]
            _BootstrapConnection(existing=exact), scope=scope
        )
        is None
    )

    with pytest.raises(RuntimeError, match="conflicting scope binding"):
        bind_bootstrap_role(  # type: ignore[arg-type]
            _BootstrapConnection(existing=(exact[0], exact[1], "env_other")), scope=scope
        )


def test_database_grants_are_explicit_and_payments_cannot_read_control_plane() -> None:
    grants = {grant.workload: grant for grant in grant_plan()}
    assert grants["api"].select == CORE_TABLES
    assert grants["api"].insert == frozenset(
        {"approvals", "patch_reviews", "state_transitions", "outbox_events", "inbox_events"}
    )
    assert grants["api"].update == frozenset({"actions", "incidents"})
    assert grants["payments"].select == frozenset(
        {"fixture_payments", "fixture_admin_actions", "fixture_runtime_state"}
    )
    assert not grants["payments"].select.intersection(CORE_TABLES)
    assert grants["publisher"].update == frozenset({"outbox_events"})
    assert grants["verifier"].insert == frozenset({"verification_runs"})
    assert grants["verifier"].update == frozenset({"agent_runs", "incidents"})
    assert "approvals" not in grants["verifier"].select
    assert grants["probe"].insert == frozenset()
    assert "database_scope_bindings" in grants["probe"].select
    assert {
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
    }.issubset(grants["probe"].select)
    assert grants["injector"].insert == frozenset(
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
    )
    assert grants["injector"].update == frozenset(
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
    )
    assert "memory_promotions" in grants["injector"].select
    assert "security_events" not in grants["injector"].select
    assert grants["oracle"].insert == frozenset()
    assert grants["oracle"].update == frozenset()
    assert "actions" in grants["oracle"].select
    assert grants["memory"].insert == frozenset({"memory_promotions"})
    assert grants["memory"].update == frozenset({"memory_candidates"})
    assert "audit_events" not in grants["coordinator"].insert
    assert "audit_events" not in grants["coordinator"].update
    assert grants["github_provider"].insert == frozenset(
        {
            "github_webhook_events",
            "github_pull_requests",
            "github_check_runs",
            "github_operations",
        }
    )
    assert "approvals" not in grants["github_provider"].select
    assert grants["relay_control"].select == frozenset()
    assert grants["relay_control"].insert == frozenset()
    assert "relay_maintenance" not in grants


def test_cloud_sql_iam_role_uses_service_account_database_username() -> None:
    assert database_role(workload="actuator", deployment_project_id="solvan-demo") == (
        "solvan-actuator@solvan-demo.iam"
    )


def test_cloud_sql_iam_role_normalizes_provider_account_id() -> None:
    assert database_role(workload="github_provider", deployment_project_id="solvan-demo") == (
        "solvan-github-provider@solvan-demo.iam"
    )


def test_bootstrap_removes_standalone_transaction_wrapper() -> None:
    value = transactional_schema_sql()
    assert "\nBEGIN;\n" not in value
    assert not value.endswith("COMMIT;")
    assert "CREATE TABLE incidents" in value


def test_operability_target_schema_is_independent_and_counted() -> None:
    value = transactional_operability_schema_sql()
    assert "\nBEGIN;\n" not in value
    assert not value.endswith("COMMIT;")
    assert "CREATE SCHEMA IF NOT EXISTS solvan_operability" in value
    assert expected_operability_tables() == 62


def test_alert_target_schema_is_independent_and_counted() -> None:
    assert expected_alert_tables() == 32


def test_target_schema_grants_are_explicit_and_never_given_to_model_agents() -> None:
    liaison = {grant.workload: grant for grant in liaison_grant_plan()}
    operability = {grant.workload: grant for grant in operability_grant_plan()}
    onboarding = {grant.workload: grant for grant in onboarding_grant_plan()}
    relay = {grant.workload: grant for grant in relay_grant_plan()}
    delivery = {grant.workload: grant for grant in delivery_grant_plan()}
    assert liaison["api"].select == LIAISON_TABLES
    assert liaison["probe"].insert == frozenset()
    assert operability["api"].select == OPERABILITY_TABLES
    assert operability["probe"].update == frozenset()
    assert "agent_run_tool_bindings" in operability["coordinator"].insert
    assert "trigger_firings" in operability["detector"].insert
    assert operability["evidence"].insert == frozenset({"tool_call_receipts"})
    assert operability["evidence"].update == frozenset({"tool_call_receipts"})
    assert "agent_run_tool_bindings" in operability["evidence"].select
    assert onboarding["api"].select == ONBOARDING_TABLES
    assert onboarding["coordinator"].insert == frozenset()
    assert onboarding["evidence"].insert == frozenset({"evidence_resource_attribution"})
    assert onboarding["probe"].update == frozenset()
    assert set(liaison).isdisjoint({"evidence", "infrastructure", "execution", "verification"})
    assert set(operability).isdisjoint({"infrastructure", "execution", "verification"})
    assert set(onboarding).isdisjoint({"infrastructure", "execution", "verification"})
    assert relay["api"].select == RELAY_TABLES
    assert relay["probe"].insert == frozenset()
    assert relay["coordinator"].insert == frozenset(
        {"collection_jobs", "collection_job_transitions"}
    )
    assert "relay_receipts" in relay["relay_control"].insert
    assert "relay_evidence_acceptances" in relay["relay_control"].insert
    assert "relay_maintenance" not in relay
    assert set(relay).isdisjoint(
        {
            "evidence",
            "infrastructure",
            "execution",
            "verification",
            "slack_liaison",
            "mcp_facade",
        }
    )
    assert delivery["probe"].select == DELIVERY_TABLES
    assert delivery["workspace_adapter"].insert == frozenset(
        {"workspace_candidate_generations", "exploratory_sandbox_receipts"}
    )
    assert delivery["workspace_adapter"].update == frozenset({"private_command_dispatches"})
    assert delivery["github_provider"].insert == frozenset(
        {
            "code_change_qualification_receipts",
            "code_change_transitions",
            "code_change_operations",
            "code_change_github_observations",
        }
    )
    assert delivery["deployment_controller"].insert == frozenset(
        {
            "code_change_transitions",
            "release_target_observations",
            "release_target_reservations",
            "deployment_rollouts",
            "deployment_rollout_operations",
        }
    )
    assert delivery["release_verifier"].insert == frozenset(
        {
            "release_health_baselines",
            "release_verification_receipts",
            "release_rollback_verification_receipts",
        }
    )
    assert delivery["api"].select == frozenset(
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
    )
    assert delivery["api"].insert == frozenset(
        {
            "repair_plan_command_definitions",
            "code_delivery_profiles",
            "code_change_decisions",
            "code_change_decision_challenges",
            "release_signer_keys",
            "release_verifier_keys",
            "release_target_profiles",
        }
    )
    assert delivery["api"].update == frozenset(
        {
            "repair_plan_command_definitions",
            "code_delivery_profiles",
            "code_change_decision_challenges",
            "release_signer_keys",
            "release_verifier_keys",
            "release_target_profiles",
        }
    )
    assert set(delivery).isdisjoint(
        {"antigravity", "actuator", "evidence", "verifier", "slack_liaison", "mcp_facade"}
    )
