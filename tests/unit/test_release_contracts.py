from __future__ import annotations

from pathlib import Path

import yaml

from apps.api.console_fixture import console_snapshot

ROOT = Path(__file__).resolve().parents[2]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_registry_catalog_is_complete_versioned_and_cross_department_discoverable() -> None:
    value = yaml.safe_load(_text("specs/artifacts/agent-manifests.yaml"))
    agents = value["agents"]
    assert value["platform"]["framework"] == "google-adk"
    assert value["platform"]["location"] == "europe-west1"
    assert value["platform"]["model_location"] == "eu"
    assert value["platform"]["model_endpoint"] == "https://aiplatform.eu.rep.googleapis.com"
    assert len(agents) == 6
    assert len({agent["agent_key"] for agent in agents}) == 6
    assert value["status"] == "implementation_complete_pending_cloud_evidence"
    statuses = {agent["agent_key"]: agent["implementation_status"] for agent in agents}
    assert statuses == {
        "incident-supervisor": "IMPLEMENTED",
        "evidence-agent": "IMPLEMENTED",
        "infrastructure-agent": "IMPLEMENTED",
        "execution-agent": "IMPLEMENTED",
        "verification-agent": "IMPLEMENTED",
        "workspace-agent": "IMPLEMENTED",
    }
    assert all(len(agent["discoverable_by"]) >= 2 for agent in agents)
    assert all(agent["immutable_resource_env"].startswith("SOLVAN_") for agent in agents)


def test_agent_identity_matrix_has_separate_read_execute_verify_and_memory_authority() -> None:
    terraform = _text("infra/terraform/environments/gcp/iam.tf")
    locals = _text("infra/terraform/environments/gcp/locals.tf")
    variables = _text("infra/terraform/environments/gcp/variables.tf")
    for identity in ("evidence", "actuator", "verifier", "memory", "coordinator"):
        assert f"{identity} = {{" in locals
    assert 'member  = google_service_account.workload["actuator"].member' in terraform
    assert 'member  = google_service_account.workload["verifier"].member' in terraform
    assert 'member  = google_service_account.workload["coordinator"].member' in terraform
    assert "account_id   = local.service_account_ids[each.key]" in terraform
    assert "service_account_id_overrides" in locals
    assert "execution_agent_principal" in variables
    assert "evidence_agent_principal" in variables
    assert "verification_agent_principal" in variables
    assert "roles/owner" not in terraform
    assert "roles/editor" not in terraform


def test_cloud_run_service_graph_uses_deterministic_provider_audience() -> None:
    terraform = _text("infra/terraform/environments/gcp/cloud_run.tf")
    locals_text = _text("infra/terraform/environments/gcp/locals.tf")
    assert "local.github_provider_url" in terraform
    assert "github_provider_url = format(" in locals_text
    assert 'google_cloud_run_v2_service.service["github_provider"].uri' not in terraform


def test_synthetic_fault_drill_is_opt_in_and_forbidden_in_production() -> None:
    variables = _text("infra/terraform/environments/gcp/variables.tf")
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    platform = _text("infra/terraform/environments/gcp/platform.tf")
    iam = _text("infra/terraform/environments/gcp/iam.tf")

    assert 'contains(["dev", "staging", "production"], var.environment)' in variables
    assert '!(var.environment == "production" && var.fault_drill_enabled)' in variables
    assert '(key != "payments" || var.fault_drill_enabled)' in cloud_run
    assert "count = var.fault_drill_enabled ? 1 : 0" in platform
    assert 'resource "google_cloud_run_v2_service_iam_member" "injector_payments"' in cloud_run
    assert 'resource "google_project_iam_member" "scenario_injector"' in iam
    assert iam.count("count = var.fault_drill_enabled ? 1 : 0") >= 7


def test_gateway_is_registry_governed_fail_closed_and_has_no_generic_mutation_route() -> None:
    platform = _text("infra/terraform/environments/gcp/platform.tf")
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    assert 'governed_access_path = "AGENT_TO_ANYWHERE"' in platform
    assert 'governed_access_path = "CLIENT_TO_AGENT"' in platform
    assert platform.count("//agentregistry.googleapis.com/projects/") >= 2
    assert platform.count("fail_open   = false") == 2
    mcp_start = cloud_run.index(
        'resource "google_cloud_run_v2_service_iam_member" "mcp_facade_gateway"'
    )
    mcp_block = cloud_run[mcp_start : cloud_run.index("\n}", mcp_start) + 2]
    assert "member   = local.agent_gateway_service_agent" in mcp_block
    assert 'member   = "allUsers"' not in mcp_block
    assert "Typed action-ID-only endpoint" in platform
    binder_start = platform.index(
        'resource "google_project_iam_custom_role" "agent_platform_gateway_binder"'
    )
    binder_block = platform[binder_start : platform.index("\n}", binder_start) + 2]
    assert '"networkservices.agentGateways.get"' in binder_block
    assert '"networkservices.agentGateways.use"' in binder_block
    assert "member  = local.agent_platform_service_agent" in platform
    for forbidden in ("generic shell", "arbitrary http", "generic sql"):
        assert forbidden not in platform.lower()


def test_model_armor_covers_both_gateway_directions_and_pii_fail_closed() -> None:
    platform = _text("infra/terraform/environments/gcp/platform.tf")
    variables = _text("infra/terraform/environments/gcp/variables.tf")
    outputs = _text("infra/terraform/environments/gcp/outputs.tf")
    deploy = _text("tools/deploy_release.py")
    assert 'filter_enforcement = "ENABLED"' in platform
    assert "pi_and_jailbreak_filter_settings" in platform
    assert "malicious_uri_filter_settings" in platform
    assert "sdp_settings" in platform
    assert "request_template_id" in platform
    assert "response_template_id" in platform
    assert "google_network_services_agent_gateway.egress.id" in platform
    assert "google_network_services_agent_gateway.ingress.id" in platform
    assert 'enforcement_type                         = "INSPECT_AND_BLOCK"' in platform
    assert "count       = var.gateway_extensions_enabled ? 1 : 0" in platform
    assert (
        "count          = var.gateway_extensions_enabled && var.gateway_model_armor_enabled ? 1 : 0"
    ) in platform
    assert 'variable "gateway_model_armor_enabled"' in variables
    assert (
        'inline_model_armor     = !var.gateway_extensions_enabled ? "DISABLED" : '
        '(var.gateway_model_armor_enabled ? "ENFORCED"'
    ) in outputs
    assert 'iap                    = var.gateway_extensions_enabled ? "ENFORCED"' in outputs
    assert 'resource "google_network_security_authz_policy" "iap_egress"' in platform
    assert "resources = [google_network_services_agent_gateway.egress.id]" in platform
    assert 'resource "google_network_security_authz_policy" "iap_ingress"' in platform
    assert "resources = [google_network_services_agent_gateway.ingress.id]" in platform
    assert "google_network_security_authz_policy.iap_egress" in platform
    assert "iap_egress_policy" in outputs
    assert "iap_ingress_policy" in outputs
    assert '"gateway_model_armor_enabled": False' in deploy


def test_oracle_and_injector_are_outside_every_agent_visible_namespace() -> None:
    fixture = yaml.safe_load(_text("specs/artifacts/release-fixtures.yaml"))
    experiment = fixture["experiment_contract"]
    assert experiment["isolation"] == {
        "injector_identity_separate_from_agents": True,
        "oracle_identity_separate_from_agents": True,
        "agent_access_to_fixture_and_oracle_namespaces": "DENIED",
    }
    prohibited = set(experiment["agent_prohibited"])
    assert {
        "injected_fault_definition",
        "expected_root_cause",
        "expected_action",
        "oracle_source_or_threshold_answer",
        "grading_result",
    } <= prohibited
    assert fixture["scenarios"]["S1"]["oracle"]["connector_success_is_recovery"] is False


def test_console_governance_projection_is_scope_labeled_and_never_grants_authority() -> None:
    value = console_snapshot()
    assert value["authority"] == "NO_PRODUCTION_AUTHORITY"
    assert value["data_status"] == "SCRIPTED_RELEASE_FIXTURE"
    assert value["environment"]["region"] == "europe-west1"
    assert len(value["fleet"]["agents"]) == 6
    assert all(item["status"] == "IMPLEMENTED" for item in value["fleet"]["agents"])
    assert "a memory is never permission" in _text("apps/console/src/FleetGovernance.tsx")
    assert value["release"]["cloud"] == "No cloud release receipt yet"


def test_operator_brief_has_freshness_resolvable_sources_and_labels_inference() -> None:
    incident = console_snapshot()["incidents"][0]
    brief = incident["brief"]
    assert brief["freshness"].startswith("Committed event ")
    assert brief["citations"]
    assert all(item.startswith(("evd_", "ver_")) for item in brief["citations"])
    assert incident["findings"]["validated"]
    assert incident["findings"]["inferred"]
    assert all(not item["citations"] for item in incident["findings"]["inferred"])


def test_release_projection_labels_every_non_cloud_scenario_without_overclaim() -> None:
    release = console_snapshot()["release"]
    assert [item["id"] for item in release["scenarios"]] == [
        "S1",
        "S2",
        "S3",
        "S4",
        "S5",
        "S6",
    ]
    assert release["cloud"] == "No cloud release receipt yet"
    assert "in progress" in release["gate"].lower()
    assert all(item["status"] != "PASS" for item in release["scenarios"])


def test_live_release_projection_has_exact_read_only_cloud_bindings() -> None:
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    storage = _text("infra/terraform/environments/gcp/storage.tf")
    variables = _text("infra/terraform/environments/gcp/variables.tf")
    assert 'name  = "SOLVAN_RELEASE_COMMIT"' in cloud_run
    assert "value = var.release_commit" in cloud_run
    assert 'name  = "SOLVAN_DEPLOYMENT_ID"' in cloud_run
    assert "value = var.deployment_id" in cloud_run
    assert 'for_each = toset(["api", "coordinator", "detector", "evidence"])' in storage
    assert 'resource "google_storage_bucket_iam_member" "evidence_viewer"' in storage
    assert 'role   = "roles/storage.objectViewer"' in storage
    assert 'variable "release_commit"' in variables
    assert 'variable "deployment_id"' in variables


def test_external_channel_health_is_secret_bound_and_receipt_qualified() -> None:
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    variables = _text("infra/terraform/environments/gcp/variables.tf")
    outputs = _text("infra/terraform/environments/gcp/outputs.tf")
    discord = _text("apps/discord_liaison/main.py")

    assert 'variable "discord_public_key_secret_name"' in variables
    assert 'variable "discord_public_key"' not in variables
    assert 'name  = "SOLVAN_DISCORD_PUBLIC_KEY_REF"' in cloud_run
    assert "SOLVAN_DISCORD_PUBLIC_KEY_REF" in discord
    assert 'SOLVAN_DISCORD_PUBLIC_KEY"' not in discord
    assert 'variable "channel_qualification_receipts"' in variables
    assert 'resource "google_cloud_run_v2_job" "channel_provider_health"' in cloud_run
    assert 'args  = ["record-channel-provider-health"]' in cloud_run
    assert "channel_provider_health = {" in outputs
    assert (
        "A channel qualification receipt cannot be ingested for a disabled provider." in cloud_run
    )


def test_release_jobs_with_execution_overrides_have_the_exact_override_role() -> None:
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    for resource in (
        "approver_database_probe",
        "approver_memory_probe",
        "approver_model_armor_probe",
        "approver_scenario_injector",
        "approver_scenario_oracle",
    ):
        start = cloud_run.index(f'resource "google_cloud_run_v2_job_iam_member" "{resource}"')
        block = cloud_run[start : cloud_run.index("\n}", start) + 2]
        assert 'role     = "roles/run.jobsExecutorWithOverrides"' in block


def test_catalog_publication_binds_every_immutable_agent_resource() -> None:
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    start = cloud_run.index('resource "google_cloud_run_v2_job" "catalog_publication"')
    end = cloud_run.index('resource "google_cloud_run_v2_job" "calibration_seed"', start)
    block = cloud_run[start:end]
    expected = {
        "SOLVAN_INCIDENT_SUPERVISOR_RESOURCE": "incident_supervisor",
        "SOLVAN_EVIDENCE_AGENT_RESOURCE": "evidence_agent",
        "SOLVAN_INFRASTRUCTURE_AGENT_RESOURCE": "infrastructure_agent",
        "SOLVAN_EXECUTION_AGENT_RESOURCE": "execution_agent",
        "SOLVAN_VERIFICATION_AGENT_RESOURCE": "verification_agent",
        "SOLVAN_WORKSPACE_AGENT_RESOURCE": "workspace_agent",
    }
    for setting, resource in expected.items():
        assert f"{setting}" in block
        assert f"var.agent_runtime_resources.{resource}" in block


def test_catalog_release_uses_google_native_approval_and_supply_chain_controls() -> None:
    cloud_deploy = _text("infra/terraform/environments/gcp/cloud_deploy.tf")
    artifacts = _text("infra/terraform/environments/gcp/artifacts.tf")
    iam = _text("infra/terraform/environments/gcp/iam.tf")
    storage = _text("infra/terraform/environments/gcp/storage.tf")
    binary = _text("infra/terraform/environments/gcp/binary_authorization.tf")
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    cloud_build = _text("cloudbuild.yaml")

    assert cloud_deploy.count("stages {") == 2
    assert cloud_deploy.count('resource "google_clouddeploy_custom_target_type"') == 1
    assert (
        cloud_deploy.count("custom_target_type = google_clouddeploy_custom_target_type.catalog.id")
        == 2
    )
    assert "SOLVAN_CATALOG_STAGE" not in cloud_deploy
    assert "require_approval = false" in cloud_deploy
    assert "require_approval = true" in cloud_deploy
    assert 'role     = "roles/clouddeploy.approver"' in iam
    approver = iam.split(
        'resource "google_clouddeploy_delivery_pipeline_iam_member" "catalog_approver"',
        maxsplit=1,
    )[1].split("\n}\n", maxsplit=1)[0]
    assert "google_clouddeploy_delivery_pipeline.catalog.name" in approver
    assert 'api.getAttribute(\\"clouddeploy.googleapis.com/rolloutTarget\\"' in approver
    assert "google_clouddeploy_target.catalog_publication.name" in approver
    run_observer = iam.split(
        'resource "google_project_iam_custom_role" "catalog_run_execution_reader"',
        maxsplit=1,
    )[1].split("\n}\n", maxsplit=1)[0]
    assert '"run.executions.get"' in run_observer
    assert '"run.operations.get"' in run_observer
    assert '"run.executions.list"' not in run_observer
    assert '"run.operations.list"' not in run_observer
    observer_binding = iam.split(
        'resource "google_project_iam_member" "catalog_deploy_run_execution_reader"',
        maxsplit=1,
    )[1].split("\n}\n", maxsplit=1)[0]
    assert "google_project_iam_custom_role.catalog_run_execution_reader.name" in observer_binding
    assert 'google_service_account.workload["catalog_deploy"].member' in observer_binding
    assert 'role     = "roles/run.jobsExecutorWithOverrides"' in cloud_run
    assert 'member   = google_service_account.workload["catalog_deploy"].member' in cloud_run
    catalog_reader = artifacts.split(
        'resource "google_artifact_registry_repository_iam_member" "catalog_deploy_reader"',
        maxsplit=1,
    )[1].split("\n}\n", maxsplit=1)[0]
    assert 'role       = "roles/artifactregistry.reader"' in catalog_reader
    assert 'member     = google_service_account.workload["catalog_deploy"].member' in catalog_reader
    assert "google_artifact_registry_repository.containers.repository_id" in catalog_reader
    assert "is_locked        = true" in storage
    assert '"projects/${var.project_id}/attestors/built-by-cloud-build"' in binary
    assert "requestedVerifyOption: VERIFIED" in cloud_build
    assert "verify_build_supply_chain(" in _text("tools/deploy_release.py")
    assert cloud_run.count("binary_authorization {") == 14


def test_governed_tool_bindings_derive_only_identity_from_runtime_receipts() -> None:
    locals_text = _text("infra/terraform/environments/gcp/locals.tf")
    cloud_run = _text("infra/terraform/environments/gcp/cloud_run.tf")
    principals = {
        "incident_supervisor": "incident_supervisor_agent_principal",
        "evidence_agent": "evidence_agent_principal",
        "infrastructure_agent": "infrastructure_agent_principal",
        "execution_agent": "execution_agent_principal",
        "verification_agent": "verification_agent_principal",
        "workspace_agent": "workspace_agent_principal",
    }
    for agent, principal in principals.items():
        assert f"merge(var.agent_tool_bindings.{agent}" in locals_text
        assert f"var.{principal}" in locals_text
        assert f"var.agent_tool_bindings.{agent}.identity_ref" in locals_text
    assert cloud_run.count("jsonencode(local.governed_agent_tool_bindings)") == 3
    old_inline_binding = (
        'jsonencode({\n              "incident-supervisor"  = var.agent_tool_bindings'
    )
    assert old_inline_binding not in cloud_run


def test_the_only_production_mutation_seat_is_registered_and_model_free() -> None:
    """The fleet's security claim is only checkable if the actuator is catalogued."""

    value = yaml.safe_load(_text("specs/artifacts/agent-manifests.yaml"))
    services = value["deterministic_services"]
    actuator = next(item for item in services if item["service_key"] == "action-actuator")

    assert actuator["model_backed"] is False
    assert actuator["permission_ceiling"] == "PRODUCTION_MUTATION_ALLOWLIST_ONLY"
    assert actuator["caller_ceiling"] == "EXECUTION_AGENT_IDENTITY_ONLY"
    assert set(actuator["allowed_operations"]) == {
        "PAYMENTS_POOL_RECYCLE",
        "CLOUD_RUN_TRAFFIC_ROLLBACK",
    }
    # The caller names an action; it never supplies the material to execute.
    assert set(actuator["accepts_from_caller"]).isdisjoint(
        {"payload", "target", "action_type", "expected_target_version"}
    )
    # No model-backed agent may hold what this seat holds.
    for agent in value["agents"]:
        assert agent["permission_ceiling"] != "PRODUCTION_MUTATION_ALLOWLIST_ONLY"


def test_only_a_model_backed_actor_wears_the_agent_tone_on_the_timeline() -> None:
    """Violet reads as \"a model is working\"; deterministic actors must not borrow it."""

    source = _text("apps/api/incident_projection.py")
    assert 'if row["actor_type"] == "AGENT"' in source

    timeline = console_snapshot()["incidents"][0]["timeline"]
    for event in timeline:
        if event["kind"] == "agent":
            assert "Coordinator" not in event["actor"]
            assert "actuator" not in event["actor"].lower()
