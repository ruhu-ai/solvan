output "region" {
  value = var.region
}

output "solvan_scope" {
  description = "Exact logical tenant scope bound to the release database and Memory Bank."
  value = {
    organization_id = var.organization_id
    project_id      = var.scope_project_id
    environment_id  = var.environment_id
  }
}

output "required_services" {
  description = "Exact Google APIs declared by this release topology."
  value       = sort(tolist(local.services))
}

output "billing_budget" {
  description = "Competition budget with notifications at $75 and $120."
  value       = google_billing_budget.release.name
}

output "cloud_sql_connection_name" {
  value = google_sql_database_instance.control.connection_name
}

output "release_jobs" {
  description = "Private one-shot release jobs; seed is null until an approved calibration receipt is bound."
  value = {
    migration         = google_cloud_run_v2_job.database_migration.name
    catalog           = google_cloud_run_v2_job.catalog_publication.name
    database_probe    = google_cloud_run_v2_job.database_probe.name
    memory_probe      = google_cloud_run_v2_job.memory_probe.name
    model_armor_probe = google_cloud_run_v2_job.model_armor_probe.name
    channel_provider_health = {
      for key, job in google_cloud_run_v2_job.channel_provider_health : key => job.name
    }
    scenario_injector = (
      length(google_cloud_run_v2_job.scenario_injector) == 0 ?
      null : google_cloud_run_v2_job.scenario_injector[0].name
    )
    scenario_oracle = (
      length(google_cloud_run_v2_job.scenario_oracle) == 0 ?
      null : google_cloud_run_v2_job.scenario_oracle[0].name
    )
    seed = (
      length(google_cloud_run_v2_job.calibration_seed) == 0 ?
      null : google_cloud_run_v2_job.calibration_seed[0].name
    )
  }
}

output "scheduler_jobs" {
  description = "Automated work remains paused until a passing preflight is explicitly promoted."
  value = {
    detector_burst      = google_cloud_scheduler_job.detector_burst.name
    case_wakeups        = google_cloud_scheduler_job.case_wakeups.name
    outbox_publisher    = google_cloud_scheduler_job.outbox_publisher.name
    memory_promotions   = google_cloud_scheduler_job.memory_promotions.name
    liaison_maintenance = var.target_product_enabled ? google_cloud_scheduler_job.liaison_maintenance[0].name : null
    trigger_tick        = var.target_product_enabled ? google_cloud_scheduler_job.trigger_tick[0].name : null
    slack_liaison       = var.target_product_enabled && var.slack_liaison_enabled ? google_cloud_scheduler_job.slack_liaison[0].name : null
  }
}

output "release_images" {
  description = "Exact immutable images bound to this Terraform release."
  value       = var.images
}

output "scenario_identities" {
  description = "Non-agent, mutually asymmetric fault-drill identities; null unless the isolated drill is enabled."
  value = {
    injector = var.fault_drill_enabled ? try(google_service_account.workload["injector"].email, null) : null
    oracle   = var.fault_drill_enabled ? try(google_service_account.workload["oracle"].email, null) : null
  }
}

output "approval_token_audience" {
  description = "Exact OAuth audience accepted for one-time human approval identity tokens."
  value       = var.approval_token_audience
}

output "service_uris" {
  value = merge(
    { for key, service in google_cloud_run_v2_service.service : key => service.uri },
    { console = google_cloud_run_v2_service.console.uri },
    { workspace_sandbox = google_cloud_run_v2_service.workspace_sandbox.uri },
    var.antigravity_demo_enabled ? {
      antigravity_workspace = google_cloud_run_v2_service.antigravity_workspace[0].uri
    } : {},
    var.github_release_enabled ? {
      github_provider = try(google_cloud_run_v2_service.service["github_provider"].uri, null)
    } : {},
  )
  sensitive = true
}

output "workspace_sandbox" {
  description = "Regional no-egress repair-validation service and its identity fence."
  value = {
    service_name        = google_cloud_run_v2_service.workspace_sandbox.name
    uri                 = google_cloud_run_v2_service.workspace_sandbox.uri
    region              = var.region
    service_account     = try(google_service_account.workload["workspace_sandbox"].email, null)
    coordinator_account = try(google_service_account.workload["coordinator"].email, null)
    revision            = var.workspace_sandbox_revision
    network_policy      = "nested-sandbox-no-egress"
  }
  sensitive = true
}

output "github_release_provider" {
  description = "Conditional GitHub App release-provider service and policy binding."
  value = {
    enabled         = var.github_release_enabled
    service_name    = var.github_release_enabled ? try(google_cloud_run_v2_service.service["github_provider"].name, null) : null
    uri             = var.github_release_enabled ? try(google_cloud_run_v2_service.service["github_provider"].uri, null) : null
    service_account = try(google_service_account.workload["github_provider"].email, null)
    repository_id   = var.github_repository_id
    policy          = "coordinator-only; signed-webhook; approval-bound-merge"
  }
  sensitive = true
}

output "antigravity_workspace_provider" {
  description = "Optional self-hosted SDK provider and exact policy/provenance bindings."
  value = {
    enabled                          = var.antigravity_demo_enabled
    service_name                     = var.antigravity_demo_enabled ? google_cloud_run_v2_service.antigravity_workspace[0].name : null
    uri                              = var.antigravity_demo_enabled ? google_cloud_run_v2_service.antigravity_workspace[0].uri : null
    service_account                  = try(google_service_account.workload["antigravity"].email, null)
    coordinator_service_account      = try(google_service_account.workload["coordinator"].email, null)
    provider_revision                = var.antigravity_provider_revision
    implementation_sdk               = "google-antigravity"
    implementation_sdk_version       = "0.1.10"
    implementation_distribution_hash = "sha256:249c102cac831e290a4a62918a2e0c01482696b6533b2a02e8215890080d634a"
    provider_artifact_digest         = split("@", var.images.antigravity_workspace)[1]
    effective_tool_set_hash          = local.antigravity_tool_set_hash
    effective_network_policy_hash    = local.antigravity_network_policy_hash
  }
  sensitive = true
}

output "synthetic_fixture_attester" {
  description = "Optional isolated signer and exact KMS/public-fixture bindings."
  value = var.antigravity_demo_enabled ? {
    uri             = google_cloud_run_v2_service.fixture_attester[0].uri
    service_account = try(google_service_account.workload["fixture_attester"].email, null)
    kms_key_version = google_kms_crypto_key_version.synthetic_attester[0].name
    fixture_prefix  = "gs://${google_storage_bucket.runtime.name}/${var.organization_id}/${var.scope_project_id}/${var.environment_id}/fixtures/payments-leak-v1/"
  } : null
  sensitive = true
}

output "antigravity_workspace_registry_binding" {
  description = "Conditional Agent Registry catalog binding for the optional provider."
  value = var.antigravity_demo_enabled ? {
    registry_resource = google_agent_registry_service.antigravity_workspace_endpoint[0].registry_resource
    service_uri       = google_cloud_run_v2_service.antigravity_workspace[0].uri
    lifecycle         = "EXPERIMENT_ONLY"
  } : null
}

output "evidence_bucket" {
  value = google_storage_bucket.evidence.name
}

output "runtime_bucket" {
  value = google_storage_bucket.runtime.name
}

output "skills_bucket" {
  value = google_storage_bucket.skills.name
}

output "security_log_sink" {
  description = "Cloud Audit Log sink feeding the safe durable security projection."
  value       = google_logging_project_sink.security_controls.id
}

output "agent_gateway_resource" {
  value = google_network_services_agent_gateway.egress.id
}

output "agent_gateway_resources" {
  value = {
    egress  = google_network_services_agent_gateway.egress.id
    ingress = google_network_services_agent_gateway.ingress.id
  }
}

output "model_armor_template" {
  value = google_model_armor_template.agent_boundary.name
}

output "fast_fleet_inference" {
  description = "Exact qualified Gemini fast-fleet model and EU jurisdictional endpoint."
  value = {
    model_resource = "gemini-3.6-flash"
    location       = "eu"
    endpoint       = "https://aiplatform.eu.rep.googleapis.com"
  }
}

output "agent_runtime_resources" {
  description = "Exact immutable Runtime resources currently wired into the coordinator."
  value       = var.agent_runtime_resources
}

output "agent_runtime_revisions" {
  description = "Release revisions currently wired into the coordinator."
  value       = var.agent_runtime_revisions
}

output "agent_runtime_principals" {
  description = "System-attested Runtime principals used for workload authorization."
  value = {
    incident_supervisor  = var.incident_supervisor_agent_principal
    evidence_agent       = var.evidence_agent_principal
    execution_agent      = var.execution_agent_principal
    infrastructure_agent = var.infrastructure_agent_principal
    verification_agent   = var.verification_agent_principal
    workspace_agent      = var.workspace_agent_principal
  }
}

output "registered_endpoints" {
  value = {
    actuator              = google_agent_registry_service.actuator_endpoint.registry_resource
    evidence              = google_agent_registry_service.evidence_broker_endpoint.registry_resource
    verifier              = google_agent_registry_service.verifier_endpoint.registry_resource
    payments              = var.fault_drill_enabled ? google_agent_registry_service.payments_endpoint[0].registry_resource : null
    monitoring            = google_agent_registry_service.monitoring_endpoint.registry_resource
    aiplatform            = try(google_agent_registry_service.runtime_dependencies["aiplatform"].registry_resource, null)
    aiplatform_mtls       = try(google_agent_registry_service.runtime_dependencies["aiplatform_mtls"].registry_resource, null)
    aiplatform_rep        = try(google_agent_registry_service.runtime_dependencies["aiplatform_rep"].registry_resource, null)
    aiplatform_eu_rep     = try(google_agent_registry_service.runtime_dependencies["aiplatform_eu_rep"].registry_resource, null)
    resource_manager      = try(google_agent_registry_service.runtime_dependencies["resource_manager"].registry_resource, null)
    resource_manager_mtls = try(google_agent_registry_service.runtime_dependencies["resource_manager_mtls"].registry_resource, null)
    logging               = try(google_agent_registry_service.runtime_dependencies["logging"].registry_resource, null)
    telemetry             = try(google_agent_registry_service.runtime_dependencies["telemetry"].registry_resource, null)
    telemetry_mtls        = try(google_agent_registry_service.runtime_dependencies["telemetry_mtls"].registry_resource, null)
  }
}

output "gateway_policy_resources" {
  value = {
    model_armor_extension = var.gateway_extensions_enabled ? google_network_services_authz_extension.model_armor[0].id : null
    model_armor_policy    = var.gateway_extensions_enabled ? google_network_security_authz_policy.model_armor[0].id : null
    iap_extension         = var.gateway_extensions_enabled ? google_network_services_authz_extension.iap[0].id : null
    iap_policy            = var.gateway_extensions_enabled ? google_network_security_authz_policy.iap[0].id : null
  }
}

output "target_product_channel_services" {
  description = "Target-only channel endpoints; presence is not a deployment qualification receipt."
  value = var.target_product_enabled ? {
    mcp_facade = try(google_cloud_run_v2_service.service["mcp_facade"].uri, null)
    slack      = var.slack_liaison_enabled ? try(google_cloud_run_v2_service.service["slack_liaison"].uri, null) : null
    discord    = var.discord_liaison_enabled ? try(google_cloud_run_v2_service.service["discord_liaison"].uri, null) : null
    email      = var.email_liaison_enabled ? try(google_cloud_run_v2_service.service["email_liaison"].uri, null) : null
  } : null
}

output "email_relay_expected_invokers" {
  description = "Exact Solvan principals the private email relay must allow: API sends enrollment messages; Email Liaison sends governed answers."
  value = var.target_product_enabled && var.email_liaison_enabled ? [
    try(google_service_account.workload["api"].email, null),
    try(google_service_account.workload["email_liaison"].email, null),
  ] : []
}

output "liaison_registry_binding" {
  description = "Target-only Agent Registry binding for the optional Liaison surface."
  value = var.target_product_enabled ? {
    registry_resource = google_agent_registry_service.liaison_endpoint[0].registry_resource
    service_url       = try(google_cloud_run_v2_service.service["api"].uri, null)
    model             = "gemini-3.6-flash"
    model_location    = "eu"
  } : null
}
