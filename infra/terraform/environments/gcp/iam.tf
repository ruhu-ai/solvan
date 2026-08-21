resource "google_service_account" "workload" {
  for_each = local.service_accounts

  project = var.project_id
  # Google service-account account IDs may contain lowercase letters, digits,
  # and hyphens only. Registry/workload keys intentionally use underscores;
  # keep those stable internally while deriving a provider-valid account ID.
  account_id   = local.service_account_ids[each.key]
  display_name = each.value.display_name
  description  = each.value.description

  lifecycle {
    precondition {
      condition     = length(local.service_account_ids[each.key]) <= 30
      error_message = "Service account ID for ${each.key} exceeds Google's 30-character limit; add a short form to local.service_account_id_overrides."
    }
  }

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}

resource "google_service_account_iam_member" "pubsub_alert_ingress_push_token" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  service_account_id = google_service_account.workload["alert_ingress_push"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_cloud_run_v2_service_iam_member" "pubsub_alert_ingress" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["alert_ingress"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["alert_ingress_push"].member
}

resource "google_cloud_run_v2_service_iam_member" "api_direct_gcp_reader" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["direct_gcp_reader"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["api"].member
}

resource "google_cloud_run_v2_service_iam_member" "detector_direct_gcp_reader" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["direct_gcp_reader"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["detector"].member
}

resource "google_cloud_run_v2_service_iam_member" "api_pilot_qualification_verifier" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["pilot_qualification_verifier"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["api"].member
}

resource "google_project_iam_custom_role" "traffic_mutator" {
  project     = var.project_id
  role_id     = "solvanCloudRunTrafficMutator"
  title       = "Solvan exact Cloud Run traffic mutator"
  description = "Only reads and updates the approval-bound Cloud Run service traffic."
  stage       = "GA"
  permissions = [
    "run.operations.get",
    "run.services.get",
    "run.services.update",
  ]
}

resource "google_project_iam_member" "actuator_traffic" {
  count = var.fault_drill_enabled ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.traffic_mutator.name
  member  = google_service_account.workload["actuator"].member

  condition {
    title       = "OnlyApprovedPaymentsService"
    description = "The release actuator cannot mutate another Cloud Run service."
    expression = format(
      "resource.name == 'projects/%s/locations/%s/services/%s-payments'",
      var.project_id,
      var.region,
      local.prefix,
    )
  }
}

# The evidence broker holds no customer grant of its own. It reaches an
# enrolled customer reader service account only by minting through the single
# delegator identity the customer authorized, so the customer-side
# serviceAccountTokenCreator grant stays exactly the one the probe workload
# already has and no read runs on Solvan's ambient runtime identity.
resource "google_service_account_iam_member" "evidence_direct_gcp_delegation" {
  service_account_id = google_service_account.workload["direct_gcp_reader"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = google_service_account.workload["evidence"].member
}

resource "google_project_iam_member" "evidence_read_roles" {
  project = var.project_id
  role    = google_project_iam_custom_role.evidence_reader.name
  member  = google_service_account.workload["evidence"].member
}

resource "google_project_iam_custom_role" "evidence_reader" {
  project     = var.project_id
  role_id     = "solvanEvidenceReader"
  title       = "Solvan bounded evidence reader"
  description = "Exact provider GET/list permissions used by typed broker adapters."
  stage       = "GA"
  permissions = [
    "cloudasset.assets.searchAllResources",
    "cloudbuild.builds.list",
    "cloudsql.instances.get",
    "cloudtrace.traces.get",
    "logging.logEntries.list",
    "monitoring.timeSeries.list",
    "run.services.get",
  ]
}

resource "google_project_iam_member" "verifier_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = google_service_account.workload["verifier"].member
}

resource "google_project_iam_member" "coordinator_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = google_service_account.workload["coordinator"].member
}

resource "google_project_iam_member" "github_secret_accessor" {
  count   = var.github_release_enabled ? 1 : 0
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = google_service_account.workload["github_provider"].member

  condition {
    title       = "OnlyConfiguredGitHubSecrets"
    description = "The GitHub provider may read only the App identity and webhook secrets named by this release."
    expression = format(
      join(" || ", [
        "resource.name == 'projects/%s/secrets/%s'",
        "resource.name == 'projects/%s/secrets/%s'",
        "resource.name == 'projects/%s/secrets/%s'",
        "resource.name == 'projects/%s/secrets/%s'",
      ]),
      var.project_id,
      var.github_webhook_secret_name,
      var.project_id,
      var.github_installation_token_secret_name,
      var.project_id,
      var.github_app_id_secret_name,
      var.project_id,
      var.github_app_private_key_secret_name,
    )
  }
}

# The API lists the App's own installations and their repositories during
# onboarding, which is an App-JWT read, so it needs the same App identity the
# provider holds. It is granted per secret rather than by widening the
# provider's project-level condition: the two workloads read the same two
# secrets and nothing else, and neither can reach the other's.
resource "google_secret_manager_secret_iam_member" "api_github_app_id_accessor" {
  count     = var.github_release_enabled && var.github_app_id_secret_name != "UNCONFIGURED" ? 1 : 0
  project   = var.project_id
  secret_id = var.github_app_id_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.workload["api"].member
}

resource "google_secret_manager_secret_iam_member" "api_github_app_private_key_accessor" {
  count = (
    var.github_release_enabled && var.github_app_private_key_secret_name != "UNCONFIGURED" ? 1 : 0
  )
  project   = var.project_id
  secret_id = var.github_app_private_key_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.workload["api"].member
}

resource "google_project_iam_member" "github_identity_secret_accessor" {
  count   = var.github_release_enabled ? 1 : 0
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = google_service_account.workload["github_identity_broker"].member

  condition {
    title       = "OnlyGitHubIdentitySecrets"
    description = "The identity broker may read only its OAuth client and callback-cookie secrets."
    expression = format(
      "resource.name == 'projects/%s/secrets/%s' || resource.name == 'projects/%s/secrets/%s'",
      var.project_id,
      var.github_oauth_client_secret_name,
      var.project_id,
      var.github_identity_cookie_secret_name,
    )
  }
}

resource "google_secret_manager_secret_iam_member" "database_migration_admin_secret_accessor" {
  count     = var.database_admin_secret_name == "UNCONFIGURED" ? 0 : 1
  project   = var.project_id
  secret_id = var.database_admin_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.workload["migration"].member
}

resource "google_secret_manager_secret_iam_member" "api_alert_cursor_secret_accessor" {
  count     = var.target_product_enabled && var.alert_cursor_signing_secret_name != "UNCONFIGURED" ? 1 : 0
  project   = var.project_id
  secret_id = var.alert_cursor_signing_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.workload["api"].member
}

# The API mounts the OAuth client secret to exchange authorization codes. It is
# named beside the other secrets the API reads rather than left to a project-wide
# grant: without this binding `terraform apply` succeeds and the revision then
# fails to start, which reads as a deployment fault rather than a missing grant.
resource "google_secret_manager_secret_iam_member" "api_oauth_client_secret_accessor" {
  project   = var.project_id
  secret_id = var.oauth_client_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.workload["api"].member
}

resource "google_secret_manager_secret_iam_member" "api_operator_step_up_pepper_accessor" {
  project   = var.project_id
  secret_id = var.operator_step_up_pepper_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.workload["api"].member
}

resource "google_secret_manager_secret_iam_member" "api_channel_enrollment_secret_accessor" {
  count     = var.target_product_enabled && var.channel_enrollment_hmac_secret_name != "UNCONFIGURED" ? 1 : 0
  project   = var.project_id
  secret_id = var.channel_enrollment_hmac_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.workload["api"].member
}

resource "google_project_iam_member" "slack_secret_accessor" {
  count   = var.target_product_enabled && var.slack_liaison_enabled ? 1 : 0
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = google_service_account.workload["slack_liaison"].member

  condition {
    title       = "OnlyConfiguredSlackSecrets"
    description = "Slack adapter reads only its signing secret and bot token."
    expression = format(
      "resource.name == 'projects/%s/secrets/%s' || resource.name == 'projects/%s/secrets/%s'",
      var.project_id,
      var.slack_signing_secret_name,
      var.project_id,
      var.slack_bot_token_secret_name,
    )
  }
}

resource "google_storage_bucket_iam_member" "slack_payload_writer" {
  count  = var.target_product_enabled && var.slack_liaison_enabled ? 1 : 0
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectUser"
  member = google_service_account.workload["slack_liaison"].member
}

resource "google_project_iam_member" "discord_secret_accessor" {
  count   = var.target_product_enabled && var.discord_liaison_enabled ? 1 : 0
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = google_service_account.workload["discord_liaison"].member

  condition {
    title       = "OnlyConfiguredDiscordSecrets"
    description = "Discord adapter reads only its public verification key and bot token."
    expression = format(
      "resource.name == 'projects/%s/secrets/%s' || resource.name == 'projects/%s/secrets/%s'",
      var.project_id,
      var.discord_public_key_secret_name,
      var.project_id,
      var.discord_bot_token_secret_name,
    )
  }
}

resource "google_storage_bucket_iam_member" "channel_payload_users" {
  for_each = {
    for key in ["discord_liaison", "email_liaison"] : key => key
    if var.target_product_enabled && (
      (key == "discord_liaison" && var.discord_liaison_enabled) ||
      (key == "email_liaison" && var.email_liaison_enabled)
    )
  }
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectUser"
  member = google_service_account.workload[each.key].member
}

resource "google_cloud_run_v2_service_iam_member" "github_coordinator_invoker" {
  count    = var.github_release_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["github_provider"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

resource "google_cloud_run_v2_service_iam_member" "deployment_controller_coordinator_invoker" {
  count    = var.github_release_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["deployment_controller"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

resource "google_cloud_run_v2_service_iam_member" "release_verifier_coordinator_invoker" {
  count    = var.github_release_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["release_verifier"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

resource "google_project_iam_member" "deployment_controller_release_key_reader" {
  count   = var.github_release_enabled ? 1 : 0
  project = var.project_id
  role    = "roles/cloudkms.publicKeyViewer"
  member  = google_service_account.workload["deployment_controller"].member
}

resource "google_cloud_run_v2_service_iam_member" "github_evidence_invoker" {
  count    = var.github_release_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["github_provider"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["evidence"].member
}

resource "google_cloud_run_v2_service_iam_member" "github_webhook_invoker" {
  count    = var.github_release_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["github_provider"].name
  role     = "roles/run.invoker"
  # Cloud Run cannot express a path-scoped IAM binding. The public edge is
  # limited to the HMAC-verified webhook route; every command route still
  # requires the coordinator's Google ID token and exact service identity.
  member = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "console_github_identity_invoker" {
  count    = var.github_release_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["github_identity_broker"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["console"].member
}

resource "google_project_iam_custom_role" "antigravity_model_invoker" {
  project     = var.project_id
  role_id     = "solvanAntigravityModelInvoker"
  title       = "Solvan Antigravity exact model invoker"
  description = "Invokes the exact global Vertex model endpoint; grants no model, agent, data, or deployment administration."
  stage       = "BETA"
  permissions = ["aiplatform.endpoints.predict"]
}

resource "google_project_iam_member" "antigravity_model_invoker" {
  project = var.project_id
  role    = google_project_iam_custom_role.antigravity_model_invoker.name
  member  = google_service_account.workload["antigravity"].member
}

resource "google_project_iam_custom_role" "liaison_model_invoker" {
  count       = var.target_product_enabled ? 1 : 0
  project     = var.project_id
  role_id     = "solvanLiaisonModelInvoker"
  title       = "Solvan Liaison exact model invoker"
  description = "Invokes the pinned Gemini query head; grants no model, agent, data, or deployment administration."
  stage       = "BETA"
  permissions = ["aiplatform.endpoints.predict"]
}

resource "google_project_iam_member" "liaison_model_invoker" {
  for_each = var.target_product_enabled ? toset(["api", "liaison_maintenance"]) : toset([])
  project  = var.project_id
  role     = google_project_iam_custom_role.liaison_model_invoker[0].name
  member   = google_service_account.workload[each.value].member
}

resource "google_project_iam_custom_role" "liaison_model_armor" {
  count       = var.target_product_enabled ? 1 : 0
  project     = var.project_id
  role_id     = "solvanLiaisonModelArmor"
  title       = "Solvan Liaison Model Armor screener"
  description = "Screens Liaison query-head input and closed structured output; grants no template administration."
  stage       = "BETA"
  permissions = [
    "modelarmor.templates.useToSanitizeUserPrompt",
    "modelarmor.templates.useToSanitizeModelResponse",
  ]
}

resource "google_project_iam_member" "liaison_model_armor" {
  for_each = var.target_product_enabled ? toset(["api", "liaison_maintenance"]) : toset([])
  project  = var.project_id
  role     = google_project_iam_custom_role.liaison_model_armor[0].name
  member   = google_service_account.workload[each.value].member
}

resource "google_project_iam_custom_role" "antigravity_model_armor" {
  project     = var.project_id
  role_id     = "solvanAntigravityModelArmor"
  title       = "Solvan Antigravity Model Armor screener"
  description = "Screens public-synthetic workspace input and model output with the release template."
  stage       = "BETA"
  permissions = [
    "modelarmor.templates.useToSanitizeUserPrompt",
    "modelarmor.templates.useToSanitizeModelResponse",
  ]
}

resource "google_project_iam_member" "antigravity_model_armor" {
  project = var.project_id
  role    = google_project_iam_custom_role.antigravity_model_armor.name
  member  = google_service_account.workload["antigravity"].member
}

resource "google_project_iam_custom_role" "memory_promoter" {
  project     = var.project_id
  role_id     = "solvanMemoryPromoter"
  title       = "Solvan exact Memory Bank promoter"
  description = "Creates and retrieves only pre-approved exact-scope Memory Bank facts."
  stage       = "BETA"
  permissions = [
    "aiplatform.memories.create",
    "aiplatform.memories.retrieve",
  ]
}

resource "google_project_iam_member" "memory_promoter" {
  project = var.project_id
  role    = google_project_iam_custom_role.memory_promoter.name
  member  = google_service_account.workload["memory"].member
}

resource "google_project_iam_custom_role" "model_armor_probe" {
  project     = var.project_id
  role_id     = "solvanModelArmorProbe"
  title       = "Solvan exact Model Armor release probe"
  description = "Sanitizes the three fixed release-preflight prompt classes only."
  stage       = "BETA"
  permissions = ["modelarmor.templates.useToSanitizeUserPrompt"]
}

resource "google_project_iam_member" "model_armor_probe" {
  project = var.project_id
  role    = google_project_iam_custom_role.model_armor_probe.name
  member  = google_service_account.workload["probe"].member
}

resource "google_project_iam_member" "model_armor_injector" {
  count = var.fault_drill_enabled ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.model_armor_probe.name
  member  = google_service_account.workload["injector"].member
}

resource "google_project_iam_custom_role" "scenario_injector" {
  project     = var.project_id
  role_id     = "solvanScenarioInjector"
  title       = "Solvan isolated scenario injector"
  description = "Changes only the isolated payments Cloud Run revision for the release experiment."
  stage       = "BETA"
  permissions = [
    "run.operations.get",
    "run.services.get",
    "run.services.update",
  ]
}

resource "google_project_iam_custom_role" "scenario_fixture_reader" {
  project     = var.project_id
  role_id     = "solvanScenarioFixtureReader"
  title       = "Solvan synthetic scenario log reader"
  description = "Reads the isolated payments fixture log written by the S5 synthetic request."
  stage       = "BETA"
  permissions = ["logging.logEntries.list"]
}

resource "google_project_iam_member" "scenario_fixture_reader" {
  count = var.fault_drill_enabled ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.scenario_fixture_reader.name
  member  = google_service_account.workload["injector"].member
}

resource "google_project_iam_member" "scenario_injector" {
  count = var.fault_drill_enabled ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.scenario_injector.name
  member  = google_service_account.workload["injector"].member

  condition {
    title       = "OnlyIsolatedPaymentsFixture"
    description = "The injector cannot update a Solvan control-plane service."
    expression = format(
      "resource.name == 'projects/%s/locations/%s/services/%s-payments'",
      var.project_id,
      var.region,
      local.prefix,
    )
  }
}

resource "google_storage_bucket_iam_member" "scenario_injector_evidence" {
  count = var.fault_drill_enabled ? 1 : 0

  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["injector"].member
}

resource "google_storage_bucket_iam_member" "scenario_oracle_evidence" {
  count = var.fault_drill_enabled ? 1 : 0

  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["oracle"].member
}

resource "google_project_iam_custom_role" "scenario_oracle" {
  project     = var.project_id
  role_id     = "solvanScenarioOracle"
  title       = "Solvan read-only scenario oracle"
  description = "Reads only release telemetry and service state for deterministic grading."
  stage       = "BETA"
  permissions = [
    "logging.logEntries.list",
    "monitoring.timeSeries.list",
    "run.services.get",
  ]
}

resource "google_project_iam_member" "scenario_oracle" {
  count = var.fault_drill_enabled ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.scenario_oracle.name
  member  = google_service_account.workload["oracle"].member
}

# Designated release operators may mint short-lived tokens for the two
# non-agent harness identities. Agent Runtime identities receive no such grant.
resource "google_service_account_iam_member" "approver_injector_token" {
  for_each = var.fault_drill_enabled ? var.approver_principals : toset([])

  service_account_id = google_service_account.workload["injector"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = each.value
}

resource "google_service_account_iam_member" "approver_oracle_token" {
  for_each = var.fault_drill_enabled ? var.approver_principals : toset([])

  service_account_id = google_service_account.workload["oracle"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = each.value
}

resource "google_storage_bucket_iam_member" "runtime_bucket_coordinator" {
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectAdmin"
  member = google_service_account.workload["coordinator"].member
}

resource "google_project_iam_member" "trace_agents" {
  for_each = toset(concat(["api", "console", "coordinator", "detector", "actuator", "evidence", "verifier", "publisher", "memory", "antigravity", "fixture_attester"], var.fault_drill_enabled ? ["payments"] : []))

  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = google_service_account.workload[each.value].member
}

resource "google_project_iam_member" "metrics_agents" {
  for_each = toset(concat(["api", "console", "coordinator", "detector", "actuator", "evidence", "verifier", "publisher", "memory", "antigravity", "fixture_attester"], var.fault_drill_enabled ? ["payments"] : []))

  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = google_service_account.workload[each.value].member
}

resource "google_project_iam_member" "logs_agents" {
  for_each = toset(concat(["api", "console", "coordinator", "detector", "actuator", "evidence", "verifier", "publisher", "memory", "antigravity", "fixture_attester"], var.fault_drill_enabled ? ["payments"] : []))

  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.workload[each.value].member
}

resource "google_project_iam_member" "approver_role" {
  for_each = var.approver_principals

  project = var.project_id
  role    = "roles/run.viewer"
  member  = each.value
}

resource "google_cloud_run_v2_service_iam_member" "approver_api" {
  for_each = var.approver_principals

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["api"].name
  role     = "roles/run.invoker"
  member   = each.value
}
