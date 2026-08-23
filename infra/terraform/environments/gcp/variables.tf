variable "project_id" {
  description = "Existing dedicated GCP project for this Solvan environment."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a canonical Google Cloud project ID."
  }
}

variable "billing_account_id" {
  description = "Billing account owning this dedicated Solvan project."
  type        = string

  validation {
    condition     = can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account_id))
    error_message = "billing_account_id must use the canonical XXXXXX-XXXXXX-XXXXXX form."
  }
}

variable "region" {
  description = "Single approved region for control plane, data, and Agent Platform resources."
  type        = string
  default     = "europe-west1"

  validation {
    condition     = var.region == "europe-west1"
    error_message = "Solvan environments are pinned to europe-west1."
  }
}

variable "environment" {
  description = "Deployment boundary. Dev is mutable, staging qualifies releases, and production serves declared customer estates."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be exactly dev, staging, or production."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly project budget alert amount in USD; alerts do not cap spend."
  type        = number
  default     = 120

  validation {
    condition     = var.monthly_budget_usd >= 10 && var.monthly_budget_usd <= 1000
    error_message = "monthly_budget_usd must be between 10 and 1000."
  }
}

variable "organization_id" {
  description = "Solvan tenant organization ULID used in every scoped row."
  type        = string

  validation {
    condition     = can(regex("^org_[0-7][0-9A-HJKMNP-TV-Z]{25}$", var.organization_id))
    error_message = "organization_id must be a canonical org_ ULID."
  }
}

variable "scope_project_id" {
  description = "Solvan logical project ULID; distinct from the GCP project ID."
  type        = string

  validation {
    condition     = can(regex("^prj_[0-7][0-9A-HJKMNP-TV-Z]{25}$", var.scope_project_id))
    error_message = "scope_project_id must be a canonical prj_ ULID."
  }
}

variable "environment_id" {
  description = "Solvan environment ULID used in every scoped row."
  type        = string

  validation {
    condition     = can(regex("^env_[0-7][0-9A-HJKMNP-TV-Z]{25}$", var.environment_id))
    error_message = "environment_id must be a canonical env_ ULID."
  }
}

variable "release_commit" {
  description = "Full immutable git commit bound by the release orchestrator."
  type        = string
  default     = "UNCONFIGURED"

  validation {
    condition     = var.release_commit == "UNCONFIGURED" || can(regex("^[0-9a-f]{40}$", var.release_commit))
    error_message = "release_commit must be UNCONFIGURED or a full lowercase git SHA."
  }
}

variable "deployment_id" {
  description = "Canonical deployment identifier bound by the release orchestrator."
  type        = string
  default     = "UNCONFIGURED"

  validation {
    condition     = var.deployment_id == "UNCONFIGURED" || can(regex("^[a-z0-9][a-z0-9-]{2,62}$", var.deployment_id))
    error_message = "deployment_id must be UNCONFIGURED or a canonical lowercase release label."
  }
}

variable "release_source_repository_uri" {
  description = "Public judging repository used only by the approval-gated managed release-image trigger."
  type        = string
  default     = "https://github.com/ruhu-ai/solvan.git"

  validation {
    condition     = can(regex("^https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\.git$", var.release_source_repository_uri))
    error_message = "release_source_repository_uri must be a canonical public GitHub HTTPS .git URI."
  }
}

variable "images" {
  description = "Immutable, digest-pinned container images. Tags are rejected."
  type = object({
    api                          = string
    alert_ingress                = string
    direct_gcp_reader            = string
    pilot_qualification_verifier = string
    coordinator                  = string
    detector                     = string
    actuator                     = string
    evidence_broker              = string
    verifier                     = string
    payments_good                = string
    payments_bad                 = string
    console                      = string
    outbox_publisher             = string
    memory_promoter              = string
    antigravity_workspace        = string
    workspace_sandbox            = string
    workspace_adapter            = string
    fixture_attester             = string
    release_admin                = string
    github_provider              = string
    github_identity_broker       = string
    deployment_controller        = string
    release_verifier             = string
    slack_liaison                = string
    liaison_maintenance          = string
    trigger_scheduler            = string
    mcp_facade                   = string
    discord_liaison              = string
    email_liaison                = string
    relay_control                = string
  })

  validation {
    condition     = alltrue([for image in values(var.images) : can(regex("@sha256:[0-9a-f]{64}$", image))])
    error_message = "Every release image must be pinned by sha256 digest."
  }
}

variable "antigravity_demo_enabled" {
  description = "Deploy the public-synthetic Antigravity SDK demonstration provider."
  type        = bool
  default     = false
}

variable "fault_drill_enabled" {
  description = "Deploy the isolated synthetic payments fault-drill workload and narrowly scoped drill identities. It is never a customer-estate dependency."
  type        = bool
  default     = false

  validation {
    condition     = !(var.environment == "production" && var.fault_drill_enabled)
    error_message = "fault_drill_enabled is forbidden in production; use an isolated dev or staging drill."
  }
}

variable "github_release_enabled" {
  description = "Enable the governed GitHub code-delivery and Cloud Run release-controller services."
  type        = bool
  default     = false
}

variable "github_oauth_client_secret_name" {
  description = "Existing Secret Manager secret containing the GitHub App user-to-server client secret."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_oauth_client_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.github_oauth_client_secret_name
    ))
    error_message = "github_oauth_client_secret_name must be a Secret Manager name."
  }
}

variable "github_oauth_client_id" {
  description = "GitHub App client ID used by the fixed user-to-server reviewer-link flow."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition     = var.github_oauth_client_id == "UNCONFIGURED" || can(regex("^[A-Za-z0-9_-]{8,255}$", var.github_oauth_client_id))
    error_message = "github_oauth_client_id must be a bounded GitHub client ID."
  }
}

variable "github_oauth_client_secret_version" {
  description = "Pinned numeric Secret Manager version for the GitHub App OAuth client secret."
  type        = string
  default     = "1"
  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.github_oauth_client_secret_version))
    error_message = "github_oauth_client_secret_version must be a positive numeric version."
  }
}

check "github_identity_configuration" {
  assert {
    condition = !var.github_release_enabled || (
      var.github_oauth_client_id != "UNCONFIGURED" &&
      var.github_oauth_client_secret_name != "UNCONFIGURED" &&
      var.github_identity_cookie_secret_name != "UNCONFIGURED"
    )
    error_message = "github_release_enabled requires the reviewer-link client ID, OAuth secret, and cookie secret."
  }
}

variable "github_identity_cookie_secret_name" {
  description = "Existing Secret Manager secret used only to authenticate reviewer-link callback cookies."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_identity_cookie_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.github_identity_cookie_secret_name
    ))
    error_message = "github_identity_cookie_secret_name must be a Secret Manager name."
  }
}

variable "target_product_enabled" {
  description = "Deploy target-only conversational and operability services outside the MSR gate."
  type        = bool
  default     = false
}

variable "direct_gcp_alert_triage_pilot_enabled" {
  description = "Deploy only the dedicated direct-GCP Alert Ingress and independent pilot qualification verifier. This is independent of target_product_enabled and defaults off."
  type        = bool
  default     = false

  validation {
    condition     = !(var.environment == "production" && var.direct_gcp_alert_triage_pilot_enabled)
    error_message = "direct_gcp_alert_triage_pilot_enabled is a non-production qualification profile and is forbidden in production."
  }
}

variable "direct_gcp_pilot_deployment_revisions" {
  description = "Exact deployed revisions independently bound into a direct-GCP pilot qualification receipt."
  type = object({
    alert_ingress = string
    api           = string
    coordinator   = string
  })
  default = {
    alert_ingress = "UNCONFIGURED"
    api           = "UNCONFIGURED"
    coordinator   = "UNCONFIGURED"
  }

  validation {
    condition = !var.direct_gcp_alert_triage_pilot_enabled || (
      var.release_commit != "UNCONFIGURED" &&
      alltrue([for revision in values(var.direct_gcp_pilot_deployment_revisions) : revision != "UNCONFIGURED" && can(regex("^[a-z0-9-]{1,255}$", revision))])
    )
    error_message = "an enabled direct-GCP pilot requires an immutable release commit and exact deployed alert-ingress, API, and coordinator revisions."
  }
}

variable "solvant_relay_enabled" {
  description = "Deploy Solvant Relay's target-only customer-evidence control plane."
  type        = bool
  default     = false
}

variable "solvant_relay_invoker_members" {
  description = "Exact customer workload-identity principals allowed to invoke the Relay control plane; never use a public member."
  type        = set(string)
  default     = []

  validation {
    condition     = !var.solvant_relay_enabled || length(var.solvant_relay_invoker_members) > 0
    error_message = "solvant_relay_enabled requires at least one exact customer Relay invoker principal."
  }

  validation {
    condition     = !contains(var.solvant_relay_invoker_members, "allUsers") && !contains(var.solvant_relay_invoker_members, "allAuthenticatedUsers")
    error_message = "Solvant Relay control cannot be public or all-authenticated-users invokable."
  }
}

variable "alert_cursor_signing_secret_name" {
  description = "Existing Secret Manager secret containing at least 32 bytes for audience-bound Alert queue cursor signatures. Required when target_product_enabled is true."
  type        = string
  default     = "UNCONFIGURED"

  validation {
    condition = var.alert_cursor_signing_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.alert_cursor_signing_secret_name
    ))
    error_message = "alert_cursor_signing_secret_name must be UNCONFIGURED or a Secret Manager name."
  }

  validation {
    condition     = !var.target_product_enabled || var.alert_cursor_signing_secret_name != "UNCONFIGURED"
    error_message = "target_product_enabled requires alert_cursor_signing_secret_name so Alert cursors fail closed after deployment."
  }
}

variable "channel_enrollment_hmac_secret_name" {
  description = "Existing Secret Manager secret containing at least 32 random bytes for one-time conversational channel enrollment proofs. Required when target_product_enabled is true."
  type        = string
  default     = "UNCONFIGURED"

  validation {
    condition = var.channel_enrollment_hmac_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.channel_enrollment_hmac_secret_name
    ))
    error_message = "channel_enrollment_hmac_secret_name must be UNCONFIGURED or a Secret Manager name."
  }

  validation {
    condition     = !var.target_product_enabled || var.channel_enrollment_hmac_secret_name != "UNCONFIGURED"
    error_message = "target_product_enabled requires channel_enrollment_hmac_secret_name so channel enrollment fails closed after deployment."
  }
}

variable "gateway_extensions_enabled" {
  description = "Create the fail-closed IAP Network Services authorization extension and policy. Staging must keep this enabled."
  type        = bool
  default     = true
}

variable "gateway_model_armor_enabled" {
  description = "Create the inline Model Armor AuthzPolicy independently of IAP. The staging release workflow sets this false only for the documented Google code-13 policy-creation failure; the healthy extension remains provisioned and the in-process sanitizeUserPrompt/sanitizeModelResponse gate remains fail-closed."
  type        = bool
  default     = true
}

variable "agent_runtime_service_agent_bindings_enabled" {
  description = "Bind the managed Agent Platform and Agent Runtime service agents to the exact Gateway, Model Armor, and runtime-storage permissions they require. Dev may disable this until the managed service identities are provisioned; staging must keep it enabled."
  type        = bool
  default     = true
}

variable "slack_liaison_enabled" {
  description = "Deploy the signed Slack adapter; requires target_product_enabled and exact secrets."
  type        = bool
  default     = false
}

variable "slack_team_id" {
  type    = string
  default = "UNCONFIGURED"
}

variable "slack_signing_secret_name" {
  type    = string
  default = "UNCONFIGURED"
}

variable "slack_bot_token_secret_name" {
  type    = string
  default = "UNCONFIGURED"
}

variable "discord_liaison_enabled" {
  type    = bool
  default = false
}

variable "discord_application_id" {
  type    = string
  default = "UNCONFIGURED"
}

variable "discord_public_key_secret_name" {
  description = "Existing Secret Manager secret containing the Discord Ed25519 public key."
  type        = string
  default     = "UNCONFIGURED"
}

variable "discord_bot_token_secret_name" {
  type    = string
  default = "UNCONFIGURED"
}

variable "email_liaison_enabled" {
  type    = bool
  default = false
}

variable "email_relay_url" {
  type    = string
  default = "UNCONFIGURED"
}

variable "email_relay_service_account" {
  type    = string
  default = "UNCONFIGURED"
}

variable "channel_qualification_receipts" {
  description = "Approved immutable qualification receipts to ingest after exact live provider tests. Empty means no provider may become AVAILABLE."
  type = map(object({
    channel_kind = string
    uri          = string
    hash         = string
  }))
  default = {}

  validation {
    condition = alltrue([
      for key, receipt in var.channel_qualification_receipts :
      contains(["slack", "discord", "email"], key) &&
      receipt.channel_kind == upper(key) &&
      can(regex("^gs://[^/]+/.+", receipt.uri)) &&
      can(regex("^sha256:[0-9a-f]{64}$", receipt.hash))
    ])
    error_message = "Channel qualification receipts require a slack/discord/email key, matching uppercase kind, GCS URI, and sha256 digest."
  }
}

check "slack_liaison_configuration" {
  assert {
    condition = !var.slack_liaison_enabled || (
      var.target_product_enabled &&
      var.slack_team_id != "UNCONFIGURED" &&
      can(regex("^[A-Z0-9]{5,32}$", var.slack_team_id)) &&
      var.slack_signing_secret_name != "UNCONFIGURED" &&
      can(regex("^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.slack_signing_secret_name)) &&
      var.slack_bot_token_secret_name != "UNCONFIGURED" &&
      can(regex("^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.slack_bot_token_secret_name))
    )
    error_message = "Slack requires target_product_enabled, an exact team ID, and two valid Secret Manager names."
  }
}

check "discord_liaison_configuration" {
  assert {
    condition = !var.discord_liaison_enabled || (
      var.target_product_enabled &&
      can(regex("^[0-9]{5,32}$", var.discord_application_id)) &&
      var.discord_public_key_secret_name != "UNCONFIGURED" &&
      can(regex("^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.discord_public_key_secret_name)) &&
      var.discord_bot_token_secret_name != "UNCONFIGURED" &&
      can(regex("^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.discord_bot_token_secret_name))
    )
    error_message = "Discord requires target_product_enabled, an exact application ID, and public-key/token Secret Manager names."
  }
}

check "email_liaison_configuration" {
  assert {
    condition = !var.email_liaison_enabled || (
      var.target_product_enabled &&
      can(regex("^https://[^[:space:]]+$", var.email_relay_url)) &&
      can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.gserviceaccount\\.com$", var.email_relay_service_account))
    )
    error_message = "Email requires target_product_enabled, a private HTTPS relay URL, and an exact relay service-account identity."
  }
}

variable "github_repository_id" {
  description = "Scoped ghr_ binding consumed by the GitHub provider."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_repository_id == "UNCONFIGURED" || can(regex(
      "^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$", var.github_repository_id
    ))
    error_message = "github_repository_id must be a canonical ghr_ identifier."
  }
}

variable "github_installation_id" {
  description = "GitHub App installation ID bound to the scoped repository."
  type        = number
  default     = 0
  validation {
    condition     = var.github_installation_id == 0 || var.github_installation_id > 0
    error_message = "github_installation_id must be positive when configured."
  }
}

variable "github_webhook_secret_name" {
  description = "Existing Secret Manager secret name containing the GitHub webhook secret."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_webhook_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.github_webhook_secret_name
    ))
    error_message = "github_webhook_secret_name must be a Secret Manager name."
  }
}

variable "github_installation_token_secret_name" {
  description = "Existing Secret Manager secret containing a short-lived GitHub installation token."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_installation_token_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.github_installation_token_secret_name
    ))
    error_message = "github_installation_token_secret_name must be a Secret Manager name."
  }
}

variable "github_coordinator_audience" {
  description = "OAuth audience accepted for coordinator-only GitHub commands."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_coordinator_audience == "UNCONFIGURED" || can(regex(
      "^https://", var.github_coordinator_audience
    ))
    error_message = "github_coordinator_audience must be an HTTPS URL."
  }
}

variable "github_coordinator_principal" {
  description = "Exact service-account email allowed to invoke GitHub release commands."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_coordinator_principal == "UNCONFIGURED" || can(regex(
      "^[^@[:space:]]+@[^@[:space:]]+\\.gserviceaccount\\.com$", var.github_coordinator_principal
    ))
    error_message = "github_coordinator_principal must be a service-account email."
  }
}

variable "antigravity_model" {
  description = "Exact global Vertex model used by the regional self-hosted SDK provider."
  type        = string
  default     = "gemini-3.1-pro-preview"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.antigravity_model))
    error_message = "antigravity_model must be one exact model identifier."
  }
}

variable "workspace_sandbox_revision" {
  description = "Immutable application revision for the regional Cloud Run Sandbox service."
  type        = string
  default     = "workspace-sandbox-20260810-01"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{2,127}$", var.workspace_sandbox_revision))
    error_message = "workspace_sandbox_revision must be a canonical immutable label."
  }
}

variable "antigravity_provider_revision" {
  description = "Immutable application-level revision accepted by the SDK provider."
  type        = string
  default     = "antigravity-workspace-20260808-01"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{2,127}$", var.antigravity_provider_revision))
    error_message = "antigravity_provider_revision must be a canonical immutable label."
  }
}

variable "calibration_receipt_uri" {
  description = "Approved calibration receipt in the release evidence bucket; null disables the seed job."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.calibration_receipt_uri == null ||
      can(regex("^gs://[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]/[^[:space:]]+$", var.calibration_receipt_uri))
    )
    error_message = "calibration_receipt_uri must be a complete GCS object URI."
  }
}

variable "calibration_receipt_hash" {
  description = "Exact sha256 digest of the approved calibration receipt; null disables the seed job."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.calibration_receipt_hash == null ||
      can(regex("^sha256:[0-9a-f]{64}$", var.calibration_receipt_hash))
    )
    error_message = "calibration_receipt_hash must be a lowercase sha256 digest."
  }

  validation {
    condition = (
      (var.calibration_receipt_uri == null && var.calibration_receipt_hash == null) ||
      (var.calibration_receipt_uri != null && var.calibration_receipt_hash != null)
    )
    error_message = "calibration receipt URI and hash must either both be set or both be null."
  }

  validation {
    condition     = var.fault_drill_enabled || (var.calibration_receipt_uri == null && var.calibration_receipt_hash == null)
    error_message = "A payments calibration receipt requires fault_drill_enabled=true."
  }
}

variable "agent_runtime_resources" {
  description = "Immutable Agent Runtime resources copied from the deployment receipt."
  type = object({
    incident_supervisor  = string
    evidence_agent       = string
    execution_agent      = string
    infrastructure_agent = string
    verification_agent   = string
    workspace_agent      = string
  })
  default = {
    incident_supervisor  = "UNCONFIGURED"
    evidence_agent       = "UNCONFIGURED"
    execution_agent      = "UNCONFIGURED"
    infrastructure_agent = "UNCONFIGURED"
    verification_agent   = "UNCONFIGURED"
    workspace_agent      = "UNCONFIGURED"
  }

  validation {
    condition = alltrue([
      for resource in values(var.agent_runtime_resources) :
      resource == "UNCONFIGURED" || can(regex(
        "^projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]+)/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$",
        resource,
      ))
    ])
    error_message = "Agent Runtime resources must be immutable europe-west1 reasoningEngine names."
  }
}

variable "agent_runtime_revisions" {
  description = "Release identifiers bound to each immutable Runtime resource."
  type = object({
    incident_supervisor  = string
    evidence_agent       = string
    execution_agent      = string
    infrastructure_agent = string
    verification_agent   = string
    workspace_agent      = string
  })
  default = {
    incident_supervisor  = "UNCONFIGURED"
    evidence_agent       = "UNCONFIGURED"
    execution_agent      = "UNCONFIGURED"
    infrastructure_agent = "UNCONFIGURED"
    verification_agent   = "UNCONFIGURED"
    workspace_agent      = "UNCONFIGURED"
  }
}

variable "agent_tool_bindings" {
  description = "Exact approved Tool profile, Agent Identity, connection epochs, Gateway routes, and classification frozen before each Runtime dispatch."
  type = object({
    incident_supervisor = object({
      profile_ref            = string
      identity_ref           = string
      accepted_tool_ordinals = list(number)
      connection_epochs      = map(number)
      gateway_destinations   = list(string)
      data_classification    = string
    })
    evidence_agent = object({
      profile_ref            = string
      identity_ref           = string
      accepted_tool_ordinals = list(number)
      connection_epochs      = map(number)
      gateway_destinations   = list(string)
      data_classification    = string
    })
    infrastructure_agent = object({
      profile_ref            = string
      identity_ref           = string
      accepted_tool_ordinals = list(number)
      connection_epochs      = map(number)
      gateway_destinations   = list(string)
      data_classification    = string
    })
    execution_agent = object({
      profile_ref            = string
      identity_ref           = string
      accepted_tool_ordinals = list(number)
      connection_epochs      = map(number)
      gateway_destinations   = list(string)
      data_classification    = string
    })
    verification_agent = object({
      profile_ref            = string
      identity_ref           = string
      accepted_tool_ordinals = list(number)
      connection_epochs      = map(number)
      gateway_destinations   = list(string)
      data_classification    = string
    })
    workspace_agent = object({
      profile_ref            = string
      identity_ref           = string
      accepted_tool_ordinals = list(number)
      connection_epochs      = map(number)
      gateway_destinations   = list(string)
      data_classification    = string
    })
  })

  validation {
    condition = alltrue([
      for binding in values(var.agent_tool_bindings) :
      can(regex("^[a-z0-9][a-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9._-]*$", binding.profile_ref)) &&
      length(trimspace(binding.identity_ref)) > 0 &&
      length(binding.accepted_tool_ordinals) == length(distinct(binding.accepted_tool_ordinals)) &&
      alltrue([for ordinal in binding.accepted_tool_ordinals : ordinal >= 1 && floor(ordinal) == ordinal]) &&
      alltrue([for epoch in values(binding.connection_epochs) : epoch >= 1 && floor(epoch) == epoch]) &&
      alltrue([for destination in binding.gateway_destinations : length(trimspace(destination)) > 0]) &&
      contains(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"], binding.data_classification)
    ])
    error_message = "Every Agent Tool binding must contain an exact profile, identity, a sorted unique accepted-ordinal subset, positive integer epochs, explicit Gateway routes, and known classification."
  }
}

variable "catalog_network_policy_hash" {
  description = "Digest of the exact approved network policy bound to published Tool revisions."
  type        = string
  default     = "UNCONFIGURED"

  validation {
    condition = var.catalog_network_policy_hash == "UNCONFIGURED" || can(regex(
      "^sha256:[0-9a-f]{64}$", var.catalog_network_policy_hash
    ))
    error_message = "catalog_network_policy_hash must be UNCONFIGURED or a lowercase sha256 digest."
  }
}

variable "catalog_release_evidence_retention_seconds" {
  description = "Locked retention period for Google Cloud Deploy catalog evidence (seven years by default)."
  type        = number
  default     = 220752000

  validation {
    condition     = var.catalog_release_evidence_retention_seconds >= 7776000
    error_message = "catalog release evidence must be retained for at least 90 days."
  }
}

variable "database_tier" {
  description = "Smallest viable Cloud SQL tier for the isolated competition stack."
  type        = string
  default     = "db-custom-1-3840"
}

variable "database_edition" {
  description = "Cloud SQL edition. Dev uses Enterprise so the low-cost custom tier is valid; staging may explicitly select Enterprise Plus with a supported perf-optimized tier."
  type        = string
  default     = "ENTERPRISE"

  validation {
    condition     = contains(["ENTERPRISE", "ENTERPRISE_PLUS"], var.database_edition)
    error_message = "database_edition must be ENTERPRISE or ENTERPRISE_PLUS."
  }
}

variable "database_admin_secret_name" {
  description = "Existing Secret Manager secret containing the Cloud SQL postgres bootstrap password used only by the migration job. Leave UNCONFIGURED until the operator provisions it."
  type        = string
  default     = "UNCONFIGURED"

  validation {
    condition = var.database_admin_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.database_admin_secret_name
    ))
    error_message = "database_admin_secret_name must be UNCONFIGURED or a Secret Manager name."
  }
}

variable "warm_min_instances" {
  description = "Keep one instance warm to avoid cold starts. Set to 1 only while demonstrating or recording; otherwise zero."
  type        = number
  default     = 0

  validation {
    condition     = contains([0, 1], var.warm_min_instances)
    error_message = "warm_min_instances must be 0 or 1."
  }
}

variable "scheduler_paused" {
  description = "Keep all automated work paused until agents, schema, policy, and preflight inputs are bound."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Protect durable evidence and databases from accidental destroy."
  type        = bool
  default     = true
}

variable "admitted_workspace_domains" {
  description = <<-EOT
    Google Workspace domains whose verified accounts may sign in. Never inferred:
    an empty list admits nobody, which is the safe direction for a setting that
    decides who reaches the console. Eligibility is still not admission — a
    membership is what lets an account in.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.admitted_workspace_domains) > 0
    error_message = "Name at least one admitted Workspace domain; the API refuses to start without one."
  }
}

variable "founding_administrator_email" {
  description = <<-EOT
    The one account granted ADMIN on first sign-in, and only while this
    environment has no administrator at all. It exists because an invitation
    requires an administrator to author it, so the first one cannot be invited.
    Must be at an admitted Workspace domain; the address is compared against a
    verified assertion and never against a request.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.founding_administrator_email))
    error_message = "Name one email address for the founding administrator."
  }
}

variable "oauth_client_secret_name" {
  description = <<-EOT
    Secret Manager secret holding the confidential OAuth client's secret, in this
    environment's own project. One client per environment; never a downloaded key
    file and never a client shared with other tooling.
  EOT
  type        = string
}

variable "operator_step_up_email_relay_url" {
  description = <<-EOT
    Private HTTPS email-delivery endpoint used only for transaction-bound
    operator presence codes. The API calls it with its Cloud Run identity and
    never routes a code through the conversational email liaison ledger.
  EOT
  type        = string

  validation {
    condition     = can(regex("^https://[^[:space:]]+$", var.operator_step_up_email_relay_url))
    error_message = "operator_step_up_email_relay_url must be a private HTTPS endpoint."
  }
}

variable "operator_step_up_pepper_secret_name" {
  description = "Secret Manager secret containing at least 32 random bytes for operator-code HMAC verification."
  type        = string

  validation {
    condition = can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.operator_step_up_pepper_secret_name
    ))
    error_message = "operator_step_up_pepper_secret_name must be a Secret Manager name."
  }
}

variable "console_public" {
  description = "Expose the read-only competition console without authentication."
  type        = bool
  default     = false
}

variable "approver_principals" {
  description = "Static individual release approvers. Must not include agents, groups, or service accounts."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for principal in var.approver_principals :
      startswith(principal, "user:")
    ])
    error_message = "Approvers must be individual user: principals."
  }
}

variable "approval_token_audience" {
  description = "OAuth client audience of the one-time Google user identity token used for approvals."
  type        = string

  validation {
    condition = can(regex(
      "^[0-9]+(?:-[a-z0-9]+)?\\.apps\\.googleusercontent\\.com$",
      var.approval_token_audience,
    ))
    error_message = "approval_token_audience must be an explicit Google OAuth client ID."
  }
}

variable "execution_agent_principal" {
  description = "System-attested principal:// identity returned by the deployed Execution Agent Runtime."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.execution_agent_principal == null ||
      can(regex(
        "^principal://agents\\.global\\.(org-[0-9]+|project-[0-9]+)\\.system\\.id\\.goog/resources/aiplatform/projects/[0-9]+/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$",
        var.execution_agent_principal,
      ))
    )
    error_message = "execution_agent_principal must be the exact attested europe-west1 Runtime identity."
  }
}

variable "evidence_agent_principal" {
  description = "System-attested Agent Identity returned for the Evidence Agent."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.evidence_agent_principal == null || can(regex(
      "^principal://agents\\.global\\.(org-[0-9]+|project-[0-9]+)\\.system\\.id\\.goog/resources/aiplatform/projects/[0-9]+/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$",
      var.evidence_agent_principal,
    ))
    error_message = "evidence_agent_principal must be an attested europe-west1 Runtime identity."
  }
}

variable "infrastructure_agent_principal" {
  description = "System-attested Agent Identity returned for the Infrastructure Agent."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.infrastructure_agent_principal == null || can(regex(
      "^principal://agents\\.global\\.(org-[0-9]+|project-[0-9]+)\\.system\\.id\\.goog/resources/aiplatform/projects/[0-9]+/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$",
      var.infrastructure_agent_principal,
    ))
    error_message = "infrastructure_agent_principal must be an attested europe-west1 Runtime identity."
  }
}

variable "verification_agent_principal" {
  description = "System-attested Agent Identity returned for the Verification Agent."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.verification_agent_principal == null || can(regex(
      "^principal://agents\\.global\\.(org-[0-9]+|project-[0-9]+)\\.system\\.id\\.goog/resources/aiplatform/projects/[0-9]+/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$",
      var.verification_agent_principal,
    ))
    error_message = "verification_agent_principal must be an attested europe-west1 Runtime identity."
  }
}

variable "incident_supervisor_agent_principal" {
  description = "System-attested Agent Identity returned for the Incident Supervisor."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.incident_supervisor_agent_principal == null || can(regex(
      "^principal://agents\\.global\\.(org-[0-9]+|project-[0-9]+)\\.system\\.id\\.goog/resources/aiplatform/projects/[0-9]+/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$",
      var.incident_supervisor_agent_principal,
    ))
    error_message = "incident_supervisor_agent_principal must be an attested europe-west1 Runtime identity."
  }
}

variable "workspace_agent_principal" {
  description = "System-attested Agent Identity returned for the Workspace Agent."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.workspace_agent_principal == null || can(regex(
      "^principal://agents\\.global\\.(org-[0-9]+|project-[0-9]+)\\.system\\.id\\.goog/resources/aiplatform/projects/[0-9]+/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$",
      var.workspace_agent_principal,
    ))
    error_message = "workspace_agent_principal must be an attested europe-west1 Runtime identity."
  }
}

variable "actuator_max_mutations_per_hour" {
  description = "Blast-radius ceiling the actuator enforces itself, independent of any control-plane budget."
  type        = number
  default     = 20
  validation {
    condition     = var.actuator_max_mutations_per_hour >= 1
    error_message = "The actuator budget must be at least 1; the service refuses to mutate without a usable ceiling."
  }
}

# ---------------------------------------------------------------------------
# GitHub App identity.
#
# The App JWT path replaced the pasted installation token: the provider mints
# short-lived installation tokens itself, and the API needs the same App
# identity to list the installations an operator picks from during onboarding.
# Both read the App identifier and private key as pinned Secret Manager
# references; neither ever holds a token at rest.
#
# `github_installation_token_secret_name` above remains for the superseded
# pasted-token path and is not required by either workload.
# ---------------------------------------------------------------------------

variable "github_app_slug" {
  description = "The GitHub App's URL slug, used to build its install link."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_app_slug == "UNCONFIGURED" || can(regex(
      "^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$", var.github_app_slug
    ))
    error_message = "github_app_slug must be a GitHub App slug."
  }
}

variable "github_app_id_secret_name" {
  description = "Existing Secret Manager secret containing the GitHub App identifier."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_app_id_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.github_app_id_secret_name
    ))
    error_message = "github_app_id_secret_name must be a Secret Manager name."
  }
}

variable "github_app_private_key_secret_name" {
  description = "Existing Secret Manager secret containing the GitHub App RSA private key."
  type        = string
  default     = "UNCONFIGURED"
  validation {
    condition = var.github_app_private_key_secret_name == "UNCONFIGURED" || can(regex(
      "^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.github_app_private_key_secret_name
    ))
    error_message = "github_app_private_key_secret_name must be a Secret Manager name."
  }
}

# Pinned rather than `latest`, because rotating the App key must be a decision
# somebody makes and reviews, not something a revision picks up on its next
# start. The provider refuses an unparsable reference, so a wrong version fails
# closed at boot rather than midway through a release.
variable "github_app_id_secret_version" {
  description = "Pinned version of the GitHub App identifier secret."
  type        = string
  default     = "latest"
  validation {
    condition     = can(regex("^([1-9][0-9]*|latest)$", var.github_app_id_secret_version))
    error_message = "github_app_id_secret_version must be a positive version or latest."
  }
}

variable "github_app_private_key_secret_version" {
  description = "Pinned version of the GitHub App private-key secret."
  type        = string
  default     = "latest"
  validation {
    condition     = can(regex("^([1-9][0-9]*|latest)$", var.github_app_private_key_secret_version))
    error_message = "github_app_private_key_secret_version must be a positive version or latest."
  }
}

# Without these the connect routes answer GITHUB_APP_NOT_CONFIGURED and the
# console reads "Not configured" forever, which is exactly the failure this
# check exists to make loud at plan time instead of at first use.
check "github_app_configuration" {
  assert {
    condition = !var.github_release_enabled || (
      var.github_app_slug != "UNCONFIGURED" &&
      var.github_app_id_secret_name != "UNCONFIGURED" &&
      var.github_app_private_key_secret_name != "UNCONFIGURED" &&
      var.github_webhook_secret_name != "UNCONFIGURED"
    )
    error_message = "github_release_enabled requires the App slug, App identifier, private key, and webhook secret."
  }
}

variable "alert_notification_email" {
  description = "Address receiving Solvan operational alerts and budget notifications."
  type        = string
  default     = "UNCONFIGURED"

  validation {
    condition = var.alert_notification_email == "UNCONFIGURED" || can(
      regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.alert_notification_email)
    )
    error_message = "alert_notification_email must be an email address."
  }
}

# Alert policies are created either way, so a firing condition is always visible
# in Cloud Monitoring. What an unconfigured address removes is *delivery* — the
# policy opens an incident nobody is told about. That is worth a plan-time
# warning rather than a silent default, because the failure it produces is
# indistinguishable from "nothing went wrong".
check "alert_delivery_configured" {
  assert {
    condition     = var.alert_notification_email != "UNCONFIGURED"
    error_message = "alert_notification_email is unset; alert policies will open incidents that notify nobody."
  }
}
