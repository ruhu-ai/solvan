locals {
  cloud_run_services = {
    alert_ingress = {
      image           = var.images.alert_ingress
      service_account = "alert_ingress"
      port            = 8080
      min_instances   = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "60s"
    }
    direct_gcp_reader = {
      image           = var.images.direct_gcp_reader
      service_account = "direct_gcp_reader"
      port            = 8080
      min_instances   = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "60s"
    }
    pilot_qualification_verifier = {
      image           = var.images.pilot_qualification_verifier
      service_account = "pilot_qualification_verifier"
      port            = 8080
      min_instances   = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0
      max_instances   = 1
      cpu_idle        = true
      timeout         = "60s"
    }
    api = {
      image           = var.images.api
      service_account = "api"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 3
      cpu_idle        = true
      timeout         = "60s"
    }
    coordinator = {
      image           = var.images.coordinator
      service_account = "coordinator"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
    detector = {
      image           = var.images.detector
      service_account = "detector"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 1
      cpu_idle        = false
      timeout         = "180s"
    }
    actuator = {
      image           = var.images.actuator
      service_account = "actuator"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 1
      cpu_idle        = true
      timeout         = "300s"
    }
    evidence = {
      image           = var.images.evidence_broker
      service_account = "evidence"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 2
      cpu_idle        = true
      timeout         = "60s"
    }
    relay_control = {
      image           = var.images.relay_control
      service_account = "relay_control"
      port            = 8080
      min_instances   = var.solvant_relay_enabled ? var.warm_min_instances : 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "60s"
    }
    verifier = {
      image           = var.images.verifier
      service_account = "verifier"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
    payments = {
      image           = var.images.payments_good
      service_account = "payments"
      port            = 8080
      min_instances   = var.warm_min_instances
      # The defective fixture leaks four connections in one process-local
      # bounded pool. Multiple instances would create independent pools and
      # make the S1 onset/load threshold nondeterministic.
      max_instances = 1
      cpu_idle      = true
      timeout       = "60s"
    }
    publisher = {
      image           = var.images.outbox_publisher
      service_account = "publisher"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 1
      cpu_idle        = false
      timeout         = "300s"
    }
    memory = {
      image           = var.images.memory_promoter
      service_account = "memory"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 1
      cpu_idle        = true
      timeout         = "300s"
    }
    github_provider = {
      image           = var.images.github_provider
      service_account = "github_provider"
      port            = 8080
      min_instances   = var.github_release_enabled ? var.warm_min_instances : 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
    github_identity_broker = {
      image           = var.images.github_identity_broker
      service_account = "github_identity_broker"
      port            = 8080
      min_instances   = var.github_release_enabled ? var.warm_min_instances : 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "60s"
    }
    deployment_controller = {
      image           = var.images.deployment_controller
      service_account = "deployment_controller"
      port            = 8080
      min_instances   = var.github_release_enabled ? var.warm_min_instances : 0
      max_instances   = 1
      cpu_idle        = true
      timeout         = "300s"
    }
    release_verifier = {
      image           = var.images.release_verifier
      service_account = "release_verifier"
      port            = 8080
      min_instances   = var.github_release_enabled ? var.warm_min_instances : 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
    workspace_adapter = {
      image           = var.images.workspace_adapter
      service_account = "workspace_adapter"
      port            = 8080
      min_instances   = var.warm_min_instances
      max_instances   = 2
      cpu_idle        = true
      timeout         = "360s"
    }
    slack_liaison = {
      image           = var.images.slack_liaison
      service_account = "slack_liaison"
      port            = 8080
      min_instances   = var.slack_liaison_enabled ? var.warm_min_instances : 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
    liaison_maintenance = {
      image           = var.images.liaison_maintenance
      service_account = "liaison_maintenance"
      port            = 8080
      min_instances   = 0
      max_instances   = 1
      cpu_idle        = true
      timeout         = "300s"
    }
    trigger_scheduler = {
      image           = var.images.trigger_scheduler
      service_account = "trigger_scheduler"
      port            = 8080
      min_instances   = 0
      max_instances   = 1
      cpu_idle        = true
      timeout         = "300s"
    }
    mcp_facade = {
      image           = var.images.mcp_facade
      service_account = "mcp_facade"
      port            = 8080
      min_instances   = 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
    discord_liaison = {
      image           = var.images.discord_liaison
      service_account = "discord_liaison"
      port            = 8080
      min_instances   = 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
    email_liaison = {
      image           = var.images.email_liaison
      service_account = "email_liaison"
      port            = 8080
      min_instances   = 0
      max_instances   = 2
      cpu_idle        = true
      timeout         = "300s"
    }
  }

  # The direct-GCP pilot is a deliberately narrow deployment profile.  It
  # does not merely scale unrelated workloads to zero: they are absent from
  # the Cloud Run graph, eliminating accidental invocation or credential use.
  direct_gcp_pilot_service_keys = toset([
    "api",
    "coordinator",
    "publisher",
    "alert_ingress",
    "direct_gcp_reader",
    "pilot_qualification_verifier",
  ])
}

resource "google_cloud_run_v2_service" "console" {
  project             = var.project_id
  name                = "${local.prefix}-console"
  location            = var.region
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.workload["console"].email
    timeout         = "60s"

    scaling {
      min_instance_count = var.warm_min_instances
      max_instance_count = 3
    }

    containers {
      image = var.images.console

      ports {
        container_port = 8080
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = true
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "SOLVAN_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "SOLVAN_API_UPSTREAM"
        value = google_cloud_run_v2_service.service["api"].uri
      }
      env {
        name  = "SOLVAN_API_AUDIENCE"
        value = google_cloud_run_v2_service.service["api"].uri
      }
      env {
        name  = "SOLVAN_GITHUB_IDENTITY_UPSTREAM"
        value = var.github_release_enabled ? google_cloud_run_v2_service.service["github_identity_broker"].uri : "DISABLED"
      }
      env {
        name  = "SOLVAN_GITHUB_IDENTITY_AUDIENCE"
        value = var.github_release_enabled ? google_cloud_run_v2_service.service["github_identity_broker"].uri : "DISABLED"
      }
    }

    max_instance_request_concurrency = 40
  }

  depends_on = [google_project_service.required["run.googleapis.com"]]
}

resource "google_cloud_run_v2_service" "service" {
  lifecycle {
    precondition {
      # github_release_enabled without a real ghr_ binding deployed a
      # coordinator that 500ed on unrelated routes (staging-20260823-05).
      # Refuse the contradiction at plan time instead of at runtime.
      condition = !var.github_release_enabled || can(regex("^ghr_", var.github_repository_id))
      error_message = "github_release_enabled requires a real github_repository_id (ghr_...); complete the console GitHub onboarding first or disable the provider."
    }
  }

  for_each = {
    for key, value in local.cloud_run_services : key => value
    if(!var.direct_gcp_alert_triage_pilot_enabled || contains(local.direct_gcp_pilot_service_keys, key)) &&
    (!contains(["github_provider", "github_identity_broker", "deployment_controller", "release_verifier"], key) || var.github_release_enabled) &&
    (!contains(["alert_ingress", "direct_gcp_reader", "pilot_qualification_verifier"], key) || var.direct_gcp_alert_triage_pilot_enabled) &&
    (!contains(["slack_liaison", "liaison_maintenance", "trigger_scheduler", "mcp_facade", "discord_liaison", "email_liaison"], key) || var.target_product_enabled) &&
    (key != "relay_control" || var.solvant_relay_enabled) &&
    (key != "payments" || var.fault_drill_enabled) &&
    (key != "slack_liaison" || var.slack_liaison_enabled) &&
    (key != "discord_liaison" || var.discord_liaison_enabled) &&
    (key != "email_liaison" || var.email_liaison_enabled)
  }

  project = var.project_id
  # Cloud Run service names admit lowercase letters, digits, and hyphens only.
  # Registry keys intentionally use underscores; derive the name for every key
  # rather than listing the multi-word ones, because a key that is missed here
  # does not fall back to something safe — it produces a name the API rejects.
  name                = "${local.prefix}-${replace(each.key, "_", "-")}"
  location            = var.region
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.workload[each.value.service_account].email
    timeout         = each.value.timeout

    scaling {
      min_instance_count = each.value.min_instances
      max_instance_count = each.value.max_instances
    }

    containers {
      image = each.value.image

      ports {
        container_port = each.value.port
      }

      resources {
        cpu_idle          = each.value.cpu_idle
        startup_cpu_boost = true
        limits = {
          cpu    = "1"
          memory = each.key == "coordinator" ? "1Gi" : "512Mi"
        }
      }

      env {
        name  = "SOLVAN_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "SOLVAN_GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "SOLVAN_GCP_PROJECT_NUMBER"
        value = data.google_project.current.number
      }
      env {
        name  = "SOLVAN_GCP_REGION"
        value = var.region
      }
      env {
        name  = "SOLVAN_GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "SOLVAN_MODEL_LOCATION"
        value = "eu"
      }
      env {
        name  = "SOLVAN_ORGANIZATION_ID"
        value = var.organization_id
      }
      env {
        name  = "SOLVAN_SCOPE_PROJECT_ID"
        value = var.scope_project_id
      }
      env {
        name  = "SOLVAN_ENVIRONMENT_ID"
        value = var.environment_id
      }
      env {
        name  = "SOLVAN_CLOUD_SQL_INSTANCE"
        value = google_sql_database_instance.control.connection_name
      }
      env {
        name  = "SOLVAN_DATABASE_NAME"
        value = google_sql_database.solvan.name
      }
      env {
        name = "SOLVAN_DATABASE_USER"
        value = trimsuffix(
          google_service_account.workload[each.value.service_account].email,
          ".gserviceaccount.com",
        )
      }
      env {
        name  = "SOLVAN_EVIDENCE_BUCKET"
        value = google_storage_bucket.evidence.name
      }
      env {
        name  = "SOLVAN_RUNTIME_BUCKET"
        value = google_storage_bucket.runtime.name
      }
      env {
        name  = "SOLVAN_GUIDANCE_BUCKET"
        value = google_storage_bucket.runtime.name
      }
      dynamic "env" {
        for_each = contains(["api", "liaison_maintenance"], each.key) && var.target_product_enabled ? [1] : []
        content {
          name  = "SOLVAN_SKILLS_BUCKET"
          value = google_storage_bucket.skills.name
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.target_product_enabled ? [1] : []
        content {
          name  = "SOLVAN_GUIDANCE_EVALUATION_BUCKET"
          value = google_storage_bucket.skills.name
        }
      }
      env {
        name  = "SOLVAN_WORKFLOW_TOPIC"
        value = google_pubsub_topic.workflow.name
      }
      env {
        name  = "SOLVAN_OTEL_EXPORTER"
        value = "google_cloud"
      }

      dynamic "env" {
        for_each = contains(["api", "detector"], each.key) && var.direct_gcp_alert_triage_pilot_enabled ? [1] : []
        content {
          name  = "SOLVAN_DIRECT_GCP_READER_URL"
          value = local.direct_gcp_reader_url
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.direct_gcp_alert_triage_pilot_enabled ? [1] : []
        content {
          name  = "SOLVAN_PILOT_QUALIFICATION_VERIFIER_URL"
          value = local.pilot_qualification_verifier_url
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.direct_gcp_alert_triage_pilot_enabled ? [1] : []
        content {
          name  = "SOLVAN_READER_SERVICE_ACCOUNT"
          value = google_service_account.workload["direct_gcp_reader"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "direct_gcp_reader" ? [1] : []
        content {
          name  = "SOLVAN_DIRECT_GCP_READER_AUDIENCE"
          value = local.direct_gcp_reader_url
        }
      }
      dynamic "env" {
        for_each = each.key == "direct_gcp_reader" ? [1] : []
        content {
          name = "SOLVAN_DIRECT_GCP_READER_CALLERS_JSON"
          value = jsonencode([
            google_service_account.workload["api"].email,
            google_service_account.workload["detector"].email,
          ])
        }
      }
      dynamic "env" {
        for_each = each.key == "direct_gcp_reader" ? [1] : []
        content {
          name  = "SOLVAN_READER_SERVICE_ACCOUNT"
          value = google_service_account.workload["direct_gcp_reader"].email
        }
      }
      # Specification 13 §1.1/§3.4. Every evidence connector read runs as the
      # enrolled customer reader account, reached only through the one delegator
      # identity the customer's grant names. Without this the broker would read
      # Solvan's own project with its ambient runtime identity.
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name  = "SOLVAN_READER_SERVICE_ACCOUNT"
          value = google_service_account.workload["direct_gcp_reader"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_PILOT_QUALIFICATION_AUDIENCE"
          value = local.pilot_qualification_verifier_url
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_PILOT_QUALIFICATION_CALLER"
          value = google_service_account.workload["api"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_PILOT_QUALIFICATION_VERIFIER_SERVICE_ACCOUNT"
          value = google_service_account.workload["pilot_qualification_verifier"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_GCP_PROJECT"
          value = var.project_id
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_REGION"
          value = var.region
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_COMMIT"
          value = var.release_commit
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_ALERT_INGRESS_REVISION"
          value = var.direct_gcp_pilot_deployment_revisions.alert_ingress
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_API_REVISION"
          value = var.direct_gcp_pilot_deployment_revisions.api
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_REVISION"
          value = var.direct_gcp_pilot_deployment_revisions.coordinator
        }
      }

      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_PILOT_QUALIFICATION_RECEIPT_BUCKET"
          value = google_storage_bucket.direct_gcp_pilot_receipts[0].name
        }
      }
      dynamic "env" {
        for_each = each.key == "pilot_qualification_verifier" ? [1] : []
        content {
          name  = "SOLVAN_PILOT_QUALIFICATION_KMS_KEY_VERSION"
          value = google_kms_crypto_key_version.direct_gcp_pilot_receipt_signer[0].name
        }
      }

      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_PLATFORM_AUTHORITY_MODE"
          value = "GOOGLE_CLOUD_IAM"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL"
          value = var.operator_step_up_email_relay_url
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name = "SOLVAN_OPERATOR_STEP_UP_PEPPER"
          value_source {
            secret_key_ref {
              secret  = var.operator_step_up_pepper_secret_name
              version = "latest"
            }
          }
        }
      }
      dynamic "env" {
        for_each = (
          each.key == "api" && var.target_product_enabled
          && var.alert_cursor_signing_secret_name != "UNCONFIGURED"
          ? [1] : []
        )
        content {
          name = "SOLVAN_ALERT_CURSOR_SIGNING_KEY"
          value_source {
            secret_key_ref {
              secret  = var.alert_cursor_signing_secret_name
              version = "latest"
            }
          }
        }
      }
      dynamic "env" {
        for_each = (
          each.key == "api" && var.target_product_enabled
          && var.channel_enrollment_hmac_secret_name != "UNCONFIGURED"
          ? [1] : []
        )
        content {
          name = "SOLVAN_CHANNEL_ENROLLMENT_HMAC_KEY"
          value_source {
            secret_key_ref {
              secret  = var.channel_enrollment_hmac_secret_name
              version = "latest"
            }
          }
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DB_POOL_MIN_SIZE"
          value = "1"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DB_POOL_MAX_SIZE"
          value = "16"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DB_POOL_ACQUISITION_TIMEOUT_SECONDS"
          value = "5"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DB_POOL_IDLE_LIFETIME_SECONDS"
          value = "300"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DB_POOL_MAX_CONNECTION_LIFETIME_SECONDS"
          value = "900"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DB_POOL_IAM_TOKEN_LIFETIME_SECONDS"
          value = "3600"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DB_POOL_IDENTITY_SAFETY_MARGIN_SECONDS"
          value = "60"
        }
      }
      dynamic "env" {
        for_each = contains(["api", "liaison_maintenance"], each.key) ? [1] : []
        content {
          name  = "SOLVAN_LIAISON_COMPOSER"
          value = var.target_product_enabled ? "ADK" : "DETERMINISTIC"
        }
      }
      dynamic "env" {
        for_each = contains(["api", "liaison_maintenance"], each.key) ? [1] : []
        content {
          name  = "SOLVAN_MODEL_RESOURCE"
          value = "gemini-3.6-flash"
        }
      }
      dynamic "env" {
        for_each = contains(["api", "liaison_maintenance"], each.key) ? [1] : []
        content {
          name  = "GOOGLE_GENAI_USE_VERTEXAI"
          value = "true"
        }
      }
      dynamic "env" {
        for_each = contains(["api", "liaison_maintenance"], each.key) ? [1] : []
        content {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }
      }
      dynamic "env" {
        for_each = contains(["api", "liaison_maintenance"], each.key) ? [1] : []
        content {
          name  = "GOOGLE_CLOUD_LOCATION"
          value = "eu"
        }
      }
      dynamic "env" {
        for_each = contains(["api", "liaison_maintenance"], each.key) ? [1] : []
        content {
          name  = "SOLVAN_MODEL_ARMOR_TEMPLATE"
          value = google_model_armor_template.agent_boundary.name
        }
      }
      dynamic "env" {
        for_each = each.key == "slack_liaison" ? [1] : []
        content {
          name  = "SOLVAN_PROJECT_ID"
          value = var.scope_project_id
        }
      }
      dynamic "env" {
        for_each = each.key == "slack_liaison" ? [1] : []
        content {
          name  = "SOLVAN_SLACK_TEAM_ID"
          value = var.slack_team_id
        }
      }
      dynamic "env" {
        for_each = each.key == "slack_liaison" ? [1] : []
        content {
          name  = "SOLVAN_SLACK_SIGNING_SECRET_REF"
          value = "projects/${var.project_id}/secrets/${var.slack_signing_secret_name}/versions/latest"
        }
      }
      dynamic "env" {
        for_each = each.key == "slack_liaison" ? [1] : []
        content {
          name  = "SOLVAN_SLACK_BOT_TOKEN_REF"
          value = "projects/${var.project_id}/secrets/${var.slack_bot_token_secret_name}/versions/latest"
        }
      }
      dynamic "env" {
        for_each = each.key == "slack_liaison" ? [1] : []
        content {
          name  = "SOLVAN_LIAISON_PAYLOAD_BUCKET"
          value = google_storage_bucket.runtime.name
        }
      }
      # The API builds the URL an operator lands on after installing the App
      # on GitHub. Absent, the redirect degrades to a same-origin relative path
      # — which works through the console proxy but says nothing useful in a
      # log or a bookmark.
      dynamic "env" {
        for_each = contains(["api", "slack_liaison"], each.key) ? [1] : []
        content {
          name  = "SOLVAN_CONSOLE_BASE_URL"
          value = local.console_url
        }
      }
      dynamic "env" {
        for_each = each.key == "slack_liaison" ? [1] : []
        content {
          name  = "SOLVAN_SLACK_LIAISON_AUDIENCE"
          value = local.slack_liaison_url
        }
      }
      dynamic "env" {
        for_each = each.key == "slack_liaison" ? [1] : []
        content {
          name  = "SOLVAN_SLACK_LIAISON_SERVICE_ACCOUNT"
          value = google_service_account.workload["slack_liaison"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "liaison_maintenance" ? [1] : []
        content {
          name  = "SOLVAN_LIAISON_MAINTENANCE_AUDIENCE"
          value = local.liaison_maintenance_url
        }
      }
      dynamic "env" {
        for_each = each.key == "liaison_maintenance" ? [1] : []
        content {
          name  = "SOLVAN_LIAISON_MAINTENANCE_PRINCIPAL"
          value = google_service_account.workload["liaison_maintenance"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "trigger_scheduler" ? [1] : []
        content {
          name  = "SOLVAN_TRIGGER_SCHEDULER_AUDIENCE"
          value = local.trigger_scheduler_url
        }
      }
      dynamic "env" {
        for_each = each.key == "mcp_facade" ? [1] : []
        content {
          name  = "SOLVAN_MCP_AUDIENCE"
          value = var.approval_token_audience
        }
      }
      dynamic "env" {
        for_each = contains(["discord_liaison", "email_liaison"], each.key) ? [1] : []
        content {
          name  = "SOLVAN_LIAISON_PAYLOAD_BUCKET"
          value = google_storage_bucket.runtime.name
        }
      }
      dynamic "env" {
        for_each = contains(["discord_liaison", "email_liaison"], each.key) ? [1] : []
        content {
          name  = "SOLVAN_CONSOLE_BASE_URL"
          value = local.console_url
        }
      }
      dynamic "env" {
        for_each = each.key == "discord_liaison" ? [1] : []
        content {
          name  = "SOLVAN_DISCORD_APPLICATION_ID"
          value = var.discord_application_id
        }
      }
      dynamic "env" {
        for_each = each.key == "discord_liaison" ? [1] : []
        content {
          name  = "SOLVAN_DISCORD_PUBLIC_KEY_REF"
          value = "projects/${var.project_id}/secrets/${var.discord_public_key_secret_name}/versions/latest"
        }
      }
      dynamic "env" {
        for_each = each.key == "discord_liaison" ? [1] : []
        content {
          name  = "SOLVAN_DISCORD_BOT_TOKEN_REF"
          value = "projects/${var.project_id}/secrets/${var.discord_bot_token_secret_name}/versions/latest"
        }
      }
      dynamic "env" {
        for_each = each.key == "discord_liaison" ? [1] : []
        content {
          name  = "SOLVAN_DISCORD_LIAISON_AUDIENCE"
          value = local.discord_liaison_url
        }
      }
      dynamic "env" {
        for_each = each.key == "discord_liaison" ? [1] : []
        content {
          name  = "SOLVAN_DISCORD_LIAISON_SERVICE_ACCOUNT"
          value = google_service_account.workload["discord_liaison"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "email_liaison" ? [1] : []
        content {
          name  = "SOLVAN_EMAIL_LIAISON_AUDIENCE"
          value = local.email_liaison_url
        }
      }
      dynamic "env" {
        for_each = each.key == "email_liaison" ? [1] : []
        content {
          name  = "SOLVAN_EMAIL_LIAISON_SERVICE_ACCOUNT"
          value = google_service_account.workload["email_liaison"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "email_liaison" ? [1] : []
        content {
          name  = "SOLVAN_EMAIL_RELAY_URL"
          value = var.email_relay_url
        }
      }
      dynamic "env" {
        for_each = each.key == "email_liaison" ? [1] : []
        content {
          name  = "SOLVAN_EMAIL_RELAY_SERVICE_ACCOUNT"
          value = var.email_relay_service_account
        }
      }
      dynamic "env" {
        for_each = each.key == "mcp_facade" ? [1] : []
        content {
          name  = "SOLVAN_MCP_TOOL_LIST_HASH"
          value = "sha256:c6f253424a22c456cd56f1c87d13773e0e29ce3b82ca29b26ac80c8e61d4bfb0"
        }
      }
      dynamic "env" {
        for_each = each.key == "mcp_facade" ? [1] : []
        content {
          name  = "SOLVAN_CONSOLE_BASE_URL"
          value = local.console_url
        }
      }
      dynamic "env" {
        for_each = each.key == "trigger_scheduler" ? [1] : []
        content {
          name  = "SOLVAN_TRIGGER_SCHEDULER_PRINCIPALS"
          value = google_service_account.workload["scheduler"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "trigger_scheduler" ? [1] : []
        content {
          name  = "SOLVAN_TRIGGER_SOURCE_PRINCIPALS"
          value = google_service_account.workload["detector"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_COMMIT"
          value = var.release_commit
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_ID"
          value = var.deployment_id
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_APPROVAL_AUDIENCE"
          value = var.approval_token_audience
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_CONSOLE_BASE_URL"
          value = local.console_url
        }
      }
      # Sign-in configuration. The API refuses to start without these, which is
      # the point: they were absent here entirely, so the deployed API reported
      # "sign-in unavailable" and the console rendered itself as a signed-in
      # reader. The callback lands on the console, which proxies it to the API —
      # so the session cookie is set on the origin the console can read.
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_OAUTH_REDIRECT_URI"
          value = "${local.console_url}/api/auth/callback"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_ADMITTED_DOMAINS"
          value = join(",", var.admitted_workspace_domains)
        }
      }
      # The first administrator cannot be invited: authoring an invitation
      # requires one, and a new environment has none. This account is granted
      # ADMIN on first sign-in and only while no administrator exists at all, so
      # it starts an environment rather than opening one, and reconfiguring it
      # later grants nothing.
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name  = "SOLVAN_FOUNDING_ADMINISTRATOR"
          value = var.founding_administrator_email
        }
      }
      dynamic "env" {
        for_each = each.key == "api" ? [1] : []
        content {
          name = "SOLVAN_OAUTH_CLIENT_SECRET"
          value_source {
            secret_key_ref {
              secret  = var.oauth_client_secret_name
              version = "latest"
            }
          }
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.email_liaison_enabled ? [1] : []
        content {
          name  = "SOLVAN_EMAIL_RELAY_URL"
          value = var.email_relay_url
        }
      }
      dynamic "env" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name  = "SOLVAN_PLATFORM_AUTHORITY_MODE"
          value = "AGENT_IDENTITY_IAM_GATEWAY"
        }
      }
      dynamic "env" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name  = "SOLVAN_ACTUATOR_ID"
          value = "atr_00000000000000000000000001"
        }
      }
      dynamic "env" {
        for_each = each.key == "verifier" ? [1] : []
        content {
          name  = "SOLVAN_PLATFORM_AUTHORITY_MODE"
          value = "AGENT_IDENTITY_IAM_GATEWAY"
        }
      }
      # Each service verifies its caller's token in process against its own
      # exact audience, so a token minted for one service cannot authorize a
      # call to another. An unset audience refuses rather than skipping.
      dynamic "env" {
        for_each = contains(["actuator", "verifier", "evidence"], each.key) ? [1] : []
        content {
          name = lookup({
            actuator = "SOLVAN_ACTUATOR_AUDIENCE",
            verifier = "SOLVAN_VERIFIER_AUDIENCE",
            evidence = "SOLVAN_EVIDENCE_AUDIENCE",
          }, each.key)
          value = local.service_audiences[each.key]
        }
      }
      # Controls the actuator enforces itself, so they hold when the control
      # plane is unreachable or wrong. An unset value refuses to mutate.
      dynamic "env" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name  = "SOLVAN_ACTUATOR_KILL_SWITCH_FILE"
          value = "/var/run/solvan/kill-switch"
        }
      }
      dynamic "env" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name  = "SOLVAN_ACTUATOR_MAX_MUTATIONS_PER_HOUR"
          value = tostring(var.actuator_max_mutations_per_hour)
        }
      }
      dynamic "env" {
        for_each = each.key == "verifier" ? [1] : []
        content {
          name  = "SOLVAN_VERIFICATION_PRINCIPAL"
          value = var.verification_agent_principal == null ? "UNCONFIGURED" : var.verification_agent_principal
        }
      }
      dynamic "env" {
        for_each = each.key == "verifier" ? [1] : []
        content {
          name  = "SOLVAN_PAYMENTS_URL"
          value = local.payments_url
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_INCIDENT_SUPERVISOR_RESOURCE"
          value = var.agent_runtime_resources.incident_supervisor
        }
      }
      # The App identity both the provider and the API authenticate with. The
      # provider mints installation tokens for release operations; the API
      # lists installations and repositories so onboarding selects among what
      # GitHub actually reports. Neither receives a token — only the pinned
      # references it reads for itself.
      dynamic "env" {
        for_each = (
          contains(["github_provider", "api"], each.key) && var.github_release_enabled ? [1] : []
        )
        content {
          name  = "SOLVAN_GITHUB_APP_SLUG"
          value = var.github_app_slug
        }
      }
      dynamic "env" {
        for_each = (
          contains(["github_provider", "api"], each.key) && var.github_release_enabled ? [1] : []
        )
        content {
          name  = "SOLVAN_GITHUB_APP_ID_SECRET_REF"
          value = "projects/${var.project_id}/secrets/${var.github_app_id_secret_name}/versions/${var.github_app_id_secret_version}"
        }
      }
      dynamic "env" {
        for_each = (
          contains(["github_provider", "api"], each.key) && var.github_release_enabled ? [1] : []
        )
        content {
          name  = "SOLVAN_GITHUB_APP_PRIVATE_KEY_SECRET_REF"
          value = "projects/${var.project_id}/secrets/${var.github_app_private_key_secret_name}/versions/${var.github_app_private_key_secret_version}"
        }
      }
      # The API records this on a binding; the provider verifies signatures
      # with the secret itself, which it reads through its own reference.
      dynamic "env" {
        for_each = (
          contains(["github_provider", "api"], each.key) && var.github_release_enabled ? [1] : []
        )
        content {
          name  = "SOLVAN_GITHUB_WEBHOOK_SECRET_REF"
          value = "projects/${var.project_id}/secrets/${var.github_webhook_secret_name}/versions/latest"
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.github_release_enabled ? [1] : []
        content {
          name  = "SOLVAN_API_SERVICE_ACCOUNT"
          value = google_service_account.workload["api"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.github_release_enabled ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_CONTROLLER_SERVICE_ACCOUNT"
          value = google_service_account.workload["deployment_controller"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.github_release_enabled ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_SERVICE_ACCOUNT"
          value = google_service_account.workload["release_verifier"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "api" && var.github_release_enabled ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_SIGNING_KEY_VERSION"
          value = google_kms_crypto_key_version.release_verifier.id
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_ADAPTER_URL"
          value = local.workspace_adapter_url
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_ADAPTER_AUDIENCE"
          value = local.workspace_adapter_url
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_TOOL_BROKER_AUDIENCE"
          value = local.coordinator_url
        }
      }
      dynamic "env" {
        for_each = each.key == "workspace_adapter" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_ADAPTER_AUDIENCE"
          value = local.workspace_adapter_url
        }
      }
      dynamic "env" {
        for_each = each.key == "workspace_adapter" ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_SERVICE_ACCOUNT"
          value = google_service_account.workload["coordinator"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "workspace_adapter" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_SANDBOX_URL"
          value = google_cloud_run_v2_service.workspace_sandbox.uri
        }
      }
      dynamic "env" {
        for_each = each.key == "workspace_adapter" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_SANDBOX_AUDIENCE"
          value = local.workspace_sandbox_url
        }
      }
      dynamic "env" {
        for_each = each.key == "workspace_adapter" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_SANDBOX_IMAGE_HASH"
          value = regex("sha256:[0-9a-f]{64}$", var.images.workspace_sandbox)
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_PROVIDER_URL"
          value = var.github_release_enabled ? local.github_provider_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_CONTROLLER_ENABLED"
          value = tostring(var.github_release_enabled)
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_CONTROLLER_URL"
          value = var.github_release_enabled ? local.deployment_controller_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_CONTROLLER_AUDIENCE"
          value = var.github_release_enabled ? local.deployment_controller_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_CONTROLLER_SERVICE_ACCOUNT"
          value = google_service_account.workload["deployment_controller"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_ENABLED"
          value = tostring(var.github_release_enabled)
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_URL"
          value = var.github_release_enabled ? local.release_verifier_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_AUDIENCE"
          value = var.github_release_enabled ? local.release_verifier_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_SERVICE_ACCOUNT"
          value = google_service_account.workload["release_verifier"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" && var.solvant_relay_enabled ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_URL"
          value = local.coordinator_url
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" && var.solvant_relay_enabled ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_AUDIENCE"
          value = local.coordinator_url
        }
      }
      dynamic "env" {
        for_each = each.key == "relay_control" ? [1] : []
        content {
          name  = "SOLVAN_RELAY_CONTROL_AUDIENCE"
          value = local.relay_control_url
        }
      }
      dynamic "env" {
        for_each = each.key == "relay_control" ? [1] : []
        content {
          name  = "SOLVAN_RELAY_CONTROL_SIGNING_KEY_VERSION"
          value = google_kms_crypto_key_version.relay_job_signer.name
        }
      }
      dynamic "env" {
        for_each = each.key == "relay_control" ? [1] : []
        content {
          name  = "SOLVAN_RELAY_EVIDENCE_BUCKET"
          value = google_storage_bucket.relay_evidence.name
        }
      }
      dynamic "env" {
        for_each = each.key == "relay_control" ? [1] : []
        content {
          # This digest binds the encryption key named by the dedicated Relay
          # evidence bucket. Receipt verification retains the value, so it
          # cannot be silently changed after a customer upload.
          name  = "SOLVAN_RELAY_EVIDENCE_CMEK_DIGEST"
          value = "sha256:${sha256(google_kms_crypto_key.relay_evidence_cmek.id)}"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" && var.solvant_relay_enabled ? [1] : []
        content {
          name  = "SOLVAN_RELAY_JOB_SIGNING_KEY_ID"
          value = google_kms_crypto_key.relay_job_signer.id
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" && var.solvant_relay_enabled ? [1] : []
        content {
          name  = "SOLVAN_RELAY_EVIDENCE_BUCKET"
          value = google_storage_bucket.relay_evidence.name
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" && var.solvant_relay_enabled ? [1] : []
        content {
          name  = "SOLVAN_RELAY_JOB_SIGNING_KEY_VERSION"
          value = google_kms_crypto_key_version.relay_job_signer.name
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_PROVIDER_AUDIENCE"
          value = var.github_release_enabled ? local.github_provider_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_REPOSITORY_ID"
          value = var.github_repository_id
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_RELEASE_ENABLED"
          value = tostring(var.github_release_enabled)
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_SANDBOX_URL"
          value = google_cloud_run_v2_service.workspace_sandbox.uri
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_SANDBOX_AUDIENCE"
          value = local.workspace_sandbox_url
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_SANDBOX_REVISION"
          value = var.workspace_sandbox_revision
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_SANDBOX_IMAGE_HASH"
          value = regex("sha256:[0-9a-f]{64}$", var.images.workspace_sandbox)
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_PROVIDER_URL"
          value = var.github_release_enabled ? local.github_provider_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_PROVIDER_AUDIENCE"
          value = var.github_release_enabled ? local.github_provider_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_REPOSITORY_ID"
          value = var.github_repository_id
        }
      }
      dynamic "env" {
        for_each = each.key == "antigravity" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_ARTIFACT_DIGEST"
          value = split("@", var.images.antigravity_workspace)[1]
        }
      }
      dynamic "env" {
        for_each = each.key == "github_provider" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_REPOSITORY_ID"
          value = var.github_repository_id
        }
      }
      dynamic "env" {
        for_each = each.key == "deployment_controller" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_CONTROLLER_AUDIENCE"
          value = local.deployment_controller_url
        }
      }
      dynamic "env" {
        for_each = each.key == "release_verifier" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_AUDIENCE"
          value = local.release_verifier_url
        }
      }
      dynamic "env" {
        for_each = each.key == "release_verifier" ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_SERVICE_ACCOUNT"
          value = google_service_account.workload["coordinator"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "release_verifier" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_SERVICE_ACCOUNT"
          value = google_service_account.workload["release_verifier"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "release_verifier" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_VERIFIER_SIGNING_KEY_VERSION"
          value = google_kms_crypto_key_version.release_verifier.id
        }
      }
      dynamic "env" {
        for_each = each.key == "deployment_controller" ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_SERVICE_ACCOUNT"
          value = google_service_account.workload["coordinator"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "deployment_controller" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_CONTROLLER_SERVICE_ACCOUNT"
          value = google_service_account.workload["deployment_controller"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "github_provider" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_EVIDENCE_PRINCIPAL"
          value = google_service_account.workload["evidence"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "github_provider" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_PROVIDER_SERVICE_ACCOUNT"
          value = google_service_account.workload["github_provider"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "github_provider" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_INSTALLATION_ID"
          value = tostring(var.github_installation_id)
        }
      }
      dynamic "env" {
        for_each = each.key == "github_provider" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_COORDINATOR_AUDIENCE"
          value = var.github_coordinator_audience
        }
      }
      dynamic "env" {
        for_each = each.key == "github_provider" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_COORDINATOR_PRINCIPAL"
          value = var.github_coordinator_principal
        }
      }
      dynamic "env" {
        for_each = each.key == "github_identity_broker" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_IDENTITY_APPROVAL_AUDIENCE"
          value = local.api_url
        }
      }
      dynamic "env" {
        for_each = each.key == "github_identity_broker" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_IDENTITY_PKCE_KMS_KEY"
          value = google_kms_crypto_key.github_identity_pkce.id
        }
      }
      dynamic "env" {
        for_each = each.key == "github_identity_broker" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_IDENTITY_COOKIE_SECRET_REF"
          value = "projects/${var.project_id}/secrets/${var.github_identity_cookie_secret_name}/versions/latest"
        }
      }
      dynamic "env" {
        for_each = each.key == "github_identity_broker" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_IDENTITY_SUCCESS_URL"
          value = "${local.console_url}/integrations"
        }
      }
      dynamic "env" {
        for_each = each.key == "github_identity_broker" ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_IDENTITY_REFUSAL_URL"
          value = "${local.console_url}/integrations?github_link=refused"
        }
      }
      # The console API may ask the provider to observe a binding it just
      # created, so a newly connected repository does not stay PENDING until
      # somebody runs release tooling. Asking is not attesting: the provider
      # still reads GitHub itself with its own credentials.
      dynamic "env" {
        for_each = each.key == "github_provider" && var.github_release_enabled ? [1] : []
        content {
          name  = "SOLVAN_GITHUB_API_SERVICE_ACCOUNT"
          value = google_service_account.workload["api"].email
        }
      }
      dynamic "env" {
        for_each = (
          each.key == "github_provider"
          && var.github_webhook_secret_name != "UNCONFIGURED"
          ? [1] : []
        )
        content {
          name = "SOLVAN_GITHUB_WEBHOOK_SECRET"
          value_source {
            secret_key_ref {
              secret  = var.github_webhook_secret_name
              version = "latest"
            }
          }
        }
      }
      # Only when a token secret actually exists. This variable defaults to the
      # UNCONFIGURED sentinel, and an unguarded reference asks Cloud Run to
      # mount a secret literally named UNCONFIGURED, which fails the revision's
      # secret access check and takes the whole service down. A deployment that
      # mints installation tokens from the App private key needs no static
      # token, and the reader treats it as optional.
      dynamic "env" {
        for_each = (
          each.key == "github_provider"
          && var.github_installation_token_secret_name != "UNCONFIGURED"
          ? [1] : []
        )
        content {
          name = "SOLVAN_GITHUB_INSTALLATION_TOKEN"
          value_source {
            secret_key_ref {
              secret  = var.github_installation_token_secret_name
              version = "latest"
            }
          }
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_INCIDENT_SUPERVISOR_REVISION"
          value = var.agent_runtime_revisions.incident_supervisor
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_EVIDENCE_AGENT_RESOURCE"
          value = var.agent_runtime_resources.evidence_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_EVIDENCE_AGENT_REVISION"
          value = var.agent_runtime_revisions.evidence_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_INFRASTRUCTURE_AGENT_RESOURCE"
          value = var.agent_runtime_resources.infrastructure_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_INFRASTRUCTURE_AGENT_REVISION"
          value = var.agent_runtime_revisions.infrastructure_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_EXECUTION_AGENT_RESOURCE"
          value = var.agent_runtime_resources.execution_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_EXECUTION_AGENT_REVISION"
          value = var.agent_runtime_revisions.execution_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_VERIFICATION_AGENT_RESOURCE"
          value = var.agent_runtime_resources.verification_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_VERIFICATION_AGENT_REVISION"
          value = var.agent_runtime_revisions.verification_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_AGENT_RESOURCE"
          value = var.agent_runtime_resources.workspace_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_AGENT_REVISION"
          value = var.agent_runtime_revisions.workspace_agent
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_WORKSPACE_AGENT_PRINCIPAL"
          value = var.workspace_agent_principal == null ? "UNCONFIGURED" : var.workspace_agent_principal
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_AUDIENCE"
          value = local.coordinator_url
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_PUBSUB_PUSH_SERVICE_ACCOUNT"
          value = google_service_account.workload["pubsub"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_SCHEDULER_SERVICE_ACCOUNT"
          value = google_service_account.workload["scheduler"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_EVIDENCE_SERVICE_ACCOUNT"
          value = google_service_account.workload["evidence"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" && var.fault_drill_enabled ? [1] : []
        content {
          name  = "SOLVAN_SCENARIO_INJECTOR_SERVICE_ACCOUNT"
          value = google_service_account.workload["injector"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_AGENT_TOOL_BINDINGS_JSON"
          value = jsonencode(local.governed_agent_tool_bindings)
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name  = "SOLVAN_PLATFORM_AUTHORITY_MODE"
          value = "AGENT_IDENTITY_IAM_GATEWAY"
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name  = "SOLVAN_EVIDENCE_AGENT_PRINCIPAL"
          value = var.evidence_agent_principal == null ? "UNCONFIGURED" : var.evidence_agent_principal
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name  = "SOLVAN_INFRASTRUCTURE_AGENT_PRINCIPAL"
          value = var.infrastructure_agent_principal == null ? "UNCONFIGURED" : var.infrastructure_agent_principal
        }
      }
      dynamic "env" {
        for_each = each.key == "evidence" ? [1] : []
        content {
          name = "SOLVAN_LOG_SIGNATURES_JSON"
          value = jsonencode({
            "payments-errors:connection-exhaustion" = format(
              "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"%s-payments\" AND (textPayload:\"connection\" OR jsonPayload.error_class=\"PoolTimeout\")",
              local.prefix,
            )
          })
        }
      }
      dynamic "env" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name  = "SOLVAN_EXECUTION_PRINCIPAL"
          value = var.execution_agent_principal == null ? "UNCONFIGURED" : var.execution_agent_principal
        }
      }
      dynamic "env" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name  = "SOLVAN_PAYMENTS_ADMIN_URL"
          value = local.payments_url
        }
      }
      dynamic "env" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name  = "SOLVAN_ACTUATOR_IDENTITY"
          value = "serviceAccount:${google_service_account.workload["actuator"].email}"
        }
      }
      dynamic "env" {
        for_each = each.key == "payments" ? [1] : []
        content {
          name  = "SOLVAN_PAYMENTS_AUDIENCE"
          value = local.payments_url
        }
      }
      dynamic "env" {
        for_each = each.key == "payments" ? [1] : []
        content {
          name  = "SOLVAN_ACTUATOR_CALLER"
          value = google_service_account.workload["actuator"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "memory" ? [1] : []
        content {
          name  = "SOLVAN_MEMORY_BANK_RESOURCE"
          value = var.agent_runtime_resources.incident_supervisor
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_MEMORY_BANK_RESOURCE"
          value = var.agent_runtime_resources.incident_supervisor
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_COORDINATOR_SERVICE_ACCOUNT"
          value = google_service_account.workload["coordinator"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_ENABLED"
          value = tostring(var.antigravity_demo_enabled)
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_URL"
          value = var.antigravity_demo_enabled ? local.antigravity_workspace_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_AUDIENCE"
          value = var.antigravity_demo_enabled ? local.antigravity_workspace_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_PROVIDER_REVISION"
          value = var.antigravity_provider_revision
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_TOOL_SET_HASH"
          value = local.antigravity_tool_set_hash
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_NETWORK_POLICY_HASH"
          value = local.antigravity_network_policy_hash
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_SERVICE_IDENTITY"
          value = "serviceAccount:${google_service_account.workload["antigravity"].email}"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_ARTIFACT_DIGEST"
          value = split("@", var.images.antigravity_workspace)[1]
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_FIXTURE_ATTESTER_URL"
          value = var.antigravity_demo_enabled ? local.fixture_attester_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_FIXTURE_ATTESTER_AUDIENCE"
          value = var.antigravity_demo_enabled ? local.fixture_attester_url : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_FIXTURE_ATTESTER_PRINCIPAL"
          value = "serviceAccount:${google_service_account.workload["fixture_attester"].email}"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_FIXTURE_ATTESTER_KMS_KEY_VERSION"
          value = var.antigravity_demo_enabled ? google_kms_crypto_key_version.synthetic_attester[0].name : "DISABLED"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_SYNTHETIC_FIXTURE_ID"
          value = "payments-leak-v1"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_ANTIGRAVITY_TERMS_REVISION"
          value = "google-antigravity-alpha-terms-2026-08-08"
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_RELEASE_COMMIT"
          value = var.release_commit
        }
      }
      dynamic "env" {
        for_each = each.key == "coordinator" ? [1] : []
        content {
          name  = "SOLVAN_DEPLOYMENT_ID"
          value = var.deployment_id
        }
      }
      dynamic "env" {
        for_each = each.key == "memory" ? [1] : []
        content {
          name  = "SOLVAN_MEMORY_PROMOTER_IDENTITY"
          value = "serviceAccount:${google_service_account.workload["memory"].email}"
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      # The kill-switch directory. Only the actuator mounts it, read-only:
      # engaging is an approver's object write, and the actuator can never
      # delete its own switch. See google_storage_bucket.actuator_controls.
      dynamic "volume_mounts" {
        for_each = each.key == "actuator" ? [1] : []
        content {
          name       = "actuator-controls"
          mount_path = "/var/run/solvan"
        }
      }
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.control.connection_name]
      }
    }

    dynamic "volumes" {
      for_each = each.key == "actuator" ? [1] : []
      content {
        name = "actuator-controls"
        gcs {
          bucket    = google_storage_bucket.actuator_controls.name
          read_only = true
        }
      }
    }

    vpc_access {
      connector = google_vpc_access_connector.serverless.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    max_instance_request_concurrency = each.key == "memory" ? 1 : each.key == "payments" ? 10 : 40
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_secret_manager_secret_iam_member.api_oauth_client_secret_accessor,
    google_secret_manager_secret_iam_member.api_operator_step_up_pepper_accessor,
  ]
}

resource "google_cloud_run_v2_service" "antigravity_workspace" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project             = var.project_id
  name                = "${local.prefix}-antigravity"
  location            = var.region
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.workload["antigravity"].email
    timeout         = "300s"

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      image = var.images.antigravity_workspace

      ports {
        container_port = 8080
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = true
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "SOLVAN_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "SOLVAN_GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "SOLVAN_GCP_REGION"
        value = var.region
      }
      env {
        name  = "SOLVAN_ANTIGRAVITY_MODEL_LOCATION"
        value = "global"
      }
      env {
        name  = "SOLVAN_ANTIGRAVITY_MODEL"
        value = var.antigravity_model
      }
      env {
        name  = "SOLVAN_ANTIGRAVITY_PROVIDER_REVISION"
        value = var.antigravity_provider_revision
      }
      env {
        name  = "SOLVAN_COORDINATOR_SERVICE_ACCOUNT"
        value = google_service_account.workload["coordinator"].email
      }
      env {
        name  = "SOLVAN_ANTIGRAVITY_AUDIENCE"
        value = local.antigravity_workspace_url
      }
      env {
        name  = "SOLVAN_ANTIGRAVITY_NETWORK_POLICY_HASH"
        value = local.antigravity_network_policy_hash
      }

      env {
        name  = "SOLVAN_MODEL_ARMOR_TEMPLATE"
        value = google_model_armor_template.agent_boundary.name
      }
      env {
        name  = "SOLVAN_OTEL_EXPORTER"
        value = "google_cloud"
      }
    }

    vpc_access {
      connector = google_vpc_access_connector.antigravity[0].id
      egress    = "ALL_TRAFFIC"
    }

    max_instance_request_concurrency = 1
  }

  depends_on = [
    google_compute_firewall.antigravity_allow_restricted_googleapis,
    google_compute_firewall.antigravity_deny_other_egress,
    google_dns_record_set.restricted_googleapis_a,
    google_dns_record_set.restricted_googleapis_cname,
    google_project_service.required["run.googleapis.com"],
  ]
}

resource "google_cloud_run_v2_service" "workspace_sandbox" {
  project             = var.project_id
  name                = "${local.prefix}-workspace-sandbox"
  location            = var.region
  launch_stage        = "BETA"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.workload["workspace_sandbox"].email
    timeout         = "300s"

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }

    containers {
      image = var.images.workspace_sandbox

      # The exact-patch sandbox: this container supervises nested Cloud Run
      # Sandboxes rather than running untrusted work in its own process. The
      # release probe `workspace_sandbox_launcher_enabled` observes this field
      # on the live service; it read false on staging-20260823-04 because
      # nothing had ever set it -- the "nested-sandbox" claim lived only in
      # `outputs.tf` as a string. BETA launch stage above is what admits the
      # field; provider 7.45.0 is the first pinned version that carries it.
      sandbox_launcher = true

      ports {
        container_port = 8080
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = true
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "SOLVAN_GCP_REGION"
        value = var.region
      }
      env {
        name  = "SOLVAN_GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "SOLVAN_WORKSPACE_SANDBOX_AUDIENCE"
        value = local.workspace_sandbox_url
      }
      env {
        name  = "SOLVAN_COORDINATOR_SERVICE_ACCOUNT"
        value = google_service_account.workload["coordinator"].email
      }
      # The deterministic Workspace Adapter resolves the frozen catalog before
      # an exploratory request reaches this no-egress service. A model provider
      # has no direct sandbox invoker grant and therefore cannot choose argv.
      env {
        name  = "SOLVAN_WORKSPACE_ADAPTER_SERVICE_ACCOUNT"
        value = google_service_account.workload["workspace_adapter"].email
      }
      env {
        name  = "SOLVAN_WORKSPACE_SANDBOX_REVISION"
        value = var.workspace_sandbox_revision
      }
      env {
        name  = "SOLVAN_OTEL_EXPORTER"
        value = "google_cloud"
      }
    }

    max_instance_request_concurrency = 1
  }

  depends_on = [google_project_service.required["run.googleapis.com"]]
}

resource "google_cloud_run_v2_service_iam_member" "coordinator_workspace_sandbox" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.workspace_sandbox.name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

# The Adapter is the only exploratory caller. It resolves the catalog command
# from Cloud SQL and cannot ask the sandbox for an adjudication run; the
# sandbox derives `EXPLORATORY` from this exact identity.
resource "google_cloud_run_v2_service_iam_member" "workspace_adapter_workspace_sandbox" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.workspace_sandbox.name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["workspace_adapter"].member
}

resource "google_cloud_run_v2_service_iam_member" "coordinator_workspace_adapter" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["workspace_adapter"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

resource "google_cloud_run_v2_service_iam_member" "workspace_agent_coordinator" {
  count = var.workspace_agent_principal == null ? 0 : 1

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["coordinator"].name
  role     = "roles/run.invoker"
  member   = var.workspace_agent_principal
}

resource "google_cloud_run_v2_service_iam_member" "coordinator_antigravity" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.antigravity_workspace[0].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

resource "google_cloud_run_v2_service" "fixture_attester" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project             = var.project_id
  name                = "${local.prefix}-fixture-attester"
  location            = var.region
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.workload["fixture_attester"].email
    timeout         = "60s"

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      image = var.images.fixture_attester

      ports {
        container_port = 8080
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = true
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "SOLVAN_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "SOLVAN_GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "SOLVAN_GCP_REGION"
        value = var.region
      }
      env {
        name  = "SOLVAN_ORGANIZATION_ID"
        value = var.organization_id
      }
      env {
        name  = "SOLVAN_SCOPE_PROJECT_ID"
        value = var.scope_project_id
      }
      env {
        name  = "SOLVAN_ENVIRONMENT_ID"
        value = var.environment_id
      }
      env {
        name  = "SOLVAN_RELEASE_COMMIT"
        value = var.release_commit
      }
      env {
        name  = "SOLVAN_DEPLOYMENT_ID"
        value = var.deployment_id
      }
      env {
        name  = "SOLVAN_COORDINATOR_SERVICE_ACCOUNT"
        value = google_service_account.workload["coordinator"].email
      }
      env {
        name  = "SOLVAN_FIXTURE_ATTESTER_SERVICE_ACCOUNT"
        value = google_service_account.workload["fixture_attester"].email
      }
      env {
        name  = "SOLVAN_FIXTURE_ATTESTER_AUDIENCE"
        value = local.fixture_attester_url
      }
      env {
        name  = "SOLVAN_RUNTIME_BUCKET"
        value = google_storage_bucket.runtime.name
      }
      env {
        name  = "SOLVAN_EVIDENCE_BUCKET"
        value = google_storage_bucket.evidence.name
      }
      env {
        name  = "SOLVAN_SYNTHETIC_FIXTURE_PREFIX"
        value = "gs://${google_storage_bucket.runtime.name}/${var.organization_id}/${var.scope_project_id}/${var.environment_id}/fixtures/payments-leak-v1/"
      }
      env {
        name  = "SOLVAN_SYNTHETIC_FIXTURE_IDS"
        value = "payments-leak-v1"
      }
      env {
        name  = "SOLVAN_SYNTHETIC_ATTESTER_KMS_KEY_VERSION"
        value = google_kms_crypto_key_version.synthetic_attester[0].name
      }
      env {
        name  = "SOLVAN_OTEL_EXPORTER"
        value = "google_cloud"
      }
    }

    vpc_access {
      connector = google_vpc_access_connector.antigravity[0].id
      egress    = "ALL_TRAFFIC"
    }

    max_instance_request_concurrency = 4
  }

  depends_on = [
    google_kms_crypto_key_iam_member.fixture_attester_signer,
    google_storage_bucket_iam_member.runtime_fixture_attester_reader,
    google_storage_bucket_iam_member.evidence_fixture_attester_creator,
    google_compute_firewall.antigravity_allow_restricted_googleapis,
    google_compute_firewall.antigravity_deny_other_egress,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "coordinator_fixture_attester" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.fixture_attester[0].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

resource "google_cloud_run_v2_service_iam_member" "coordinator_self" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["coordinator"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["coordinator"].member
}

resource "google_cloud_run_v2_service_iam_member" "evidence_coordinator_relay_job_author" {
  count = var.solvant_relay_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["coordinator"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["evidence"].member
}

resource "google_cloud_run_v2_service_iam_member" "customer_relay_control_invoker" {
  for_each = var.solvant_relay_enabled ? var.solvant_relay_invoker_members : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["relay_control"].name
  role     = "roles/run.invoker"
  member   = each.value
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_detector" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["detector"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_coordinator" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["coordinator"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_publisher" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["publisher"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_memory" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["memory"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_liaison_maintenance" {
  count    = var.target_product_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["liaison_maintenance"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_trigger" {
  count    = var.target_product_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["trigger_scheduler"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_slack" {
  count    = var.target_product_enabled && var.slack_liaison_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["slack_liaison"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "slack_webhook" {
  count    = var.target_product_enabled && var.slack_liaison_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["slack_liaison"].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "mcp_facade_gateway" {
  count    = var.target_product_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["mcp_facade"].name
  role     = "roles/run.invoker"
  member   = local.agent_gateway_service_agent

  depends_on = [google_network_services_agent_gateway.ingress]
}

resource "google_cloud_run_v2_service_iam_member" "discord_webhook" {
  count    = var.target_product_enabled && var.discord_liaison_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["discord_liaison"].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_channels" {
  for_each = {
    for key in ["discord_liaison", "email_liaison"] : key => key
    if var.target_product_enabled && (
      (key == "discord_liaison" && var.discord_liaison_enabled) ||
      (key == "email_liaison" && var.email_liaison_enabled)
    )
  }
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service[each.key].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["scheduler"].member
}

resource "google_cloud_run_v2_service_iam_member" "email_relay" {
  count    = var.target_product_enabled && var.email_liaison_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["email_liaison"].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.email_relay_service_account}"
}

resource "google_cloud_run_v2_service_iam_member" "pubsub_coordinator" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["coordinator"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["pubsub"].member
}

resource "google_cloud_run_v2_service_iam_member" "execution_actuator" {
  count = var.execution_agent_principal == null ? 0 : 1

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["actuator"].name
  role     = "roles/run.invoker"
  member   = var.execution_agent_principal
}

resource "google_cloud_run_v2_service_iam_member" "read_agent_evidence" {
  for_each = {
    for key, value in {
      evidence       = var.evidence_agent_principal
      infrastructure = var.infrastructure_agent_principal
    } : key => value if value != null
  }

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["evidence"].name
  role     = "roles/run.invoker"
  member   = each.value
}

resource "google_cloud_run_v2_service_iam_member" "verification_agent_verifier" {
  count = var.verification_agent_principal == null ? 0 : 1

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["verifier"].name
  role     = "roles/run.invoker"
  member   = var.verification_agent_principal
}

resource "google_cloud_run_v2_service_iam_member" "verifier_payments" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["payments"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["verifier"].member
}

resource "google_cloud_run_v2_service_iam_member" "injector_payments" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["payments"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["injector"].member
}

resource "google_cloud_run_v2_service_iam_member" "oracle_payments" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["payments"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["oracle"].member
}

resource "google_cloud_run_v2_service_iam_member" "oracle_api" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["api"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["oracle"].member
}

resource "google_cloud_run_v2_service_iam_member" "injector_api" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["api"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["injector"].member
}

resource "google_cloud_run_v2_service_iam_member" "injector_detector" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["detector"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["injector"].member
}

resource "google_cloud_run_v2_service_iam_member" "injector_coordinator" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["coordinator"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["injector"].member
}

resource "google_cloud_run_v2_service_iam_member" "actuator_payments" {
  count = var.fault_drill_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["payments"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["actuator"].member
}

resource "google_cloud_run_v2_service_iam_member" "console_api" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service["api"].name
  role     = "roles/run.invoker"
  member   = google_service_account.workload["console"].member
}

resource "google_cloud_run_v2_service_iam_member" "console_public" {
  count = var.console_public ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.console.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

locals {
  release_job_environment = {
    SOLVAN_GCP_PROJECT        = var.project_id
    SOLVAN_GCP_REGION         = var.region
    SOLVAN_RELEASE_COMMIT     = var.release_commit
    SOLVAN_DEPLOYMENT_ID      = var.deployment_id
    SOLVAN_ORGANIZATION_ID    = var.organization_id
    SOLVAN_SCOPE_PROJECT_ID   = var.scope_project_id
    SOLVAN_ENVIRONMENT_ID     = var.environment_id
    SOLVAN_CLOUD_SQL_INSTANCE = google_sql_database_instance.control.connection_name
    SOLVAN_DATABASE_NAME      = google_sql_database.solvan.name
    SOLVAN_DATABASE_USER = var.database_admin_secret_name == "UNCONFIGURED" ? trimsuffix(
      google_service_account.workload["migration"].email,
      ".gserviceaccount.com",
    ) : "postgres"
    SOLVAN_ACTUATOR_PRINCIPAL_EMAIL       = google_service_account.workload["actuator"].email
    SOLVAN_ACTUATOR_EXPECTED_AUDIENCE     = google_cloud_run_v2_service.service["actuator"].uri
    SOLVAN_ACTUATOR_IMAGE_DIGEST          = split("@", var.images.actuator)[1]
    SOLVAN_GITHUB_RELEASE_ENABLED         = tostring(var.github_release_enabled)
    SOLVAN_GITHUB_OAUTH_CLIENT_ID         = var.github_oauth_client_id
    SOLVAN_GITHUB_OAUTH_CLIENT_SECRET_REF = "projects/${var.project_id}/secrets/${var.github_oauth_client_secret_name}/versions/${var.github_oauth_client_secret_version}"
    SOLVAN_GITHUB_OAUTH_CALLBACK_URI      = "${local.console_url}/github/oauth/callback"
  }
}

resource "google_cloud_run_v2_job" "database_migration" {
  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-database-migration"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["migration"].email
      max_retries     = 0
      timeout         = "900s"

      containers {
        image = var.images.release_admin
        args  = ["migrate"]

        dynamic "env" {
          for_each = local.release_job_environment
          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = var.database_admin_secret_name == "UNCONFIGURED" ? [] : [1]
          content {
            name = "SOLVAN_DATABASE_PASSWORD"
            value_source {
              secret_key_ref {
                secret  = var.database_admin_secret_name
                version = "1"
              }
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.control.connection_name]
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.serverless.id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_sql_user.workload_iam["migration"],
    google_secret_manager_secret_iam_member.database_migration_admin_secret_accessor,
  ]
}

resource "google_cloud_run_v2_job" "catalog_publication" {
  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-catalog-publication"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["migration"].email
      max_retries     = 0
      timeout         = "900s"

      containers {
        image = var.images.release_admin
        args  = ["publish-catalog"]

        dynamic "env" {
          for_each = merge(local.release_job_environment, {
            SOLVAN_AGENT_TOOL_BINDINGS_JSON        = jsonencode(local.governed_agent_tool_bindings)
            SOLVAN_INCIDENT_SUPERVISOR_RESOURCE    = var.agent_runtime_resources.incident_supervisor
            SOLVAN_EVIDENCE_AGENT_RESOURCE         = var.agent_runtime_resources.evidence_agent
            SOLVAN_INFRASTRUCTURE_AGENT_RESOURCE   = var.agent_runtime_resources.infrastructure_agent
            SOLVAN_EXECUTION_AGENT_RESOURCE        = var.agent_runtime_resources.execution_agent
            SOLVAN_VERIFICATION_AGENT_RESOURCE     = var.agent_runtime_resources.verification_agent
            SOLVAN_WORKSPACE_AGENT_RESOURCE        = var.agent_runtime_resources.workspace_agent
            SOLVAN_CATALOG_NETWORK_POLICY_HASH     = var.catalog_network_policy_hash
            SOLVAN_CATALOG_SUBJECT_HASH            = local.catalog_release_subject_hash
            SOLVAN_CLOUD_DEPLOY_PIPELINE_ID        = local.catalog_delivery_pipeline_id
            SOLVAN_CLOUD_DEPLOY_EVALUATION_TARGET  = local.catalog_evaluation_target_id
            SOLVAN_CLOUD_DEPLOY_PUBLICATION_TARGET = local.catalog_publication_target_id
          })
          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = var.database_admin_secret_name == "UNCONFIGURED" ? [] : [1]
          content {
            name = "SOLVAN_DATABASE_PASSWORD"
            value_source {
              secret_key_ref {
                secret  = var.database_admin_secret_name
                version = "1"
              }
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.control.connection_name]
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.serverless.id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  depends_on = [
    google_cloud_run_v2_job.database_migration,
    google_project_service.required["run.googleapis.com"],
    google_sql_user.workload_iam["migration"],
    google_secret_manager_secret_iam_member.database_migration_admin_secret_accessor,
  ]
}

resource "google_cloud_run_v2_job" "calibration_seed" {
  count = var.fault_drill_enabled && var.calibration_receipt_uri != null ? 1 : 0

  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-calibration-seed"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["migration"].email
      max_retries     = 0
      timeout         = "900s"

      containers {
        image = var.images.release_admin
        args  = ["seed"]

        dynamic "env" {
          for_each = merge(local.release_job_environment, {
            SOLVAN_CALIBRATION_RECEIPT_URI  = var.calibration_receipt_uri
            SOLVAN_CALIBRATION_RECEIPT_HASH = var.calibration_receipt_hash
            SOLVAN_RUNTIME_BUCKET           = google_storage_bucket.runtime.name
            SOLVAN_RELEASE_COMMIT           = var.release_commit
            SOLVAN_REPAIR_WORKSPACE_PROVIDER = (
              var.antigravity_demo_enabled ?
              "ANTIGRAVITY_SDK_CLOUD_RUN" : "GEMINI_ADK_AGENT_ENGINE"
            )
          })
          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = var.database_admin_secret_name == "UNCONFIGURED" ? [] : [1]
          content {
            name = "SOLVAN_DATABASE_PASSWORD"
            value_source {
              secret_key_ref {
                secret  = var.database_admin_secret_name
                version = "1"
              }
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.control.connection_name]
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.serverless.id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  lifecycle {
    precondition {
      condition = startswith(
        var.calibration_receipt_uri,
        "gs://${google_storage_bucket.evidence.name}/",
      )
      error_message = "The calibration receipt must be stored in this deployment's evidence bucket."
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_sql_user.workload_iam["migration"],
    google_secret_manager_secret_iam_member.database_migration_admin_secret_accessor,
    google_storage_bucket_iam_member.evidence_migration_reader,
    google_storage_bucket_iam_member.runtime_migration_creator,
    google_storage_bucket_iam_member.runtime_migration_reader,
  ]
}

resource "google_cloud_run_v2_job" "channel_provider_health" {
  for_each = var.target_product_enabled ? var.channel_qualification_receipts : {}

  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-${each.key}-qualification-ingest"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["migration"].email
      max_retries     = 0
      timeout         = "300s"

      containers {
        image = var.images.release_admin
        args  = ["record-channel-provider-health"]

        dynamic "env" {
          for_each = merge(local.release_job_environment, {
            SOLVAN_EVIDENCE_BUCKET                    = google_storage_bucket.evidence.name
            SOLVAN_CHANNEL_QUALIFICATION_KIND         = each.value.channel_kind
            SOLVAN_CHANNEL_QUALIFICATION_RECEIPT_URI  = each.value.uri
            SOLVAN_CHANNEL_QUALIFICATION_RECEIPT_HASH = each.value.hash
          })
          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = var.database_admin_secret_name == "UNCONFIGURED" ? [] : [1]
          content {
            name = "SOLVAN_DATABASE_PASSWORD"
            value_source {
              secret_key_ref {
                secret  = var.database_admin_secret_name
                version = "1"
              }
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.control.connection_name]
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.serverless.id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  lifecycle {
    precondition {
      condition = startswith(
        each.value.uri,
        "gs://${google_storage_bucket.evidence.name}/",
      )
      error_message = "Channel qualification receipts must be stored in this deployment's immutable evidence bucket."
    }
    precondition {
      condition = (
        (each.key == "slack" && var.slack_liaison_enabled) ||
        (each.key == "discord" && var.discord_liaison_enabled) ||
        (each.key == "email" && var.email_liaison_enabled)
      )
      error_message = "A channel qualification receipt cannot be ingested for a disabled provider."
    }
  }

  depends_on = [
    google_cloud_run_v2_job.database_migration,
    google_project_service.required["run.googleapis.com"],
    google_sql_user.workload_iam["migration"],
    google_secret_manager_secret_iam_member.database_migration_admin_secret_accessor,
    google_storage_bucket_iam_member.evidence_migration_reader,
  ]
}

resource "google_cloud_run_v2_job" "database_probe" {
  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-database-probe"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["probe"].email
      max_retries     = 0
      timeout         = "300s"

      containers {
        image = var.images.release_admin
        args  = ["probe-database"]

        dynamic "env" {
          for_each = merge(local.release_job_environment, {
            SOLVAN_DATABASE_USER = trimsuffix(
              google_service_account.workload["probe"].email,
              ".gserviceaccount.com",
            )
            SOLVAN_EVIDENCE_BUCKET   = google_storage_bucket.evidence.name
            SOLVAN_PROOF_OBJECT_NAME = "preflight/${var.deployment_id}/database-${var.release_commit}.json"
          })
          content {
            name  = env.key
            value = env.value
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.control.connection_name]
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.serverless.id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_sql_user.workload_iam["probe"],
    google_storage_bucket_iam_member.evidence_probe_creator,
  ]
}

resource "google_cloud_run_v2_job" "memory_probe" {
  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-memory-probe"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["memory"].email
      max_retries     = 0
      timeout         = "300s"

      containers {
        image = var.images.release_admin
        args  = ["probe-memory"]

        dynamic "env" {
          for_each = {
            SOLVAN_GCP_PROJECT = var.project_id
            # The deployed engine resource names the project by number; the
            # probe's boundary resolver needs both spellings of this project.
            SOLVAN_GCP_PROJECT_NUMBER   = data.google_project.current.number
            SOLVAN_GCP_REGION           = var.region
            SOLVAN_RELEASE_COMMIT       = var.release_commit
            SOLVAN_DEPLOYMENT_ID        = var.deployment_id
            SOLVAN_ORGANIZATION_ID      = var.organization_id
            SOLVAN_SCOPE_PROJECT_ID     = var.scope_project_id
            SOLVAN_ENVIRONMENT_ID       = var.environment_id
            SOLVAN_EVIDENCE_BUCKET      = google_storage_bucket.evidence.name
            SOLVAN_MEMORY_BANK_RESOURCE = var.agent_runtime_resources.incident_supervisor
            SOLVAN_PROOF_OBJECT_NAME    = "preflight/${var.deployment_id}/memory-${var.release_commit}.json"
          }
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_project_iam_member.memory_promoter,
    google_storage_bucket_iam_member.evidence_memory_probe_creator,
  ]
}

resource "google_cloud_run_v2_job" "model_armor_probe" {
  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-model-armor-probe"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["probe"].email
      max_retries     = 0
      timeout         = "300s"

      containers {
        image = var.images.release_admin
        args  = ["probe-model-armor"]

        dynamic "env" {
          for_each = {
            SOLVAN_GCP_PROJECT          = var.project_id
            SOLVAN_GCP_REGION           = var.region
            SOLVAN_RELEASE_COMMIT       = var.release_commit
            SOLVAN_DEPLOYMENT_ID        = var.deployment_id
            SOLVAN_EVIDENCE_BUCKET      = google_storage_bucket.evidence.name
            SOLVAN_MODEL_ARMOR_TEMPLATE = google_model_armor_template.agent_boundary.name
            SOLVAN_PROOF_OBJECT_NAME    = "preflight/${var.deployment_id}/model-armor-${var.release_commit}.json"
          }
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_project_iam_member.model_armor_probe,
    google_storage_bucket_iam_member.evidence_probe_creator,
  ]
}

resource "google_cloud_run_v2_job" "scenario_injector" {
  count = var.fault_drill_enabled && var.calibration_receipt_uri != null ? 1 : 0

  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-scenario-injector"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["injector"].email
      max_retries     = 0
      timeout         = "600s"

      containers {
        image = var.images.release_admin
        args  = ["scenario-inject-s1"]

        dynamic "env" {
          for_each = merge(local.release_job_environment, {
            SOLVAN_DATABASE_USER = trimsuffix(
              google_service_account.workload["injector"].email,
              ".gserviceaccount.com",
            )
            SOLVAN_CALIBRATION_RECEIPT_URI  = var.calibration_receipt_uri
            SOLVAN_CALIBRATION_RECEIPT_HASH = var.calibration_receipt_hash
            SOLVAN_EVIDENCE_BUCKET          = google_storage_bucket.evidence.name
            SOLVAN_PAYMENTS_URL             = local.payments_url
            SOLVAN_EVIDENCE_BROKER_URL      = google_cloud_run_v2_service.service["evidence"].uri
            SOLVAN_MODEL_ARMOR_TEMPLATE     = google_model_armor_template.agent_boundary.name
            SOLVAN_INJECTOR_IDENTITY        = google_service_account.workload["injector"].email
            SOLVAN_AGENT_TOOL_BINDINGS_JSON = jsonencode(local.governed_agent_tool_bindings)
            SOLVAN_RELEASE_COMMIT           = "UNCONFIGURED"
            SOLVAN_DEPLOYMENT_ID            = "UNCONFIGURED"
            SOLVAN_SCENARIO_OBJECT_NAME     = "scenarios/UNCONFIGURED/S1/fault.json"
          })
          content {
            name  = env.key
            value = env.value
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.control.connection_name]
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.serverless.id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  lifecycle {
    precondition {
      condition = startswith(
        var.calibration_receipt_uri,
        "gs://${google_storage_bucket.evidence.name}/",
      )
      error_message = "The scenario injector requires this deployment's calibration receipt."
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_sql_user.workload_iam["injector"],
    google_project_iam_member.scenario_injector[0],
    google_project_iam_member.scenario_fixture_reader[0],
    google_project_iam_member.model_armor_injector[0],
    google_storage_bucket_iam_member.scenario_injector_evidence[0],
    google_storage_bucket_iam_member.evidence_injector_calibration_reader,
    google_cloud_run_v2_service_iam_member.injector_payments[0],
  ]
}

resource "google_cloud_run_v2_job" "scenario_oracle" {
  count = var.fault_drill_enabled && var.calibration_receipt_uri != null ? 1 : 0

  project             = var.project_id
  location            = var.region
  name                = "${local.prefix}-scenario-oracle"
  deletion_protection = var.deletion_protection

  binary_authorization {
    use_default = true
  }

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account = google_service_account.workload["oracle"].email
      max_retries     = 0
      timeout         = "600s"

      containers {
        image = var.images.release_admin
        args  = ["scenario-oracle-s1"]

        dynamic "env" {
          for_each = merge(local.release_job_environment, {
            SOLVAN_DATABASE_USER = trimsuffix(
              google_service_account.workload["oracle"].email,
              ".gserviceaccount.com",
            )
            SOLVAN_CALIBRATION_RECEIPT_URI  = var.calibration_receipt_uri
            SOLVAN_CALIBRATION_RECEIPT_HASH = var.calibration_receipt_hash
            SOLVAN_EVIDENCE_BUCKET          = google_storage_bucket.evidence.name
            SOLVAN_PAYMENTS_URL             = local.payments_url
            SOLVAN_ORACLE_IDENTITY          = google_service_account.workload["oracle"].email
            SOLVAN_RELEASE_COMMIT           = "UNCONFIGURED"
            SOLVAN_DEPLOYMENT_ID            = "UNCONFIGURED"
            SOLVAN_SCENARIO_OBJECT_NAME     = "scenarios/UNCONFIGURED/S1/oracle.json"
          })
          content {
            name  = env.key
            value = env.value
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.control.connection_name]
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.serverless.id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_sql_user.workload_iam["oracle"],
    google_project_iam_member.scenario_oracle[0],
    google_storage_bucket_iam_member.scenario_oracle_evidence[0],
    google_storage_bucket_iam_member.evidence_oracle_reader,
    google_cloud_run_v2_service_iam_member.oracle_payments[0],
  ]
}

resource "google_cloud_run_v2_job_iam_member" "approver_database_migration" {
  for_each = var.approver_principals

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.database_migration.name
  role     = "roles/run.invoker"
  member   = each.value
}

resource "google_cloud_run_v2_job_iam_member" "catalog_deploy_publication" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.catalog_publication.name
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = google_service_account.workload["catalog_deploy"].member
}

resource "google_cloud_run_v2_job_iam_member" "approver_calibration_seed" {
  for_each = var.fault_drill_enabled && var.calibration_receipt_uri != null ? var.approver_principals : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.calibration_seed[0].name
  role     = "roles/run.invoker"
  member   = each.value
}

resource "google_cloud_run_v2_job_iam_member" "approver_database_probe" {
  for_each = var.approver_principals

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.database_probe.name
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = each.value
}

resource "google_cloud_run_v2_job_iam_member" "approver_memory_probe" {
  for_each = var.approver_principals

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.memory_probe.name
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = each.value
}

resource "google_cloud_run_v2_job_iam_member" "approver_model_armor_probe" {
  for_each = var.approver_principals

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.model_armor_probe.name
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = each.value
}

resource "google_cloud_run_v2_job_iam_member" "approver_scenario_injector" {
  for_each = var.fault_drill_enabled && var.calibration_receipt_uri != null ? var.approver_principals : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.scenario_injector[0].name
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = each.value
}

resource "google_cloud_run_v2_job_iam_member" "approver_scenario_oracle" {
  for_each = var.fault_drill_enabled && var.calibration_receipt_uri != null ? var.approver_principals : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.scenario_oracle[0].name
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = each.value
}

resource "google_cloud_scheduler_job" "detector_burst" {
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-detector-burst"
  description      = "Starts one idempotent 0/25/50-second detector burst each minute."
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "180s"
  paused           = var.scheduler_paused

  retry_config {
    retry_count = 0
  }

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.service["detector"].uri}/internal/detection/burst"
    body        = base64encode(jsonencode({ schema_version = 1, offsets_seconds = [0, 25, 50] }))
    headers = {
      "Content-Type" = "application/json"
    }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = google_cloud_run_v2_service.service["detector"].uri
    }
  }

  depends_on = [google_project_service.required["cloudscheduler.googleapis.com"]]
}

resource "google_cloud_scheduler_job" "case_wakeups" {
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-case-wakeups"
  description      = "Wakes due Reliability Cases; Cloud SQL remains authoritative."
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"
  paused           = var.scheduler_paused

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.service["coordinator"].uri}/internal/wakeups/tick"
    body        = base64encode(jsonencode({ schema_version = 1 }))
    headers = {
      "Content-Type" = "application/json"
    }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = google_cloud_run_v2_service.service["coordinator"].uri
    }
  }

  depends_on = [google_project_service.required["cloudscheduler.googleapis.com"]]
}

resource "google_cloud_scheduler_job" "outbox_publisher" {
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-outbox-publisher"
  description      = "Claims and publishes durable outbox events with stable IDs."
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"
  paused           = var.scheduler_paused

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.service["publisher"].uri}/internal/outbox/tick"
    body        = base64encode(jsonencode({ schema_version = 1 }))
    headers = {
      "Content-Type" = "application/json"
    }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = google_cloud_run_v2_service.service["publisher"].uri
    }
  }

  depends_on = [google_project_service.required["cloudscheduler.googleapis.com"]]
}

resource "google_cloud_scheduler_job" "memory_promotions" {
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-memory-promotions"
  description      = "Reconciles approved governed facts into exact-scope Memory Bank records."
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "300s"
  paused           = var.scheduler_paused

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.service["memory"].uri}/internal/memory/promotions/tick"
    body        = base64encode(jsonencode({ schema_version = 1, limit = 20 }))
    headers = {
      "Content-Type" = "application/json"
    }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = google_cloud_run_v2_service.service["memory"].uri
    }
  }

  depends_on = [google_project_service.required["cloudscheduler.googleapis.com"]]
}

resource "google_cloud_scheduler_job" "liaison_maintenance" {
  count            = var.target_product_enabled ? 1 : 0
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-liaison-maintenance"
  description      = "Purges, reaps, and compacts the non-authoritative conversation ledger."
  schedule         = "*/5 * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "300s"
  paused           = var.scheduler_paused

  retry_config { retry_count = 1 }

  http_target {
    http_method = "POST"
    uri         = "${local.liaison_maintenance_url}/internal/v1/tick"
    body        = base64encode(jsonencode({ maximum_compactions = 10 }))
    headers     = { "Content-Type" = "application/json" }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = local.liaison_maintenance_url
    }
  }
}

resource "google_cloud_scheduler_job" "trigger_tick" {
  count            = var.target_product_enabled ? 1 : 0
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-trigger-tick"
  description      = "Claims due policy-bound trigger firings; Cloud SQL remains authoritative."
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"
  paused           = var.scheduler_paused

  retry_config { retry_count = 1 }

  http_target {
    http_method = "POST"
    uri         = "${local.trigger_scheduler_url}/internal/v1/tick"
    body        = base64encode(jsonencode({ schema_version = 1, maximum_items = 20 }))
    headers     = { "Content-Type" = "application/json" }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = local.trigger_scheduler_url
    }
  }
}

resource "google_cloud_scheduler_job" "slack_liaison" {
  count            = var.target_product_enabled && var.slack_liaison_enabled ? 1 : 0
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-slack-liaison"
  description      = "Processes durable Slack answers, subscriptions, and deliveries."
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "300s"
  paused           = var.scheduler_paused

  retry_config { retry_count = 1 }

  http_target {
    http_method = "POST"
    uri         = "${local.slack_liaison_url}/internal/tick"
    body        = base64encode(jsonencode({ maximum_jobs = 10 }))
    headers     = { "Content-Type" = "application/json" }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = local.slack_liaison_url
    }
  }
}

resource "google_cloud_scheduler_job" "channel_liaison" {
  for_each = {
    for key, url in {
      discord_liaison = local.discord_liaison_url
      email_liaison   = local.email_liaison_url
    } : key => url
    if var.target_product_enabled && (
      (key == "discord_liaison" && var.discord_liaison_enabled) ||
      (key == "email_liaison" && var.email_liaison_enabled)
    )
  }
  project          = var.project_id
  region           = var.region
  name             = "${local.prefix}-${replace(each.key, "_", "-")}"
  description      = "Processes durable ${each.key} answers and deliveries."
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "300s"
  paused           = var.scheduler_paused

  retry_config { retry_count = 1 }

  http_target {
    http_method = "POST"
    uri         = "${each.value}/internal/tick"
    body        = base64encode(jsonencode({ maximum_jobs = 10 }))
    headers     = { "Content-Type" = "application/json" }
    oidc_token {
      service_account_email = google_service_account.workload["scheduler"].email
      audience              = each.value
    }
  }
}
