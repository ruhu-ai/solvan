data "google_project" "current" {
  project_id = var.project_id
}

resource "google_model_armor_template" "agent_boundary" {
  project     = var.project_id
  location    = var.region
  template_id = "${local.prefix}-agent-boundary"
  labels      = local.labels

  filter_config {
    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = "MEDIUM_AND_ABOVE"
    }
    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }
    sdp_settings {
      basic_config {
        filter_enforcement = "ENABLED"
      }
    }
    rai_settings {
      dynamic "rai_filters" {
        for_each = toset(["DANGEROUS", "HARASSMENT", "HATE_SPEECH", "SEXUALLY_EXPLICIT"])
        content {
          filter_type      = rai_filters.value
          confidence_level = "MEDIUM_AND_ABOVE"
        }
      }
    }
  }

  template_metadata {
    enforcement_type                         = "INSPECT_AND_BLOCK"
    ignore_partial_invocation_failures       = false
    log_sanitize_operations                  = false
    log_template_operations                  = true
    custom_prompt_safety_error_code          = 400
    custom_prompt_safety_error_message       = "Request blocked by enterprise content policy."
    custom_llm_response_safety_error_code    = 400
    custom_llm_response_safety_error_message = "Response blocked by enterprise content policy."
    multi_language_detection {
      enable_multi_language_detection = true
    }
  }

  deletion_policy = "PREVENT"

  depends_on = [google_project_service.required["modelarmor.googleapis.com"]]
}

resource "google_network_services_agent_gateway" "egress" {
  project     = var.project_id
  name        = "${local.prefix}-egress"
  location    = var.region
  description = "Default-deny egress gateway for Solvan Runtime agents."
  labels      = local.labels

  google_managed {
    governed_access_path = "AGENT_TO_ANYWHERE"
  }

  registries = [
    "//agentregistry.googleapis.com/projects/${var.project_id}/locations/${var.region}",
  ]

  deletion_policy = "PREVENT"

  depends_on = [
    google_project_service.required["agentregistry.googleapis.com"],
    google_project_service.required["networkservices.googleapis.com"],
  ]
}

resource "google_network_services_agent_gateway" "ingress" {
  project     = var.project_id
  name        = "${local.prefix}-ingress"
  location    = var.region
  description = "Fail-closed client-to-Agent Runtime gateway for Solvan agents."
  labels      = local.labels

  google_managed {
    governed_access_path = "CLIENT_TO_AGENT"
  }

  registries = [
    "//agentregistry.googleapis.com/projects/${var.project_id}/locations/${var.region}",
  ]

  deletion_policy = "PREVENT"

  depends_on = [
    google_project_service.required["agentregistry.googleapis.com"],
    google_project_service.required["networkservices.googleapis.com"],
  ]
}

resource "google_network_services_authz_extension" "model_armor" {
  count       = var.gateway_extensions_enabled ? 1 : 0
  project     = var.project_id
  name        = "${local.prefix}-model-armor"
  location    = var.region
  description = "Fail-closed Model Armor request and response inspection."
  service     = "modelarmor.${var.region}.rep.googleapis.com"
  timeout     = "1s"
  fail_open   = false
  wire_format = "EXT_PROC_GRPC"
  labels      = local.labels
  metadata = {
    model_armor_settings = jsonencode([
      {
        request_template_id  = google_model_armor_template.agent_boundary.name
        response_template_id = google_model_armor_template.agent_boundary.name
      }
    ])
  }

  deletion_policy = "PREVENT"

  # The authorization extension is served by Network Services; there is no
  # separate "serviceextensions" API in Google's catalog to depend on.
  depends_on = [google_project_service.required["networkservices.googleapis.com"]]
}

resource "google_network_security_authz_policy" "model_armor" {
  count          = var.gateway_extensions_enabled && var.gateway_model_armor_enabled ? 1 : 0
  project        = var.project_id
  name           = "${local.prefix}-model-armor"
  location       = var.region
  description    = "Apply inline Model Armor to both Solvan gateway directions."
  policy_profile = "CONTENT_AUTHZ"
  action         = "CUSTOM"
  labels         = local.labels

  target {
    resources = [
      google_network_services_agent_gateway.egress.id,
      google_network_services_agent_gateway.ingress.id,
    ]
  }

  custom_provider {
    authz_extension {
      resources = [google_network_services_authz_extension.model_armor[0].id]
    }
  }

  deletion_policy = "PREVENT"

  depends_on = [google_project_service.required["networksecurity.googleapis.com"]]
}

resource "google_network_services_authz_extension" "iap" {
  count       = var.gateway_extensions_enabled ? 1 : 0
  project     = var.project_id
  name        = "${local.prefix}-iap"
  location    = var.region
  description = "Fail-closed IAP request authorization for Agent Gateway."
  service     = "iap.googleapis.com"
  timeout     = "1s"
  fail_open   = false
  wire_format = "EXT_AUTHZ_GRPC"
  labels      = local.labels
  metadata = {
    iapPolicyVersion = "V1"
  }

  deletion_policy = "PREVENT"

  # The authorization extension is served by Network Services; there is no
  # separate "serviceextensions" API in Google's catalog to depend on.
  depends_on = [google_project_service.required["networkservices.googleapis.com"]]
}

resource "google_network_security_authz_policy" "iap" {
  count          = var.gateway_extensions_enabled ? 1 : 0
  project        = var.project_id
  name           = "${local.prefix}-iap"
  location       = var.region
  description    = "Apply IAP request authorization to Solvan Agent Gateways."
  policy_profile = "REQUEST_AUTHZ"
  action         = "CUSTOM"
  labels         = local.labels

  target {
    resources = [
      google_network_services_agent_gateway.egress.id,
      google_network_services_agent_gateway.ingress.id,
    ]
  }

  custom_provider {
    authz_extension {
      resources = [google_network_services_authz_extension.iap[0].id]
    }
  }

  deletion_policy = "PREVENT"

  # Both policies target the same Agent Gateways, and a gateway serializes
  # tenant-configuration updates: created in parallel, one fails with an ongoing
  # operation on the gateway and the other can leave a half-written tenant
  # config that then reports itself as already existing. Terraform has no reason
  # to order two resources that never reference each other, so the order is
  # stated here.
  depends_on = [
    google_project_service.required["networksecurity.googleapis.com"],
    google_network_security_authz_policy.model_armor,
  ]
}

resource "google_agent_registry_service" "actuator_endpoint" {
  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-actuator"
  display_name = "Solvan private action actuator"
  description  = "Typed action-ID-only endpoint; not a model-facing mutation payload API."

  interfaces {
    url              = "${google_cloud_run_v2_service.service["actuator"].uri}/internal/v1/actions"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "payments_endpoint" {
  count = var.fault_drill_enabled ? 1 : 0

  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-payments-admin"
  display_name = "Payments bounded administration endpoint"
  description  = "Private pool-generation recycle and reconciliation surface."

  interfaces {
    url              = "${google_cloud_run_v2_service.service["payments"].uri}/v1/admin/connection-pool"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "evidence_broker_endpoint" {
  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-evidence-broker"
  display_name = "Solvan bounded evidence broker"
  description  = "Private typed-query broker; agents cannot submit provider query syntax."

  interfaces {
    url              = "${google_cloud_run_v2_service.service["evidence"].uri}/internal/v1/evidence"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "verifier_endpoint" {
  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-verifier"
  display_name = "Solvan independent verifier"
  description  = "Private profile-bound verification endpoint; callers cannot supply thresholds."

  interfaces {
    url              = "${google_cloud_run_v2_service.service["verifier"].uri}/internal/v1/verifications:run"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "mcp_facade_endpoint" {
  count        = var.target_product_enabled ? 1 : 0
  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-mcp-facade"
  display_name = "Solvan read-only MCP facade"
  description  = "Exactly ask, catch_up, and resolve_ref; no steer or mutation tool."

  interfaces {
    url              = "${local.mcp_facade_url}/mcp"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec { type = "NO_SPEC" }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "liaison_endpoint" {
  count        = var.target_product_enabled ? 1 : 0
  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-liaison"
  display_name = "Solvan Liaison Agent"
  description  = "Delegated projection reads and conversation-ledger writes only; no direct telemetry, dispatch, approval, or mutation authority."

  interfaces {
    url              = "${google_cloud_run_v2_service.service["api"].uri}/api/v1/threads"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec { type = "NO_SPEC" }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "monitoring_endpoint" {
  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-cloud-monitoring"
  display_name = "Scoped Cloud Monitoring API"
  description  = "Registered destination; application code still enforces query/resource bounds."

  interfaces {
    url              = "https://monitoring.googleapis.com/v3/projects/${var.project_id}/timeSeries"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "antigravity_workspace_endpoint" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-antigravity-workspace"
  display_name = "Solvan Antigravity incident workspace provider"
  description  = "Private public-synthetic experiment provider; no production authority."

  interfaces {
    url              = "${google_cloud_run_v2_service.antigravity_workspace[0].uri}/internal/v1/workspace-tasks:execute"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

resource "google_agent_registry_service" "runtime_dependencies" {
  for_each = {
    aiplatform = {
      display_name = "Regional Agent Platform API"
      description  = "Gemini model, Sessions, Runtime, and Memory Bank API destination."
      url          = "https://${var.region}-aiplatform.googleapis.com"
      service_id   = "aiplatform"
    }
    aiplatform_mtls = {
      display_name = "Regional mTLS Agent Platform API"
      description  = "Documented mTLS hostname used by the Agent Platform SDK."
      url          = "https://${var.region}-aiplatform.mtls.googleapis.com"
      service_id   = "aiplatform-mtls"
    }
    aiplatform_rep = {
      display_name = "Regional REP Agent Platform API"
      description  = "Documented regional REP hostname used by Agent Runtime."
      url          = "https://aiplatform.${var.region}.rep.googleapis.com"
      service_id   = "aiplatform-rep"
    }
    aiplatform_eu_rep = {
      display_name = "EU multi-region Gemini inference API"
      description  = "Jurisdictional REP hostname for the qualified Gemini 3.6 Flash route."
      url          = "https://aiplatform.eu.rep.googleapis.com"
      service_id   = "aiplatform-eu-rep"
    }
    resource_manager = {
      display_name = "Cloud Resource Manager API"
      description  = "Project-number resolution required during Runtime startup."
      url          = "https://cloudresourcemanager.googleapis.com"
      service_id   = "resource-manager"
    }
    resource_manager_mtls = {
      display_name = "Cloud Resource Manager mTLS API"
      description  = "Documented mTLS project-resolution hostname used during Runtime startup."
      url          = "https://cloudresourcemanager.mtls.googleapis.com"
      service_id   = "resource-manager-mtls"
    }
    logging = {
      display_name = "Cloud Logging API"
      description  = "OTel log export destination for governed Runtime agents."
      url          = "https://logging.googleapis.com"
      service_id   = "logging"
    }
    telemetry = {
      display_name = "Cloud Telemetry API"
      description  = "OTel trace and metric export destination for governed Runtime agents."
      url          = "https://telemetry.googleapis.com"
      service_id   = "telemetry"
    }
    telemetry_mtls = {
      display_name = "Cloud Telemetry mTLS API"
      description  = "Documented mTLS OTel export destination for governed Runtime agents."
      url          = "https://telemetry.mtls.googleapis.com"
      service_id   = "telemetry-mtls"
    }
  }

  project      = var.project_id
  location     = var.region
  service_id   = "${local.prefix}-${each.value.service_id}"
  display_name = each.value.display_name
  description  = each.value.description

  interfaces {
    url              = each.value.url
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.required["agentregistry.googleapis.com"]]
}

locals {
  agent_gateway_service_agent = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-dep.iam.gserviceaccount.com"
  runtime_service_agent       = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"
  model_armor_callers = var.agent_runtime_service_agent_bindings_enabled ? toset([
    local.agent_gateway_service_agent,
    local.runtime_service_agent,
  ]) : toset([local.agent_gateway_service_agent])
}

resource "google_project_iam_member" "model_armor_callout" {
  for_each = local.model_armor_callers

  project = var.project_id
  role    = "roles/modelarmor.calloutUser"
  member  = each.value

  depends_on = [
    google_network_services_agent_gateway.egress,
    google_network_services_agent_gateway.ingress,
  ]
}

resource "google_project_iam_member" "model_armor_user" {
  for_each = local.model_armor_callers

  project = var.project_id
  role    = "roles/modelarmor.user"
  member  = each.value

  depends_on = [google_model_armor_template.agent_boundary]
}

resource "google_project_iam_member" "gateway_service_usage" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = local.agent_gateway_service_agent

  depends_on = [google_network_services_agent_gateway.egress]
}
