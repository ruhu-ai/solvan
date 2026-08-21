locals {
  prefix = "solvan-${var.environment}"
  api_url = format(
    "https://solvan-%s-api-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  console_url = format(
    "https://solvan-%s-console-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  # Each mutation-path service verifies its caller's token against its own exact
  # audience. Derived from the naming pattern rather than the service resource
  # so a service does not depend on itself.
  service_audiences = {
    actuator = format(
      "https://solvan-%s-actuator-%s.%s.run.app",
      var.environment,
      data.google_project.current.number,
      var.region,
    )
    verifier = format(
      "https://solvan-%s-verifier-%s.%s.run.app",
      var.environment,
      data.google_project.current.number,
      var.region,
    )
    evidence = format(
      "https://solvan-%s-evidence-%s.%s.run.app",
      var.environment,
      data.google_project.current.number,
      var.region,
    )
  }
  payments_url = format(
    "https://solvan-%s-payments-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  antigravity_workspace_url = format(
    "https://solvan-%s-antigravity-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  workspace_sandbox_url = format(
    "https://solvan-%s-workspace-sandbox-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  workspace_adapter_url = format(
    "https://solvan-%s-workspace-adapter-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  github_identity_broker_url = format(
    "https://solvan-%s-github-identity-broker-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  deployment_controller_url = format(
    "https://solvan-%s-deployment-controller-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  release_verifier_url = format(
    "https://solvan-%s-release-verifier-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  coordinator_url = format(
    "https://solvan-%s-coordinator-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  direct_gcp_reader_url = format(
    "https://solvan-%s-direct-gcp-reader-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  pilot_qualification_verifier_url = format(
    "https://solvan-%s-pilot-qualification-verifier-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  fixture_attester_url = format(
    "https://solvan-%s-fixture-attester-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  slack_liaison_url = format(
    "https://solvan-%s-slack-liaison-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  liaison_maintenance_url = format(
    "https://solvan-%s-liaison-maintenance-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  trigger_scheduler_url = format(
    "https://solvan-%s-trigger-scheduler-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  mcp_facade_url = format(
    "https://solvan-%s-mcp-facade-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  discord_liaison_url = format(
    "https://solvan-%s-discord-liaison-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  email_liaison_url = format(
    "https://solvan-%s-email-liaison-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  github_provider_url = format(
    "https://solvan-%s-github-provider-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  relay_control_url = format(
    "https://solvan-%s-relay-control-%s.%s.run.app",
    var.environment,
    data.google_project.current.number,
    var.region,
  )
  antigravity_tool_policy = {
    allowed_tools = [
      "read_workspace_artifact",
      "write_candidate_artifact",
    ]
    policy_version = "antigravity-workspace-tools-v1"
  }
  antigravity_tool_set_hash = "sha256:${sha256(jsonencode(local.antigravity_tool_policy))}"
  antigravity_network_policy = {
    allowed_destination_cidrs = ["199.36.153.4/30"]
    allowed_ports             = ["tcp:443"]
    dns_mode                  = "restricted.googleapis.com"
    egress                    = "ALL_TRAFFIC"
    policy_version            = "antigravity-egress-v1"
  }
  antigravity_network_policy_hash = "sha256:${sha256(jsonencode(local.antigravity_network_policy))}"
  labels = {
    application = "solvan"
    environment = var.environment
    managed_by  = "terraform"
    data_class  = "synthetic"
  }

  services = toset(compact([
    "aiplatform.googleapis.com",
    "agentregistry.googleapis.com",
    "apphub.googleapis.com",
    "apptopology.googleapis.com",
    "artifactregistry.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudapiregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "cloudtrace.googleapis.com",
    "compute.googleapis.com",
    "discoveryengine.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "iap.googleapis.com",
    "logging.googleapis.com",
    "modelarmor.googleapis.com",
    "monitoring.googleapis.com",
    "networksecurity.googleapis.com",
    "networkservices.googleapis.com",
    "observability.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    (var.gateway_extensions_enabled ? "serviceextensions.googleapis.com" : ""),
    "servicenetworking.googleapis.com",
    "serviceusage.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "telemetry.googleapis.com",
    "vpcaccess.googleapis.com",
  ]))

  service_accounts = {
    alert_ingress = {
      display_name = "Solvan Alert Ingress"
      description  = "Accepts only authenticated Cloud Monitoring Pub/Sub push and writes bounded ingress receipts."
    }
    alert_ingress_push = {
      display_name = "Solvan Alert Ingress Push"
      description  = "Mints the exact OIDC token for the configured Pub/Sub push subscription only."
    }
    direct_gcp_reader = {
      display_name = "Solvan Direct GCP Reader"
      description  = "The sole workload allowed to impersonate an enrolled customer read-only service account for bounded direct GCP observation."
    }
    api = {
      display_name = "Solvan API"
      description  = "Reads scoped projections and records exact role-bound human approvals."
    }
    build = {
      display_name = "Solvan Cloud Build"
      description  = "Builds and publishes immutable release containers only."
    }
    console = {
      display_name = "Solvan Operator Console"
      description  = "Serves the browser UI and invokes only the private projection API."
    }
    coordinator = {
      display_name = "Solvan Coordinator"
      description  = "Owns durable workflow dispatch and Agent Runtime invocation."
    }
    detector = {
      display_name = "Solvan Detector"
      description  = "Reads approved metrics and writes canonical detection events."
    }
    evidence = {
      display_name = "Solvan Evidence Broker"
      description  = "Runs typed read-only production queries and writes immutable evidence."
    }
    relay_control = {
      display_name = "Solvant Relay Control Plane"
      description  = "Leases and accepts read-only customer Relay evidence; it holds no customer credential."
    }
    actuator = {
      display_name = "Solvan Private Actuator"
      description  = "Only identity holding bounded release mutation permissions."
    }
    payments = {
      display_name = "Solvan Payments Fixture"
      description  = "Isolated synthetic competition workload."
    }
    verifier = {
      display_name = "Solvan Independent Verifier"
      description  = "Reads oracle signals and synthetic results; cannot mutate."
    }
    pilot_qualification_verifier = {
      display_name = "Solvan Pilot Qualification Verifier"
      description  = "Independently verifies and signs direct-GCP pilot qualification receipts; it cannot invoke producer services."
    }
    scheduler = {
      display_name = "Solvan Scheduler Invoker"
      description  = "Invokes authenticated detector and coordinator timer routes."
    }
    publisher = {
      display_name = "Solvan Outbox Publisher"
      description  = "Publishes token-fenced Cloud SQL outbox rows to Pub/Sub."
    }
    pubsub = {
      display_name = "Solvan Pub/Sub Push"
      description  = "Signs push delivery requests to the private coordinator endpoint."
    }
    memory = {
      display_name = "Solvan Memory Promotion"
      description  = "Sole identity allowed to create governed Memory Bank facts."
    }
    antigravity = {
      display_name = "Solvan Antigravity Workspace Provider"
      description  = "Runs the self-hosted SDK with Vertex model invocation and telemetry permissions only."
    }
    workspace_sandbox = {
      display_name = "Solvan Regional Workspace Sandbox"
      description  = "Runs exact repair validation inside a no-egress nested Cloud Run sandbox; it has no Google Cloud data or mutation permissions."
    }
    workspace_adapter = {
      display_name = "Solvan Code Repair Workspace Adapter"
      description  = "Materializes only bounded code-repair tools and exploratory sandbox receipts; it has no repository, approval, or deployment authority."
    }
    fixture_attester = {
      display_name = "Solvan Synthetic Fixture Attester"
      description  = "Validates isolated public fixtures and signs exact workspace manifests; it has no model, SQL, or production authority."
    }
    github_provider = {
      display_name = "Solvan GitHub Release Provider"
      description  = "Creates and merges only approval-bound GitHub pull requests through the configured App installation."
    }
    github_identity_broker = {
      display_name = "Solvan GitHub Identity Broker"
      description  = "Completes session-bound GitHub reviewer identity links; it cannot create branches, pull requests, merges, or deployments."
    }
    deployment_controller = {
      display_name = "Solvan Release Deployment Controller"
      description  = "Performs only reservation-bound Cloud Run canary, promotion, and approved rollback operations."
    }
    release_verifier = {
      display_name = "Solvan Release Effect Verifier"
      description  = "Independently signs release-effect observations; it cannot deploy, roll back, approve, or merge."
    }
    slack_liaison = {
      display_name = "Solvan Slack Liaison"
      description  = "Verifies signed Slack events and delivers reader-filtered conversation output."
    }
    liaison_maintenance = {
      display_name = "Solvan Liaison Maintenance"
      description  = "Runs deterministic transcript retention, reaping, and compaction."
    }
    trigger_scheduler = {
      display_name = "Solvan Trigger Scheduler"
      description  = "Matches verified source events and enqueues policy-bound incident work."
    }
    mcp_facade = {
      display_name = "Solvan MCP Facade"
      description  = "Serves exactly three reader-delegated MCP tools through the governed gateway."
    }
    discord_liaison = {
      display_name = "Solvan Discord Liaison"
      description  = "Verifies signed Discord interactions and delivers reader-filtered output."
    }
    email_liaison = {
      display_name = "Solvan Email Liaison"
      description  = "Accepts only an OIDC-authenticated mail relay and delivers frozen payloads through it."
    }
    migration = {
      display_name = "Solvan Release Migration"
      description  = "Runs one-shot schema migration and approved calibration seed jobs."
    }
    probe = {
      display_name = "Solvan Release Probe"
      description  = "Read-only release oracle for schema and tenant-isolation preflight evidence."
    }
    injector = {
      display_name = "Solvan Release Injector"
      description  = "Competition-fixture identity; may change only the isolated payments revision and invoke synthetic traffic."
    }
    oracle = {
      display_name = "Solvan Release Oracle"
      description  = "Read-only deterministic scenario grader; it is not an agent and has no production mutation authority."
    }
  }

  # Google caps a service-account account ID at 30 characters, which the
  # derived "solvan-<key>" form silently exceeds for a long registry key. A key
  # that overruns carries an explicit short form here rather than being
  # truncated: a principal's name is what an IAM binding and an audit record
  # are read against, so it stays chosen rather than whatever a substring
  # produced. iam.tf refuses at plan time if a key has neither a short form nor
  # a derived ID that fits.
  service_account_id_overrides = {
    pilot_qualification_verifier = "solvan-pilot-qual-verifier"
  }

  service_account_ids = {
    for key in keys(local.service_accounts) :
    key => lookup(
      local.service_account_id_overrides,
      key,
      "solvan-${replace(key, "_", "-")}",
    )
  }
}
