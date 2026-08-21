resource "google_sql_database_instance" "control" {
  project          = var.project_id
  name             = "${local.prefix}-control"
  region           = var.region
  database_version = "POSTGRES_16"

  deletion_protection = var.deletion_protection

  settings {
    edition           = var.database_edition
    tier              = var.database_tier
    availability_type = "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = 10
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.control.id
      enable_private_path_for_google_cloud_services = true
    }

    maintenance_window {
      day          = 7
      hour         = 4
      update_track = "stable"
    }

    user_labels = local.labels
  }

  depends_on = [
    google_project_service.required["sqladmin.googleapis.com"],
    google_service_networking_connection.private_services,
  ]
}

resource "google_sql_database" "solvan" {
  project  = var.project_id
  name     = "solvan"
  instance = google_sql_database_instance.control.name
}

locals {
  workload_sql_service_names = var.direct_gcp_alert_triage_pilot_enabled ? [
    "api", "coordinator", "publisher", "alert_ingress", "pilot_qualification_verifier",
    ] : concat(
    ["api", "coordinator", "detector", "actuator", "evidence", "relay_control", "verifier", "publisher", "memory", "migration", "probe", "github_provider", "workspace_adapter", "github_identity_broker", "deployment_controller", "release_verifier", "slack_liaison", "liaison_maintenance", "trigger_scheduler", "mcp_facade", "discord_liaison", "email_liaison"],
    var.fault_drill_enabled ? ["payments", "injector", "oracle"] : [],
  )
}

resource "google_sql_user" "workload_iam" {
  for_each = toset(local.workload_sql_service_names)

  project  = var.project_id
  instance = google_sql_database_instance.control.name
  name     = trimsuffix(google_service_account.workload[each.value].email, ".gserviceaccount.com")
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_project_iam_member" "sql_client" {
  for_each = toset(local.workload_sql_service_names)

  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = google_service_account.workload[each.value].member
}

resource "google_project_iam_member" "sql_instance_user" {
  for_each = toset(local.workload_sql_service_names)

  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = google_service_account.workload[each.value].member
}
