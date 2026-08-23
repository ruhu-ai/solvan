resource "google_storage_bucket" "evidence" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-solvan-evidence"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

# Cloud Deploy release artifacts are governance records. Bucket Lock makes the
# retention policy irreversible; this bucket is intentionally separate from
# ordinary operational evidence, which has a short lifecycle.
resource "google_storage_bucket" "catalog_release_evidence" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-catalog-release-evidence"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = var.catalog_release_evidence_retention_seconds
    is_locked        = true
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

resource "google_storage_bucket_iam_member" "catalog_deploy_evidence_user" {
  bucket = google_storage_bucket.catalog_release_evidence.name
  role   = "roles/storage.objectUser"
  member = google_service_account.workload["catalog_deploy"].member
}

# Qualification receipts are immutable deployment evidence, not ordinary Alert
# payloads. Only the independent verifier can create objects here.
resource "google_storage_bucket" "direct_gcp_pilot_receipts" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-solvan-direct-gcp-pilot-receipts"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  encryption {
    default_kms_key_name = google_kms_crypto_key.direct_gcp_pilot_receipt_cmek[0].id
  }

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = 7776000
  }

  depends_on = [
    google_project_service.required["storage.googleapis.com"],
    google_kms_crypto_key_iam_member.direct_gcp_pilot_receipt_storage,
  ]
}

resource "google_storage_bucket_iam_member" "direct_gcp_pilot_receipt_creator" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  bucket = google_storage_bucket.direct_gcp_pilot_receipts[0].name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["pilot_qualification_verifier"].member
}

resource "google_storage_bucket_iam_member" "direct_gcp_pilot_receipt_viewer" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  bucket = google_storage_bucket.direct_gcp_pilot_receipts[0].name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["api"].member
}

# Relay evidence has a dedicated object namespace and IAM surface. The normal
# evidence bucket stays on its release-proven access set; customer Relay
# uploads never inherit its broad writer identities.
resource "google_storage_bucket" "relay_evidence" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-solvant-relay-evidence"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  encryption {
    default_kms_key_name = google_kms_crypto_key.relay_evidence_cmek.id
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [
    google_project_service.required["storage.googleapis.com"],
    google_kms_crypto_key_iam_member.relay_evidence_storage,
  ]
}

resource "google_storage_bucket" "runtime" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-agent-runtime"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  lifecycle_rule {
    condition {
      age = 14
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

resource "google_storage_bucket" "skills" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-solvan-skills"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

resource "google_storage_bucket_iam_member" "evidence_creator" {
  for_each = toset(["api", "detector", "evidence"])

  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload[each.value].member
}

resource "google_storage_bucket_iam_member" "github_identity_evidence_creator" {
  count = var.github_release_enabled ? 1 : 0

  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["github_identity_broker"].member
}

resource "google_storage_bucket_iam_member" "evidence_viewer" {
  for_each = toset(["api", "coordinator", "detector", "evidence"])

  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload[each.value].member
}

resource "google_storage_bucket_iam_member" "relay_evidence_writer" {
  bucket = google_storage_bucket.relay_evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["relay_control"].member
}

resource "google_storage_bucket_iam_member" "relay_evidence_viewer" {
  for_each = toset(["api", "evidence", "relay_control"])

  bucket = google_storage_bucket.relay_evidence.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload[each.value].member
}

resource "google_storage_bucket_iam_member" "skills_writer" {
  for_each = var.target_product_enabled ? toset(["api"]) : toset([])

  bucket = google_storage_bucket.skills.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload[each.value].member
}

resource "google_storage_bucket_iam_member" "skills_reader" {
  for_each = var.target_product_enabled ? toset(["api", "liaison_maintenance"]) : toset([])

  bucket = google_storage_bucket.skills.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload[each.value].member
}

resource "google_storage_bucket_iam_member" "skills_deleter" {
  count  = var.target_product_enabled ? 1 : 0
  bucket = google_storage_bucket.skills.name
  role   = "roles/storage.objectAdmin"
  member = google_service_account.workload["liaison_maintenance"].member
}

resource "google_storage_bucket_iam_member" "runtime_agent_platform_creator" {
  for_each = var.agent_runtime_service_agent_bindings_enabled ? toset(["agent-runtime"]) : toset([])
  bucket   = google_storage_bucket.runtime.name
  role     = "roles/storage.objectCreator"
  member   = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "runtime_agent_platform_reader" {
  for_each = var.agent_runtime_service_agent_bindings_enabled ? toset(["agent-runtime"]) : toset([])
  bucket   = google_storage_bucket.runtime.name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "runtime_verifier_creator" {
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["verifier"].member
}

resource "google_storage_bucket_iam_member" "runtime_verifier_reader" {
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["verifier"].member
}

resource "google_storage_bucket_iam_member" "runtime_workspace_adapter" {
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectUser"
  member = google_service_account.workload["workspace_adapter"].member
}

resource "google_storage_bucket_iam_member" "runtime_github_provider_creator" {
  count  = var.github_release_enabled ? 1 : 0
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["github_provider"].member
}

resource "google_storage_bucket_iam_member" "runtime_github_provider_reader" {
  count  = var.github_release_enabled ? 1 : 0
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["github_provider"].member
}

resource "google_storage_bucket_iam_member" "runtime_deployment_controller_creator" {
  count  = var.github_release_enabled ? 1 : 0
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["deployment_controller"].member
}

resource "google_storage_bucket_iam_member" "runtime_deployment_controller_reader" {
  count  = var.github_release_enabled ? 1 : 0
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["deployment_controller"].member
}

resource "google_storage_bucket_iam_member" "runtime_release_verifier_creator" {
  count  = var.github_release_enabled ? 1 : 0
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["release_verifier"].member
}

resource "google_storage_bucket_iam_member" "runtime_release_verifier_reader" {
  count  = var.github_release_enabled ? 1 : 0
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["release_verifier"].member
}

resource "google_storage_bucket_iam_member" "runtime_fixture_attester_reader" {
  count = var.antigravity_demo_enabled ? 1 : 0

  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["fixture_attester"].member
}

resource "google_storage_bucket_iam_member" "evidence_fixture_attester_creator" {
  count = var.antigravity_demo_enabled ? 1 : 0

  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["fixture_attester"].member
}

resource "google_storage_bucket_iam_member" "evidence_migration_reader" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["migration"].member
}

resource "google_storage_bucket_iam_member" "runtime_migration_creator" {
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["migration"].member
}

resource "google_storage_bucket_iam_member" "runtime_migration_reader" {
  bucket = google_storage_bucket.runtime.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["migration"].member
}

resource "google_storage_bucket_iam_member" "evidence_injector_calibration_reader" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["injector"].member
}

resource "google_storage_bucket_iam_member" "evidence_oracle_reader" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["oracle"].member
}

resource "google_storage_bucket_iam_member" "evidence_probe_creator" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["probe"].member
}

resource "google_storage_bucket_iam_member" "evidence_memory_probe_creator" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.workload["memory"].member
}

# The actuator's kill switch, made operable. The binary has always refused to
# mutate when /var/run/solvan/kill-switch exists (apps/actuator/local_policy),
# but no volume ever backed that path on Cloud Run, so there was no way to
# make the file exist in a running container: the control was real in code
# and unreachable in the deployed topology. This bucket is FUSE-mounted
# read-only at /var/run/solvan on the actuator alone. Engaging is one object
# write by a release approver:
#
#   gcloud storage cp /dev/null gs://<project>-<env>-actuator-controls/kill-switch
#
# and disengaging is the corresponding delete. The mount is read-only so the
# actuator can never remove its own switch; gcsfuse stat caching means an
# engage takes effect within about a minute, which is the accepted latency of
# this control. A failed mount fails the revision -- fail closed at deploy.
resource "google_storage_bucket" "actuator_controls" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-actuator-controls"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

resource "google_storage_bucket_iam_member" "actuator_controls_reader" {
  bucket = google_storage_bucket.actuator_controls.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["actuator"].member
}

resource "google_storage_bucket_iam_member" "actuator_controls_operator" {
  for_each = var.approver_principals

  bucket = google_storage_bucket.actuator_controls.name
  role   = "roles/storage.objectAdmin"
  member = each.value
}
