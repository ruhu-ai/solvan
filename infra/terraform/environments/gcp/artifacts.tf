resource "google_artifact_registry_repository_iam_member" "build_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.containers.location
  repository = google_artifact_registry_repository.containers.repository_id
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.workload["build"].member
}

resource "google_project_iam_member" "build_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.workload["build"].member
}

resource "google_service_account_iam_member" "cloud_build_service_agent_token" {
  service_account_id = google_service_account.workload["build"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
}

# Cloud Build uploads the release source to a bucket and the build then reads it
# back as solvan-build. Cloud Build's own default bucket is created lazily on
# first submit, which is after this IAM is applied, so binding to it would order
# the grant behind the thing that needs it. This bucket is created here and
# named explicitly on submit, so the read is granted on exactly one bucket
# rather than at project scope.
resource "google_storage_bucket" "build_source" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.environment}-solvan-build-source"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  labels = local.labels

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

resource "google_storage_bucket_iam_member" "build_source_reader" {
  bucket = google_storage_bucket.build_source.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.workload["build"].member
}
