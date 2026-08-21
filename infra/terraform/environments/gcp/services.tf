resource "google_project_service" "required" {
  for_each = local.services

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "containers" {
  project       = var.project_id
  location      = var.region
  repository_id = "solvan"
  description   = "Immutable Solvan release container images."
  format        = "DOCKER"
  mode          = "STANDARD_REPOSITORY"

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "retain-recent-releases"
    action = "KEEP"
    most_recent_versions {
      keep_count = 20
    }
  }

  depends_on = [google_project_service.required["artifactregistry.googleapis.com"]]
}
