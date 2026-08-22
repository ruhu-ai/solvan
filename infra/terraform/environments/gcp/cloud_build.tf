# Release image construction is a Google-managed, approval-gated operation.
# The deployment runner never uploads a local working tree and never creates a
# build. An operator invokes this one trigger for an exact published SHA and
# supplies the same SHA as _RELEASE_COMMIT; deployment accepts the resulting
# build only after independently checking trigger, source, identity, approval,
# provenance, and every immutable image digest.
resource "google_cloudbuild_trigger" "release_images" {
  project     = var.project_id
  location    = var.region
  name        = "${local.prefix}-release-images"
  description = "Approval-gated build of the exact published Solvan release commit."

  service_account = google_service_account.workload["build"].id

  source_to_build {
    uri       = var.release_source_repository_uri
    ref       = "refs/heads/main"
    repo_type = "GITHUB"
  }

  git_file_source {
    path      = "cloudbuild.yaml"
    uri       = var.release_source_repository_uri
    revision  = "refs/heads/main"
    repo_type = "GITHUB"
  }

  substitutions = {
    _REGION         = var.region
    _REPOSITORY     = google_artifact_registry_repository.containers.repository_id
    _RELEASE_COMMIT = "UNCONFIGURED"
  }

  approval_config {
    approval_required = true
  }

  depends_on = [
    google_artifact_registry_repository_iam_member.build_writer,
    google_project_iam_member.build_logs,
    google_service_account_iam_member.cloud_build_service_agent_token,
  ]
}
