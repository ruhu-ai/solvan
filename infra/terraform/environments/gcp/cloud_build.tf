# Release image construction is a Google-managed, approval-gated operation.
# The deployment runner never uploads a local working tree and never creates a
# build. An operator invokes this one trigger for an exact published SHA and
# supplies the same SHA as _RELEASE_COMMIT; deployment accepts the resulting
# build only after independently checking trigger, source, identity, approval,
# provenance, and every immutable image digest.
locals {
  release_source_connection_name = "${local.prefix}-github"
  release_source_repository_name = "${local.prefix}-release-source"
  release_source_connection = format(
    "projects/%s/locations/%s/connections/%s",
    var.project_id,
    var.region,
    local.release_source_connection_name,
  )
}

# GitHub App authorization is an explicit human bootstrap and is deliberately
# not encoded as a token in Terraform. Once that regional connection is
# COMPLETE, Terraform owns the exact linked public repository used by the
# release trigger.
resource "google_cloudbuildv2_repository" "release_source" {
  project           = var.project_id
  location          = var.region
  name              = local.release_source_repository_name
  parent_connection = local.release_source_connection
  remote_uri        = var.release_source_repository_uri

  deletion_policy = "PREVENT"
}

resource "google_cloudbuild_trigger" "release_images" {
  project     = var.project_id
  location    = var.region
  name        = "${local.prefix}-release-images"
  description = "Approval-gated build of the exact published Solvan release commit."

  service_account = google_service_account.workload["build"].id

  source_to_build {
    repository = google_cloudbuildv2_repository.release_source.id
    ref        = "refs/heads/main"
    repo_type  = "GITHUB"
  }

  git_file_source {
    path       = "cloudbuild.yaml"
    repository = google_cloudbuildv2_repository.release_source.id
    revision   = "refs/heads/main"
    repo_type  = "GITHUB"
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
    google_cloudbuildv2_repository.release_source,
    google_artifact_registry_repository_iam_member.build_writer,
    google_project_iam_member.build_logs,
    google_service_account_iam_member.cloud_build_service_agent_token,
  ]
}
