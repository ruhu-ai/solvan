# Cloud Build creates the project-owned built-by-cloud-build attestor on the
# first build. The release harness applies this policy only after that build,
# then every Cloud Run service and job opts into the default policy.
resource "google_binary_authorization_policy" "release" {
  project                       = var.project_id
  description                   = "Only immutable images attested by this project's Cloud Build may run."
  global_policy_evaluation_mode = "ENABLE"

  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [
      "projects/${var.project_id}/attestors/built-by-cloud-build",
    ]
  }

  depends_on = [
    google_project_service.required["binaryauthorization.googleapis.com"],
    google_project_service.required["containeranalysis.googleapis.com"],
  ]
}
