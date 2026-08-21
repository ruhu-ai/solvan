resource "google_kms_key_ring" "workspace_attestation" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project  = var.project_id
  name     = "${local.prefix}-workspace-attestation"
  location = var.region

  depends_on = [google_project_service.required["cloudkms.googleapis.com"]]
}

resource "google_kms_crypto_key" "synthetic_attester" {
  count = var.antigravity_demo_enabled ? 1 : 0

  name            = "synthetic-fixture-attester"
  key_ring        = google_kms_key_ring.workspace_attestation[0].id
  purpose         = "ASYMMETRIC_SIGN"
  rotation_period = null

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_version" "synthetic_attester" {
  count = var.antigravity_demo_enabled ? 1 : 0

  crypto_key = google_kms_crypto_key.synthetic_attester[0].id
  state      = "ENABLED"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "fixture_attester_signer" {
  count = var.antigravity_demo_enabled ? 1 : 0

  crypto_key_id = google_kms_crypto_key.synthetic_attester[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = google_service_account.workload["fixture_attester"].member
}

resource "google_kms_crypto_key_iam_member" "coordinator_public_key_reader" {
  count = var.antigravity_demo_enabled ? 1 : 0

  crypto_key_id = google_kms_crypto_key.synthetic_attester[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = google_service_account.workload["coordinator"].member
}

# OAuth PKCE verifiers exist only for a ten-minute reviewer-link ceremony.
# This symmetric key is usable only by the identity broker and is unrelated to
# repository installation credentials or deployment signing authority.
resource "google_kms_key_ring" "github_identity" {
  count = var.github_release_enabled ? 1 : 0

  project  = var.project_id
  name     = "${local.prefix}-github-identity"
  location = var.region

  depends_on = [google_project_service.required["cloudkms.googleapis.com"]]
}

resource "google_kms_crypto_key" "github_identity_pkce" {
  count = var.github_release_enabled ? 1 : 0

  name            = "oauth-pkce-envelope"
  key_ring        = google_kms_key_ring.github_identity[0].id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "github_identity_pkce_user" {
  count = var.github_release_enabled ? 1 : 0

  crypto_key_id = google_kms_crypto_key.github_identity_pkce[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_service_account.workload["github_identity_broker"].member
}

# Release health evidence is signed by an identity that has no deployment or
# rollback authority. The Deployment Controller may read only its public key.
resource "google_kms_key_ring" "release_verification" {
  count = var.github_release_enabled ? 1 : 0

  project  = var.project_id
  name     = "${local.prefix}-release-verification"
  location = var.region

  depends_on = [google_project_service.required["cloudkms.googleapis.com"]]
}

resource "google_kms_crypto_key" "release_verifier" {
  count = var.github_release_enabled ? 1 : 0

  name            = "release-health-verifier"
  key_ring        = google_kms_key_ring.release_verification[0].id
  purpose         = "ASYMMETRIC_SIGN"
  rotation_period = null

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_version" "release_verifier" {
  count      = var.github_release_enabled ? 1 : 0
  crypto_key = google_kms_crypto_key.release_verifier[0].id
  state      = "ENABLED"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "release_verifier_signer" {
  count         = var.github_release_enabled ? 1 : 0
  crypto_key_id = google_kms_crypto_key.release_verifier[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = google_service_account.workload["release_verifier"].member
}

resource "google_kms_crypto_key_iam_member" "release_verifier_public_key_readers" {
  for_each = var.github_release_enabled ? toset(["api", "coordinator", "deployment_controller"]) : toset([])

  crypto_key_id = google_kms_crypto_key.release_verifier[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = google_service_account.workload[each.value].member
}

# Dedicated Relay signing authority. It is distinct from fixture attestation
# and never carries customer-provider or mutation capability.
resource "google_kms_key_ring" "relay" {
  project  = var.project_id
  name     = "${local.prefix}-relay"
  location = var.region

  depends_on = [google_project_service.required["cloudkms.googleapis.com"]]
}

resource "google_kms_crypto_key" "relay_job_signer" {
  name            = "relay-job-signer"
  key_ring        = google_kms_key_ring.relay.id
  purpose         = "ASYMMETRIC_SIGN"
  rotation_period = null

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "relay_evidence_cmek" {
  name            = "relay-evidence-cmek"
  key_ring        = google_kms_key_ring.relay.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}

data "google_storage_project_service_account" "relay_evidence" {
  project = var.project_id
}

resource "google_kms_crypto_key_iam_member" "relay_evidence_storage" {
  crypto_key_id = google_kms_crypto_key.relay_evidence_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.relay_evidence.email_address}"
}

resource "google_kms_crypto_key_version" "relay_job_signer" {
  crypto_key = google_kms_crypto_key.relay_job_signer.id
  state      = "ENABLED"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "relay_job_signers" {
  for_each = toset(["coordinator", "relay_control"])

  crypto_key_id = google_kms_crypto_key.relay_job_signer.id
  role          = "roles/cloudkms.signerVerifier"
  member        = google_service_account.workload[each.value].member
}

# Direct-GCP pilot qualification uses a signing key that is not shared with the
# action verifier, Relay, ingress, or any producer service.
resource "google_kms_key_ring" "direct_gcp_pilot" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  project  = var.project_id
  name     = "${local.prefix}-direct-gcp-pilot"
  location = var.region

  depends_on = [google_project_service.required["cloudkms.googleapis.com"]]
}

resource "google_kms_crypto_key" "direct_gcp_pilot_receipt_signer" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  name            = "direct-gcp-pilot-receipt-signer"
  key_ring        = google_kms_key_ring.direct_gcp_pilot[0].id
  purpose         = "ASYMMETRIC_SIGN"
  rotation_period = null

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "direct_gcp_pilot_receipt_cmek" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  name            = "direct-gcp-pilot-receipt-cmek"
  key_ring        = google_kms_key_ring.direct_gcp_pilot[0].id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}

data "google_storage_project_service_account" "direct_gcp_pilot_receipts" {
  count   = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0
  project = var.project_id
}

resource "google_kms_crypto_key_iam_member" "direct_gcp_pilot_receipt_storage" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  crypto_key_id = google_kms_crypto_key.direct_gcp_pilot_receipt_cmek[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.direct_gcp_pilot_receipts[0].email_address}"
}

resource "google_kms_crypto_key_version" "direct_gcp_pilot_receipt_signer" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  crypto_key = google_kms_crypto_key.direct_gcp_pilot_receipt_signer[0].id
  state      = "ENABLED"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "direct_gcp_pilot_receipt_signer" {
  count = var.direct_gcp_alert_triage_pilot_enabled ? 1 : 0

  crypto_key_id = google_kms_crypto_key.direct_gcp_pilot_receipt_signer[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = google_service_account.workload["pilot_qualification_verifier"].member
}
