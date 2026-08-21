resource "google_project_iam_audit_config" "model_armor_data_access" {
  project = var.project_id
  service = "modelarmor.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
}

resource "google_project_iam_audit_config" "agent_platform_data_access" {
  project = var.project_id
  service = "aiplatform.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

resource "google_logging_project_sink" "security_controls" {
  project                = var.project_id
  name                   = "${local.prefix}-security-controls"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.security.id}"
  unique_writer_identity = true
  description            = "Metadata-only policy-denial and Model Armor audit projection."
  filter                 = <<-EOT
    (log_id("cloudaudit.googleapis.com/policy") AND
      (protoPayload.serviceName="iap.googleapis.com" OR
       protoPayload.serviceName="aiplatform.googleapis.com" OR
       protoPayload.serviceName="networkservices.googleapis.com"))
    OR
    (protoPayload.serviceName="modelarmor.googleapis.com" AND
      protoPayload.methodName=~"Sanitize(UserPrompt|ModelResponse)$")
  EOT

  depends_on = [google_project_service.required["logging.googleapis.com"]]
}

resource "google_pubsub_topic_iam_member" "security_log_sink" {
  project = var.project_id
  topic   = google_pubsub_topic.security.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.security_controls.writer_identity
}
