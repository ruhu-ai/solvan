resource "google_pubsub_topic" "workflow" {
  project = var.project_id
  name    = "${local.prefix}-workflow"

  message_retention_duration = "604800s"

  depends_on = [google_project_service.required["pubsub.googleapis.com"]]
}

resource "google_pubsub_topic" "security" {
  project = var.project_id
  name    = "${local.prefix}-security"

  message_retention_duration = "604800s"

  depends_on = [google_project_service.required["pubsub.googleapis.com"]]
}

resource "google_pubsub_topic" "dead_letter" {
  project = var.project_id
  name    = "${local.prefix}-dead-letter"
}

resource "google_pubsub_subscription" "coordinator" {
  project = var.project_id
  name    = "${local.prefix}-coordinator"
  topic   = google_pubsub_topic.workflow.id

  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"
  retain_acked_messages      = false

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.service["coordinator"].uri}/internal/pubsub/workflow"

    oidc_token {
      service_account_email = google_service_account.workload["pubsub"].email
      audience              = google_cloud_run_v2_service.service["coordinator"].uri
    }
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 10
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  expiration_policy {
    ttl = ""
  }
}

resource "google_pubsub_subscription" "security" {
  project = var.project_id
  name    = "${local.prefix}-security-collector"
  topic   = google_pubsub_topic.security.id

  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"
  retain_acked_messages      = false

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.service["coordinator"].uri}/internal/pubsub/security"

    oidc_token {
      service_account_email = google_service_account.workload["pubsub"].email
      audience              = google_cloud_run_v2_service.service["coordinator"].uri
    }
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 10
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  expiration_policy {
    ttl = ""
  }
}

resource "google_pubsub_topic_iam_member" "publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.workflow.name
  role    = "roles/pubsub.publisher"
  member  = google_service_account.workload["publisher"].member
}

resource "google_service_account_iam_member" "pubsub_push_token" {
  service_account_id = google_service_account.workload["pubsub"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_pubsub_subscription_iam_member" "dead_letter_subscriber" {
  for_each = {
    workflow = google_pubsub_subscription.coordinator.name
    security = google_pubsub_subscription.security.name
  }

  project      = var.project_id
  subscription = each.value
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_pubsub_topic_iam_member" "dead_letter_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.dead_letter.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}
