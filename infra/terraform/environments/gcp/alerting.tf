# Operational alerting.
#
# Every policy here watches a signal the platform already emits. That ordering
# is deliberate: an alert bound to telemetry nothing produces is worse than no
# alert, because it reads as coverage. The actuator refusal metrics below exist
# only because `record_control_refusal` emits the reason code — before that the
# in-binary controls refused into an access log as anonymous 403s.

resource "google_monitoring_notification_channel" "operations" {
  count = var.alert_notification_email == "UNCONFIGURED" ? 0 : 1

  project      = var.project_id
  display_name = "${local.prefix} operations"
  type         = "email"

  labels = {
    email_address = var.alert_notification_email
  }

  depends_on = [google_project_service.required["monitoring.googleapis.com"]]
}

# --- Log-based metrics over the actuator's in-binary controls -----------------
#
# The filters match the log *body* written by `record_control_refusal`, which is
# `solvan.control.refused:<REASON_CODE>`. The reason codes are enumerated in
# `apps/actuator/local_policy.py` and appear nowhere else in the log stream.
#
# A `condition_threshold` filter must restrict `resource.type`; naming only the
# metric is rejected by the API at create time with HTTP 400, which is how both
# of these first failed to deploy. The actuator writes these entries from Cloud
# Run, so the log-based metrics carry `cloud_run_revision`.
#
# Unverified until a staging run: how the OTel Cloud Logging exporter projects
# this record — specifically whether `logName` is the configured
# `solvan-control-plane` and whether severity maps to WARNING. Both are asserted
# from the exporter's documented behaviour, not observed. Recorded as TD-016;
# the deployed probe named there is what turns this into an observation.

resource "google_logging_metric" "actuator_kill_switch_engaged" {
  project     = var.project_id
  name        = "${local.prefix}/actuator/kill_switch_engaged"
  description = "Mutations refused because the actuator's local kill switch is engaged."

  filter = <<-EOT
    logName="projects/${var.project_id}/logs/solvan-control-plane"
    AND severity>=WARNING
    AND "LOCAL_KILL_SWITCH_ENGAGED"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }

  depends_on = [google_project_service.required["logging.googleapis.com"]]
}

resource "google_logging_metric" "actuator_local_control_refusal" {
  project     = var.project_id
  name        = "${local.prefix}/actuator/local_control_refusal"
  description = "Any local-policy refusal in the actuator binary, by reason code."

  filter = <<-EOT
    logName="projects/${var.project_id}/logs/solvan-control-plane"
    AND severity>=WARNING
    AND "solvan.control.refused"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }

  depends_on = [google_project_service.required["logging.googleapis.com"]]
}

# --- Alert policies -----------------------------------------------------------

# An engaged kill switch is not an error, it is a deliberate customer act that
# has halted production mutation. It pages because the halted state is invisible
# otherwise: incidents proceed, actions are authorized, and every execution
# fails at the last hop.
resource "google_monitoring_alert_policy" "actuator_kill_switch_engaged" {
  project      = var.project_id
  display_name = "${local.prefix} actuator kill switch engaged"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "a mutation was refused by the local kill switch"

    condition_threshold {
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "metric.type=\"logging.googleapis.com/user/${google_logging_metric.actuator_kill_switch_engaged.name}\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_DELTA"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = google_monitoring_notification_channel.operations[*].id

  documentation {
    content   = "The actuator refused a mutation because its local kill-switch file is present. Production mutation is halted for this instance. Confirm the halt is intended; if not, remove the file at SOLVAN_ACTUATOR_KILL_SWITCH_FILE."
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "604800s"
  }
}

# Distinct from the switch: this fires on an exhausted hourly budget or an
# unparsable local policy. Both mean the actuator is refusing work it was asked
# to do, which is correct behaviour and still needs an operator.
resource "google_monitoring_alert_policy" "actuator_local_control_refusal" {
  project      = var.project_id
  display_name = "${local.prefix} actuator local control refusal"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "local policy refused a mutation"

    condition_threshold {
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "metric.type=\"logging.googleapis.com/user/${google_logging_metric.actuator_local_control_refusal.name}\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_DELTA"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = google_monitoring_notification_channel.operations[*].id

  documentation {
    content   = "The actuator refused a mutation from its own binary. Reason codes: LOCAL_KILL_SWITCH_*, LOCAL_BUDGET_UNCONFIGURED, LOCAL_BUDGET_INVALID, LOCAL_RATE_BUDGET_EXHAUSTED. An UNCONFIGURED or INVALID code means the deployment is misconfigured and no mutation can succeed."
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "604800s"
  }
}

# A message reaches the quarantine queue only after ten failed deliveries to the
# coordinator. Nothing drains it automatically, by design — so depth above zero
# is durable, and an alert on it is the only thing that makes a poisoned
# workflow message visible before its retention expires.
resource "google_monitoring_alert_policy" "dead_letter_quarantine" {
  project      = var.project_id
  display_name = "${local.prefix} dead-letter quarantine is not empty"
  combiner     = "OR"
  severity     = "ERROR"

  conditions {
    display_name = "undelivered messages in the dead-letter quarantine"

    condition_threshold {
      filter = join(" AND ", [
        "resource.type=\"pubsub_subscription\"",
        "resource.label.\"subscription_id\"=\"${google_pubsub_subscription.dead_letter.name}\"",
        "metric.type=\"pubsub.googleapis.com/subscription/num_undelivered_messages\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = google_monitoring_notification_channel.operations[*].id

  documentation {
    content   = "A workflow or security event exhausted delivery and was quarantined. Pull from the subscription to inspect it. These messages are not retried automatically; retention is seven days."
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "604800s"
  }
}

# Scoped to the services whose failure stops incident handling. A 5xx here is
# the control plane failing, not a customer estate degrading.
resource "google_monitoring_alert_policy" "control_plane_server_errors" {
  project      = var.project_id
  display_name = "${local.prefix} control-plane 5xx"
  combiner     = "OR"
  severity     = "ERROR"

  conditions {
    display_name = "sustained 5xx from a control-plane service"

    condition_threshold {
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "metric.type=\"run.googleapis.com/request_count\"",
        "metric.label.\"response_code_class\"=\"5xx\"",
        "resource.label.\"service_name\"=monitoring.regex.full_match(\"${local.prefix}-(api|coordinator|actuator|verifier|evidence)\")",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "300s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.label.service_name"]
      }
    }
  }

  notification_channels = google_monitoring_notification_channel.operations[*].id

  documentation {
    content   = "A control-plane service returned 5xx for five minutes. Check the service's revision health and the Cloud SQL connection envelope before restarting anything."
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "604800s"
  }
}
