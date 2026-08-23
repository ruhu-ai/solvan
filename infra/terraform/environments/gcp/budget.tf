resource "google_billing_budget" "release" {
  billing_account = var.billing_account_id
  display_name    = "${local.prefix} project budget"

  budget_filter {
    projects = ["projects/${data.google_project.current.number}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(var.monthly_budget_usd)
    }
  }

  threshold_rules {
    threshold_percent = 0.625
    spend_basis       = "CURRENT_SPEND"
  }

  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "CURRENT_SPEND"
  }

  # Without this rule a crossed threshold notifies billing administrators only,
  # which for this project is an address nobody watches during a release. The
  # channel is the same one the operational policies use, so budget and outage
  # reach the same place.
  dynamic "all_updates_rule" {
    for_each = google_monitoring_notification_channel.operations

    content {
      monitoring_notification_channels = [all_updates_rule.value.id]
      disable_default_iam_recipients   = false
    }
  }

  depends_on = [google_project_service.required["billingbudgets.googleapis.com"]]
}
