terraform {
  required_version = ">= 1.12.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.45.0"
    }
  }

  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region

  # Billing Budgets rejects a call made with user credentials that carries no
  # quota project, so the release fails on the budget alone unless whoever runs
  # it happens to have set one on their local ADC. Naming the deployment project
  # here makes that a property of the configuration rather than of the operator's
  # machine.
  user_project_override = true
  billing_project       = var.project_id

  default_labels = local.labels
}
