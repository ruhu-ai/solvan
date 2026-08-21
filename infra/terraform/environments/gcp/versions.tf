terraform {
  required_version = ">= 1.12.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.43.0"
    }
  }

  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region

  default_labels = local.labels
}
