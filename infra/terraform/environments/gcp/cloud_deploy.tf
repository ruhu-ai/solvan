locals {
  catalog_delivery_pipeline_id  = "${local.prefix}-catalog"
  catalog_evaluation_target_id  = "${local.prefix}-catalog-evaluation"
  catalog_publication_target_id = "${local.prefix}-catalog-publication"
  catalog_deploy_environment = {
    SOLVAN_AGENT_TOOL_BINDINGS_JSON        = jsonencode(local.governed_agent_tool_bindings)
    SOLVAN_CATALOG_EVIDENCE_BUCKET         = google_storage_bucket.catalog_release_evidence.name
    SOLVAN_CATALOG_NETWORK_POLICY_HASH     = var.catalog_network_policy_hash
    SOLVAN_CATALOG_SUBJECT_HASH            = local.catalog_release_subject_hash
    SOLVAN_CLOUD_DEPLOY_PIPELINE_ID        = local.catalog_delivery_pipeline_id
    SOLVAN_CLOUD_DEPLOY_EVALUATION_TARGET  = local.catalog_evaluation_target_id
    SOLVAN_CLOUD_DEPLOY_PUBLICATION_TARGET = local.catalog_publication_target_id
    SOLVAN_CLOUD_RUN_CATALOG_JOB           = google_cloud_run_v2_job.catalog_publication.name
    SOLVAN_DEPLOYMENT_ID                   = var.deployment_id
    SOLVAN_ENVIRONMENT_ID                  = var.environment_id
    SOLVAN_EVIDENCE_AGENT_RESOURCE         = var.agent_runtime_resources.evidence_agent
    SOLVAN_EXECUTION_AGENT_RESOURCE        = var.agent_runtime_resources.execution_agent
    SOLVAN_GCP_PROJECT                     = var.project_id
    SOLVAN_GCP_REGION                      = var.region
    SOLVAN_INCIDENT_SUPERVISOR_RESOURCE    = var.agent_runtime_resources.incident_supervisor
    SOLVAN_INFRASTRUCTURE_AGENT_RESOURCE   = var.agent_runtime_resources.infrastructure_agent
    SOLVAN_ORGANIZATION_ID                 = var.organization_id
    SOLVAN_RELEASE_COMMIT                  = var.release_commit
    SOLVAN_SCOPE_PROJECT_ID                = var.scope_project_id
    SOLVAN_VERIFICATION_AGENT_RESOURCE     = var.agent_runtime_resources.verification_agent
    SOLVAN_WORKSPACE_AGENT_RESOURCE        = var.agent_runtime_resources.workspace_agent
  }
}

resource "google_clouddeploy_custom_target_type" "catalog_evaluation" {
  project     = var.project_id
  location    = var.region
  name        = "${local.prefix}-catalog-evaluation"
  description = "Deterministically evaluates the exact Solvan governed catalog subject."

  tasks {
    render {
      container {
        image = var.images.release_admin
        args  = ["cloud-deploy-catalog"]
        env   = merge(local.catalog_deploy_environment, { SOLVAN_CATALOG_STAGE = "EVALUATION" })
      }
    }
    deploy {
      container {
        image = var.images.release_admin
        args  = ["cloud-deploy-catalog"]
        env   = merge(local.catalog_deploy_environment, { SOLVAN_CATALOG_STAGE = "EVALUATION" })
      }
    }
  }

  depends_on = [google_project_service.required["clouddeploy.googleapis.com"]]
}

resource "google_clouddeploy_custom_target_type" "catalog_publication" {
  project     = var.project_id
  location    = var.region
  name        = "${local.prefix}-catalog-publication"
  description = "Invokes catalog publication only inside an approved Cloud Deploy rollout."

  tasks {
    render {
      container {
        image = var.images.release_admin
        args  = ["cloud-deploy-catalog"]
        env   = merge(local.catalog_deploy_environment, { SOLVAN_CATALOG_STAGE = "PUBLICATION" })
      }
    }
    deploy {
      container {
        image = var.images.release_admin
        args  = ["cloud-deploy-catalog"]
        env   = merge(local.catalog_deploy_environment, { SOLVAN_CATALOG_STAGE = "PUBLICATION" })
      }
    }
  }

  depends_on = [google_project_service.required["clouddeploy.googleapis.com"]]
}

resource "google_clouddeploy_target" "catalog_evaluation" {
  project          = var.project_id
  location         = var.region
  name             = local.catalog_evaluation_target_id
  description      = "Automated deterministic catalog evaluation."
  require_approval = false

  custom_target {
    custom_target_type = google_clouddeploy_custom_target_type.catalog_evaluation.id
  }

  execution_configs {
    usages            = ["RENDER", "DEPLOY"]
    execution_timeout = "1200s"
    default_pool {
      service_account  = google_service_account.workload["catalog_deploy"].email
      artifact_storage = "gs://${google_storage_bucket.catalog_release_evidence.name}/cloud-deploy"
    }
  }
}

resource "google_clouddeploy_target" "catalog_publication" {
  project          = var.project_id
  location         = var.region
  name             = local.catalog_publication_target_id
  description      = "Human-approved governed catalog publication."
  require_approval = true

  custom_target {
    custom_target_type = google_clouddeploy_custom_target_type.catalog_publication.id
  }

  execution_configs {
    usages            = ["RENDER", "DEPLOY"]
    execution_timeout = "1200s"
    default_pool {
      service_account  = google_service_account.workload["catalog_deploy"].email
      artifact_storage = "gs://${google_storage_bucket.catalog_release_evidence.name}/cloud-deploy"
    }
  }
}

resource "google_clouddeploy_delivery_pipeline" "catalog" {
  project     = var.project_id
  location    = var.region
  name        = local.catalog_delivery_pipeline_id
  description = "Ordered deterministic evaluation and human-approved catalog publication."

  serial_pipeline {
    stages {
      target_id = google_clouddeploy_target.catalog_evaluation.name
    }
    stages {
      target_id = google_clouddeploy_target.catalog_publication.name
    }
  }
}
