"""Scripted tenant-integration fixture for local console development.

Mirrors the shape of the live Cloud SQL projection so the Integrations route
renders identically against either source. It carries no credential values and
no cloud authority.
"""

from __future__ import annotations

from typing import Any

from solvan.application.tenant_integration import connectable_provider_projection


def integration_fixture() -> dict[str, Any]:
    return {
        # Shared with the live projection rather than restated. The fixture's
        # own hand-written catalog had already drifted to a subset, which is
        # exactly the divergence this module's docstring promises not to have.
        "providers": connectable_provider_projection(),
        "connections": [
            {
                "id": "con_…GCPM",
                "display_name": "Payments production telemetry",
                "kind": "GCP_NATIVE",
                "provider": "CLOUD_MONITORING",
                "credential_posture": "FEDERATED_SHORT_LIVED",
                "classification": "INTERNAL",
                "residency_region": "europe-west1",
                "external_resource_kind": "GCP_PROJECT",
                "external_resource_id": "ruhu-production",
                "workload_region": "europe-west2",
                "lifecycle": "ENABLED",
                "availability": "DEGRADED",
                "availability_reason_code": "PARTIAL_CAPABILITY",
                "availability_explanation": (
                    "2 of 3 capabilities are proven; audit.read is not, because "
                    "verified identity reached the provider and the required "
                    "permission was refused"
                ),
                "availability_missing_grant": "roles/logging.privateLogViewer",
                "availability_remediation_kind": "GRANT_ROLE",
                "availability_reference": None,
                "availability_receipt_ref": "probe://con_GCPM/audit.read",
                "last_probe_result": "PARTIAL",
                "last_success_at": "2026-08-13T08:12:00Z",
                "proof_expires_at": None,
                "holds_stored_secret": False,
                "read_only_scope_verified": True,
                "capabilities": [
                    {
                        "capability": "metrics.read",
                        "available": True,
                        "outcome": "GRANTED",
                        "missing_grant": None,
                    },
                    {
                        "capability": "logs.read",
                        "available": True,
                        "outcome": "GRANTED",
                        "missing_grant": None,
                    },
                    {
                        "capability": "audit.read",
                        "available": False,
                        "outcome": "DENIED",
                        "missing_grant": "roles/logging.privateLogViewer",
                    },
                ],
            },
            {
                "id": "con_…DDOG",
                "display_name": "Checkout observability (Datadog)",
                "kind": "VENDOR_API",
                "provider": "DATADOG",
                "credential_posture": "STORED_LONG_LIVED",
                "classification": "INTERNAL",
                "residency_region": "europe-west1",
                "external_resource_kind": None,
                "external_resource_id": None,
                "workload_region": None,
                "lifecycle": "ENABLED",
                "availability": "READY",
                "availability_reason_code": None,
                "availability_explanation": None,
                "availability_missing_grant": None,
                "availability_remediation_kind": None,
                "availability_reference": None,
                "availability_receipt_ref": "probe://con_DDOG/metrics.read",
                "last_probe_result": "SUCCEEDED",
                "last_success_at": "2026-08-13T08:12:00Z",
                "proof_expires_at": "2026-08-20T08:12:00Z",
                "holds_stored_secret": True,
                "read_only_scope_verified": True,
                "capabilities": [
                    {
                        "capability": "metrics.read",
                        "available": True,
                        "outcome": "GRANTED",
                        "missing_grant": None,
                    }
                ],
            },
            {
                "id": "con_…TRCE",
                "display_name": "Checkout traces",
                "kind": "GCP_NATIVE",
                "provider": "CLOUD_TRACE",
                "credential_posture": "FEDERATED_SHORT_LIVED",
                "classification": "INTERNAL",
                "residency_region": "europe-west1",
                "external_resource_kind": "GCP_PROJECT",
                "external_resource_id": "ruhu-production",
                "workload_region": "europe-west2",
                "lifecycle": "ENABLED",
                "availability": "UNREACHABLE",
                "availability_reason_code": "PROVIDER_UNREACHABLE",
                "availability_explanation": (
                    "the bounded probe could not reach or authenticate the provider "
                    "conclusively, so no permission conclusion was drawn"
                ),
                "availability_missing_grant": (
                    "roles/cloudtrace.user (probe could not reach the provider)"
                ),
                "availability_remediation_kind": "RETRY_PROBE",
                "availability_reference": None,
                "availability_receipt_ref": "probe://con_TRCE/traces.read",
                "last_probe_result": "FAILED",
                "last_success_at": None,
                "proof_expires_at": None,
                "holds_stored_secret": False,
                "read_only_scope_verified": True,
                "capabilities": [
                    {
                        "capability": "traces.read",
                        "available": False,
                        "outcome": "UNREACHABLE",
                        "missing_grant": (
                            "roles/cloudtrace.user (probe could not reach the provider)"
                        ),
                    }
                ],
            },
            {
                "id": "con_…COLL",
                "display_name": "Ruhu estate collector",
                "kind": "COLLECTOR",
                "provider": "SOLVAN_COLLECTOR",
                "credential_posture": "CUSTOMER_SIDE_NONE",
                "classification": "CONFIDENTIAL",
                "residency_region": "europe-west1",
                "external_resource_kind": None,
                "external_resource_id": None,
                "workload_region": None,
                "lifecycle": "PENDING",
                "availability": "NOT_CONFIGURED",
                "availability_reason_code": "NEVER_PROBED",
                "availability_explanation": (
                    "this connection has never been probed, so nothing about it is proven"
                ),
                "availability_missing_grant": None,
                "availability_remediation_kind": "RETRY_PROBE",
                "availability_reference": None,
                "availability_receipt_ref": "probe://absent",
                "last_probe_result": None,
                "last_success_at": None,
                "proof_expires_at": None,
                "holds_stored_secret": False,
                "read_only_scope_verified": False,
                "capabilities": [
                    {
                        "capability": "telemetry.forward",
                        "available": False,
                        "outcome": "NOT_PROBED",
                        "missing_grant": "actuator deployment",
                    },
                    {
                        "capability": "action.execute",
                        "available": False,
                        "outcome": "NOT_PROBED",
                        "missing_grant": "customer policy allowlist",
                    },
                ],
            },
        ],
        "actuators": [
            {
                "id": "atr_…RUN1",
                "connection_id": "con_…COLL",
                "host_kind": "CLOUD_RUN",
                "production_eligible": True,
                "risk_accepted": False,
                "principal_email": "solvan-actuator@ruhu-prod.iam.gserviceaccount.com",
                "posture": "COLLECTOR",
                "image_digest": "sha256:" + "c" * 64,
                "actuator_version": "0.1.0",
                "policy_hash": None,
                "customer_audit_configured": False,
                "kill_switch_engaged": False,
                "status": "REGISTERED",
                "last_poll_at": None,
            },
        ],
        "github": {
            "repositories": [
                {
                    "id": "ghr_…DEMO",
                    "owner": "solvan-demo",
                    "name": "payments-service",
                    "default_branch": "main",
                    "classification": "INTERNAL",
                    "status": "ACTIVE",
                    "last_probe_result": "SUCCEEDED",
                    "policy_hash": "sha256:" + "a" * 64,
                    "allowed_operations_json": [
                        "CREATE_PULL_REQUEST",
                        "SYNC_PULL_REQUEST",
                        "MERGE_PULL_REQUEST",
                    ],
                }
            ],
            "pull_requests": [
                {
                    "id": "ghp_…DEMO",
                    "repository_id": "ghr_…DEMO",
                    "owner": "solvan-demo",
                    "name": "payments-service",
                    "external_number": 42,
                    "html_url": "https://github.com/solvan-demo/payments-service/pull/42",
                    "branch_name": "solvan/repair/pool-leak",
                    "base_commit_sha": "a" * 40,
                    "head_commit_sha": "b" * 40,
                    "title": "Repair connection-pool leak",
                    "status": "OPEN",
                    "latest_checks_state": "PASSING",
                    "mergeable_state": "clean",
                    "merge_commit_sha": None,
                    "patch_artifact_id": "pat_…DEMO",
                    "patch_digest": "sha256:" + "b" * 64,
                    "created_at": "2026-08-09T00:00:00+00:00",
                    "updated_at": "2026-08-09T00:05:00+00:00",
                }
            ],
            "operations": [
                {
                    "id": "gho_…DEMO",
                    "repository_id": "ghr_…DEMO",
                    "pull_request_id": "ghp_…DEMO",
                    "operation": "SYNC_PULL_REQUEST",
                    "status": "SUCCEEDED",
                    "external_number": 42,
                    "response_hash": "sha256:" + "c" * 64,
                    "receipt_ref": "gs://demo-evidence/github/gho-demo.json",
                    "error_class": None,
                    "actor_principal": (
                        "serviceAccount:solvan-coordinator@example.iam.gserviceaccount.com"
                    ),
                    "created_at": "2026-08-09T00:05:00+00:00",
                    "completed_at": "2026-08-09T00:05:01+00:00",
                }
            ],
            "webhooks": [
                {
                    "event_name": "pull_request",
                    "action": "synchronize",
                    "processing_status": "PROCESSED",
                    "received_at": "2026-08-09T00:05:00+00:00",
                    "processed_at": "2026-08-09T00:05:01+00:00",
                }
            ],
        },
    }
