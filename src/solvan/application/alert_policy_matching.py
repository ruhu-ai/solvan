"""Deterministic matching and fingerprinting for approved Alert policies."""

from __future__ import annotations

import hashlib
import json

from solvan.application.alert_triage import (
    AlertPolicyError,
    AlertPolicyRevisionV1,
    AlertSelectorV1,
    CanonicalCloudMonitoringAlert,
)
from solvan.application.workspace_hashing import canonical_sha256


def canonical_json_hash(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def canonical_resource_identifier(alert: CanonicalCloudMonitoringAlert) -> str | None:
    """Derive one closed provider resource identity without fuzzy matching."""

    labels = alert.resource_labels
    project = alert.monitored_resource_project_id
    if alert.resource_type == "cloud_run_revision":
        service = labels.get("service_name")
        location = labels.get("location")
        if service and location:
            return (
                f"//run.googleapis.com/projects/{project}/locations/{location}/services/{service}"
            )
    if alert.resource_type in {"cloudsql_database", "cloudsql_instance"}:
        database = labels.get("database_id") or labels.get("instance_id")
        if database:
            return f"//sqladmin.googleapis.com/projects/{project}/instances/{database}"
    if alert.resource_type in {"k8s_container", "k8s_pod"}:
        cluster = labels.get("cluster_name")
        location = labels.get("location")
        namespace = labels.get("namespace_name")
        pod = labels.get("pod_name")
        if cluster and location and namespace and pod:
            return (
                f"//container.googleapis.com/projects/{project}/locations/{location}/"
                f"clusters/{cluster}/namespaces/{namespace}/pods/{pod}"
            )
    return None


def canonical_alert_field(
    alert: CanonicalCloudMonitoringAlert, field: str, key: str | None = None
) -> str | None:
    values = {
        "SOURCE_RULE_ID": alert.normalized_labels.get("policy_name"),
        "SOURCE_STATE": alert.lifecycle_state,
        "PROVIDER_SEVERITY": alert.provider_severity,
        "RESOURCE_KIND": alert.resource_type,
        "RESOURCE_IDENTIFIER": canonical_resource_identifier(alert),
    }
    if field == "NORMALIZED_LABEL":
        return None if key is None else alert.resource_labels.get(key)
    return values.get(field)


def alert_selector_matches(
    *, selector: AlertSelectorV1, alert: CanonicalCloudMonitoringAlert
) -> bool:
    results = []
    for clause in selector.clauses:
        observed = canonical_alert_field(alert, str(clause.field), clause.key)
        accepted = {value.casefold() for value in clause.values}
        results.append(observed is not None and observed.casefold() in accepted)
    return all(results) if selector.combine == "ALL_OF" else any(results)


def alert_fingerprint(
    *,
    policy: AlertPolicyRevisionV1,
    source_identity_id: str,
    target_node_key: str,
    alert: CanonicalCloudMonitoringAlert,
) -> str:
    selected: dict[str, str] = {}
    for field in policy.selector.fingerprint_fields:
        if field.startswith("normalized_labels."):
            key = field.split(".", 1)[1]
            value = alert.resource_labels.get(key)
        else:
            value = canonical_alert_field(alert, field.upper())
        if value is None:
            raise AlertPolicyError("fingerprint input is absent from the canonical alert")
        selected[field] = value
    return canonical_sha256(
        {
            "alert_material_hash": policy.alert_material_hash,
            "provider_source_identity_id": source_identity_id,
            "selected_fields": selected,
            "target_node_key": target_node_key,
        }
    )
