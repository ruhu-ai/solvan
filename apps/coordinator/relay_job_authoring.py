"""Coordinator-only authorship of one bounded Cloud Monitoring Relay job.

The Evidence Broker has already reserved the ordinary governed Tool call when
this command runs.  It supplies only the semantic, typed monitoring arguments;
this module re-derives the source, Relay transport, profile, graph resource,
limits, region and signing material from Cloud SQL.  It never accepts an
endpoint, credential, Relay address, provider query, or arbitrary adapter
parameter from a caller.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from apps.evidence_broker.contracts import (
    KubernetesMetadataArgs,
    LoggingArgs,
    ManagedPrometheusArgs,
    MonitoringArgs,
    TraceArgs,
)
from solvan.domain import (
    CollectionJobMaterial,
    RelayAdapter,
    Scope,
    canonical_digest,
    new_identifier,
)
from solvan.persistence.relay_store import PostgresRelayStore, RelayConflict
from solvan.platform.relay_signing import KmsSigner


class RelayJobAuthoringError(RuntimeError):
    """The coordinator cannot safely author the requested Relay job."""


RelayObservabilityArguments = (
    MonitoringArgs | ManagedPrometheusArgs | LoggingArgs | TraceArgs | KubernetesMetadataArgs
)


def _relay_specification(arguments: RelayObservabilityArguments) -> dict[str, str]:
    if isinstance(arguments, MonitoringArgs):
        return {
            "expected_tool_name": "cloud_monitoring_query",
            "expected_provider": "CLOUD_MONITORING",
            "expected_capability_key": "METRIC_READ",
            "expected_adapter_key": RelayAdapter.CLOUD_MONITORING.value,
            "operation": "monitoring.time-series.read.v1",
        }
    if isinstance(arguments, ManagedPrometheusArgs):
        return {
            "expected_tool_name": "managed_prometheus_query",
            "expected_provider": "MANAGED_PROMETHEUS",
            "expected_capability_key": "PROMQL_READ",
            "expected_adapter_key": RelayAdapter.MANAGED_PROMETHEUS.value,
            "operation": "prometheus.registered-range.read.v1",
        }
    if isinstance(arguments, LoggingArgs):
        return {
            "expected_tool_name": "cloud_logging_query",
            "expected_provider": "CLOUD_LOGGING",
            "expected_capability_key": "LOG_SEARCH",
            "expected_adapter_key": RelayAdapter.CLOUD_LOGGING.value,
            "operation": "logging.entries.read.v1",
        }
    if isinstance(arguments, TraceArgs):
        return {
            "expected_tool_name": "cloud_trace_read",
            "expected_provider": "CLOUD_TRACE",
            "expected_capability_key": "TRACE_READ",
            "expected_adapter_key": RelayAdapter.CLOUD_TRACE.value,
            "operation": "trace.spans.read.v1",
        }
    if isinstance(arguments, KubernetesMetadataArgs):
        return {
            "expected_tool_name": "kubernetes_metadata_read",
            "expected_provider": "KUBERNETES",
            "expected_capability_key": "KUBERNETES_METADATA_READ",
            "expected_adapter_key": RelayAdapter.KUBERNETES_METADATA.value,
            "operation": "kubernetes.metadata.list.v1",
        }
    raise RelayJobAuthoringError("Relay has no authoring contract for this Tool")


def _relay_parameters(
    *,
    arguments: RelayObservabilityArguments,
    resource_binding_id: str,
    resource_project_id: str,
    resource_name: str,
    window_start: datetime,
    window_end: datetime,
) -> dict[str, object]:
    if isinstance(arguments, MonitoringArgs):
        metric_key = {
            "HTTP_5XX_RATIO": "http_5xx_ratio",
            "HTTP_P95_LATENCY": "p95_latency_ms",
        }.get(arguments.signal_kind)
        if metric_key is None:
            raise RelayJobAuthoringError("Relay SQL monitoring is not yet qualified")
        return {
            "metric_key": metric_key,
            "resource_binding_id": resource_binding_id,
            "resource_project_id": resource_project_id,
            "resource_kind": "CLOUD_RUN_SERVICE",
            "resource_name": resource_name,
            "window_start": window_start.astimezone(UTC).isoformat(),
            "window_end": window_end.astimezone(UTC).isoformat(),
            "alignment_seconds": 60,
            "maximum_points": 900,
        }
    if isinstance(arguments, ManagedPrometheusArgs):
        if arguments.query_template_key not in {
            "http_requests_total",
            "http_error_ratio",
            "http_p95_latency_ms",
        }:
            raise RelayJobAuthoringError("Prometheus query template is not registered")
        return {
            "query_template_key": arguments.query_template_key,
            "resource_binding_id": resource_binding_id,
            "resource_project_id": resource_project_id,
            "service_key": resource_name,
            "window_start": window_start.astimezone(UTC).isoformat(),
            "window_end": window_end.astimezone(UTC).isoformat(),
            "step_seconds": 60,
            "maximum_series": 100,
            "maximum_points": 900,
        }
    if isinstance(arguments, LoggingArgs):
        return {
            "signature_key": arguments.signature_key,
            "resource_binding_id": resource_binding_id,
            "resource_project_id": resource_project_id,
            "service_name": resource_name,
            "window_start": window_start.astimezone(UTC).isoformat(),
            "window_end": window_end.astimezone(UTC).isoformat(),
            "maximum_entries": arguments.maximum_entries,
        }
    if isinstance(arguments, TraceArgs):
        return {
            "trace_id": arguments.trace_id,
            "resource_binding_id": resource_binding_id,
            "resource_project_id": resource_project_id,
            "service_name": resource_name,
            "maximum_spans": 100,
        }
    if isinstance(arguments, KubernetesMetadataArgs):
        return {
            "resource_binding_id": resource_binding_id,
            "namespace": arguments.namespace,
            "resource_kind": arguments.resource_kind,
            "service_key": resource_name,
            "maximum_items": 100,
        }
    raise RelayJobAuthoringError("Relay has no parameter contract for this Tool")


class RelayJobAuthor:
    """Create a signed job only from one live reserved monitoring Tool call."""

    def __init__(
        self,
        *,
        connection: Connection[Any],
        signer: KmsSigner,
        signing_key_id: str,
        signing_key_version: str,
    ) -> None:
        if not signing_key_id or not signing_key_version:
            raise ValueError("Relay job signing key configuration is required")
        self._connection = connection
        self._signer = signer
        self._signing_key_id = signing_key_id
        self._signing_key_version = signing_key_version

    def author_observability_job(
        self,
        *,
        scope: Scope,
        agent_run_id: str,
        tool_call_id: str,
        arguments: RelayObservabilityArguments,
        issued_at: datetime | None = None,
    ) -> str:
        """Persist one signed Relay job for a reserved semantic monitoring Tool.

        A replay returns the existing job.  Every source and resource selector
        below is re-resolved from durable bindings, so changing the JSON request
        cannot redirect a customer-local read.
        """

        now = issued_at or datetime.now(UTC)
        if now.tzinfo is None:
            raise ValueError("Relay job issue time must be timezone-aware")
        specification = _relay_specification(arguments)
        if isinstance(arguments, MonitoringArgs | ManagedPrometheusArgs | LoggingArgs):
            window_start, window_end = arguments.checked_window()
        else:
            window_start = window_end = now
        canonical_arguments = json.dumps(
            arguments.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        arguments_hash = "sha256:" + hashlib.sha256(canonical_arguments.encode()).hexdigest()
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT id FROM solvan_relay.collection_jobs
                     WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                       AND environment_id=%(environment_id)s AND tool_call_id=%(tool_call_id)s
                     FOR SHARE""",
                {**scope.canonical_dict(), "tool_call_id": tool_call_id},
            )
            existing = cur.fetchone()
            if existing is not None:
                return str(existing["id"])

            cur.execute(
                """SELECT r.id AS agent_run_id,r.incident_id,r.input_hash,
                          incident.production_graph_snapshot_id,
                          call.id AS tool_call_id,call.arguments_hash,
                          profile.profile_key,profile.profile_version,
                          profile.profile_material_hash,
                          accepted.ordinal AS profile_ordinal,accepted.tool_key,
                          accepted.tool_version,accepted.connection_id,
                          accepted.connection_epoch,accepted.capability_receipt_id,
                          accepted.capability_receipt_hash,
                          source_binding.id AS source_binding_id,
                          source_binding.enrollment_id,source_binding.enrollment_epoch,
                          source_binding.adapter_key,source_binding.adapter_revision,
                          enrollment.relay_connection_id,enrollment.placement_epoch,
                          enrollment.cell_id,enrollment.connector_catalog_digest,
                          enrollment.redaction_revision,enrollment.classification_ceiling,
                          enrollment.region,
                          relay_connection.connection_epoch AS relay_connection_epoch,
                          service.service_key,
                          node.node_id AS resource_binding_id,node.resource_ref,
                          node.external_project_id,node.node_kind,
                          solvan_relay.relay_resource_binding_hash(
                            1,node.organization_id,node.project_id,node.environment_id,
                            node.cell_id,node.placement_epoch,node.snapshot_id,
                            snapshot.material_hash,node.node_id,node.node_key,node.node_kind,
                            node.resource_ref,node.external_project_id,
                            coalesce(node.data_classification,graph_scope.classification_ceiling),
                            node.region,node.instrumentation_state,node.observation_id,
                            node.source_key,node.source_revision
                          ) AS resource_binding_hash
                     FROM solvan.agent_runs r
                     JOIN solvan.incidents incident
                       ON (incident.organization_id,incident.project_id,incident.environment_id,
                           incident.id)=(r.organization_id,r.project_id,r.environment_id,r.incident_id)
                     JOIN solvan.services service
                       ON (service.organization_id,service.project_id,
                           service.environment_id,service.id)=
                          (incident.organization_id,incident.project_id,incident.environment_id,
                           incident.primary_service_id)
                     JOIN solvan.tool_calls call
                       ON (call.organization_id,call.project_id,call.environment_id,
                           call.agent_run_id,
                           call.id)=(r.organization_id,r.project_id,r.environment_id,r.id,
                           %(tool_call_id)s)
                     JOIN solvan_operability.agent_run_tool_bindings profile
                       ON (profile.organization_id,profile.project_id,profile.environment_id,
                           profile.agent_run_id)=(r.organization_id,r.project_id,r.environment_id,r.id)
                     JOIN solvan_operability.agent_run_accepted_tool_bindings accepted
                       ON (accepted.organization_id,accepted.project_id,accepted.environment_id,
                           accepted.agent_run_id,accepted.tool_key)=
                          (profile.organization_id,profile.project_id,profile.environment_id,
                           profile.agent_run_id,call.tool_name)
                     JOIN solvan_relay.relay_source_bindings source_binding
                       ON (source_binding.organization_id,source_binding.project_id,
                           source_binding.environment_id,source_binding.source_connection_id,
                           source_binding.source_connection_epoch)=
                          (accepted.organization_id,accepted.project_id,accepted.environment_id,
                           accepted.connection_id,accepted.connection_epoch)
                     JOIN solvan_relay.relay_enrollments enrollment
                       ON (enrollment.organization_id,enrollment.project_id,
                           enrollment.environment_id,
                           enrollment.id,enrollment.enrollment_epoch)=
                          (source_binding.organization_id,source_binding.project_id,
                           source_binding.environment_id,source_binding.enrollment_id,
                           source_binding.enrollment_epoch)
                     JOIN solvan.tenant_connections relay_connection
                       ON (relay_connection.organization_id,relay_connection.project_id,
                           relay_connection.environment_id,relay_connection.id)=
                          (enrollment.organization_id,enrollment.project_id,
                           enrollment.environment_id,enrollment.relay_connection_id)
                     JOIN solvan_graph.graph_nodes node
                       ON (node.organization_id,node.project_id,node.environment_id,node.cell_id,
                           node.placement_epoch,node.snapshot_id,node.resource_ref)=
                          (incident.organization_id,incident.project_id,incident.environment_id,
                           enrollment.cell_id,enrollment.placement_epoch,
                           incident.production_graph_snapshot_id,service.platform_resource)
                     JOIN solvan_graph.graph_snapshots snapshot
                       USING (organization_id,project_id,environment_id,cell_id,
                              placement_epoch,snapshot_id)
                     JOIN solvan_graph.graph_scope_bindings graph_scope
                       USING (organization_id,project_id,environment_id,cell_id,placement_epoch)
                    WHERE r.organization_id=%(organization_id)s AND r.project_id=%(project_id)s
                      AND r.environment_id=%(environment_id)s AND r.id=%(agent_run_id)s
                      AND r.incident_id IS NOT NULL AND r.status IN ('DISPATCHED','RUNNING')
                      AND r.deadline > %(issued_at)s
                      AND call.tool_name=%(expected_tool_name)s
                      AND call.status='RESERVED' AND call.arguments_hash=%(arguments_hash)s
                      AND accepted.provider=%(expected_provider)s
                      AND accepted.capability_key=%(expected_capability_key)s
                      AND accepted.binding_kind='POLICY_SOURCE_CONNECTION'
                      AND source_binding.adapter_key=%(expected_adapter_key)s
                      AND source_binding.lifecycle='READY' AND enrollment.lifecycle='READY'
                      AND enrollment.region=relay_connection.residency_region
                      AND relay_connection.kind='RELAY' AND relay_connection.provider='SOLVAN_RELAY'
                      AND relay_connection.credential_posture='CUSTOMER_SIDE_NONE'
                      AND relay_connection.lifecycle='ENABLED'
                      AND relay_connection.availability='READY'
                      AND node.node_kind='SERVICE'
                      AND node.external_project_id=accepted.external_project_id
                      AND snapshot.status='APPROVED' AND snapshot.material_hash IS NOT NULL
                      AND EXISTS (
                        SELECT 1 FROM solvan_relay.relay_readiness_receipts receipt
                         WHERE (receipt.organization_id,receipt.project_id,receipt.environment_id,
                                receipt.enrollment_id,receipt.enrollment_epoch)=
                               (enrollment.organization_id,enrollment.project_id,enrollment.environment_id,
                                enrollment.id,enrollment.enrollment_epoch)
                           AND receipt.decision='ALLOW' AND receipt.expires_at > %(issued_at)s)
                    FOR SHARE OF r,call,profile,accepted,source_binding,enrollment,
                                 relay_connection,node,snapshot,graph_scope""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "tool_call_id": tool_call_id,
                    "arguments_hash": arguments_hash,
                    "issued_at": now,
                    **specification,
                },
            )
            row = cur.fetchone()
            if row is None:
                raise RelayJobAuthoringError(
                    "reserved Tool call has no current qualified Relay source binding"
                )
            resource_ref = str(row["resource_ref"])
            resource_name = resource_ref.rsplit("/", 1)[-1]
            if not resource_name or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
                for character in resource_name
            ):
                raise RelayJobAuthoringError("approved Graph resource has no closed Cloud Run name")
            if isinstance(arguments, KubernetesMetadataArgs):
                resource_name = str(row["service_key"])
                if not resource_name or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
                    for character in resource_name
                ):
                    raise RelayJobAuthoringError(
                        "approved service has no closed Kubernetes selector"
                    )
            if isinstance(arguments, TraceArgs):
                cur.execute(
                    """SELECT 1 FROM solvan.evidence_items
                         WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                           AND environment_id=%(environment_id)s AND incident_id=%(incident_id)s
                           AND provenance_json->'trace_ids' ? %(trace_id)s LIMIT 1""",
                    {
                        **scope.canonical_dict(),
                        "incident_id": str(row["incident_id"]),
                        "trace_id": arguments.trace_id,
                    },
                )
                if cur.fetchone() is None:
                    raise RelayJobAuthoringError("trace was not discovered in incident evidence")
            parameters = _relay_parameters(
                arguments=arguments,
                resource_binding_id=str(row["resource_binding_id"]),
                resource_project_id=str(row["external_project_id"]),
                resource_name=resource_name,
                window_start=window_start,
                window_end=window_end,
            )
            material = CollectionJobMaterial(
                collection_job_id=new_identifier("rcj"),
                enrollment_id=str(row["enrollment_id"]),
                enrollment_epoch=int(row["enrollment_epoch"]),
                relay_connection_id=str(row["relay_connection_id"]),
                relay_connection_epoch=int(row["relay_connection_epoch"]),
                source_binding_id=str(row["source_binding_id"]),
                source_connection_id=str(row["connection_id"]),
                source_connection_epoch=int(row["connection_epoch"]),
                placement_epoch=int(row["placement_epoch"]),
                cell_id=str(row["cell_id"]),
                agent_run_id=str(row["agent_run_id"]),
                tool_call_id=str(row["tool_call_id"]),
                tool_arguments_hash=str(row["arguments_hash"]),
                incident_id=str(row["incident_id"]),
                profile_key=str(row["profile_key"]),
                profile_version=str(row["profile_version"]),
                profile_material_hash=str(row["profile_material_hash"]),
                profile_ordinal=int(row["profile_ordinal"]),
                tool_key=str(row["tool_key"]),
                tool_version=str(row["tool_version"]),
                capability_receipt_id=str(row["capability_receipt_id"]),
                capability_receipt_hash=str(row["capability_receipt_hash"]),
                connector_catalog_digest=str(row["connector_catalog_digest"]),
                adapter_key=RelayAdapter(specification["expected_adapter_key"]),
                adapter_revision=str(row["adapter_revision"]),
                operation=str(specification["operation"]),
                typed_parameters=parameters,
                parameters_hash=canonical_digest(parameters),
                resource_binding_id=str(row["resource_binding_id"]),
                graph_snapshot_id=str(row["production_graph_snapshot_id"]),
                resource_binding_hash=str(row["resource_binding_hash"]),
                window_start=window_start,
                window_end=window_end,
                maximum_pages=(
                    1
                    if isinstance(
                        arguments, ManagedPrometheusArgs | TraceArgs | KubernetesMetadataArgs
                    )
                    else 10
                ),
                maximum_items=1000,
                maximum_bytes=1_048_576,
                maximum_calls=(
                    1
                    if isinstance(
                        arguments, ManagedPrometheusArgs | TraceArgs | KubernetesMetadataArgs
                    )
                    else 10
                ),
                maximum_attempts=2,
                redaction_revision=str(row["redaction_revision"]),
                classification_ceiling=str(row["classification_ceiling"]),
                residency_region=str(row["region"]),
                input_hash=str(row["input_hash"]),
                issued_at=now,
                expires_at=now + timedelta(seconds=90),
                job_digest="sha256:" + "0" * 64,
                job_nonce=secrets.token_urlsafe(24),
                signing_key_id=self._signing_key_id,
                signature_base64="",
            )
            job_digest = canonical_digest(material.signed_projection(scope=scope))
            signature = self._signer.sign_sha256(
                bytes.fromhex(job_digest.removeprefix("sha256:")),
                key_version=self._signing_key_version,
            )
            signed = replace(
                material,
                job_digest=job_digest,
                signature_base64=base64.b64encode(signature).decode("ascii"),
            )
            try:
                return str(
                    PostgresRelayStore(self._connection).create_collection_job(
                        scope=scope,
                        material=signed,
                        wakeup_outbox_event_id=new_identifier("evt"),
                        wakeup_idempotency_key=f"relay-job:{tool_call_id}",
                    )
                )
            except RelayConflict as error:
                raise RelayJobAuthoringError(str(error)) from error
