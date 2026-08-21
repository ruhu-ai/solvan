"""Run-bound, budgeted evidence-tool authorization and ledger writes."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.effective_tool_set import (
    EffectiveToolSetError,
    validate_effective_tool_set_at_boundary,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.evidence_alert_predicates import AlertPredicateEvidenceMixin
from solvan.persistence.evidence_completion import EvidenceCompletionMixin
from solvan.persistence.evidence_errors import ToolAuthorizationError, ToolCallBusy
from solvan.persistence.evidence_types import (
    EvidenceToolReservation,
    GraphNodeResource,
    ProductionGraphSlice,
    StoredEvidence,
)
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore


class PostgresEvidenceToolStore(AlertPredicateEvidenceMixin, EvidenceCompletionMixin):
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def reserve(
        self,
        *,
        invocation_id: str,
        expected_agent_key: str,
        tool_name: str,
        service_id: str,
        arguments_hash: str,
        input_bytes: int,
        otel_span_id: str,
    ) -> EvidenceToolReservation:
        if input_bytes < 1:
            raise ToolAuthorizationError("tool input byte count is invalid")
        if len(otel_span_id) != 16 or any(
            character not in "0123456789abcdef" for character in otel_span_id
        ):
            raise ToolAuthorizationError("tool call span identifier is invalid")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.organization_id, r.project_id, r.environment_id,
                    r.id AS run_id, r.incident_id, r.alert_episode_id,
                    r.budget_json, r.agent_key,
                    coalesce(i.primary_service_id,alert_service.id) AS primary_service_id,
                    coalesce(i.production_graph_snapshot_id,alert_run.graph_snapshot_id)
                      AS production_graph_snapshot_id,
                    s.service_key, s.platform_kind, s.platform_resource,
                    service_node.external_project_id AS service_project_id,
                    service_node.attributes_json->>'region' AS service_workload_region,
                    binding.profile_key,
                    binding.profile_version, binding.identity_ref,
                    binding.runtime_region,binding.effective_tool_set_hash,
                    accepted.ordinal AS accepted_binding_ordinal,
                    accepted.binding_kind,accepted.connection_id,
                    accepted.connection_epoch,accepted.capability_receipt_id,
                    accepted.capability_receipt_hash,accepted.external_project_id,
                    accepted.capability_key,
                    revision.version AS tool_version,
                    revision.required_connection_providers_json,
                    revision.registry_resource, revision.network_policy_hash,
                    revision.max_input_bytes,revision.max_output_bytes,
                    revision.default_call_budget,
                    profile.maximum_parallel_calls,
                    profile.maximum_aggregate_evidence_bytes
                  FROM solvan.agent_runs r
                  LEFT JOIN solvan.investigation_steps step
                    ON (step.organization_id, step.project_id, step.environment_id, step.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.investigation_step_id)
                  LEFT JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (r.organization_id, r.project_id, r.environment_id, r.incident_id)
                  LEFT JOIN solvan_alerts.alert_triage_runs alert_run
                    ON (alert_run.organization_id,alert_run.project_id,
                        alert_run.environment_id,alert_run.agent_run_id)=
                       (r.organization_id,r.project_id,r.environment_id,r.id)
                  LEFT JOIN solvan_graph.graph_nodes alert_target_node
                    ON (alert_target_node.organization_id,
                        alert_target_node.project_id,
                        alert_target_node.environment_id,
                        alert_target_node.cell_id,
                        alert_target_node.placement_epoch,
                        alert_target_node.snapshot_id,
                        alert_target_node.node_key)=
                       (alert_run.organization_id,alert_run.project_id,
                        alert_run.environment_id,alert_run.cell_id,
                        alert_run.placement_epoch,alert_run.graph_snapshot_id,
                        alert_run.target_node_key)
                   AND alert_target_node.node_kind='SERVICE'
                  LEFT JOIN solvan.services alert_service
                    ON (alert_service.organization_id,alert_service.project_id,
                        alert_service.environment_id,
                        alert_service.platform_resource)=
                       (alert_target_node.organization_id,
                        alert_target_node.project_id,
                        alert_target_node.environment_id,
                        alert_target_node.resource_ref)
                   AND alert_service.lifecycle='ACTIVE'
                  JOIN solvan.services s
                    ON (s.organization_id, s.project_id, s.environment_id, s.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        coalesce(i.primary_service_id,alert_service.id))
                  -- Specification 13 §4.2. The project a read addresses comes
                  -- from the frozen graph node, not from the tenancy row. The
                  -- tenancy row holds one project per Solvan project, which
                  -- §4.3 removes; the graph node holds the project this service
                  -- actually runs in, in the snapshot this incident pinned.
                  -- LEFT, so a snapshot with no service node refuses with its
                  -- own reason below rather than looking like an unauthorized
                  -- tool. A missing address and a missing permission are
                  -- different problems and an operator must be able to tell.
                  LEFT JOIN solvan.production_graph_nodes service_node
                    ON (service_node.organization_id, service_node.project_id,
                        service_node.environment_id, service_node.snapshot_id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        coalesce(i.production_graph_snapshot_id,alert_run.graph_snapshot_id))
                   AND service_node.node_kind = 'SERVICE'
                   AND service_node.resource_ref = s.platform_resource
                  JOIN solvan_operability.agent_run_tool_bindings binding
                    ON (binding.organization_id,binding.project_id,
                        binding.environment_id,binding.agent_run_id)
                     = (r.organization_id,r.project_id,r.environment_id,r.id)
                  JOIN solvan_operability.agent_run_accepted_tool_bindings accepted
                    ON (accepted.organization_id,accepted.project_id,
                        accepted.environment_id,accepted.agent_run_id)=
                       (binding.organization_id,binding.project_id,
                        binding.environment_id,binding.agent_run_id)
                   AND accepted.tool_key=%(tool_name)s
                  JOIN solvan_operability.tool_revisions revision
                    ON (revision.tool_key,revision.version)
                     = (accepted.tool_key,accepted.tool_version)
                  JOIN solvan_operability.tool_profile_revisions profile
                    ON (profile.profile_key,profile.version)=
                       (binding.profile_key,binding.profile_version)
                  JOIN solvan_operability.tool_revision_requesters requester
                    ON (requester.tool_key,requester.tool_version,requester.requester_key)
                     = (revision.tool_key,revision.version,r.agent_key)
                  WHERE r.invocation_id = %(invocation_id)s
                    AND r.agent_key = %(expected_agent_key)s
                    AND r.status IN ('DISPATCHED','RUNNING') AND r.deadline > now()
                    AND ((r.incident_id IS NOT NULL
                          AND step.allowed_tool_names_json ? %(tool_name)s)
                         OR (r.alert_episode_id IS NOT NULL
                             AND alert_run.id IS NOT NULL))
                    AND revision.lifecycle = 'APPROVED'
                  FOR UPDATE OF r""",
                {
                    "invocation_id": invocation_id,
                    "expected_agent_key": expected_agent_key,
                    "tool_name": tool_name,
                },
            )
            runs = cursor.fetchall()
            if not runs:
                raise ToolAuthorizationError("invocation or allowed tool is unavailable")
            if len(runs) != 1:
                raise ToolAuthorizationError(
                    "frozen Alert target does not resolve to exactly one service"
                )
            run = runs[0]
            if input_bytes > int(run["max_input_bytes"]):
                raise ToolAuthorizationError("tool input exceeds its approved byte ceiling")
            run_scope = Scope(
                str(run["organization_id"]),
                str(run["project_id"]),
                str(run["environment_id"]),
            )
            effective = PostgresToolCatalogStore(self._connection).load_bound_effective_tool_set(
                scope=run_scope, agent_run_id=str(run["run_id"])
            )
            try:
                validate_effective_tool_set_at_boundary(
                    material=effective.canonical_dict(),
                    expected_hash=str(run["effective_tool_set_hash"]),
                    expected_agent_key=expected_agent_key,
                    expected_tool_key=tool_name,
                )
            except EffectiveToolSetError as error:
                raise ToolAuthorizationError(
                    "Gateway effective Tool set does not match the frozen run binding"
                ) from error
            if service_id != run["primary_service_id"]:
                raise ToolAuthorizationError("requested service is outside the frozen run target")
            if run["service_project_id"] is None:
                # Specification 13 §4.2. Without a service node in the pinned
                # snapshot has no address; guessing would read the caller's project.
                raise ToolAuthorizationError(
                    "the pinned production graph has no service node naming a "
                    "Google Cloud project for this service"
                )
            if not run["service_workload_region"]:
                raise ToolAuthorizationError(
                    "the pinned production graph has no workload region for this service"
                )
            eligible_connection: dict[str, Any] | None = None
            if run["binding_kind"] == "POLICY_SOURCE_CONNECTION":
                if run["external_project_id"] != run["service_project_id"]:
                    raise ToolAuthorizationError(
                        "the frozen Tool binding does not match the incident Graph target"
                    )
                if run["capability_key"] is None:
                    raise ToolAuthorizationError("source Tool binding has no capability class")
                cursor.execute(
                    """SELECT connection.id AS connection_id,
                          connection.connection_epoch::bigint AS connection_epoch,
                          probe.gateway_policy_ref
                     FROM solvan.tenant_connections connection
                     JOIN solvan_operability.tool_probe_receipts probe
                       ON (probe.organization_id,probe.project_id,
                           probe.environment_id,probe.connection_id,
                           probe.connection_epoch)=
                          (connection.organization_id,connection.project_id,
                           connection.environment_id,connection.id,
                           connection.connection_epoch)
                      AND probe.id=%(capability_receipt_id)s
                      AND probe.receipt_hash=%(capability_receipt_hash)s
                     JOIN solvan_onboarding.connection_external_project_coverage coverage
                       ON (coverage.organization_id,coverage.project_id,
                           coverage.environment_id,coverage.connection_id,
                           coverage.connection_epoch)=
                          (probe.organization_id,probe.project_id,
                           probe.environment_id,probe.connection_id,
                           probe.connection_epoch)
                      AND coverage.capability_class=%(capability_key)s
                      AND coverage.external_project_id=%(external_project_id)s
                      AND coverage.workload_region=%(workload_region)s
                      AND coverage.probe_receipt_ref=probe.receipt_ref
                     JOIN solvan_onboarding.environment_external_project_bindings authorized
                       ON (authorized.organization_id,authorized.project_id,
                           authorized.environment_id,authorized.external_project_id)=
                          (coverage.organization_id,coverage.project_id,
                           coverage.environment_id,coverage.external_project_id)
                      AND authorized.workload_region=coverage.workload_region
                      AND authorized.is_current
                    WHERE connection.organization_id=%(organization_id)s
                      AND connection.project_id=%(project_id)s
                      AND connection.environment_id=%(environment_id)s
                      AND connection.id=%(connection_id)s
                      AND connection.connection_epoch=%(connection_epoch)s
                      AND probe.tool_key=%(tool_name)s
                      AND probe.tool_version=%(tool_version)s
                      AND probe.agent_key=%(agent_key)s
                      AND probe.identity_ref=%(identity_ref)s
                      AND probe.registry_resource=%(registry_resource)s
                      AND probe.network_policy_hash=%(network_policy_hash)s
                      AND probe.outcome='PASSED' AND probe.expires_at > now()
                      AND connection.provider=ANY(%(required_providers)s)
                      AND connection.availability IN ('READY','DEGRADED')
                      AND connection.residency_region=%(runtime_region)s
                    """,
                    {
                        **run,
                        "tool_name": tool_name,
                        "required_providers": list(run["required_connection_providers_json"]),
                        "runtime_region": run.get("runtime_region", "europe-west1"),
                        "workload_region": run["service_workload_region"],
                        "capability_key": run["capability_key"],
                    },
                )
                eligible_connections = cursor.fetchall()
                if len(eligible_connections) != 1:
                    raise ToolAuthorizationError(
                        "frozen Tool call requires exactly one current eligible connection"
                    )
                eligible_connection = dict(eligible_connections[0])
            elif run["binding_kind"] != "COMPUTE_ONLY":
                raise ToolAuthorizationError("frozen Tool binding kind is invalid")
            budget = run["budget_json"]
            if not isinstance(budget, dict) or type(budget.get("max_tool_calls")) is not int:
                raise ToolAuthorizationError("stored tool budget is invalid")
            cursor.execute(
                """SELECT COALESCE(sum(request_count), 0) AS request_count
                  FROM solvan.tool_calls
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND agent_run_id = %(run_id)s""",
                run,
            )
            request_total = cursor.fetchone()
            if request_total is None or int(request_total["request_count"]) >= int(
                budget["max_tool_calls"]
            ):
                raise ToolAuthorizationError("agent run tool-call budget is exhausted")
            cursor.execute(
                """SELECT COALESCE(sum(request_count), 0) AS request_count
                     FROM solvan.tool_calls
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND agent_run_id=%(run_id)s
                      AND tool_name=%(tool_name)s""",
                {**run, "tool_name": tool_name},
            )
            tool_total = cursor.fetchone()
            if tool_total is None or int(tool_total["request_count"]) >= int(
                run["default_call_budget"]
            ):
                raise ToolAuthorizationError("Tool revision call budget is exhausted")
            cursor.execute(
                """SELECT id, status, evidence_item_id,
                    created_at < now() - interval '45 seconds' AS stale
                  FROM solvan.tool_calls
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND agent_run_id = %(run_id)s AND tool_name = %(tool_name)s
                    AND arguments_hash = %(arguments_hash)s
                  FOR UPDATE""",
                {**run, "tool_name": tool_name, "arguments_hash": arguments_hash},
            )
            existing = cursor.fetchone()
            scope = Scope(run["organization_id"], run["project_id"], run["environment_id"])

            def reservation(
                call_id: str, existing_evidence_id: str | None = None
            ) -> EvidenceToolReservation:
                return EvidenceToolReservation(
                    call_id=call_id,
                    scope=scope,
                    run_id=str(run["run_id"]),
                    incident_id=(None if run["incident_id"] is None else str(run["incident_id"])),
                    alert_episode_id=(
                        None if run["alert_episode_id"] is None else str(run["alert_episode_id"])
                    ),
                    service_id=service_id,
                    service_key=str(run["service_key"]),
                    platform_kind=str(run["platform_kind"]),
                    platform_resource=str(run["platform_resource"]),
                    graph_snapshot_id=str(run["production_graph_snapshot_id"]),
                    service_project_id=str(run["service_project_id"]),
                    tool_name=tool_name,
                    tool_version=str(run["tool_version"]),
                    profile_key=str(run["profile_key"]),
                    profile_version=str(run["profile_version"]),
                    binding_kind=str(run["binding_kind"]),
                    capability_key=(
                        None if run["capability_key"] is None else str(run["capability_key"])
                    ),
                    connection_id=(
                        None
                        if eligible_connection is None
                        else str(eligible_connection["connection_id"])
                    ),
                    connection_epoch=(
                        None
                        if eligible_connection is None
                        else int(eligible_connection["connection_epoch"])
                    ),
                    identity_ref=str(run["identity_ref"]),
                    gateway_policy_ref=(
                        "COMPUTE_ONLY"
                        if eligible_connection is None
                        else str(eligible_connection["gateway_policy_ref"])
                    ),
                    input_bytes=input_bytes,
                    otel_span_id=otel_span_id,
                    arguments_hash=arguments_hash,
                    max_output_bytes=int(run["max_output_bytes"]),
                    maximum_aggregate_evidence_bytes=int(run["maximum_aggregate_evidence_bytes"]),
                    existing_evidence_id=existing_evidence_id,
                )

            if existing is not None:
                cursor.execute(
                    """UPDATE solvan.tool_calls
                      SET request_count = request_count + 1, last_requested_at = now()
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s AND id = %(call_id)s""",
                    {**scope.canonical_dict(), "call_id": existing["id"]},
                )
                if existing["status"] == "SUCCEEDED":
                    return reservation(str(existing["id"]), str(existing["evidence_item_id"]))
                if existing["status"] == "RESERVED" and not existing["stale"]:
                    raise ToolCallBusy("identical evidence query is already running")
                if existing["status"] == "FAILED":
                    raise ToolAuthorizationError("identical evidence query already failed")
                cursor.execute(
                    """UPDATE solvan.tool_calls SET created_at = now()
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s AND id = %(call_id)s""",
                    {**scope.canonical_dict(), "call_id": existing["id"]},
                )
                return reservation(str(existing["id"]))
            cursor.execute(
                """SELECT count(*) AS active_calls FROM solvan.tool_calls
                     WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                       AND environment_id=%(environment_id)s AND agent_run_id=%(run_id)s
                       AND status='RESERVED'""",
                run,
            )
            active_calls = cursor.fetchone()
            if active_calls is None or int(active_calls["active_calls"]) >= int(
                run["maximum_parallel_calls"]
            ):
                raise ToolAuthorizationError("Tool profile parallel-call budget is exhausted")
            call_id = new_identifier("tcl")
            cursor.execute(
                """INSERT INTO solvan.tool_calls
                  (organization_id, project_id, environment_id, id, agent_run_id,
                   invocation_id, tool_name, arguments_hash, status)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(call_id)s, %(run_id)s, %(invocation_id)s, %(tool_name)s,
                    %(arguments_hash)s, 'RESERVED')""",
                {
                    **scope.canonical_dict(),
                    "call_id": call_id,
                    "run_id": run["run_id"],
                    "invocation_id": invocation_id,
                    "tool_name": tool_name,
                    "arguments_hash": arguments_hash,
                },
            )
            cursor.execute(
                """INSERT INTO solvan_operability.tool_call_receipts
                  (organization_id,project_id,environment_id,tool_call_id,agent_run_id,
                   tool_key,tool_version,profile_key,profile_version,connection_id,
                   accepted_binding_ordinal,binding_kind,connection_epoch,
                   capability_receipt_id,capability_receipt_hash,external_project_id,
                   identity_ref,gateway_policy_ref,
                   gateway_attestation_status,input_bytes,cache_status,otel_span_id)
                  VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                    %(call_id)s,%(run_id)s,%(tool_name)s,%(tool_version)s,
                    %(profile_key)s,%(profile_version)s,%(connection_id)s,
                    %(accepted_binding_ordinal)s,%(binding_kind)s,%(connection_epoch)s,
                    %(capability_receipt_id)s,%(capability_receipt_hash)s,
                    %(external_project_id)s,%(identity_ref)s,%(gateway_policy_ref)s,
                    'PENDING',%(input_bytes)s,'MISS',%(otel_span_id)s)""",
                {
                    **scope.canonical_dict(),
                    "call_id": call_id,
                    "run_id": run["run_id"],
                    "tool_name": tool_name,
                    "tool_version": run["tool_version"],
                    "profile_key": run["profile_key"],
                    "profile_version": run["profile_version"],
                    "connection_id": (
                        None
                        if eligible_connection is None
                        else eligible_connection["connection_id"]
                    ),
                    "connection_epoch": (
                        None
                        if eligible_connection is None
                        else eligible_connection["connection_epoch"]
                    ),
                    "accepted_binding_ordinal": run["accepted_binding_ordinal"],
                    "binding_kind": run["binding_kind"],
                    "capability_receipt_id": run["capability_receipt_id"],
                    "capability_receipt_hash": run["capability_receipt_hash"],
                    "external_project_id": run["external_project_id"],
                    "identity_ref": run["identity_ref"],
                    "gateway_policy_ref": (
                        "COMPUTE_ONLY"
                        if eligible_connection is None
                        else eligible_connection["gateway_policy_ref"]
                    ),
                    "input_bytes": input_bytes,
                    "otel_span_id": otel_span_id,
                },
            )
        return reservation(call_id)

    def requires_customer_relay(self, *, reservation: EvidenceToolReservation) -> bool:
        """Return whether the exact frozen source lacks a Solvan-held credential.

        A customer-side source never silently falls back to a central provider
        read merely because its Relay is unavailable.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            if reservation.connection_id is None or reservation.connection_epoch is None:
                return False
            cursor.execute(
                """SELECT credential_posture FROM solvan.tenant_connections
                     WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                       AND environment_id=%(environment_id)s AND id=%(connection_id)s
                       AND connection_epoch=%(connection_epoch)s""",
                {
                    **reservation.scope.canonical_dict(),
                    "connection_id": reservation.connection_id,
                    "connection_epoch": reservation.connection_epoch,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ToolAuthorizationError("frozen evidence source connection is no longer current")
        return str(row["credential_posture"]) == "CUSTOMER_SIDE_NONE"

    def load_evidence(self, *, scope: Scope, evidence_id: str) -> StoredEvidence:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, content_ref, content_hash, classification
                  FROM solvan.evidence_items
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(evidence_id)s""",
                {**scope.canonical_dict(), "evidence_id": evidence_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise ToolAuthorizationError("completed evidence item is unavailable")
        return StoredEvidence(
            evidence_id=str(row["id"]),
            content_ref=str(row["content_ref"]),
            content_hash=str(row["content_hash"]),
            classification=str(row["classification"]),
        )

    def load_incident_evidence(
        self, *, reservation: EvidenceToolReservation, evidence_id: str
    ) -> StoredEvidence:
        """Load one input only when it belongs to the current incident.

        Derived tools must not turn a tenant-wide evidence identifier into a
        cross-incident read capability.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, content_ref, content_hash, classification
                  FROM solvan.evidence_items
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND incident_id = %(incident_id)s AND id = %(evidence_id)s""",
                {
                    **reservation.scope.canonical_dict(),
                    "incident_id": reservation.incident_id,
                    "evidence_id": evidence_id,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ToolAuthorizationError("input evidence is outside the current incident")
        return StoredEvidence(
            evidence_id=str(row["id"]),
            content_ref=str(row["content_ref"]),
            content_hash=str(row["content_hash"]),
            classification=str(row["classification"]),
        )

    def graph_node(
        self, *, reservation: EvidenceToolReservation, node_id: str, node_kind: str
    ) -> GraphNodeResource:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, node_key, node_kind, resource_ref, external_project_id
                  FROM solvan.production_graph_nodes
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND snapshot_id = %(snapshot_id)s AND id = %(node_id)s
                    AND node_kind = %(node_kind)s AND resource_ref IS NOT NULL""",
                {
                    **reservation.scope.canonical_dict(),
                    "snapshot_id": reservation.graph_snapshot_id,
                    "node_id": node_id,
                    "node_kind": node_kind,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ToolAuthorizationError("graph node is outside the frozen incident snapshot")
        return GraphNodeResource(
            node_id=str(row["id"]),
            node_key=str(row["node_key"]),
            node_kind=str(row["node_kind"]),
            resource_ref=str(row["resource_ref"]),
            external_project_id=str(row["external_project_id"]),
        )

    def graph_slice(self, *, reservation: EvidenceToolReservation) -> ProductionGraphSlice:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """WITH root AS (
                    SELECT id FROM solvan.production_graph_nodes
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND snapshot_id = %(snapshot_id)s
                      AND node_kind = 'SERVICE'
                      AND (resource_ref = %(platform_resource)s
                        OR node_key = %(service_key)s)
                    LIMIT 1
                  ), selected_edges AS (
                    SELECT e.* FROM solvan.production_graph_edges e, root
                    WHERE e.organization_id = %(organization_id)s
                      AND e.project_id = %(project_id)s
                      AND e.environment_id = %(environment_id)s
                      AND e.snapshot_id = %(snapshot_id)s
                      AND (e.source_node_id = root.id OR e.target_node_id = root.id)
                    ORDER BY e.id LIMIT 100
                  )
                  SELECT id, source_node_id, target_node_id, edge_kind, provenance_ref,
                    (SELECT id FROM root) AS root_node_id
                  FROM selected_edges
                  UNION ALL
                  SELECT NULL, NULL, NULL, NULL, NULL, id FROM root
                  LIMIT 101""",
                {
                    **reservation.scope.canonical_dict(),
                    "snapshot_id": reservation.graph_snapshot_id,
                    "platform_resource": reservation.platform_resource,
                    "service_key": reservation.service_key,
                },
            )
            rows = cursor.fetchall()
            root_node_ids = {str(row["root_node_id"]) for row in rows if row["root_node_id"]}
            edges = tuple(
                {
                    key: row[key]
                    for key in (
                        "id",
                        "source_node_id",
                        "target_node_id",
                        "edge_kind",
                        "provenance_ref",
                    )
                }
                for row in rows
                if row["id"] is not None
            )
            node_ids = sorted(
                root_node_ids
                | {str(edge[key]) for edge in edges for key in ("source_node_id", "target_node_id")}
            )
            cursor.execute(
                """SELECT id, node_key, node_kind, resource_ref, external_project_id,
                    classification, provenance_ref
                  FROM solvan.production_graph_nodes
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND snapshot_id = %(snapshot_id)s
                    AND id = ANY(%(node_ids)s::text[])
                  ORDER BY id LIMIT 101""",
                {
                    **reservation.scope.canonical_dict(),
                    "snapshot_id": reservation.graph_snapshot_id,
                    "node_ids": node_ids,
                },
            )
            nodes = tuple(dict(row) for row in cursor.fetchall())
        return ProductionGraphSlice(nodes=nodes, edges=edges)

    def require_discovered_trace(
        self, *, reservation: EvidenceToolReservation, trace_id: str
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT 1 FROM solvan.evidence_items
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND incident_id = %(incident_id)s
                    AND provenance_json->'trace_ids' ? %(trace_id)s
                  LIMIT 1""",
                {
                    **reservation.scope.canonical_dict(),
                    "incident_id": reservation.incident_id,
                    "trace_id": trace_id,
                },
            )
            found = cursor.fetchone()
        if found is None:
            raise ToolAuthorizationError("trace was not discovered in prior incident evidence")
