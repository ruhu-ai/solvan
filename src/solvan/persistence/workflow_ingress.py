"""Deduplicated event ingress and incident opening for the workflow store."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.ports import (
    IncidentDisposition,
    IncidentOpenRequest,
    IncidentOpenResult,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.postgres_types import (
    IngressDisposition as IngressDisposition,
)
from solvan.persistence.postgres_types import (
    IngressResult as IngressResult,
)


class WorkflowIngressMixin:
    _connection: Connection[Any]

    def ingest_event(
        self,
        *,
        scope: Scope,
        source: str,
        source_event_id: str,
        event_type: str,
        payload_ref: str,
        payload_hash: str,
    ) -> IngressResult:
        """Persist a canonical event once; duplicates return the original ledger row."""

        event_id = new_identifier("evt")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan.inbox_events
                  (organization_id, project_id, environment_id, id, source,
                   source_event_id, event_type, payload_ref, payload_hash)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(event_id)s, %(source)s, %(source_event_id)s, %(event_type)s,
                    %(payload_ref)s, %(payload_hash)s)
                  ON CONFLICT (organization_id, project_id, environment_id,
                    source, source_event_id) DO NOTHING
                  RETURNING id, processing_state""",
                {
                    **scope.canonical_dict(),
                    "event_id": event_id,
                    "source": source,
                    "source_event_id": source_event_id,
                    "event_type": event_type,
                    "payload_ref": payload_ref,
                    "payload_hash": payload_hash,
                },
            )
            row = cursor.fetchone()
            if row is not None:
                return IngressResult(
                    event_id=row["id"],
                    disposition=IngressDisposition.ACCEPTED,
                    processing_state=row["processing_state"],
                )
            cursor.execute(
                """SELECT id, processing_state FROM solvan.inbox_events
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND source = %(source)s AND source_event_id = %(source_event_id)s""",
                {
                    **scope.canonical_dict(),
                    "source": source,
                    "source_event_id": source_event_id,
                },
            )
            duplicate = cursor.fetchone()
        if duplicate is None:  # defensive: conflict target must be visible after wait
            raise RuntimeError("deduplicated inbox event could not be reloaded")
        return IngressResult(
            event_id=duplicate["id"],
            disposition=IngressDisposition.DUPLICATE,
            processing_state=duplicate["processing_state"],
        )

    def open_or_attach_incident(
        self, *, scope: Scope, request: IncidentOpenRequest
    ) -> IncidentOpenResult:
        """Open one active incident per dedupe key or attach to its current projection."""

        incident_id = new_identifier("inc")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan.display_sequences
                  (organization_id, project_id, environment_id, entity_type, next_value)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s, 'INC', 2)
                  ON CONFLICT (organization_id, project_id, environment_id, entity_type)
                  DO UPDATE SET next_value = solvan.display_sequences.next_value + 1
                  RETURNING next_value - 1 AS allocated""",
                scope.canonical_dict(),
            )
            sequence = cursor.fetchone()
            if sequence is None:  # pragma: no cover - INSERT always returns
                raise RuntimeError("display sequence allocation failed")
            display_id = f"INC-{int(sequence['allocated']):04d}"
            cursor.execute(
                """SELECT id FROM solvan.incidents
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND deduplication_key = %(deduplication_key)s
                    AND state IN ('RESOLVED','ESCALATED','UNRESOLVABLE',
                      'FALSE_POSITIVE','CANCELLED')
                  ORDER BY detected_at DESC, id DESC LIMIT 1""",
                {**scope.canonical_dict(), "deduplication_key": request.deduplication_key},
            )
            previous = cursor.fetchone()
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, recurrence_of, production_graph_snapshot_id,
                   detected_at, detection_rule_id, detection_rule_version,
                   trigger_policy_key, trigger_policy_version,
                   deduplication_key, action_budget, repeated_action_limit)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(incident_id)s, %(display_id)s, %(state_machine_version)s,
                    'DETECTED', %(severity)s, %(incident_class)s,
                    %(primary_service_id)s, %(recurrence_of)s,
                    %(production_graph_snapshot_id)s, %(detected_at)s,
                    %(detection_rule_id)s, %(detection_rule_version)s,
                    %(trigger_policy_key)s, %(trigger_policy_version)s,
                    %(deduplication_key)s, %(action_budget)s, %(repeated_action_limit)s)
                  ON CONFLICT (organization_id, project_id, environment_id, deduplication_key)
                    WHERE state NOT IN ('RESOLVED','ESCALATED','UNRESOLVABLE',
                      'FALSE_POSITIVE','CANCELLED')
                  DO NOTHING
                  RETURNING id, display_id, workflow_version""",
                {
                    **scope.canonical_dict(),
                    "incident_id": incident_id,
                    "display_id": display_id,
                    "state_machine_version": request.state_machine_version,
                    "severity": request.severity,
                    "incident_class": request.incident_class,
                    "primary_service_id": request.primary_service_id,
                    "recurrence_of": None if previous is None else previous["id"],
                    "production_graph_snapshot_id": request.production_graph_snapshot_id,
                    "detected_at": request.detected_at,
                    "detection_rule_id": request.detection_rule_id,
                    "detection_rule_version": request.detection_rule_version,
                    "trigger_policy_key": request.trigger_policy_key,
                    "trigger_policy_version": request.trigger_policy_version,
                    "deduplication_key": request.deduplication_key,
                    "action_budget": request.action_budget,
                    "repeated_action_limit": request.repeated_action_limit,
                },
            )
            created = cursor.fetchone()
            if created is not None:
                cursor.execute(
                    """INSERT INTO solvan.outbox_events
                      (organization_id, project_id, environment_id, id, aggregate_type,
                       aggregate_id, aggregate_version, topic, event_type, payload_json,
                       idempotency_key)
                      VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                        %(event_id)s, 'INCIDENT', %(incident_id)s, 1, 'incidents',
                        'IncidentDetected', %(payload)s, %(idempotency_key)s)""",
                    {
                        **scope.canonical_dict(),
                        "event_id": new_identifier("evt"),
                        "incident_id": created["id"],
                        "payload": Jsonb(
                            {
                                "incident_id": created["id"],
                                "display_id": created["display_id"],
                                "state": "DETECTED",
                                "workflow_version": created["workflow_version"],
                            }
                        ),
                        "idempotency_key": f"incident-created:{created['id']}",
                    },
                )
                return IncidentOpenResult(
                    incident_id=created["id"],
                    display_id=created["display_id"],
                    workflow_version=created["workflow_version"],
                    disposition=IncidentDisposition.CREATED,
                )
            cursor.execute(
                """SELECT id, display_id, workflow_version FROM solvan.incidents
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND deduplication_key = %(deduplication_key)s
                    AND state NOT IN ('RESOLVED','ESCALATED','UNRESOLVABLE',
                      'FALSE_POSITIVE','CANCELLED')""",
                {**scope.canonical_dict(), "deduplication_key": request.deduplication_key},
            )
            active = cursor.fetchone()
        if active is None:  # defensive: conflict target must exist
            raise RuntimeError("active deduplicated incident could not be reloaded")
        return IncidentOpenResult(
            incident_id=active["id"],
            display_id=active["display_id"],
            workflow_version=active["workflow_version"],
            disposition=IncidentDisposition.ATTACHED,
        )
