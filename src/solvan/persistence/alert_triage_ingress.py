"""Durable Cloud Monitoring delivery and semantic-event intake."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.alert_triage import (
    AlertIngressError,
    AlertIngressReceipt,
    CanonicalCloudMonitoringAlert,
    CloudMonitoringSourceBinding,
    PubSubEnvelopeIdentity,
    VerifiedPushIdentity,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_triage_source import AlertSourcePersistenceMixin
from solvan.persistence.alert_triage_types import jsonb


class AlertIngressPersistenceMixin(AlertSourcePersistenceMixin):
    """Cloud SQL transport identity, deduplication, and event authority."""

    _connection: Connection[Any]

    def record_committed_delivery(
        self,
        *,
        binding: CloudMonitoringSourceBinding,
        identity: VerifiedPushIdentity,
        alert: CanonicalCloudMonitoringAlert,
    ) -> AlertIngressReceipt:
        if alert.envelope.subscription_name != binding.subscription_name:
            raise AlertIngressError("PUBSUB_SUBSCRIPTION_MISMATCH")
        if alert.scoping_project_id != binding.scoping_project_id:
            raise AlertIngressError("SCOPING_PROJECT_MISMATCH")
        if identity.email.lower() != binding.push_principal.lower():
            raise AlertIngressError("PUSH_PRINCIPAL_MISMATCH")
        if identity.audience != binding.oidc_audience:
            raise AlertIngressError("OIDC_AUDIENCE_MISMATCH")
        self.require_monitored_project(
            binding=binding, monitored_project_id=alert.monitored_resource_project_id
        )
        scope_values = binding.scope.canonical_dict()
        receive_attempt_id = new_identifier("ala")
        proposed_delivery_id = new_identifier("ald")
        proposed_event_id = new_identifier("ale")
        proposed_generation_id = new_identifier("alg")
        values: dict[str, Any] = {
            **scope_values,
            **asdict(binding),
            **asdict(alert),
            "message_id": alert.envelope.message_id,
            "subscription_name": alert.envelope.subscription_name,
            "publish_time": alert.envelope.publish_time,
            "envelope_hash": alert.envelope.envelope_hash,
            "delivery_id": proposed_delivery_id,
            "event_id": proposed_event_id,
            "generation_id": proposed_generation_id,
            "attempt_id": receive_attempt_id,
            "principal": identity.principal,
            "resource_labels": jsonb(alert.resource_labels),
            "normalized_labels": jsonb(alert.normalized_labels),
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("SET CONSTRAINTS ALL DEFERRED")
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (
                    ":".join(
                        (
                            binding.scope.digest(),
                            binding.source_identity_id,
                            alert.provider_incident_key,
                            alert.transition_discriminator,
                        )
                    ),
                ),
            )
            cursor.execute(
                """SELECT id,semantic_event_id,envelope_hash,outcome
                     FROM solvan_alerts.alert_ingress_deliveries
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND connection_id=%(connection_id)s
                      AND connection_epoch=%(connection_epoch)s
                      AND subscription_name=%(subscription_name)s
                      AND pubsub_message_id=%(message_id)s FOR UPDATE""",
                values,
            )
            duplicate = cursor.fetchone()
            if duplicate is not None:
                if duplicate["envelope_hash"] != alert.envelope.envelope_hash:
                    raise AlertIngressError("TRANSPORT_IDENTITY_HASH_CONFLICT")
                if duplicate["outcome"] != "COMMITTED":
                    raise AlertIngressError("TRANSPORT_DELIVERY_PREVIOUSLY_REFUSED")
                values["delivery_id"] = str(duplicate["id"])
                values["event_id"] = str(duplicate["semantic_event_id"])
                self._insert_receive_attempt(cursor=cursor, values=values)
                cursor.execute(
                    """SELECT id FROM solvan_alerts.alert_provider_generations
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND provider_source_identity_id=%(source_identity_id)s
                          AND provider_incident_key=%(provider_incident_key)s
                          AND started_at=%(started_at)s""",
                    values,
                )
                generation = cursor.fetchone()
                return AlertIngressReceipt(
                    delivery_id=values["delivery_id"],
                    receive_attempt_id=receive_attempt_id,
                    semantic_event_id=values["event_id"],
                    provider_generation_id=None if generation is None else str(generation["id"]),
                    outcome="COMMITTED",
                    reason_code="DUPLICATE_TRANSPORT_RECONCILED",
                    created=False,
                )
            cursor.execute(
                """SELECT id FROM solvan_alerts.alert_events
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND provider_source_identity_id=%(source_identity_id)s
                      AND provider_incident_key=%(provider_incident_key)s
                      AND transition_discriminator=%(transition_discriminator)s""",
                values,
            )
            existing_event = cursor.fetchone()
            event_created = existing_event is None
            if existing_event is not None:
                values["event_id"] = str(existing_event["id"])
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_ingress_deliveries (
                      organization_id,project_id,environment_id,id,cell_id,placement_epoch,
                      connection_id,connection_epoch,provider_kind,provider_source_identity_id,
                      topic_binding_receipt_ref,subscription_name,authenticated_push_principal,
                      oidc_audience,pubsub_message_id,publish_time,envelope_hash,semantic_event_id,
                      outcome,reason_code,raw_payload_hash,classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(delivery_id)s,
                      %(cell_id)s,%(placement_epoch)s,%(connection_id)s,%(connection_epoch)s,
                      'CLOUD_MONITORING',%(source_identity_id)s,%(topic_binding_receipt_ref)s,
                      %(subscription_name)s,%(principal)s,%(oidc_audience)s,%(message_id)s,
                      %(publish_time)s,%(envelope_hash)s,%(event_id)s,'COMMITTED',
                      'SEMANTIC_EVENT_COMMITTED',%(raw_payload_hash)s,%(classification)s,
                      %(retention_policy_revision)s)""",
                values,
            )
            if event_created:
                cursor.execute(
                    """INSERT INTO solvan_alerts.alert_events (
                          organization_id,project_id,environment_id,id,cell_id,placement_epoch,
                          first_admitted_delivery_id,provider_source_identity_id,
                          observed_connection_id,observed_connection_epoch,provider_incident_key,
                          lifecycle_state,transition_discriminator,transition_sequence,started_at,
                          ended_at,observed_at,scoping_project_id,monitored_resource_project_id,
                          resource_type,resource_labels_json,normalized_labels_json,
                          provider_severity,canonical_projection_version,canonical_event_hash,
                          classification,retention_policy_revision)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(event_id)s,
                          %(cell_id)s,%(placement_epoch)s,%(delivery_id)s,%(source_identity_id)s,
                          %(connection_id)s,%(connection_epoch)s,%(provider_incident_key)s,
                          %(lifecycle_state)s,%(transition_discriminator)s,
                          %(transition_sequence)s,%(started_at)s,%(ended_at)s,%(observed_at)s,
                          %(scoping_project_id)s,%(monitored_resource_project_id)s,
                          %(resource_type)s,%(resource_labels)s,%(normalized_labels)s,
                          %(provider_severity)s,'cloud-monitoring/1.2',%(canonical_event_hash)s,
                          %(classification)s,%(retention_policy_revision)s)""",
                    values,
                )
            # The generation lock prevents a close-first/open-late race from
            # reopening the provider projection.
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (
                    ":".join(
                        (
                            binding.scope.digest(),
                            binding.source_identity_id,
                            alert.provider_incident_key,
                            alert.started_at.isoformat(),
                        )
                    ),
                ),
            )
            cursor.execute(
                """SELECT id,provider_state_projection FROM solvan_alerts.alert_provider_generations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND provider_source_identity_id=%(source_identity_id)s
                      AND provider_incident_key=%(provider_incident_key)s
                      AND started_at=%(started_at)s FOR UPDATE""",
                values,
            )
            generation = cursor.fetchone()
            occurrence_kind = "TRANSITION" if event_created else "RENOTIFICATION"
            if generation is None:
                cursor.execute(
                    """INSERT INTO solvan_alerts.alert_provider_generations (
                          organization_id,project_id,environment_id,id,
                          provider_source_identity_id,provider_incident_key,started_at,
                          first_semantic_event_id,last_semantic_event_id,
                          provider_state_projection,classification,retention_policy_revision)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                          %(generation_id)s,%(source_identity_id)s,%(provider_incident_key)s,
                          %(started_at)s,%(event_id)s,%(event_id)s,%(lifecycle_state)s,
                          %(classification)s,%(retention_policy_revision)s)""",
                    values,
                )
            else:
                values["generation_id"] = str(generation["id"])
                if (
                    generation["provider_state_projection"] == "CLOSED"
                    and alert.lifecycle_state == "OPEN"
                ):
                    occurrence_kind = "LATE_HISTORY"
                elif alert.lifecycle_state == "CLOSED":
                    cursor.execute(
                        """UPDATE solvan_alerts.alert_provider_generations
                              SET provider_state_projection='CLOSED',
                                  last_semantic_event_id=%(event_id)s,
                                  row_version=row_version+1,updated_at=now()
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                              AND id=%(generation_id)s""",
                        values,
                    )
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_provider_generation_occurrences (
                      organization_id,project_id,environment_id,id,delivery_id,semantic_event_id,
                      provider_generation_id,observed_at,source_state,occurrence_kind,
                      safe_reason_code,classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(occurrence_id)s,
                      %(delivery_id)s,%(event_id)s,%(generation_id)s,%(observed_at)s,
                      %(lifecycle_state)s,%(occurrence_kind)s,%(safe_reason_code)s,
                      %(classification)s,%(retention_policy_revision)s)""",
                {
                    **values,
                    "occurrence_id": new_identifier("aoc"),
                    "occurrence_kind": occurrence_kind,
                    "safe_reason_code": occurrence_kind,
                },
            )
            self._insert_receive_attempt(cursor=cursor, values=values)
        return AlertIngressReceipt(
            delivery_id=values["delivery_id"],
            receive_attempt_id=receive_attempt_id,
            semantic_event_id=values["event_id"],
            provider_generation_id=values["generation_id"],
            outcome="COMMITTED",
            reason_code="SEMANTIC_EVENT_COMMITTED",
            created=True,
        )

    def record_refused_delivery(
        self,
        *,
        binding: CloudMonitoringSourceBinding,
        envelope: PubSubEnvelopeIdentity,
        reason_code: str,
        authenticated_identity: VerifiedPushIdentity | None,
    ) -> AlertIngressReceipt:
        """Persist a safe refusal without admitting provider semantics."""

        delivery_id = new_identifier("ald")
        attempt_id = new_identifier("ala")
        principal = None if authenticated_identity is None else authenticated_identity.principal
        values = {
            **binding.scope.canonical_dict(),
            **asdict(binding),
            "delivery_id": delivery_id,
            "attempt_id": attempt_id,
            "message_id": envelope.message_id,
            "subscription_name": envelope.subscription_name,
            "publish_time": envelope.publish_time,
            "envelope_hash": envelope.envelope_hash,
            "reason_code": reason_code,
            "principal": principal,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_ingress_deliveries (
                      organization_id,project_id,environment_id,id,cell_id,placement_epoch,
                      connection_id,connection_epoch,provider_kind,provider_source_identity_id,
                      topic_binding_receipt_ref,subscription_name,authenticated_push_principal,
                      oidc_audience,pubsub_message_id,publish_time,envelope_hash,outcome,
                      reason_code,classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(delivery_id)s,
                      %(cell_id)s,%(placement_epoch)s,%(connection_id)s,%(connection_epoch)s,
                      'CLOUD_MONITORING',%(source_identity_id)s,%(topic_binding_receipt_ref)s,
                      %(subscription_name)s,%(principal)s,%(oidc_audience)s,%(message_id)s,
                      %(publish_time)s,%(envelope_hash)s,'REFUSED',%(reason_code)s,
                      %(classification)s,%(retention_policy_revision)s)
                   ON CONFLICT (organization_id,project_id,environment_id,connection_id,
                                connection_epoch,subscription_name,pubsub_message_id)
                   DO NOTHING RETURNING id,envelope_hash""",
                values,
            )
            inserted = cursor.fetchone()
            if inserted is None:
                cursor.execute(
                    """SELECT id,envelope_hash FROM solvan_alerts.alert_ingress_deliveries
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND connection_id=%(connection_id)s
                          AND connection_epoch=%(connection_epoch)s
                          AND subscription_name=%(subscription_name)s
                          AND pubsub_message_id=%(message_id)s FOR UPDATE""",
                    values,
                )
                existing = cursor.fetchone()
                if existing is None or existing["envelope_hash"] != envelope.envelope_hash:
                    raise AlertIngressError("TRANSPORT_IDENTITY_HASH_CONFLICT")
                values["delivery_id"] = str(existing["id"])
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_ingress_receive_attempts (
                      organization_id,project_id,environment_id,id,delivery_id,
                      authenticated_identity,authentication_result,envelope_hash,
                      failure_reason_code,classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(attempt_id)s,
                      %(delivery_id)s,%(principal)s,'REFUSED',%(envelope_hash)s,
                      %(reason_code)s,%(classification)s,%(retention_policy_revision)s)""",
                values,
            )
        return AlertIngressReceipt(
            delivery_id=str(values["delivery_id"]),
            receive_attempt_id=attempt_id,
            semantic_event_id=None,
            provider_generation_id=None,
            outcome="REFUSED",
            reason_code=reason_code,
            created=inserted is not None,
        )

    def record_response_selected(
        self,
        *,
        scope: Scope,
        receipt: AlertIngressReceipt,
        success: bool,
    ) -> str:
        event_id = new_identifier("alr")
        self._connection.execute(
            """INSERT INTO solvan_alerts.alert_ingress_response_events (
                  organization_id,project_id,environment_id,id,delivery_id,receive_attempt_id,
                  event_kind,write_result,safe_reason_code,classification,
                  retention_policy_revision)
               SELECT %(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      %(delivery_id)s,%(attempt_id)s,%(event_kind)s,NULL,%(reason_code)s,
                      classification,retention_policy_revision
                 FROM solvan_alerts.alert_ingress_deliveries
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(delivery_id)s""",
            {
                **scope.canonical_dict(),
                "id": event_id,
                "delivery_id": receipt.delivery_id,
                "attempt_id": receipt.receive_attempt_id,
                "event_kind": "HTTP_SUCCESS_RESPONSE_SELECTED"
                if success
                else "HTTP_REFUSAL_RESPONSE_SELECTED",
                "reason_code": receipt.reason_code,
            },
        )
        return event_id

    @staticmethod
    def _insert_receive_attempt(*, cursor: Any, values: dict[str, Any]) -> None:
        cursor.execute(
            """INSERT INTO solvan_alerts.alert_ingress_receive_attempts (
                  organization_id,project_id,environment_id,id,delivery_id,
                  authenticated_identity,authentication_result,envelope_hash,
                  classification,retention_policy_revision)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                  %(attempt_id)s,%(delivery_id)s,%(principal)s,'VERIFIED',
                  %(envelope_hash)s,%(classification)s,%(retention_policy_revision)s)""",
            values,
        )
