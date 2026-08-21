"""Source registration and Alert-policy persistence."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.alert_triage import (
    AlertIngressError,
    AlertPolicyError,
    AlertPolicyRevisionV1,
    CloudMonitoringSourceBinding,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_triage_types import (
    AlertPolicyDraftCommit,
    SourceQualificationDelivery,
    SourceRegistration,
    jsonb,
)


class AlertSourcePersistenceMixin:
    """Cloud SQL source, membership, and typed policy authority."""

    _connection: Connection[Any]

    def qualify_source_binding(self, *, scope: Scope, delivery: SourceQualificationDelivery) -> str:
        """Accept the one non-semantic, authenticated provider proof.

        This method writes only the qualification delivery and binding state;
        it intentionally cannot create a provider generation, Alert Episode,
        Agent run, or Incident.
        """

        delivery_id = new_identifier("aqd")
        values = {**scope.canonical_dict(), **asdict(delivery), "delivery_id": delivery_id}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT b.connection_id,b.connection_epoch,b.binding_epoch,b.status,
                          b.subscription_name,
                          push_service_account,oidc_audience,configuration_digest
                     FROM solvan_alerts.alert_source_bindings b
                     JOIN solvan.tenant_connections c
                       ON (c.organization_id,c.project_id,c.environment_id,c.id)=
                          (b.organization_id,b.project_id,b.environment_id,b.connection_id)
                    WHERE b.organization_id=%(organization_id)s AND b.project_id=%(project_id)s
                      AND b.environment_id=%(environment_id)s AND b.id=%(source_binding_id)s
                      AND c.connection_epoch=b.connection_epoch
                      AND c.lifecycle='ENABLED' AND c.availability='READY'
                    FOR UPDATE""",
                values,
            )
            binding = cursor.fetchone()
            if binding is None:
                raise AlertIngressError("SOURCE_BINDING_NOT_FOUND")
            if binding["status"] not in {"PENDING_CONFIGURATION", "QUALIFIED"}:
                raise AlertIngressError("SOURCE_BINDING_NOT_QUALIFIABLE")
            if (
                binding["subscription_name"] != delivery.subscription_name
                or binding["push_service_account"] != delivery.authenticated_push_principal
                or binding["oidc_audience"] != delivery.oidc_audience
                or binding["configuration_digest"] != delivery.configuration_digest
            ):
                raise AlertIngressError("SOURCE_QUALIFICATION_BINDING_MISMATCH")
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_source_qualification_deliveries (
                       organization_id,project_id,environment_id,id,source_binding_id,
                       connection_id,connection_epoch,source_binding_epoch,subscription_name,pubsub_message_id,
                       authenticated_push_principal,oidc_audience,envelope_hash,
                       configuration_digest)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(delivery_id)s,%(source_binding_id)s,%(connection_id)s,
                           %(connection_epoch)s,%(source_binding_epoch)s,%(subscription_name)s,%(pubsub_message_id)s,
                           %(authenticated_push_principal)s,%(oidc_audience)s,
                           %(envelope_hash)s,%(configuration_digest)s)
                   ON CONFLICT (organization_id,project_id,environment_id,
                                source_binding_id,pubsub_message_id)
                   DO UPDATE SET id=solvan_alerts.alert_source_qualification_deliveries.id
                   RETURNING id""",
                {
                    **values,
                    "connection_id": binding["connection_id"],
                    "connection_epoch": binding["connection_epoch"],
                    "source_binding_epoch": binding["binding_epoch"],
                },
            )
            accepted = cursor.fetchone()
            assert accepted is not None
            accepted_id = str(accepted["id"])
            cursor.execute(
                """UPDATE solvan_alerts.alert_source_bindings
                      SET status='QUALIFIED', qualification_delivery_id=%(delivery_id)s,
                          qualified_at=now(),
                          qualified_by_principal=%(authenticated_push_principal)s,
                          updated_at=now(), invalidated_reason=NULL
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(source_binding_id)s""",
                {**values, "delivery_id": accepted_id},
            )
        return accepted_id

    def register_cloud_monitoring_source(
        self,
        *,
        scope: Scope,
        registration: SourceRegistration,
        actor_principal: str,
        idempotency_key: str,
        request_hash: str,
    ) -> str:
        source_id = new_identifier("asi")
        membership_id = new_identifier("asm")
        source_binding_id = new_identifier("asb")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,source_material_hash
                     FROM solvan_alerts.alert_provider_source_identities
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND initial_connection_id=%(connection_id)s
                      AND initial_connection_epoch=%(connection_epoch)s""",
                {**scope.canonical_dict(), **asdict(registration)},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["source_material_hash"] != registration.source_material_hash:
                    raise AlertIngressError("SOURCE_REGISTRATION_CONFLICT")
                return str(existing["id"])
            cursor.execute(
                """SELECT connection_epoch,provider,lifecycle,availability,classification
                     FROM solvan.tenant_connections
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(connection_id)s FOR UPDATE""",
                {**scope.canonical_dict(), **asdict(registration)},
            )
            connection = cursor.fetchone()
            if connection is None:
                raise AlertIngressError("SOURCE_CONNECTION_NOT_FOUND")
            if (
                int(connection["connection_epoch"]) != registration.connection_epoch
                or connection["provider"] != "CLOUD_MONITORING"
                or connection["lifecycle"] != "ENABLED"
                or connection["availability"] != "READY"
                or connection["classification"] != registration.classification
            ):
                raise AlertIngressError("SOURCE_CONNECTION_INELIGIBLE")
            values = {
                **scope.canonical_dict(),
                **asdict(registration),
                "source_id": source_id,
                "membership_id": membership_id,
                "actor_principal": actor_principal,
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
            }
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_provider_source_identities (
                      organization_id,project_id,environment_id,id,provider_kind,
                      initial_connection_id,initial_connection_epoch,scoping_project_id,
                      topic_name,topic_binding_receipt_ref,subscription_name,push_principal,
                      oidc_audience,payload_schema_version,source_material_hash,
                      classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(source_id)s,
                      'CLOUD_MONITORING',%(connection_id)s,%(connection_epoch)s,
                      %(scoping_project_id)s,%(topic_name)s,%(topic_binding_receipt_ref)s,
                      %(subscription_name)s,%(push_principal)s,%(oidc_audience)s,'1.2',
                      %(source_material_hash)s,%(classification)s,
                      %(retention_policy_revision)s)""",
                values,
            )
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_provider_source_epoch_memberships (
                      organization_id,project_id,environment_id,id,source_identity_id,
                      continuity_epoch,successor_connection_id,successor_connection_epoch,
                      compared_material_hash,decision,decision_ref,actor_principal,
                      idempotency_key,request_hash,classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(membership_id)s,%(source_id)s,1,%(connection_id)s,
                      %(connection_epoch)s,%(source_material_hash)s,'CONTINUITY_ACCEPTED',
                      'ref_initial_source_registration',%(actor_principal)s,
                      %(idempotency_key)s,%(request_hash)s,%(classification)s,
                      %(retention_policy_revision)s)""",
                values,
            )
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_provider_source_current_memberships (
                      organization_id,project_id,environment_id,source_identity_id,
                      membership_id,continuity_epoch,connection_id,connection_epoch,
                      classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(source_id)s,%(membership_id)s,1,%(connection_id)s,
                      %(connection_epoch)s,%(classification)s,%(retention_policy_revision)s)""",
                values,
            )
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_source_bindings (
                       organization_id,project_id,environment_id,id,connection_id,
                       connection_epoch,source_identity_id,status,scoping_project_id,
                       topic_name,subscription_name,push_service_account,oidc_audience,
                       payload_schema_version,configuration_digest,
                       pubsub_token_minting_receipt_ref,created_by_principal)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(source_binding_id)s,%(connection_id)s,%(connection_epoch)s,
                           %(source_id)s,'PENDING_CONFIGURATION',%(scoping_project_id)s,
                           %(topic_name)s,%(subscription_name)s,
                           'serviceAccount:' || %(push_principal)s,%(oidc_audience)s,
                           '1.2',%(configuration_digest)s,
                           %(pubsub_token_minting_receipt_ref)s,%(actor_principal)s)""",
                {**values, "source_binding_id": source_binding_id},
            )
        return source_id

    def record_alert_policy_subtype(
        self,
        *,
        scope: Scope,
        policy: AlertPolicyRevisionV1,
        generic_policy_hash: str,
        retention_policy_revision: str,
    ) -> AlertPolicyDraftCommit:
        """Bind typed Alert material to the exact generic approval digest.

        The caller creates the generic trigger-policy draft in the same
        transaction. Its digest includes ``bound_selector_ref``, which is
        derived from every Alert-specific field.
        """

        values = {
            **scope.canonical_dict(),
            "policy_key": policy.policy_key,
            "policy_version": policy.version,
            "policy_hash": generic_policy_hash,
            "alert_material_hash": policy.alert_material_hash,
            "selector": jsonb(policy.selector.model_dump(mode="json")),
            "target_mapping": jsonb(policy.target_mapping.model_dump(mode="json")),
            "severity_mapping": jsonb(policy.severity_mapping.model_dump(mode="json")),
            "mode": policy.mode,
            "triage_profile_ref": policy.triage_profile_ref,
            "incident_profile_ref": policy.incident_profile_ref,
            "escalation_expression": None
            if policy.escalation_expression is None
            else jsonb(policy.escalation_expression.model_dump(mode="json")),
            "admission_expression": None
            if policy.full_incident_admission_expression is None
            else jsonb(policy.full_incident_admission_expression.model_dump(mode="json")),
            "triage_budget": jsonb(policy.triage_budget.model_dump(mode="json")),
            "admission_budget": jsonb(policy.incident_admission_budget.model_dump(mode="json")),
            "episode_horizon_ms": policy.episode_horizon_ms,
            "delivery_policy_ref": policy.delivery_policy_ref,
            "template_ref": policy.template_ref,
            "calibration_receipt_refs": jsonb(list(policy.calibration_receipt_refs)),
            "recommendation_ref": policy.recommendation_ref,
            "classification": policy.classification_ceiling,
            "retention_policy_revision": retention_policy_revision,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_policy_revisions (
                      organization_id,project_id,environment_id,policy_key,policy_version,
                      policy_hash,alert_material_hash,source_kind,selector_json,
                      target_mapping_json,severity_mapping_json,mode,triage_profile_ref,
                      incident_profile_ref,escalation_expression_json,
                      full_incident_admission_expression_json,triage_budget_json,
                      incident_admission_budget_json,episode_horizon_ms,delivery_policy_ref,
                      template_ref,calibration_receipt_refs_json,recommendation_ref,
                      classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(policy_key)s,%(policy_version)s,%(policy_hash)s,
                      %(alert_material_hash)s,'CLOUD_MONITORING',%(selector)s,
                      %(target_mapping)s,%(severity_mapping)s,%(mode)s,
                      %(triage_profile_ref)s,%(incident_profile_ref)s,
                      %(escalation_expression)s,%(admission_expression)s,%(triage_budget)s,
                      %(admission_budget)s,%(episode_horizon_ms)s,%(delivery_policy_ref)s,
                      %(template_ref)s,%(calibration_receipt_refs)s,%(recommendation_ref)s,
                      %(classification)s,%(retention_policy_revision)s)
                   ON CONFLICT (organization_id,project_id,environment_id,
                                policy_key,policy_version) DO NOTHING
                   RETURNING alert_material_hash""",
                values,
            )
            inserted = cursor.fetchone()
            if inserted is None:
                cursor.execute(
                    """SELECT policy_hash,alert_material_hash
                         FROM solvan_alerts.alert_policy_revisions
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s
                          AND policy_version=%(policy_version)s""",
                    values,
                )
                existing = cursor.fetchone()
                if existing is None or (
                    existing["policy_hash"] != generic_policy_hash
                    or existing["alert_material_hash"] != policy.alert_material_hash
                ):
                    raise AlertPolicyError(
                        "an Alert policy revision already has different immutable material"
                    )
        return AlertPolicyDraftCommit(
            policy_key=policy.policy_key,
            version=policy.version,
            policy_hash=generic_policy_hash,
            alert_material_hash=policy.alert_material_hash,
            created=inserted is not None,
        )

    def source_binding(
        self, *, scope: Scope, connection_id: str, require_qualified: bool = True
    ) -> CloudMonitoringSourceBinding:
        binding_status_clause = (
            "b.status='QUALIFIED'"
            if require_qualified
            else ("b.status IN ('PENDING_CONFIGURATION','QUALIFIED')")
        )
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                f"""SELECT s.id AS source_identity_id,b.id AS source_binding_id,b.binding_epoch,
                          m.connection_id,m.connection_epoch,
                          m.continuity_epoch,p.cell_id,p.placement_epoch,
                          s.scoping_project_id,s.topic_name,s.topic_binding_receipt_ref,
                          s.subscription_name,s.push_principal,s.oidc_audience,
                          s.payload_schema_version,s.source_material_hash,s.classification,
                          s.retention_policy_revision
                     FROM solvan_alerts.alert_provider_source_current_memberships m
                     JOIN solvan_alerts.alert_provider_source_identities s
                       ON (s.organization_id,s.project_id,s.environment_id,s.id)=
                          (m.organization_id,m.project_id,m.environment_id,m.source_identity_id)
                     JOIN solvan.tenant_connections c
                       ON (c.organization_id,c.project_id,c.environment_id,c.id)=
                          (m.organization_id,m.project_id,m.environment_id,m.connection_id)
                     JOIN solvan_alerts.alert_source_bindings b
                       ON (b.organization_id,b.project_id,b.environment_id,b.source_identity_id,
                           b.connection_id,b.connection_epoch)=
                          (m.organization_id,m.project_id,m.environment_id,m.source_identity_id,
                           m.connection_id,m.connection_epoch)
                     JOIN solvan_scale.tenant_placements p
                       ON p.organization_id=m.organization_id AND p.is_current
                    WHERE m.organization_id=%(organization_id)s
                      AND m.project_id=%(project_id)s
                      AND m.environment_id=%(environment_id)s
                      AND m.connection_id=%(connection_id)s
                      AND m.connection_epoch=c.connection_epoch
                      AND {binding_status_clause}
                      AND c.provider='CLOUD_MONITORING'
                      AND c.lifecycle='ENABLED' AND c.availability='READY'
                      AND p.lifecycle='ACTIVE'""",
                {**scope.canonical_dict(), "connection_id": connection_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise AlertIngressError("SOURCE_BINDING_INELIGIBLE")
        return CloudMonitoringSourceBinding(scope=scope, **row)

    def require_monitored_project(
        self,
        *,
        binding: CloudMonitoringSourceBinding,
        monitored_project_id: str,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT EXISTS (
                     SELECT 1
                       FROM solvan_onboarding.environment_external_project_bindings b
                       JOIN solvan_onboarding.connection_external_project_coverage c
                         ON (c.organization_id,c.project_id,c.environment_id,
                             c.external_project_id)=
                            (b.organization_id,b.project_id,b.environment_id,
                             b.external_project_id)
                      WHERE b.organization_id=%(organization_id)s
                        AND b.project_id=%(project_id)s
                        AND b.environment_id=%(environment_id)s
                        AND b.external_project_id=%(external_project_id)s
                        AND b.is_current
                        AND c.connection_id=%(connection_id)s
                        AND c.connection_epoch=%(connection_epoch)s
                        AND c.capability_class='METRIC_READ')""",
                {
                    **binding.scope.canonical_dict(),
                    "external_project_id": monitored_project_id,
                    "connection_id": binding.connection_id,
                    "connection_epoch": binding.connection_epoch,
                },
            )
            permitted = cursor.fetchone()
        if permitted != (True,):
            raise AlertIngressError("MONITORED_PROJECT_NOT_AUTHORIZED")
