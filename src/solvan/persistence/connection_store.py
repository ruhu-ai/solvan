"""PostgreSQL authority for tenant connections, capabilities, and actuators."""

from __future__ import annotations

from typing import Any, cast

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.tenant_integration import (
    ActuatorRegistration,
    CapabilityObservation,
    ConnectionPolicyError,
    ConnectionRegistration,
    connectable_provider_projection,
    derive_availability,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.github_store import GitHubStore


class PostgresConnectionStore:
    """Every method is scope-bound; row-level security is the second control."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def register_connection(
        self, *, scope: Scope, registration: ConnectionRegistration, actor: str
    ) -> str:
        checked = registration.validated()
        connection_id = new_identifier("con")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.tenant_connections (
                      organization_id, project_id, environment_id, id, display_name,
                      kind, provider, credential_posture, authentication_mode,
                      solvan_delegator_principal, customer_reader_principal,
                      delegation_condition_digest, token_lifetime_seconds,
                      credential_secret_ref,
                      credential_cmek_key_ref, read_only_scope_state,
                      read_only_scope_reason_code, read_only_scope_verified_at,
                      read_only_scope_evidence_ref,
                      residency_region, classification, created_by_principal)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                      %(id)s, %(display_name)s, %(kind)s, %(provider)s,
                      %(credential_posture)s, %(authentication_mode)s,
                      %(solvan_delegator_principal)s, %(customer_reader_principal)s,
                      %(delegation_condition_digest)s, %(token_lifetime_seconds)s,
                      %(credential_secret_ref)s,
                      %(credential_cmek_key_ref)s, %(read_only_scope_state)s,
                      %(read_only_scope_reason_code)s, %(read_only_scope_verified_at)s,
                      %(read_only_scope_evidence_ref)s,
                      %(residency_region)s, %(classification)s, %(actor)s)""",
                {
                    **scope.canonical_dict(),
                    "id": connection_id,
                    "display_name": checked.display_name,
                    "kind": checked.kind,
                    "provider": checked.provider,
                    "credential_posture": str(checked.credential_posture),
                    "authentication_mode": str(checked.authentication_mode),
                    "solvan_delegator_principal": checked.solvan_delegator_principal,
                    "customer_reader_principal": checked.customer_reader_principal,
                    "delegation_condition_digest": checked.delegation_condition_digest,
                    "token_lifetime_seconds": checked.token_lifetime_seconds,
                    "credential_secret_ref": checked.credential_secret_ref,
                    "credential_cmek_key_ref": checked.credential_cmek_key_ref,
                    "read_only_scope_state": (
                        verdict.state if (verdict := checked.scope_verification) else "UNVERIFIABLE"
                    ),
                    "read_only_scope_reason_code": verdict.reason_code if verdict else None,
                    "read_only_scope_verified_at": (
                        verdict.evaluated_at if verdict and verdict.read_only else None
                    ),
                    "read_only_scope_evidence_ref": (
                        verdict.evidence_ref if verdict and verdict.read_only else None
                    ),
                    "residency_region": checked.residency_region,
                    "classification": checked.classification,
                    "actor": actor,
                },
            )
            if checked.resource_scope is not None:
                resource_scope = checked.resource_scope.validated()
                cursor.execute(
                    """INSERT INTO solvan_onboarding.connection_external_resource_scopes (
                           organization_id, project_id, environment_id, connection_id,
                           resource_kind, resource_id, metrics_scoping_project_id,
                           workload_region, authored_by_principal, decision_ref)
                       VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                               %(connection_id)s, %(resource_kind)s, %(resource_id)s,
                               %(metrics_scoping_project_id)s, %(workload_region)s,
                               %(actor)s, %(decision_ref)s)""",
                    {
                        **scope.canonical_dict(),
                        "connection_id": connection_id,
                        "resource_kind": str(resource_scope.resource_kind),
                        "resource_id": resource_scope.resource_id,
                        "metrics_scoping_project_id": resource_scope.metrics_scoping_project_id,
                        "workload_region": resource_scope.workload_region,
                        "actor": actor,
                        "decision_ref": resource_scope.decision_ref,
                    },
                )
                if str(resource_scope.resource_kind) == "GCP_PROJECT":
                    self.bind_environment_external_project(
                        scope=scope,
                        external_project_id=resource_scope.resource_id,
                        workload_region=resource_scope.workload_region,
                        deciding_principal=actor,
                        decision_ref=resource_scope.decision_ref,
                    )
        return connection_id

    def bind_environment_external_project(
        self,
        *,
        scope: Scope,
        external_project_id: str,
        workload_region: str,
        deciding_principal: str,
        decision_ref: str,
    ) -> int:
        """Author a new current environment/project binding without rewriting history.

        Enrollment is an admin-authorized decision, not a side effect of a
        probe. The advisory transaction lock serializes the absent-row case;
        otherwise two first writers could both calculate binding epoch one.
        A project/region already bound to another environment refuses rather
        than silently moving capability reach across a blast-radius boundary.
        """

        if not external_project_id or not workload_region or not decision_ref:
            raise ConnectionPolicyError("external project binding material is incomplete")
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%(lock_key)s, 0))",
                {"lock_key": (f"{scope.organization_id}:{external_project_id}:{workload_region}")},
            )
            cursor.execute(
                """SELECT project_id,environment_id,binding_epoch,decision_ref
                     FROM solvan_onboarding.environment_external_project_bindings
                    WHERE organization_id=%(organization_id)s
                      AND external_project_id=%(external_project_id)s
                      AND workload_region=%(workload_region)s AND is_current
                    FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "external_project_id": external_project_id,
                    "workload_region": workload_region,
                },
            )
            current = cursor.fetchone()
            if current is not None:
                if (str(current[0]), str(current[1])) != (
                    scope.project_id,
                    scope.environment_id,
                ):
                    raise ConnectionPolicyError(
                        "external project and workload region belong to another environment"
                    )
                if str(current[3]) == decision_ref:
                    return int(current[2])
                cursor.execute(
                    """UPDATE solvan_onboarding.environment_external_project_bindings
                          SET is_current=false
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND external_project_id=%(external_project_id)s
                          AND workload_region=%(workload_region)s AND is_current""",
                    {
                        **scope.canonical_dict(),
                        "external_project_id": external_project_id,
                        "workload_region": workload_region,
                    },
                )
                next_epoch = int(current[2]) + 1
            else:
                next_epoch = 1
            cursor.execute(
                """INSERT INTO solvan_onboarding.environment_external_project_bindings
                     (organization_id,project_id,environment_id,external_project_id,
                      workload_region,binding_epoch,deciding_principal,decision_ref,is_current)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(external_project_id)s,%(workload_region)s,%(binding_epoch)s,
                           %(deciding_principal)s,%(decision_ref)s,true)""",
                {
                    **scope.canonical_dict(),
                    "external_project_id": external_project_id,
                    "workload_region": workload_region,
                    "binding_epoch": next_epoch,
                    "deciding_principal": deciding_principal,
                    "decision_ref": decision_ref,
                },
            )
        return next_epoch

    def record_probe(
        self,
        *,
        scope: Scope,
        connection_id: str,
        observations: tuple[CapabilityObservation, ...],
        expected_epoch: int | None = None,
    ) -> str:
        """Record observed capability and derive connection status from it.

        A connection becomes ACTIVE only when a probe succeeded, so an
        unprobed or failing connection can never back an incident.
        """

        if not observations:
            raise ConnectionPolicyError("a probe must record at least one capability")
        checked = tuple(observation.validated() for observation in observations)
        available = sum(1 for observation in checked if observation.available)
        if available == len(checked):
            result = "SUCCEEDED"
        elif available:
            result = "PARTIAL"
        else:
            result = "FAILED"
        with self._connection.cursor() as cursor:
            if expected_epoch is not None:
                cursor.execute(
                    """SELECT connection_epoch FROM solvan.tenant_connections
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(connection_id)s
                          AND lifecycle NOT IN ('REVOKED','DISABLED') FOR UPDATE""",
                    {**scope.canonical_dict(), "connection_id": connection_id},
                )
                epoch_row = cursor.fetchone()
                if epoch_row is None or int(epoch_row[0]) != expected_epoch:
                    raise ConnectionPolicyError("connection authority changed during the probe")
            for observation in checked:
                cursor.execute(
                    """INSERT INTO solvan.connection_capabilities (
                          organization_id, project_id, environment_id, connection_id,
                          capability, available, outcome, missing_grant,
                          probe_receipt_ref)
                       VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                          %(connection_id)s, %(capability)s, %(available)s,
                          %(outcome)s, %(missing_grant)s, %(probe_receipt_ref)s)
                       ON CONFLICT (organization_id, project_id, environment_id,
                          connection_id, capability)
                       DO UPDATE SET available = EXCLUDED.available,
                          outcome = EXCLUDED.outcome,
                          missing_grant = EXCLUDED.missing_grant,
                          probe_receipt_ref = EXCLUDED.probe_receipt_ref,
                          observed_at = now()""",
                    {
                        **scope.canonical_dict(),
                        "connection_id": connection_id,
                        "capability": observation.capability,
                        "available": observation.available,
                        "outcome": observation.outcome,
                        "missing_grant": observation.missing_grant,
                        "probe_receipt_ref": observation.probe_receipt_ref,
                    },
                )
            # Specification 13 §4: availability is derived, and a non-READY
            # result carries its reason in the same write. Deriving it here
            # rather than in the UPDATE keeps one classification rule that a
            # unit test can exercise without a database.
            verdict = derive_availability(lifecycle="ENABLED", observations=checked)
            cursor.execute(
                """UPDATE solvan.tenant_connections
                     SET last_probe_at = now(), last_probe_result = %(result)s,
                         last_success_at = CASE WHEN %(result)s = 'SUCCEEDED'
                                                THEN now() ELSE last_success_at END,
                         lifecycle = 'ENABLED',
                         availability = %(availability)s,
                         availability_reason_code = %(reason_code)s,
                         availability_explanation = %(explanation)s,
                         availability_missing_grant = %(missing_grant)s,
                         availability_remediation_kind = %(remediation_kind)s,
                         availability_receipt_ref = %(receipt_ref)s,
                         updated_at = now()
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND id = %(connection_id)s
                     AND (%(expected_epoch)s IS NULL OR connection_epoch=%(expected_epoch)s)
                     AND lifecycle NOT IN ('REVOKED','DISABLED')""",
                {
                    **scope.canonical_dict(),
                    "connection_id": connection_id,
                    "expected_epoch": expected_epoch,
                    "result": result,
                    "availability": verdict.availability,
                    "reason_code": verdict.reason_code,
                    "explanation": verdict.explanation,
                    "missing_grant": verdict.missing_grant,
                    "remediation_kind": verdict.remediation_kind,
                    "receipt_ref": verdict.receipt_ref,
                },
            )
            if cursor.rowcount != 1:
                raise ConnectionPolicyError("connection is absent or revoked")
        return result

    def invalidate_connection(
        self,
        *,
        scope: Scope,
        connection_id: str,
        expected_epoch: int,
        revoke: bool,
    ) -> int:
        """Fence every prior proof when connection material changes or is revoked."""

        if expected_epoch < 1:
            raise ConnectionPolicyError("expected connection epoch must be positive")
        # Fencing destroys every prior proof, so the connection is back to
        # having proven nothing. Revocation is an authored decision and outranks
        # any probe; re-registration is simply unprobed.
        verdict = derive_availability(
            lifecycle="REVOKED" if revoke else "PENDING",
            observations=(),
            receipt_ref=f"invalidate://{connection_id}/{expected_epoch + 1}",
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.tenant_connections
                      SET connection_epoch=connection_epoch+1,
                          lifecycle=%(lifecycle)s,
                          availability=%(availability)s,
                          availability_reason_code=%(reason_code)s,
                          availability_explanation=%(explanation)s,
                          availability_missing_grant=NULL,
                          availability_remediation_kind=%(remediation_kind)s,
                          availability_receipt_ref=%(receipt_ref)s,
                          last_probe_at=NULL,last_probe_result=NULL,
                          last_success_at=NULL,
                          updated_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(connection_id)s AND connection_epoch=%(expected_epoch)s
                      AND lifecycle <> 'REVOKED'
                    RETURNING connection_epoch""",
                {
                    **scope.canonical_dict(),
                    "connection_id": connection_id,
                    "expected_epoch": expected_epoch,
                    "lifecycle": "REVOKED" if revoke else "PENDING",
                    "availability": verdict.availability,
                    "reason_code": verdict.reason_code,
                    "explanation": verdict.explanation,
                    "remediation_kind": verdict.remediation_kind,
                    "receipt_ref": verdict.receipt_ref,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise ConnectionPolicyError("connection epoch is stale, absent, or revoked")
            cursor.execute(
                """DELETE FROM solvan.connection_capabilities
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND connection_id=%(connection_id)s""",
                {**scope.canonical_dict(), "connection_id": connection_id},
            )
            # Direct-GCP source bindings and their qualification receipts live
            # in the target schema.  A connection epoch is a hard fence: a
            # formerly qualified subscription cannot remain qualified, and a
            # receipt derived from its old authority can never be current.
            # The release schema deliberately does not carry these tables, so
            # retain its clean contract while making a target deployment
            # enforce the same transition atomically.
            cursor.execute("SELECT to_regclass('solvan_alerts.alert_source_bindings') IS NOT NULL")
            target_schema_present = cursor.fetchone()
            if target_schema_present == (True,):
                cursor.execute(
                    """UPDATE solvan_alerts.alert_source_bindings
                          SET status=%(binding_status)s,
                              invalidated_reason=%(reason)s,
                              updated_at=now()
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND connection_id=%(connection_id)s
                          AND connection_epoch=%(expected_epoch)s
                          AND status IN ('PENDING_CONFIGURATION','QUALIFIED')""",
                    {
                        **scope.canonical_dict(),
                        "connection_id": connection_id,
                        "expected_epoch": expected_epoch,
                        "binding_status": "REVOKED" if revoke else "PENDING_CONFIGURATION",
                        "reason": "CONNECTION_REVOKED" if revoke else "CONNECTION_EPOCH_CHANGED",
                    },
                )
                cursor.execute(
                    """UPDATE solvan_alerts.direct_gcp_pilot_qualification_receipts
                          SET superseded_at=COALESCE(superseded_at,now())
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND connection_id=%(connection_id)s
                          AND connection_epoch=%(expected_epoch)s
                          AND superseded_at IS NULL""",
                    {
                        **scope.canonical_dict(),
                        "connection_id": connection_id,
                        "expected_epoch": expected_epoch,
                    },
                )
        return int(row[0])

    def register_actuator(
        self, *, scope: Scope, registration: ActuatorRegistration, actor: str
    ) -> str:
        checked = registration.validated()
        actuator_id = new_identifier("atr")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.actuator_registrations (
                      organization_id, project_id, environment_id, id, connection_id,
                      host_kind, production_eligible, risk_acceptance_ref,
                      principal_email, expected_audience, posture, image_digest,
                      actuator_version, policy_hash, policy_source_ref,
                      customer_audit_sink_ref, registered_by_principal)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                      %(id)s, %(connection_id)s, %(host_kind)s,
                      %(production_eligible)s, %(risk_acceptance_ref)s,
                      %(principal_email)s, %(expected_audience)s, %(posture)s,
                      %(image_digest)s, %(actuator_version)s, %(policy_hash)s,
                      %(policy_source_ref)s, %(customer_audit_sink_ref)s, %(actor)s)""",
                {
                    **scope.canonical_dict(),
                    "id": actuator_id,
                    "connection_id": checked.connection_id,
                    "host_kind": str(checked.host_kind),
                    "production_eligible": checked.production_eligible,
                    "risk_acceptance_ref": checked.risk_acceptance_ref,
                    "principal_email": checked.principal_email,
                    "expected_audience": checked.expected_audience,
                    "posture": str(checked.posture),
                    "image_digest": checked.image_digest,
                    "actuator_version": checked.actuator_version,
                    "policy_hash": checked.policy_hash,
                    "policy_source_ref": checked.policy_source_ref,
                    "customer_audit_sink_ref": checked.customer_audit_sink_ref,
                    "actor": actor,
                },
            )
        return actuator_id

    def integration_projection(self, *, scope: Scope) -> dict[str, Any]:
        """Read-only projection for the console. Never returns credential values."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT c.id, c.display_name, c.kind, c.provider, c.connection_epoch,
                          c.credential_posture, c.classification, c.residency_region,
                          s.resource_kind AS external_resource_kind,
                          s.resource_id AS external_resource_id,
                          s.workload_region,
                          c.lifecycle, c.availability,
                          c.availability_reason_code, c.availability_explanation,
                          c.availability_missing_grant,
                          c.availability_remediation_kind, c.availability_reference,
                          c.availability_receipt_ref,
                          c.last_probe_at, c.last_probe_result, c.last_success_at,
                          c.proof_expires_at,
                          c.credential_secret_ref IS NOT NULL AS holds_stored_secret,
                          c.read_only_scope_verified,
                          coalesce(jsonb_agg(jsonb_build_object(
                              'capability', k.capability,
                              'available', k.available,
                              'outcome', k.outcome,
                              'missing_grant', k.missing_grant)
                            ORDER BY k.capability)
                            FILTER (WHERE k.capability IS NOT NULL), '[]'::jsonb)
                            AS capabilities
                     FROM solvan.tenant_connections c
                     LEFT JOIN solvan.connection_capabilities k
                       ON (k.organization_id, k.project_id, k.environment_id,
                           k.connection_id)
                        = (c.organization_id, c.project_id, c.environment_id, c.id)
                     LEFT JOIN solvan_onboarding.connection_external_resource_scopes s
                       ON (s.organization_id, s.project_id, s.environment_id,
                           s.connection_id)
                        = (c.organization_id, c.project_id, c.environment_id, c.id)
                    WHERE c.organization_id = %(organization_id)s
                      AND c.project_id = %(project_id)s
                      AND c.environment_id = %(environment_id)s
                    GROUP BY c.id, c.display_name, c.kind, c.provider, c.connection_epoch,
                             c.credential_posture, c.classification,
                             c.residency_region, s.resource_kind, s.resource_id,
                             s.workload_region, c.lifecycle, c.availability,
                             c.availability_reason_code, c.availability_explanation,
                             c.availability_missing_grant,
                             c.availability_remediation_kind, c.availability_reference,
                             c.availability_receipt_ref, c.last_probe_at,
                             c.last_probe_result, c.last_success_at, c.proof_expires_at,
                             c.credential_secret_ref, c.read_only_scope_verified
                    ORDER BY c.display_name""",
                scope.canonical_dict(),
            )
            connections = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT id, connection_id, host_kind, production_eligible,
                          risk_acceptance_ref IS NOT NULL AS risk_accepted,
                          principal_email, posture, image_digest, actuator_version,
                          policy_hash, customer_audit_sink_ref IS NOT NULL
                            AS customer_audit_configured,
                          kill_switch_engaged, status, last_poll_at
                     FROM solvan.actuator_registrations
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                    ORDER BY principal_email""",
                scope.canonical_dict(),
            )
            actuators = [dict(row) for row in cursor.fetchall()]
        github = GitHubStore(self._connection).project(scope=scope)
        return cast(
            dict[str, Any],
            {
                # The connectable catalog is a property of this build, not of
                # tenant state, but the console reads it from the same payload
                # as the connections it onboards into. Omitting it here is what
                # previously left the Integrations route with no catalog at all.
                "providers": connectable_provider_projection(),
                "connections": connections,
                "actuators": actuators,
                "github": github,
            },
        )
