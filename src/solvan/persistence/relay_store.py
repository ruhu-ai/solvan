"""Cloud SQL authority for Solvant Relay enrollment and collection jobs."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope, canonical_digest, new_identifier
from solvan.domain.relay import (
    CollectionJobMaterial,
    RelayAdapter,
    RelayContractError,
    RelayEnrollmentRegistration,
    RelayEnrollmentState,
    RelayIdentityBinding,
    RelayJobClaim,
    RelayReadinessChallenge,
    RelayRuntimePolicyProof,
    RelaySourceBinding,
    RelaySourceBindingRegistration,
    require_digest,
)


class RelayConflict(RelayContractError):
    """A Relay compare-and-set, idempotency, or binding check lost."""


@dataclass(frozen=True, slots=True)
class IssuedReadinessChallenge:
    """One persisted challenge plus its one-time customer-visible nonce."""

    challenge: RelayReadinessChallenge
    nonce: str


@dataclass(frozen=True, slots=True)
class RuntimeProofVerificationKey:
    """A constrained customer public-key reference, never a private credential."""

    key_id: str
    public_key_ref: str
    public_key_digest: str


@dataclass(frozen=True, slots=True)
class RelayUploadGrant:
    upload_grant_id: str
    upload_grant_digest: str
    object_ref: str
    object_generation_match: str
    content_type: str
    content_length: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RelayRetryOutcome:
    """The committed result of a closed retryable attempt outcome."""

    collection_job_id: str
    attempt_id: str
    attempt_number: int
    job_state: str
    action: str
    workflow_version: int


@dataclass(frozen=True, slots=True)
class RelayJobStatus:
    """Content-free reconciliation instruction for the customer Relay."""

    collection_job_id: str
    job_digest: str
    state: str
    action: str
    attempt_id: str | None
    attempt_number: int | None
    local_result_hash: str | None
    cancel_requested: bool


@dataclass(frozen=True, slots=True)
class RelayDeploymentProfile:
    """A customer-submitted, reviewable installation assertion.

    The profile carries only public identifiers, references, and pinned
    digests.  It is deliberately not a place for a policy body, a credential,
    or a private key.
    """

    deployment_profile_id: str
    registration: RelayEnrollmentRegistration
    local_binding_digest: str


def _time_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RelayConflict("Relay database timestamp is malformed")
    return value.isoformat()


class PostgresRelayStore:
    """Typed Relay repository; scope must come from verified identity."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def register_enrollment(
        self,
        *,
        scope: Scope,
        registration: RelayEnrollmentRegistration,
        principal: str,
        registered_at: datetime,
    ) -> str:
        """Create a fail-closed enrollment and its exact runtime proof key.

        The command intentionally has no READY, credential, endpoint, or policy
        body parameter.  Those are either customer-local or established later
        by an independently verified readiness proof.
        """

        if registered_at.tzinfo is None or not principal:
            raise ValueError("Relay enrollment registration is malformed")
        enrollment_id = new_identifier("ren")
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            **asdict(registration),
            "enrollment_id": enrollment_id,
            "production_eligible": registration.host_kind != "DEV_LOCAL",
            "principal": principal,
            "registered_at": registered_at,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT c.connection_epoch,p.placement_epoch,p.cell_id
                     FROM solvan.tenant_connections c
                     JOIN solvan_scale.tenant_placements p
                       ON p.organization_id=c.organization_id
                    WHERE c.organization_id=%(organization_id)s AND c.project_id=%(project_id)s
                      AND c.environment_id=%(environment_id)s AND c.id=%(relay_connection_id)s
                      AND c.kind='RELAY' AND c.provider='SOLVAN_RELAY'
                      AND c.credential_posture='CUSTOMER_SIDE_NONE'
                      -- A Relay's first identity-bound runtime proof is what
                      -- establishes transport readiness. Requiring a READY
                      -- transport here would make first enrollment dependent
                      -- on a seed/update outside the product authority.
                      AND c.lifecycle IN ('PENDING','ENABLED')
                      AND c.residency_region=%(region)s
                      AND p.is_current AND p.lifecycle='ACTIVE' AND p.home_region=%(region)s
                      AND EXISTS (
                        SELECT 1 FROM solvan_relay.relay_image_attestations a
                         WHERE (a.id,a.image_digest,a.decision)=(%(image_attestation_id)s,
                            %(image_digest)s,'ALLOW') AND a.issued_at <= %(registered_at)s
                           AND a.expires_at > %(registered_at)s)
                    FOR SHARE OF c,p""",
                params,
            )
            authority = cur.fetchone()
            if authority is None:
                raise RelayConflict("Relay transport, placement, or attestation is ineligible")
            cur.execute(
                """INSERT INTO solvan_relay.relay_enrollments
                     (organization_id,project_id,environment_id,id,relay_connection_id,enrollment_epoch,
                      placement_epoch,cell_id,host_kind,production_eligible,risk_acceptance_ref,
                      principal_subject,principal_issuer,expected_audience,image_digest,
                      image_attestation_id,local_policy_digest,connector_catalog_digest,
                      redaction_revision,region,classification_ceiling,relay_version,lifecycle,
                      safe_reason_code,created_by_principal,created_at,updated_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(enrollment_id)s,
                      %(relay_connection_id)s,1,%(placement_epoch)s,%(cell_id)s,%(host_kind)s,
                      %(production_eligible)s,%(risk_acceptance_ref)s,%(principal_subject)s,
                      %(principal_issuer)s,%(expected_audience)s,%(image_digest)s,
                      %(image_attestation_id)s,%(local_policy_digest)s,%(connector_catalog_digest)s,
                      %(redaction_revision)s,%(region)s,%(classification_ceiling)s,%(relay_version)s,
                      'REGISTERED','AWAITING_RUNTIME_POLICY_PROOF',%(principal)s,
                      %(registered_at)s,%(registered_at)s)""",
                {
                    **params,
                    "placement_epoch": int(authority["placement_epoch"]),
                    "cell_id": str(authority["cell_id"]),
                },
            )
            cur.execute(
                """INSERT INTO solvan_relay.relay_runtime_proof_key_revisions
                     (organization_id,project_id,environment_id,enrollment_id,enrollment_epoch,key_id,
                      public_key_digest,public_key_ref,algorithm,lifecycle,valid_from,issue_until,
                      verify_until)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(enrollment_id)s,
                      1,%(runtime_proof_key_id)s,%(runtime_proof_public_key_digest)s,
                      %(runtime_proof_public_key_ref)s,'ECDSA_P256_SHA256','ACTIVE',
                      %(registered_at)s,%(registered_at)s + interval '120 seconds',
                      %(registered_at)s + interval '2 hours')""",
                params,
            )
        return enrollment_id

    def submit_deployment_profile(
        self,
        *,
        relay_connection_id: str,
        host_kind: str,
        principal_issuer: str,
        principal_subject: str,
        expected_audience: str,
        image_digest: str,
        image_attestation_id: str,
        local_policy_digest: str,
        policy_key_id: str,
        connector_catalog_digest: str,
        redaction_revision: str,
        region: str,
        classification_ceiling: str,
        relay_version: str,
        runtime_proof_key_id: str,
        runtime_proof_public_key_ref: str,
        runtime_proof_public_key_digest: str,
        egress_manifest_digest: str,
        local_binding_digest: str,
        expires_at: datetime,
        asserted_at: datetime,
    ) -> str:
        """Persist an OIDC-bound customer deployment assertion for review.

        Scope is resolved from the credentialless Relay connection.  The caller
        never sends a scope, authenticated identity, policy body, credential, or
        private key.  Approval consumes this immutable assertion later.
        """

        if asserted_at.tzinfo is None or expires_at.tzinfo is None or expires_at <= asserted_at:
            raise ValueError("Relay deployment profile expiry is malformed")
        registration = RelayEnrollmentRegistration(
            relay_connection_id=relay_connection_id,
            host_kind=host_kind,
            risk_acceptance_ref=None,
            principal_subject=principal_subject,
            principal_issuer=principal_issuer,
            expected_audience=expected_audience,
            image_digest=image_digest,
            image_attestation_id=image_attestation_id,
            local_policy_digest=local_policy_digest,
            connector_catalog_digest=connector_catalog_digest,
            redaction_revision=redaction_revision,
            region=region,
            classification_ceiling=classification_ceiling,
            relay_version=relay_version,
            runtime_proof_key_id=runtime_proof_key_id,
            runtime_proof_public_key_ref=runtime_proof_public_key_ref,
            runtime_proof_public_key_digest=runtime_proof_public_key_digest,
        )
        require_digest(egress_manifest_digest, field="egress_manifest_digest")
        require_digest(local_binding_digest, field="local_binding_digest")
        deployment_profile_id = new_identifier("rdp")
        assertion_digest = canonical_digest(
            {
                "schema_version": 1,
                "relay_connection_id": relay_connection_id,
                "principal_issuer": principal_issuer,
                "principal_subject": principal_subject,
                "expected_audience": expected_audience,
                "host_kind": host_kind,
                "image_digest": image_digest,
                "image_attestation_id": image_attestation_id,
                "local_policy_digest": local_policy_digest,
                "policy_key_id": policy_key_id,
                "connector_catalog_digest": connector_catalog_digest,
                "redaction_revision": redaction_revision,
                "region": region,
                "classification_ceiling": classification_ceiling,
                "relay_version": relay_version,
                "runtime_proof_key_id": runtime_proof_key_id,
                "runtime_proof_public_key_digest": runtime_proof_public_key_digest,
                "egress_manifest_digest": egress_manifest_digest,
                "local_binding_digest": local_binding_digest,
                "expires_at": expires_at.isoformat(),
            }
        )
        params: dict[str, Any] = {
            **asdict(registration),
            "policy_key_id": policy_key_id,
            "egress_manifest_digest": egress_manifest_digest,
            "local_binding_digest": local_binding_digest,
            "deployment_profile_id": deployment_profile_id,
            "assertion_digest": assertion_digest,
            "asserted_at": asserted_at,
            "expires_at": expires_at,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT c.organization_id,c.project_id,c.environment_id
                     FROM solvan.tenant_connections c
                     JOIN solvan_relay.relay_policy_key_revisions key
                       ON (key.organization_id,key.project_id,key.environment_id,key.key_id)=
                          (c.organization_id,c.project_id,c.environment_id,%(policy_key_id)s)
                    WHERE c.id=%(relay_connection_id)s AND c.kind='RELAY'
                      AND c.provider='SOLVAN_RELAY' AND c.credential_posture='CUSTOMER_SIDE_NONE'
                      AND c.lifecycle IN ('PENDING','ENABLED') AND c.residency_region=%(region)s
                      AND key.lifecycle='ACTIVE' AND key.valid_from <= %(asserted_at)s
                      AND key.issue_until > %(asserted_at)s
                      AND EXISTS (
                        SELECT 1 FROM solvan_relay.relay_image_attestations attestation
                         WHERE (attestation.id,attestation.image_digest,attestation.decision)=
                               (%(image_attestation_id)s,%(image_digest)s,'ALLOW')
                           AND attestation.issued_at <= %(asserted_at)s
                           AND attestation.expires_at > %(asserted_at)s)
                    FOR SHARE OF c,key""",
                params,
            )
            scope_row = cur.fetchone()
            if scope_row is None:
                raise RelayConflict(
                    "Relay transport, policy key, or image attestation is ineligible"
                )
            params.update(
                {
                    "organization_id": str(scope_row["organization_id"]),
                    "project_id": str(scope_row["project_id"]),
                    "environment_id": str(scope_row["environment_id"]),
                }
            )
            cur.execute(
                """INSERT INTO solvan_relay.relay_deployment_profiles
                     (organization_id,project_id,environment_id,id,relay_connection_id,host_kind,
                      principal_subject,principal_issuer,expected_audience,image_digest,
                      image_attestation_id,image_attestation_decision,local_policy_digest,policy_key_id,
                      connector_catalog_digest,
                      redaction_revision,region,classification_ceiling,relay_version,runtime_proof_key_id,
                      runtime_proof_public_key_ref,runtime_proof_public_key_digest,egress_manifest_digest,
                      local_binding_digest,assertion_digest,asserted_at,expires_at,review_state)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(deployment_profile_id)s,
                      %(relay_connection_id)s,%(host_kind)s,%(principal_subject)s,%(principal_issuer)s,
                      %(expected_audience)s,%(image_digest)s,%(image_attestation_id)s,
                      'ALLOW',%(local_policy_digest)s,%(policy_key_id)s,%(connector_catalog_digest)s,
                      %(redaction_revision)s,%(region)s,%(classification_ceiling)s,%(relay_version)s,
                      %(runtime_proof_key_id)s,%(runtime_proof_public_key_ref)s,
                      %(runtime_proof_public_key_digest)s,%(egress_manifest_digest)s,
                      %(local_binding_digest)s,%(assertion_digest)s,%(asserted_at)s,%(expires_at)s,
                      'PENDING_REVIEW')""",
                params,
            )
        return deployment_profile_id

    def approve_deployment_profile(
        self,
        *,
        scope: Scope,
        deployment_profile_id: str,
        principal: str,
        approved_at: datetime,
        risk_acceptance_ref: str | None = None,
    ) -> str:
        """Approve one fresh customer assertion and consume it into enrollment.

        The administrator reviews a durable candidate rather than supplying
        identity, image, policy or proof-key values in a browser request.  The
        original registration command remains the narrow persistence primitive;
        this is the sole administrator-facing enrollment path.
        """

        if approved_at.tzinfo is None or not principal:
            raise ValueError("Relay deployment profile approval is malformed")
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT id,relay_connection_id,host_kind,principal_subject,principal_issuer,
                          expected_audience,image_digest,image_attestation_id,local_policy_digest,
                          connector_catalog_digest,redaction_revision,region,classification_ceiling,
                          relay_version,runtime_proof_key_id,runtime_proof_public_key_ref,
                          runtime_proof_public_key_digest,local_binding_digest,review_state,expires_at
                     FROM solvan_relay.relay_deployment_profiles
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(deployment_profile_id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "deployment_profile_id": deployment_profile_id},
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("Relay deployment profile is absent")
            if str(row["review_state"]) != "PENDING_REVIEW" or row["expires_at"] <= approved_at:
                raise RelayConflict("Relay deployment profile is not fresh and pending review")
            registration = RelayEnrollmentRegistration(
                relay_connection_id=str(row["relay_connection_id"]),
                host_kind=str(row["host_kind"]),
                risk_acceptance_ref=risk_acceptance_ref,
                principal_subject=str(row["principal_subject"]),
                principal_issuer=str(row["principal_issuer"]),
                expected_audience=str(row["expected_audience"]),
                image_digest=str(row["image_digest"]),
                image_attestation_id=str(row["image_attestation_id"]),
                local_policy_digest=str(row["local_policy_digest"]),
                connector_catalog_digest=str(row["connector_catalog_digest"]),
                redaction_revision=str(row["redaction_revision"]),
                region=str(row["region"]),
                classification_ceiling=str(row["classification_ceiling"]),
                relay_version=str(row["relay_version"]),
                runtime_proof_key_id=str(row["runtime_proof_key_id"]),
                runtime_proof_public_key_ref=str(row["runtime_proof_public_key_ref"]),
                runtime_proof_public_key_digest=str(row["runtime_proof_public_key_digest"]),
            )
            # Registration checks the authoritative transport, placement and
            # image-attestation records in the same database transaction.
            enrollment_id = self.register_enrollment(
                scope=scope,
                registration=registration,
                principal=principal,
                registered_at=approved_at,
            )
            cur.execute(
                """UPDATE solvan_relay.relay_enrollments
                      SET deployment_profile_id=%(deployment_profile_id)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(enrollment_id)s
                        AND deployment_profile_id IS NULL""",
                {
                    **scope.canonical_dict(),
                    "deployment_profile_id": deployment_profile_id,
                    "enrollment_id": enrollment_id,
                },
            )
            if cur.rowcount != 1:
                raise RelayConflict("Relay enrollment profile binding was lost")
            cur.execute(
                """UPDATE solvan_relay.relay_deployment_profiles
                      SET review_state='CONSUMED',reviewed_by_principal=%(principal)s,
                          reviewed_at=%(approved_at)s,enrollment_id=%(enrollment_id)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(deployment_profile_id)s
                        AND review_state='PENDING_REVIEW'""",
                {
                    **scope.canonical_dict(),
                    "deployment_profile_id": deployment_profile_id,
                    "principal": principal,
                    "approved_at": approved_at,
                    "enrollment_id": enrollment_id,
                },
            )
            if cur.rowcount != 1:
                raise RelayConflict("Relay deployment profile approval was lost")
        return enrollment_id

    def record_qualification_receipt(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        enrollment_epoch: int,
        deployment_manifest_digest: str,
        egress_manifest_digest: str,
        ledger_configuration_digest: str,
        qualified_adapter_keys: tuple[str, ...],
        kill_switch_state: str,
        receipt_digest: str,
        signature_base64: str,
        runtime_proof_key_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> str:
        """Record one independently signature-verified customer qualification."""
        for value, field in (
            (deployment_manifest_digest, "deployment_manifest_digest"),
            (egress_manifest_digest, "egress_manifest_digest"),
            (ledger_configuration_digest, "ledger_configuration_digest"),
            (receipt_digest, "receipt_digest"),
        ):
            require_digest(value, field=field)
        if issued_at.tzinfo is None or expires_at.tzinfo is None or expires_at <= issued_at:
            raise ValueError("Relay qualification receipt times are malformed")
        if not qualified_adapter_keys or len(set(qualified_adapter_keys)) != len(
            qualified_adapter_keys
        ):
            raise ValueError("Relay qualification adapters are malformed")
        receipt_id = new_identifier("rqr")
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT e.deployment_profile_id,p.egress_manifest_digest
                     FROM solvan_relay.relay_enrollments e
                     JOIN solvan_relay.relay_deployment_profiles p ON
                       (p.organization_id,p.project_id,p.environment_id,p.id)=
                       (e.organization_id,e.project_id,e.environment_id,e.deployment_profile_id)
                    WHERE e.organization_id=%(organization_id)s AND e.project_id=%(project_id)s
                      AND e.environment_id=%(environment_id)s AND e.id=%(enrollment_id)s
                      AND e.enrollment_epoch=%(enrollment_epoch)s AND e.lifecycle='READY'
                    FOR SHARE OF e,p""",
                {
                    **scope.canonical_dict(),
                    "enrollment_id": enrollment_id,
                    "enrollment_epoch": enrollment_epoch,
                },
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("Relay enrollment is not ready for qualification")
            if str(row["egress_manifest_digest"]) != egress_manifest_digest:
                raise RelayConflict("Relay qualification egress manifest does not match profile")
            cur.execute(
                """INSERT INTO solvan_relay.relay_qualification_receipts
                     (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
                      deployment_profile_id,deployment_manifest_digest,egress_manifest_digest,
                      ledger_configuration_digest,kill_switch_state,receipt_digest,signature_base64,
                      runtime_proof_key_id,qualified_adapter_keys,issued_at,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(receipt_id)s,
                      %(enrollment_id)s,%(enrollment_epoch)s,%(deployment_profile_id)s,
                      %(deployment_manifest_digest)s,%(egress_manifest_digest)s,
                      %(ledger_configuration_digest)s,%(kill_switch_state)s,%(receipt_digest)s,
                      %(signature_base64)s,%(runtime_proof_key_id)s,%(qualified_adapter_keys)s,
                      %(issued_at)s,%(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "receipt_id": receipt_id,
                    "enrollment_id": enrollment_id,
                    "enrollment_epoch": enrollment_epoch,
                    "deployment_profile_id": str(row["deployment_profile_id"]),
                    "egress_manifest_digest": str(row["egress_manifest_digest"]),
                    "deployment_manifest_digest": deployment_manifest_digest,
                    "ledger_configuration_digest": ledger_configuration_digest,
                    "kill_switch_state": kill_switch_state,
                    "receipt_digest": receipt_digest,
                    "signature_base64": signature_base64,
                    "runtime_proof_key_id": runtime_proof_key_id,
                    "qualified_adapter_keys": json.dumps(qualified_adapter_keys),
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                },
            )
        return receipt_id

    def register_source_binding(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        registration: RelaySourceBindingRegistration,
        principal: str,
        registered_at: datetime,
    ) -> str:
        """Register a closed, probed source adapter; no endpoint or query is accepted."""

        if registered_at.tzinfo is None or not principal:
            raise ValueError("Relay source binding registration is malformed")
        binding_id = new_identifier("rsb")
        source_requirements = {
            RelayAdapter.CLOUD_MONITORING: ("CLOUD_MONITORING", "metrics.read"),
            RelayAdapter.MANAGED_PROMETHEUS: ("MANAGED_PROMETHEUS", "promql.read"),
            RelayAdapter.CLOUD_LOGGING: ("CLOUD_LOGGING", "logs.read"),
            RelayAdapter.CLOUD_TRACE: ("CLOUD_TRACE", "traces.read"),
            RelayAdapter.KUBERNETES_METADATA: ("KUBERNETES", "kubernetes.metadata.read"),
        }.get(registration.adapter_key)
        if source_requirements is None:
            raise RelayConflict("Relay adapter has no qualified implementation")
        provider, capability = source_requirements
        expected_kind = (
            "COLLECTOR"
            if registration.adapter_key is RelayAdapter.KUBERNETES_METADATA
            else "GCP_NATIVE"
        )
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            **asdict(registration),
            "adapter_key": registration.adapter_key.value,
            "enrollment_id": enrollment_id,
            "binding_id": binding_id,
            "principal": principal,
            "registered_at": registered_at,
            "provider": provider,
            "expected_kind": expected_kind,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                f"""SELECT e.enrollment_epoch,e.region,e.classification_ceiling,
                          c.connection_epoch
                     FROM solvan_relay.relay_enrollments e
                     JOIN solvan.tenant_connections c
                       ON (c.organization_id,c.project_id,c.environment_id,c.id,
                           c.connection_epoch)=
                          (e.organization_id,e.project_id,e.environment_id,
                           %(source_connection_id)s,%(source_connection_epoch)s)
                    WHERE e.organization_id=%(organization_id)s AND e.project_id=%(project_id)s
                      AND e.environment_id=%(environment_id)s AND e.id=%(enrollment_id)s
                      AND e.lifecycle IN ('REGISTERED','READY','DEGRADED','STALE')
                      AND c.kind=%(expected_kind)s AND c.provider=%(provider)s
                      AND c.credential_posture='CUSTOMER_SIDE_NONE'
                      AND c.lifecycle='ENABLED' AND c.availability='READY'
                      AND c.residency_region=%(region)s
                      AND EXISTS (
                        SELECT 1 FROM solvan.connection_capabilities capability
                         WHERE (capability.organization_id,capability.project_id,
                                capability.environment_id,capability.connection_id)=
                               (c.organization_id,c.project_id,c.environment_id,c.id)
                           AND capability.capability='{capability}' AND capability.available)
                    FOR SHARE OF e,c""",
                params,
            )
            authority = cur.fetchone()
            if authority is None:
                raise RelayConflict("Relay source connection is ineligible or unprobed")
            cur.execute(
                """INSERT INTO solvan_relay.relay_source_bindings
                     (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
                      source_connection_id,source_connection_epoch,adapter_key,adapter_revision,
                      local_binding_digest,capability_receipt_id,capability_receipt_hash,region,
                      classification_ceiling,lifecycle,safe_reason_code,created_at,updated_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(binding_id)s,
                      %(enrollment_id)s,%(enrollment_epoch)s,%(source_connection_id)s,
                      %(source_connection_epoch)s,%(adapter_key)s,%(adapter_revision)s,
                      %(local_binding_digest)s,%(capability_receipt_id)s,
                      %(capability_receipt_hash)s,%(region)s,%(classification_ceiling)s,
                      'READY',NULL,%(registered_at)s,%(registered_at)s)""",
                {**params, "enrollment_epoch": int(authority["enrollment_epoch"])},
            )
        return binding_id

    def transition_enrollment_administratively(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        action: str,
        principal: str,
        occurred_at: datetime,
    ) -> str:
        """Disable or revoke an enrollment through its declared state machine."""

        transitions = {
            "DISABLE": ("ADMIN_DISABLED", "DISABLED", "ADMIN_DISABLED"),
            "REVOKE": ("REVOKED", "REVOKED", "ADMIN_REVOKED"),
        }
        try:
            event, target, reason = transitions[action]
        except KeyError as error:
            raise ValueError("unsupported Relay enrollment administrative transition") from error
        if occurred_at.tzinfo is None or not principal:
            raise ValueError("Relay enrollment administrative transition is malformed")
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            "enrollment_id": enrollment_id,
            "principal": principal,
            "occurred_at": occurred_at,
            "event": event,
            "target": target,
            "reason": reason,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT lifecycle,workflow_version,enrollment_epoch
                     FROM solvan_relay.relay_enrollments
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(enrollment_id)s
                    FOR UPDATE""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("Relay enrollment is absent")
            current = str(row["lifecycle"])
            if current == target:
                return current
            if current == "REVOKED" or (action == "DISABLE" and current == "DISABLED"):
                raise RelayConflict("Relay enrollment lifecycle transition is not allowed")
            if action == "DISABLE" and current not in {"REGISTERED", "READY", "DEGRADED", "STALE"}:
                raise RelayConflict("Relay enrollment cannot be disabled from this state")
            if action == "REVOKE" and current not in {
                "REGISTERED",
                "READY",
                "DEGRADED",
                "STALE",
                "DISABLED",
            }:
                raise RelayConflict("Relay enrollment cannot be revoked from this state")
            params.update(
                {
                    "transition_id": new_identifier("ret"),
                    "workflow_version": int(row["workflow_version"]) + 1,
                    "enrollment_epoch": int(row["enrollment_epoch"]),
                    "receipt_hash": canonical_digest(
                        {
                            "enrollment_id": enrollment_id,
                            "event": event,
                            "principal": principal,
                            "occurred_at": occurred_at.isoformat(),
                        }
                    ),
                    "from_state": current,
                }
            )
            cur.execute(
                """INSERT INTO solvan_relay.relay_enrollment_transitions
                     (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
                      from_state,event,to_state,workflow_version,reason_code,principal,receipt_hash,
                      occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(transition_id)s,
                     %(enrollment_id)s,%(enrollment_epoch)s,%(from_state)s,%(event)s,%(target)s,
                     %(workflow_version)s,%(reason)s,%(principal)s,%(receipt_hash)s,%(occurred_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.relay_enrollments SET lifecycle=%(target)s,
                      workflow_version=%(workflow_version)s,safe_reason_code=%(reason)s,
                      updated_at=%(occurred_at)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(enrollment_id)s
                      AND lifecycle=%(from_state)s AND workflow_version=%(workflow_version)s-1""",
                params,
            )
            if cur.rowcount != 1:
                raise RelayConflict("Relay enrollment administrative transition lost")
        return target

    def reenable_enrollment(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        registration: RelayEnrollmentRegistration,
        principal: str,
        occurred_at: datetime,
    ) -> str:
        """Advance a disabled enrollment into a new, proof-required epoch.

        Re-enablement deliberately does not restore ``READY``.  It replaces the
        customer-visible runtime proof key, advances the enrollment epoch, and
        leaves all old source bindings behind.  The customer must re-register
        each source binding and complete a new signed readiness proof before a
        read can be issued.
        """

        if occurred_at.tzinfo is None or not principal:
            raise ValueError("Relay enrollment re-enable is malformed")
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            **asdict(registration),
            "enrollment_id": enrollment_id,
            "principal": principal,
            "occurred_at": occurred_at,
            "production_eligible": registration.host_kind != "DEV_LOCAL",
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT e.lifecycle,e.workflow_version,e.enrollment_epoch,
                          e.relay_connection_id,e.principal_subject,e.principal_issuer,
                          c.connection_epoch,p.placement_epoch,p.cell_id
                     FROM solvan_relay.relay_enrollments e
                     JOIN solvan.tenant_connections c
                       ON (c.organization_id,c.project_id,c.environment_id,c.id)=
                          (e.organization_id,e.project_id,e.environment_id,
                           %(relay_connection_id)s)
                     JOIN solvan_scale.tenant_placements p
                       ON p.organization_id=e.organization_id
                    WHERE e.organization_id=%(organization_id)s AND e.project_id=%(project_id)s
                      AND e.environment_id=%(environment_id)s AND e.id=%(enrollment_id)s
                      AND e.lifecycle='DISABLED'
                      AND e.relay_connection_id=%(relay_connection_id)s
                      AND e.principal_subject=%(principal_subject)s
                      AND e.principal_issuer=%(principal_issuer)s
                      AND c.kind='RELAY' AND c.provider='SOLVAN_RELAY'
                      AND c.credential_posture='CUSTOMER_SIDE_NONE'
                      AND c.lifecycle='ENABLED' AND c.availability='READY'
                      AND c.residency_region=%(region)s
                      AND p.is_current AND p.lifecycle='ACTIVE' AND p.home_region=%(region)s
                      AND EXISTS (
                        SELECT 1 FROM solvan_relay.relay_image_attestations a
                         WHERE (a.id,a.image_digest,a.decision)=(%(image_attestation_id)s,
                            %(image_digest)s,'ALLOW') AND a.issued_at <= %(occurred_at)s
                           AND a.expires_at > %(occurred_at)s)
                    FOR UPDATE OF e,c,p""",
                params,
            )
            current = cur.fetchone()
            if current is None:
                raise RelayConflict("Relay enrollment cannot be re-enabled with these bindings")
            epoch = int(current["enrollment_epoch"]) + 1
            workflow_version = int(current["workflow_version"]) + 1
            params.update(
                {
                    "enrollment_epoch": epoch,
                    "workflow_version": workflow_version,
                    "placement_epoch": int(current["placement_epoch"]),
                    "cell_id": str(current["cell_id"]),
                    "transition_id": new_identifier("ret"),
                    "receipt_hash": canonical_digest(
                        {
                            "enrollment_id": enrollment_id,
                            "event": "ADMIN_REENABLED",
                            "enrollment_epoch": epoch,
                            "runtime_proof_key_digest": (
                                registration.runtime_proof_public_key_digest
                            ),
                            "principal": principal,
                            "occurred_at": occurred_at.isoformat(),
                        }
                    ),
                }
            )
            cur.execute(
                """INSERT INTO solvan_relay.relay_enrollment_transitions
                     (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
                      from_state,event,to_state,workflow_version,reason_code,principal,receipt_hash,
                      occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(transition_id)s,
                      %(enrollment_id)s,%(enrollment_epoch)s,'DISABLED','ADMIN_REENABLED',
                      'REGISTERED',%(workflow_version)s,'ADMIN_REENABLED_REQUIRES_NEW_PROOF',
                      %(principal)s,%(receipt_hash)s,%(occurred_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.relay_enrollments
                      SET enrollment_epoch=%(enrollment_epoch)s,
                          placement_epoch=%(placement_epoch)s,cell_id=%(cell_id)s,
                          host_kind=%(host_kind)s,production_eligible=%(production_eligible)s,
                          risk_acceptance_ref=%(risk_acceptance_ref)s,
                          expected_audience=%(expected_audience)s,image_digest=%(image_digest)s,
                          image_attestation_id=%(image_attestation_id)s,
                          local_policy_digest=%(local_policy_digest)s,
                          connector_catalog_digest=%(connector_catalog_digest)s,
                          redaction_revision=%(redaction_revision)s,region=%(region)s,
                          classification_ceiling=%(classification_ceiling)s,
                          relay_version=%(relay_version)s,lifecycle='REGISTERED',
                          workflow_version=%(workflow_version)s,
                          safe_reason_code='AWAITING_RUNTIME_POLICY_PROOF',
                          last_identity_verified_at=NULL,last_poll_at=NULL,last_receipt_at=NULL,
                          updated_at=%(occurred_at)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(enrollment_id)s
                      AND lifecycle='DISABLED' AND workflow_version=%(workflow_version)s-1""",
                params,
            )
            if cur.rowcount != 1:
                raise RelayConflict("Relay enrollment re-enable lost its state fence")
            cur.execute(
                """INSERT INTO solvan_relay.relay_runtime_proof_key_revisions
                     (organization_id,project_id,environment_id,enrollment_id,enrollment_epoch,key_id,
                      public_key_digest,public_key_ref,algorithm,lifecycle,valid_from,issue_until,
                      verify_until)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(enrollment_id)s,
                      %(enrollment_epoch)s,%(runtime_proof_key_id)s,
                      %(runtime_proof_public_key_digest)s,%(runtime_proof_public_key_ref)s,
                      'ECDSA_P256_SHA256','ACTIVE',%(occurred_at)s,
                      %(occurred_at)s + interval '120 seconds',
                      %(occurred_at)s + interval '2 hours')""",
                params,
            )
        return "REGISTERED"

    def resolve_verified_identity(
        self, *, issuer: str, subject: str, audience: str
    ) -> RelayIdentityBinding | None:
        """Resolve scope/enrollment from cryptographic claims, never request data."""

        row = self._connection.execute(
            """SELECT organization_id,project_id,environment_id,id,enrollment_epoch,
                      expected_audience,lifecycle
                 FROM solvan_relay.relay_enrollments
                WHERE principal_issuer=%(issuer)s AND principal_subject=%(subject)s
                  AND expected_audience=%(audience)s
                  AND lifecycle IN ('REGISTERED','READY','DEGRADED','STALE')
                FOR SHARE""",
            {"issuer": issuer, "subject": subject, "audience": audience},
        ).fetchone()
        if row is None:
            return None
        return RelayIdentityBinding(
            scope_organization_id=str(row[0]),
            scope_project_id=str(row[1]),
            scope_environment_id=str(row[2]),
            enrollment_id=str(row[3]),
            enrollment_epoch=int(row[4]),
            expected_audience=str(row[5]),
            lifecycle=RelayEnrollmentState(str(row[6])),
        )

    def issue_readiness_challenge(
        self,
        *,
        scope: Scope,
        identity: RelayIdentityBinding,
        issuer: str,
        subject: str,
        process_boot_id: str,
        relay_version: str,
        image_digest: str,
        runtime_proof_key_id: str,
        issued_at: datetime,
    ) -> IssuedReadinessChallenge:
        """Persist one single-use, identity-bound runtime-policy challenge.

        Scope, policy digest, placement, public-key revision, and signing-key
        eligibility all come from Cloud SQL.  The caller may describe only the
        running process and registered proof key; it cannot choose authority.
        """

        if issued_at.tzinfo is None or not process_boot_id or not relay_version:
            raise ValueError("readiness challenge request is malformed")
        params = {
            **scope.canonical_dict(),
            "enrollment_id": identity.enrollment_id,
            "expected_audience": identity.expected_audience,
            "enrollment_epoch": identity.enrollment_epoch,
            "issuer": issuer,
            "subject": subject,
            "process_boot_id": process_boot_id,
            "relay_version": relay_version,
            "image_digest": image_digest,
            "runtime_proof_key_id": runtime_proof_key_id,
            "issued_at": issued_at,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT e.placement_epoch,e.cell_id,e.expected_audience,e.image_digest,
                          e.local_policy_digest,e.connector_catalog_digest,e.redaction_revision,
                          e.region,e.classification_ceiling,
                          pk.key_id AS policy_key_id,
                          rk.key_id AS runtime_proof_key_id,
                          rk.public_key_digest AS runtime_proof_key_digest,
                          sk.key_id AS signing_key_id
                     FROM solvan_relay.relay_enrollments e
                     JOIN solvan_relay.relay_policy_key_revisions pk
                       ON (pk.organization_id,pk.project_id,pk.environment_id)=
                          (e.organization_id,e.project_id,e.environment_id)
                     JOIN solvan_relay.relay_runtime_proof_key_revisions rk
                       ON (rk.organization_id,rk.project_id,rk.environment_id,
                           rk.enrollment_id,rk.enrollment_epoch,rk.key_id)=
                          (e.organization_id,e.project_id,e.environment_id,
                           e.id,e.enrollment_epoch,%(runtime_proof_key_id)s)
                     JOIN solvan_relay.relay_signing_key_revisions sk
                       ON sk.region=e.region
                    WHERE e.organization_id=%(organization_id)s
                      AND e.project_id=%(project_id)s
                      AND e.environment_id=%(environment_id)s
                      AND e.id=%(enrollment_id)s
                      AND e.enrollment_epoch=%(enrollment_epoch)s
                      AND e.principal_issuer=%(issuer)s
                      AND e.principal_subject=%(subject)s
                      AND e.expected_audience IS NOT NULL
                      AND e.lifecycle IN ('REGISTERED','READY','DEGRADED','STALE')
                      AND e.relay_version=%(relay_version)s
                      AND e.image_digest=%(image_digest)s
                      AND pk.lifecycle='ACTIVE'
                      AND pk.valid_from <= %(issued_at)s AND pk.issue_until >= %(issued_at)s
                      AND rk.lifecycle='ACTIVE'
                      AND rk.valid_from <= %(issued_at)s AND rk.issue_until >= %(issued_at)s
                      AND rk.public_key_ref IS NOT NULL
                      AND sk.lifecycle='ACTIVE'
                      AND sk.valid_from <= %(issued_at)s AND sk.issue_until >= %(issued_at)s
                    ORDER BY pk.issue_until DESC,sk.issue_until DESC
                    LIMIT 1 FOR SHARE OF e,pk,rk,sk""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("Relay enrollment or proof-key is no longer eligible")
            nonce = secrets.token_urlsafe(32)
            nonce_hash = "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest()
            claims_hash = canonical_digest(
                {"audience": identity.expected_audience, "issuer": issuer, "subject": subject}
            )
            challenge_id = new_identifier("rch")
            expires_at = issued_at + timedelta(seconds=60)
            unsigned = {
                "schema_version": 1,
                "challenge_id": challenge_id,
                "nonce_hash": nonce_hash,
                "enrollment_id": identity.enrollment_id,
                "enrollment_epoch": identity.enrollment_epoch,
                "placement_epoch": int(row["placement_epoch"]),
                "cell_id": str(row["cell_id"]),
                "principal_claims_hash": claims_hash,
                "expected_audience": identity.expected_audience,
                "process_boot_id": process_boot_id,
                "image_digest": image_digest,
                "local_policy_digest": str(row["local_policy_digest"]),
                "policy_key_id": str(row["policy_key_id"]),
                "connector_catalog_digest": str(row["connector_catalog_digest"]),
                "redaction_revision": str(row["redaction_revision"]),
                "runtime_proof_key_id": str(row["runtime_proof_key_id"]),
                "runtime_proof_key_digest": str(row["runtime_proof_key_digest"]),
                "region": str(row["region"]),
                "classification_ceiling": str(row["classification_ceiling"]),
                "signing_key_id": str(row["signing_key_id"]),
                "issued_at": issued_at.isoformat(),
                "expires_at": expires_at.isoformat(),
            }
            challenge = RelayReadinessChallenge(
                challenge_id=challenge_id,
                challenge_digest=canonical_digest(unsigned),
                nonce_hash=nonce_hash,
                enrollment_id=identity.enrollment_id,
                enrollment_epoch=identity.enrollment_epoch,
                placement_epoch=int(row["placement_epoch"]),
                cell_id=str(row["cell_id"]),
                principal_claims_hash=claims_hash,
                expected_audience=identity.expected_audience,
                process_boot_id=process_boot_id,
                image_digest=image_digest,
                local_policy_digest=str(row["local_policy_digest"]),
                policy_key_id=str(row["policy_key_id"]),
                connector_catalog_digest=str(row["connector_catalog_digest"]),
                redaction_revision=str(row["redaction_revision"]),
                runtime_proof_key_id=str(row["runtime_proof_key_id"]),
                runtime_proof_key_digest=str(row["runtime_proof_key_digest"]),
                region=str(row["region"]),
                classification_ceiling=str(row["classification_ceiling"]),
                signing_key_id=str(row["signing_key_id"]),
                issued_at=issued_at,
                expires_at=expires_at,
            )
            params.update(asdict(challenge))
            cur.execute(
                """INSERT INTO solvan_relay.relay_readiness_challenges
                     (organization_id,project_id,environment_id,id,enrollment_id,
                      enrollment_epoch,placement_epoch,cell_id,principal_claims_hash,
                      expected_audience,process_boot_id,image_digest,local_policy_digest,
                      policy_key_id,connector_catalog_digest,redaction_revision,
                      runtime_proof_key_id,runtime_proof_key_digest,region,
                      classification_ceiling,nonce_hash,challenge_digest,signing_key_id,
                      issued_at,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(challenge_id)s,%(enrollment_id)s,%(enrollment_epoch)s,
                      %(placement_epoch)s,%(cell_id)s,%(principal_claims_hash)s,
                      %(expected_audience)s,%(process_boot_id)s,%(image_digest)s,
                      %(local_policy_digest)s,%(policy_key_id)s,
                      %(connector_catalog_digest)s,%(redaction_revision)s,
                      %(runtime_proof_key_id)s,%(runtime_proof_key_digest)s,%(region)s,
                      %(classification_ceiling)s,%(nonce_hash)s,%(challenge_digest)s,
                      %(signing_key_id)s,%(issued_at)s,%(expires_at)s)""",
                params,
            )
        return IssuedReadinessChallenge(challenge=challenge, nonce=nonce)

    def resolve_runtime_proof_key(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        enrollment_epoch: int,
        key_id: str,
        at: datetime,
    ) -> RuntimeProofVerificationKey | None:
        """Resolve a current, exact public-key reference after identity checks."""

        row = self._connection.execute(
            """SELECT key_id,public_key_ref,public_key_digest
                 FROM solvan_relay.relay_runtime_proof_key_revisions
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND enrollment_id=%(enrollment_id)s AND enrollment_epoch=%(enrollment_epoch)s
                  AND key_id=%(key_id)s AND lifecycle IN ('ACTIVE','VERIFY_ONLY')
                  AND valid_from <= %(at)s AND verify_until > %(at)s
                  AND public_key_ref IS NOT NULL
                FOR SHARE""",
            {
                **scope.canonical_dict(),
                "enrollment_id": enrollment_id,
                "enrollment_epoch": enrollment_epoch,
                "key_id": key_id,
                "at": at,
            },
        ).fetchone()
        if row is None:
            return None
        return RuntimeProofVerificationKey(
            key_id=str(row[0]), public_key_ref=str(row[1]), public_key_digest=str(row[2])
        )

    def record_runtime_policy_proof(
        self,
        *,
        scope: Scope,
        identity: RelayIdentityBinding,
        issuer: str,
        subject: str,
        proof: RelayRuntimePolicyProof,
        verified_at: datetime,
    ) -> RelayRuntimePolicyProof:
        """Consume one challenge and persist its exact verified runtime proof."""

        if verified_at.tzinfo is None:
            raise ValueError("runtime proof verification time must be timezone-aware")
        params = {
            **scope.canonical_dict(),
            **asdict(proof),
            "verified_at": verified_at,
            "enrollment_id": identity.enrollment_id,
            "enrollment_epoch": identity.enrollment_epoch,
            "issuer": issuer,
            "subject": subject,
            "verified_by_principal": f"{issuer}|{subject}",
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT p.proof_digest,p.signature_base64
                     FROM solvan_relay.relay_runtime_policy_proofs p
                    WHERE p.organization_id=%(organization_id)s
                      AND p.project_id=%(project_id)s AND p.environment_id=%(environment_id)s
                      AND p.challenge_id=%(challenge_id)s
                    FOR SHARE""",
                params,
            )
            existing = cur.fetchone()
            if existing is not None:
                if (
                    str(existing["proof_digest"]) == proof.proof_digest
                    and str(existing["signature_base64"]) == proof.signature_base64
                ):
                    return proof
                raise RelayConflict("readiness challenge already has a different proof")
            cur.execute(
                """SELECT c.id
                     FROM solvan_relay.relay_readiness_challenges c
                     JOIN solvan_relay.relay_enrollments e
                       ON (e.organization_id,e.project_id,e.environment_id,e.id,
                           e.enrollment_epoch,e.placement_epoch,e.cell_id)=
                          (c.organization_id,c.project_id,c.environment_id,c.enrollment_id,
                           c.enrollment_epoch,c.placement_epoch,c.cell_id)
                    WHERE c.organization_id=%(organization_id)s
                      AND c.project_id=%(project_id)s AND c.environment_id=%(environment_id)s
                      AND c.id=%(challenge_id)s AND c.challenge_digest=%(challenge_digest)s
                      AND c.enrollment_id=%(enrollment_id)s
                      AND c.enrollment_epoch=%(enrollment_epoch)s
                      AND c.principal_claims_hash=%(principal_claims_hash)s
                      AND c.expected_audience=%(expected_audience)s
                      AND c.process_boot_id=%(process_boot_id)s
                      AND c.image_digest=%(image_digest)s
                      AND c.local_policy_digest=%(local_policy_digest)s
                      AND c.policy_key_id=%(policy_key_id)s
                      AND c.connector_catalog_digest=%(connector_catalog_digest)s
                      AND c.redaction_revision=%(redaction_revision)s
                      AND c.runtime_proof_key_id=%(runtime_proof_key_id)s
                      AND c.runtime_proof_key_digest=%(runtime_proof_key_digest)s
                      AND c.region=%(region)s
                      AND c.classification_ceiling=%(classification_ceiling)s
                      AND c.consumed_at IS NULL AND c.expires_at >= %(verified_at)s
                      AND %(expires_at)s <= c.expires_at
                      AND e.principal_issuer=%(issuer)s AND e.principal_subject=%(subject)s
                    FOR UPDATE OF c,e""",
                params,
            )
            if cur.fetchone() is None:
                raise RelayConflict("runtime proof does not match a live identity-bound challenge")
            cur.execute(
                """UPDATE solvan_relay.relay_readiness_challenges
                      SET consumed_at=%(verified_at)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(challenge_id)s AND consumed_at IS NULL""",
                params,
            )
            cur.execute(
                """INSERT INTO solvan_relay.relay_runtime_policy_proofs
                     (organization_id,project_id,environment_id,id,challenge_id,challenge_digest,
                      enrollment_id,enrollment_epoch,placement_epoch,principal_claims_hash,
                      expected_audience,process_boot_id,image_digest,local_policy_digest,
                      local_policy_signature_digest,policy_key_id,connector_catalog_digest,
                      redaction_revision,runtime_proof_key_id,runtime_proof_key_digest,region,
                      classification_ceiling,local_policy_verified,proof_digest,signature_base64,
                      verified_by_principal,verified_at,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(proof_id)s,%(challenge_id)s,%(challenge_digest)s,
                      %(enrollment_id)s,%(enrollment_epoch)s,%(placement_epoch)s,
                      %(principal_claims_hash)s,%(expected_audience)s,%(process_boot_id)s,
                      %(image_digest)s,%(local_policy_digest)s,
                      %(local_policy_signature_digest)s,%(policy_key_id)s,
                      %(connector_catalog_digest)s,%(redaction_revision)s,
                      %(runtime_proof_key_id)s,%(runtime_proof_key_digest)s,%(region)s,
                      %(classification_ceiling)s,%(local_policy_verified)s,%(proof_digest)s,
                      %(signature_base64)s,%(verified_by_principal)s,%(verified_at)s,%(expires_at)s)""",
                params,
            )
        return proof

    def record_poll_readiness(
        self,
        *,
        scope: Scope,
        identity: RelayIdentityBinding,
        relay_version: str,
        process_boot_id: str,
        image_digest: str,
        image_attestation_digest: str,
        local_policy_id: str,
        local_policy_digest: str,
        runtime_policy_proof_id: str,
        runtime_policy_proof_digest: str,
        connector_catalog_digest: str,
        relay_connection_epoch: int,
        enrollment_epoch: int,
        declared_adapter_revisions: tuple[str, ...],
        observed_at: datetime,
    ) -> None:
        """Record the proof-backed readiness receipt before a poll can see work."""

        if observed_at.tzinfo is None or not declared_adapter_revisions:
            raise ValueError("poll readiness material is malformed")
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            "enrollment_id": identity.enrollment_id,
            "expected_audience": identity.expected_audience,
            "relay_version": relay_version,
            "process_boot_id": process_boot_id,
            "image_digest": image_digest,
            "image_attestation_digest": image_attestation_digest,
            "local_policy_id": local_policy_id,
            "local_policy_digest": local_policy_digest,
            "runtime_policy_proof_id": runtime_policy_proof_id,
            "runtime_policy_proof_digest": runtime_policy_proof_digest,
            "connector_catalog_digest": connector_catalog_digest,
            "relay_connection_epoch": relay_connection_epoch,
            "enrollment_epoch": enrollment_epoch,
            "declared_adapter_revisions": list(declared_adapter_revisions),
            "observed_at": observed_at,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT e.lifecycle,e.workflow_version,e.enrollment_epoch,
                          e.placement_epoch,e.cell_id,
                          e.relay_connection_id,e.expected_audience,e.image_attestation_id,
                          pk.public_key_digest AS policy_key_digest,
                          p.principal_claims_hash,p.local_policy_signature_digest,p.policy_key_id,
                          p.redaction_revision,p.region,p.classification_ceiling,p.expires_at
                     FROM solvan_relay.relay_enrollments e
                     JOIN solvan_relay.relay_image_attestations ia
                       ON (ia.id,ia.image_digest,ia.decision)=
                          (e.image_attestation_id,e.image_digest,e.image_attestation_decision)
                     JOIN solvan.tenant_connections c
                       ON (c.organization_id,c.project_id,c.environment_id,c.id)=
                          (e.organization_id,e.project_id,e.environment_id,e.relay_connection_id)
                     JOIN solvan_relay.relay_runtime_policy_proofs p
                       ON (p.organization_id,p.project_id,p.environment_id,p.id,p.proof_digest)=
                          (e.organization_id,e.project_id,e.environment_id,
                           %(runtime_policy_proof_id)s,%(runtime_policy_proof_digest)s)
                     JOIN solvan_relay.relay_policy_key_revisions pk
                       ON (pk.organization_id,pk.project_id,pk.environment_id,pk.key_id)=
                          (e.organization_id,e.project_id,e.environment_id,p.policy_key_id)
                    WHERE e.organization_id=%(organization_id)s
                      AND e.project_id=%(project_id)s AND e.environment_id=%(environment_id)s
                      AND e.id=%(enrollment_id)s
                      AND e.enrollment_epoch=%(enrollment_epoch)s
                      AND c.connection_epoch=%(relay_connection_epoch)s
                      AND e.lifecycle IN ('REGISTERED','READY','DEGRADED','STALE')
                      AND e.relay_version=%(relay_version)s AND e.image_digest=%(image_digest)s
                      AND e.local_policy_digest=%(local_policy_digest)s
                      AND e.connector_catalog_digest=%(connector_catalog_digest)s
                      AND p.enrollment_id=e.id AND p.enrollment_epoch=e.enrollment_epoch
                      AND p.process_boot_id=%(process_boot_id)s
                      AND p.expected_audience=e.expected_audience
                      AND p.image_digest=e.image_digest
                      AND p.local_policy_digest=e.local_policy_digest
                      AND p.connector_catalog_digest=e.connector_catalog_digest
                      AND p.expires_at > %(observed_at)s
                      AND pk.lifecycle IN ('ACTIVE','VERIFY_ONLY')
                      AND pk.valid_from <= %(observed_at)s AND pk.verify_until > %(observed_at)s
                      AND ia.attestation_digest=%(image_attestation_digest)s
                      AND ia.expires_at > %(observed_at)s
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_relay.relay_source_bindings b
                         WHERE b.organization_id=e.organization_id AND b.project_id=e.project_id
                           AND b.environment_id=e.environment_id AND b.enrollment_id=e.id
                           AND b.enrollment_epoch=e.enrollment_epoch
                           AND b.adapter_revision <> ALL(%(declared_adapter_revisions)s::text[])
                           AND b.lifecycle='READY')
                    FOR UPDATE OF e,p,pk,ia""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("poll no longer matches current Relay registration")
            expires_at = row["expires_at"]
            if not isinstance(expires_at, datetime):
                raise RelayConflict("runtime proof expiry is malformed")
            receipt_id = new_identifier("rrd")
            receipt_hash = canonical_digest(
                {
                    "enrollment_id": identity.enrollment_id,
                    "runtime_policy_proof_id": runtime_policy_proof_id,
                    "runtime_policy_proof_digest": runtime_policy_proof_digest,
                    "observed_at": observed_at.isoformat(),
                }
            )
            params.update(
                {
                    "receipt_id": receipt_id,
                    "receipt_hash": receipt_hash,
                    "policy_key_id": str(row["policy_key_id"]),
                    "policy_key_digest": str(row["policy_key_digest"]),
                    "principal_claims_hash": str(row["principal_claims_hash"]),
                    "local_policy_signature_digest": str(row["local_policy_signature_digest"]),
                    "redaction_revision": str(row["redaction_revision"]),
                    "region": str(row["region"]),
                    "classification_ceiling": str(row["classification_ceiling"]),
                    "placement_epoch": int(row["placement_epoch"]),
                    "cell_id": str(row["cell_id"]),
                    "relay_connection_id": str(row["relay_connection_id"]),
                    "image_attestation_id": str(row["image_attestation_id"]),
                    "expires_at": expires_at,
                }
            )
            cur.execute(
                """INSERT INTO solvan_relay.relay_readiness_receipts
                     (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
                      placement_epoch,cell_id,relay_connection_id,runtime_policy_proof_id,
                      runtime_policy_proof_digest,principal_claims_hash,expected_audience,image_digest,
                      image_attestation_id,image_attestation_decision,local_policy_id,local_policy_digest,
                      local_policy_signature_digest,policy_key_id,policy_key_digest,
                      connector_catalog_digest,redaction_revision,region,classification_ceiling,
                      relay_version,decision,safe_reason_code,verified_by_principal,
                      verification_evidence_ref,verification_evidence_digest,observed_at,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(receipt_id)s,
                      %(enrollment_id)s,%(enrollment_epoch)s,%(placement_epoch)s,%(cell_id)s,
                      %(relay_connection_id)s,%(runtime_policy_proof_id)s,
                      %(runtime_policy_proof_digest)s,%(principal_claims_hash)s,
                      %(expected_audience)s,%(image_digest)s,%(image_attestation_id)s,'ALLOW',
                      %(local_policy_id)s,%(local_policy_digest)s,
                      %(local_policy_signature_digest)s,%(policy_key_id)s,%(policy_key_digest)s,
                      %(connector_catalog_digest)s,%(redaction_revision)s,%(region)s,
                      %(classification_ceiling)s,%(relay_version)s,'ALLOW',NULL,
                      %(enrollment_id)s,'relay://runtime-proof/' || %(runtime_policy_proof_id)s,
                      %(receipt_hash)s,%(observed_at)s,%(expires_at)s)""",
                params,
            )
            # The first accepted OIDC- and policy-bound readiness receipt is
            # the Relay transport's minimal successful probe. No browser or
            # administrative registration can set READY; a later connection
            # epoch change removes this observation through the ordinary
            # connection fence.
            cur.execute(
                """INSERT INTO solvan.connection_capabilities
                     (organization_id,project_id,environment_id,connection_id,capability,
                      available,outcome,missing_grant,probe_receipt_ref)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(relay_connection_id)s,'relay.readiness',true,'GRANTED',NULL,
                      'relay://readiness/' || %(receipt_id)s)
                   ON CONFLICT (organization_id,project_id,environment_id,connection_id,capability)
                   DO UPDATE SET available=EXCLUDED.available,outcome=EXCLUDED.outcome,
                      missing_grant=EXCLUDED.missing_grant,
                      probe_receipt_ref=EXCLUDED.probe_receipt_ref,observed_at=now()""",
                params,
            )
            cur.execute(
                """UPDATE solvan.tenant_connections
                      SET lifecycle='ENABLED',availability='READY',last_probe_at=%(observed_at)s,
                          last_probe_result='SUCCEEDED',last_success_at=%(observed_at)s,
                          availability_reason_code=NULL,availability_explanation=NULL,
                          availability_missing_grant=NULL,availability_remediation_kind=NULL,
                          availability_receipt_ref='relay://readiness/' || %(receipt_id)s,
                          updated_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(relay_connection_id)s
                      AND lifecycle IN ('PENDING','ENABLED')""",
                params,
            )
            current_lifecycle = str(row["lifecycle"])
            readiness_transition = {
                "REGISTERED": ("ATTESTATION_ACCEPTED", "RUNTIME_POLICY_PROOF_ACCEPTED"),
                "DEGRADED": ("HEALTH_RESTORED", "FRESH_RUNTIME_POLICY_PROOF_ACCEPTED"),
                # A stale enrollment is not re-enabled by configuration.  The
                # Relay must first obtain a new identity-bound challenge and
                # submit a fresh signed proof against the current bindings.
                "STALE": ("REATTESTED", "FRESH_RUNTIME_POLICY_PROOF_ACCEPTED"),
            }.get(current_lifecycle)
            if readiness_transition is not None:
                event, reason_code = readiness_transition
                params["transition_id"] = new_identifier("ret")
                params["workflow_version"] = int(row["workflow_version"]) + 1
                params["event"] = event
                params["reason_code"] = reason_code
                cur.execute(
                    """INSERT INTO solvan_relay.relay_enrollment_transitions
                         (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
                          from_state,event,to_state,workflow_version,reason_code,principal,receipt_hash,
                          occurred_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                          %(transition_id)s,
                          %(enrollment_id)s,%(enrollment_epoch)s,%(lifecycle)s,%(event)s,
                          'READY',%(workflow_version)s,%(reason_code)s,
                          %(enrollment_id)s,%(receipt_hash)s,%(observed_at)s)""",
                    {**params, "lifecycle": current_lifecycle},
                )
                cur.execute(
                    """UPDATE solvan_relay.relay_enrollments
                          SET lifecycle='READY',workflow_version=%(workflow_version)s,
                              safe_reason_code=NULL,last_identity_verified_at=%(observed_at)s,
                              last_poll_at=%(observed_at)s,updated_at=%(observed_at)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(enrollment_id)s
                          AND lifecycle=%(lifecycle)s""",
                    {**params, "lifecycle": current_lifecycle},
                )
                if cur.rowcount != 1:
                    raise RelayConflict("Relay readiness lifecycle transition lost")
            else:
                cur.execute(
                    """UPDATE solvan_relay.relay_enrollments
                          SET last_identity_verified_at=%(observed_at)s,
                              last_poll_at=%(observed_at)s,
                              updated_at=%(observed_at)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(enrollment_id)s""",
                    params,
                )

    def resolve_ready_source_binding(
        self,
        *,
        scope: Scope,
        source_connection_id: str,
        source_connection_epoch: int,
    ) -> RelaySourceBinding | None:
        if source_connection_epoch < 1:
            raise ValueError("source connection epoch must be positive")
        row = self._connection.execute(
            """SELECT b.id,b.enrollment_id,b.enrollment_epoch,
                      b.source_connection_id,b.source_connection_epoch,
                      b.adapter_key,b.adapter_revision,b.capability_receipt_id,
                      b.capability_receipt_hash,b.region,b.classification_ceiling
                 FROM solvan_relay.relay_source_bindings b
                 JOIN solvan_relay.relay_enrollments e
                   ON (e.organization_id,e.project_id,e.environment_id,e.id,e.enrollment_epoch)=
                      (b.organization_id,b.project_id,b.environment_id,
                       b.enrollment_id,b.enrollment_epoch)
                WHERE b.organization_id=%(organization_id)s
                  AND b.project_id=%(project_id)s
                  AND b.environment_id=%(environment_id)s
                  AND b.source_connection_id=%(source_connection_id)s
                  AND b.source_connection_epoch=%(source_connection_epoch)s
                  AND b.lifecycle='READY' AND e.lifecycle='READY'
                  AND EXISTS (
                    SELECT 1 FROM solvan_relay.relay_readiness_receipts r
                     WHERE (r.organization_id,r.project_id,r.environment_id,
                            r.enrollment_id,r.enrollment_epoch)=
                           (e.organization_id,e.project_id,e.environment_id,
                            e.id,e.enrollment_epoch)
                       AND r.decision='ALLOW' AND r.expires_at > clock_timestamp())
                FOR SHARE OF b,e""",
            {
                **scope.canonical_dict(),
                "source_connection_id": source_connection_id,
                "source_connection_epoch": source_connection_epoch,
            },
        ).fetchone()
        if row is None:
            return None
        return RelaySourceBinding(
            binding_id=str(row[0]),
            enrollment_id=str(row[1]),
            enrollment_epoch=int(row[2]),
            source_connection_id=str(row[3]),
            source_connection_epoch=int(row[4]),
            adapter_key=RelayAdapter(str(row[5])),
            adapter_revision=str(row[6]),
            capability_receipt_id=str(row[7]),
            capability_receipt_hash=str(row[8]),
            region=str(row[9]),
            classification_ceiling=str(row[10]),
        )

    def create_collection_job(
        self,
        *,
        scope: Scope,
        material: CollectionJobMaterial,
        wakeup_outbox_event_id: str,
        wakeup_idempotency_key: str,
    ) -> str:
        """Persist the signed job and wake-up after its Agent run and Tool call."""

        material.require_signed_digest(scope=scope)
        values = asdict(material)
        values["adapter_key"] = material.adapter_key.value
        values["typed_parameters"] = dict(material.typed_parameters)
        values.update(scope.canonical_dict())
        values["wakeup_outbox_event_id"] = wakeup_outbox_event_id
        values["wakeup_idempotency_key"] = wakeup_idempotency_key
        with self._connection.transaction():
            existing = self._connection.execute(
                """SELECT id,job_digest FROM solvan_relay.collection_jobs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND tool_call_id=%(tool_call_id)s
                    FOR SHARE""",
                values,
            ).fetchone()
            if existing is not None:
                if existing == (material.collection_job_id, material.job_digest):
                    return material.collection_job_id
                raise RelayConflict("Relay Tool call already has different job material")
            self._connection.execute(
                """INSERT INTO solvan.outbox_events
                     (organization_id,project_id,environment_id,id,aggregate_type,
                      aggregate_id,aggregate_version,topic,event_type,payload_json,
                      idempotency_key,available_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(wakeup_outbox_event_id)s,'RELAY_COLLECTION_JOB',
                      %(collection_job_id)s,0,'relay.job.available','RELAY_JOB_AVAILABLE',
                      jsonb_build_object('collection_job_id',%(collection_job_id)s),
                      %(wakeup_idempotency_key)s,%(issued_at)s)""",
                values,
            )
            self._connection.execute(
                """INSERT INTO solvan_relay.collection_jobs
                     (schema_version,canonicalization_version,organization_id,project_id,
                      environment_id,id,enrollment_id,enrollment_epoch,relay_connection_id,
                      relay_connection_epoch,source_binding_id,source_connection_id,
                      source_connection_epoch,placement_epoch,cell_id,agent_run_id,
                      tool_call_id,tool_arguments_hash,incident_id,profile_key,profile_version,
                      profile_material_hash,profile_ordinal,tool_key,tool_version,
                      capability_receipt_id,capability_receipt_hash,connector_catalog_key,
                      connector_catalog_revision,connector_catalog_digest,adapter_key,
                      adapter_revision,operation,typed_parameters_json,parameters_hash,
                      resource_binding_id,graph_snapshot_id,resource_binding_hash,
                      window_start,window_end,maximum_pages,maximum_items,maximum_bytes,
                      maximum_calls,maximum_attempts,redaction_revision,
                      classification_ceiling,residency_region,input_hash,job_digest,
                      job_nonce,signing_key_id,signature_base64,job_wakeup_outbox_event_id,
                      state,workflow_version,issued_at,expires_at)
                   VALUES (1,1,%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(collection_job_id)s,%(enrollment_id)s,%(enrollment_epoch)s,
                      %(relay_connection_id)s,%(relay_connection_epoch)s,
                      %(source_binding_id)s,%(source_connection_id)s,
                      %(source_connection_epoch)s,%(placement_epoch)s,%(cell_id)s,
                      %(agent_run_id)s,%(tool_call_id)s,%(tool_arguments_hash)s,
                      %(incident_id)s,%(profile_key)s,%(profile_version)s,
                      %(profile_material_hash)s,%(profile_ordinal)s,%(tool_key)s,
                      %(tool_version)s,%(capability_receipt_id)s,
                      %(capability_receipt_hash)s,'gcp-observe.v1',1,
                      %(connector_catalog_digest)s,%(adapter_key)s,%(adapter_revision)s,
                      %(operation)s,%(typed_parameters)s,%(parameters_hash)s,
                      %(resource_binding_id)s,%(graph_snapshot_id)s,
                      %(resource_binding_hash)s,%(window_start)s,%(window_end)s,
                      %(maximum_pages)s,%(maximum_items)s,%(maximum_bytes)s,
                      %(maximum_calls)s,%(maximum_attempts)s,%(redaction_revision)s,
                      %(classification_ceiling)s,%(residency_region)s,%(input_hash)s,
                      %(job_digest)s,%(job_nonce)s,%(signing_key_id)s,%(signature_base64)s,
                      %(wakeup_outbox_event_id)s,'PENDING',0,%(issued_at)s,%(expires_at)s)""",
                values,
            )
        return material.collection_job_id

    def poll_signed_job(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        now: datetime,
    ) -> dict[str, Any] | None:
        """Return one current full signed job; the poll response creates no lease."""

        if now.tzinfo is None:
            raise ValueError("poll time must be timezone-aware")
        with self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.*
                     FROM solvan_relay.collection_jobs j
                     JOIN solvan_relay.relay_enrollments e
                       ON (e.organization_id,e.project_id,e.environment_id,e.id,
                           e.enrollment_epoch,e.cell_id,e.placement_epoch)=
                          (j.organization_id,j.project_id,j.environment_id,j.enrollment_id,
                           j.enrollment_epoch,j.cell_id,j.placement_epoch)
                    WHERE j.organization_id=%(organization_id)s
                      AND j.project_id=%(project_id)s AND j.environment_id=%(environment_id)s
                      AND j.enrollment_id=%(enrollment_id)s AND j.state='PENDING'
                      AND j.expires_at > %(now)s AND e.lifecycle='READY'
                      AND EXISTS (
                        SELECT 1 FROM solvan_relay.relay_readiness_receipts r
                         WHERE (r.organization_id,r.project_id,r.environment_id,
                                r.enrollment_id,r.enrollment_epoch)=
                               (j.organization_id,j.project_id,j.environment_id,
                                j.enrollment_id,j.enrollment_epoch)
                           AND r.decision='ALLOW' AND r.expires_at > %(now)s)
                    ORDER BY j.issued_at
                    LIMIT 1 FOR SHARE OF j,e""",
                {**scope.canonical_dict(), "enrollment_id": enrollment_id, "now": now},
            )
            row = cur.fetchone()
        if row is None:
            return None
        typed_parameters = row["typed_parameters_json"]
        if not isinstance(typed_parameters, dict):
            raise RelayConflict("collection job typed parameters are malformed")
        job = {
            "schema_version": int(row["schema_version"]),
            "canonicalization_version": int(row["canonicalization_version"]),
            "scope_hash": canonical_digest(scope.canonical_dict()),
            "collection_job_id": str(row["id"]),
            "enrollment_id": str(row["enrollment_id"]),
            "enrollment_epoch": int(row["enrollment_epoch"]),
            "relay_connection_id": str(row["relay_connection_id"]),
            "relay_connection_epoch": int(row["relay_connection_epoch"]),
            "source_binding_id": str(row["source_binding_id"]),
            "source_connection_id": str(row["source_connection_id"]),
            "source_connection_epoch": int(row["source_connection_epoch"]),
            "placement_epoch": int(row["placement_epoch"]),
            "cell_id": str(row["cell_id"]),
            "agent_run_id": str(row["agent_run_id"]),
            "tool_call_id": str(row["tool_call_id"]),
            "tool_arguments_hash": str(row["tool_arguments_hash"]),
            "incident_id": str(row["incident_id"]),
            "profile_key": str(row["profile_key"]),
            "profile_version": str(row["profile_version"]),
            "profile_material_hash": str(row["profile_material_hash"]),
            "profile_ordinal": int(row["profile_ordinal"]),
            "tool_key": str(row["tool_key"]),
            "tool_version": str(row["tool_version"]),
            "capability_receipt_id": str(row["capability_receipt_id"]),
            "capability_receipt_hash": str(row["capability_receipt_hash"]),
            "connector_catalog_key": str(row["connector_catalog_key"]),
            "connector_catalog_revision": int(row["connector_catalog_revision"]),
            "connector_catalog_digest": str(row["connector_catalog_digest"]),
            "adapter_key": str(row["adapter_key"]),
            "adapter_revision": str(row["adapter_revision"]),
            "operation": str(row["operation"]),
            "typed_parameters": typed_parameters,
            "parameters_hash": str(row["parameters_hash"]),
            "resource_binding_id": str(row["resource_binding_id"]),
            "graph_snapshot_id": str(row["graph_snapshot_id"]),
            "resource_binding_hash": str(row["resource_binding_hash"]),
            "window_start": _time_text(row["window_start"]),
            "window_end": _time_text(row["window_end"]),
            "maximum_pages": int(row["maximum_pages"]),
            "maximum_items": int(row["maximum_items"]),
            "maximum_bytes": int(row["maximum_bytes"]),
            "maximum_calls": int(row["maximum_calls"]),
            "maximum_attempts": int(row["maximum_attempts"]),
            "redaction_revision": str(row["redaction_revision"]),
            "classification_ceiling": str(row["classification_ceiling"]),
            "residency_region": str(row["residency_region"]),
            "input_hash": str(row["input_hash"]),
            "issued_at": _time_text(row["issued_at"]),
            "expires_at": _time_text(row["expires_at"]),
            "job_nonce": str(row["job_nonce"]),
            "signing_key_id": str(row["signing_key_id"]),
        }
        digest = str(row["job_digest"])
        if canonical_digest(job) != digest:
            raise RelayConflict("stored collection job digest does not bind its poll projection")
        job["job_digest"] = digest
        return {
            "job": job,
            "job_digest": digest,
            "signing_key_id": str(row["signing_key_id"]),
            "signature_base64": str(row["signature_base64"]),
        }

    def create_upload_grant(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        collection_job_id: str,
        job_digest: str,
        claim_token: str,
        attempt_id: str,
        attempt_number: int,
        process_boot_id: str,
        attempt_outcome_hash: str,
        local_result_hash: str,
        content_hash: str,
        evidence_manifest_hash: str,
        redaction_manifest_hash: str,
        resource_binding_hash: str,
        classification: str,
        residency_region: str,
        content_type: str,
        content_length: int,
        object_ref: str,
        cmek_digest: str,
        requested_at: datetime,
    ) -> RelayUploadGrant:
        """Persist the local-result and one-time grant state before URL issue."""

        if requested_at.tzinfo is None or content_type != "application/json":
            raise ValueError("upload grant material is malformed")
        request = {
            "schema_version": 1,
            "collection_job_id": collection_job_id,
            "job_digest": job_digest,
            "claim_token": claim_token,
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "process_boot_id": process_boot_id,
            "attempt_outcome_hash": attempt_outcome_hash,
            "local_result_hash": local_result_hash,
            "content_hash": content_hash,
            "manifest_hash": evidence_manifest_hash,
            "redaction_manifest_hash": redaction_manifest_hash,
            "resource_binding_hash": resource_binding_hash,
            "classification": classification,
            "residency_region": residency_region,
            "content_type": content_type,
            "content_length": content_length,
        }
        request_digest = canonical_digest(request)
        grant_id = new_identifier("rug")
        expires_at = requested_at + timedelta(minutes=5)
        grant_material = {
            "upload_grant_id": grant_id,
            "request_digest": request_digest,
            "object_ref": object_ref,
            "object_generation_match": "0",
            "content_hash": content_hash,
            "evidence_manifest_hash": evidence_manifest_hash,
            "redaction_manifest_hash": redaction_manifest_hash,
            "resource_binding_hash": resource_binding_hash,
            "classification": classification,
            "residency_region": residency_region,
            "content_type": content_type,
            "content_length": content_length,
            "cmek_digest": cmek_digest,
            "expires_at": expires_at.isoformat(),
        }
        grant_digest = canonical_digest(grant_material)
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            **request,
            **grant_material,
            "enrollment_id": enrollment_id,
            "grant_digest": grant_digest,
            "requested_at": requested_at,
            "execution_transition_id": new_identifier("rjt"),
            "result_transition_id": new_identifier("rjt"),
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.state,j.workflow_version,a.state AS attempt_state
                     FROM solvan_relay.collection_jobs j
                     JOIN solvan_relay.relay_attempts a
                       ON (a.organization_id,a.project_id,a.environment_id,a.id,
                           a.collection_job_id,a.job_digest)=
                          (j.organization_id,j.project_id,j.environment_id,%(attempt_id)s,
                           j.id,j.job_digest)
                    WHERE j.organization_id=%(organization_id)s
                      AND j.project_id=%(project_id)s AND j.environment_id=%(environment_id)s
                      AND j.id=%(collection_job_id)s AND j.job_digest=%(job_digest)s
                      AND j.enrollment_id=%(enrollment_id)s AND j.claim_token=%(claim_token)s
                      AND j.lease_owner=%(process_boot_id)s
                      AND j.lease_expires_at > %(requested_at)s
                      AND a.claim_token=%(claim_token)s AND a.attempt_number=%(attempt_number)s
                    FOR UPDATE OF j,a""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("upload grant no longer has a live claimed attempt")
            if str(row["state"]) == "RESULT_STORED":
                cur.execute(
                    """SELECT id,grant_digest,object_ref,object_generation_match,content_type,
                              content_length,expires_at
                         FROM solvan_relay.relay_upload_grants
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND request_digest=%(request_digest)s
                        FOR SHARE""",
                    params,
                )
                existing = cur.fetchone()
                if existing is None:
                    raise RelayConflict("stored result has a different upload grant request")
                return RelayUploadGrant(
                    str(existing["id"]),
                    str(existing["grant_digest"]),
                    str(existing["object_ref"]),
                    str(existing["object_generation_match"]),
                    str(existing["content_type"]),
                    int(existing["content_length"]),
                    existing["expires_at"],
                )
            if str(row["state"]) != "CLAIMED" or str(row["attempt_state"]) != "STARTED":
                raise RelayConflict("attempt cannot store a result in its current state")
            version = int(row["workflow_version"])
            params["execution_version"] = version + 1
            params["result_version"] = version + 2
            cur.execute(
                """INSERT INTO solvan_relay.collection_job_transitions
                     (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                      from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(execution_transition_id)s,%(collection_job_id)s,%(execution_version)s,
                      'CLAIMED','EXECUTION_STARTED','EXECUTING','LIVE_CLAIM_REVALIDATED',
                      %(claim_token)s,%(process_boot_id)s,%(requested_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.collection_jobs SET state='EXECUTING',
                      workflow_version=%(execution_version)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                      AND state='CLAIMED' AND workflow_version=%(execution_version)s-1""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.relay_attempts SET state='LOCAL_RESULT_STORED',
                      outcome_hash=%(attempt_outcome_hash)s,local_result_hash=%(local_result_hash)s,
                      local_result_stored_at=%(requested_at)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(attempt_id)s
                      AND state='STARTED'""",
                params,
            )
            cur.execute(
                """INSERT INTO solvan_relay.collection_job_transitions
                     (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                      from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(result_transition_id)s,%(collection_job_id)s,%(result_version)s,
                      'EXECUTING','LOCAL_RESULT_STORED','RESULT_STORED','REDACTED_RESULT_BOUND',
                      %(claim_token)s,%(process_boot_id)s,%(requested_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.collection_jobs SET state='RESULT_STORED',
                      workflow_version=%(result_version)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                      AND state='EXECUTING' AND workflow_version=%(execution_version)s""",
                params,
            )
            cur.execute(
                """INSERT INTO solvan_relay.relay_upload_grants
                     (organization_id,project_id,environment_id,id,collection_job_id,job_digest,
                      attempt_id,attempt_number,claim_token,request_digest,grant_digest,object_ref,
                      object_generation_match,content_hash,evidence_manifest_hash,redaction_manifest_hash,
                      resource_binding_hash,classification,residency_region,content_type,content_length,
                      cmek_digest,issued_at,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(upload_grant_id)s,
                      %(collection_job_id)s,%(job_digest)s,%(attempt_id)s,%(attempt_number)s,
                      %(claim_token)s,%(request_digest)s,%(grant_digest)s,%(object_ref)s,
                      %(object_generation_match)s,%(content_hash)s,%(evidence_manifest_hash)s,
                      %(redaction_manifest_hash)s,%(resource_binding_hash)s,%(classification)s,
                      %(residency_region)s,%(content_type)s,%(content_length)s,%(cmek_digest)s,
                      %(requested_at)s,%(expires_at)s)""",
                params,
            )
        return RelayUploadGrant(
            grant_id,
            grant_digest,
            object_ref,
            "0",
            content_type,
            content_length,
            expires_at,
        )

    def commit_success_receipt(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        collection_job_id: str,
        job_digest: str,
        claim_token: str,
        attempt_id: str,
        attempt_number: int,
        process_boot_id: str,
        input_hash: str,
        attempt_outcome_hash: str,
        local_result_hash: str,
        content_hash: str,
        evidence_manifest_hash: str,
        redaction_manifest_hash: str,
        resource_binding_hash: str,
        classification: str,
        residency_region: str,
        upload_grant_id: str,
        upload_grant_digest: str,
        object_ref: str,
        object_generation: str,
        object_metadata_hash: str,
        item_count: int,
        page_count: int,
        byte_count: int,
        call_count: int,
        started_at: datetime,
        completed_at: datetime,
        receipt_nonce: str,
    ) -> str:
        """Call the sole atomic Relay success command with internally-built rows."""

        if started_at.tzinfo is None or completed_at.tzinfo is None:
            raise ValueError("receipt times must be timezone-aware")
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            "enrollment_id": enrollment_id,
            "collection_job_id": collection_job_id,
            "job_digest": job_digest,
            "claim_token": claim_token,
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "process_boot_id": process_boot_id,
            "input_hash": input_hash,
            "attempt_outcome_hash": attempt_outcome_hash,
            "local_result_hash": local_result_hash,
            "content_hash": content_hash,
            "evidence_manifest_hash": evidence_manifest_hash,
            "redaction_manifest_hash": redaction_manifest_hash,
            "resource_binding_hash": resource_binding_hash,
            "classification": classification,
            "residency_region": residency_region,
            "upload_grant_id": upload_grant_id,
            "upload_grant_digest": upload_grant_digest,
            "object_ref": object_ref,
            "object_generation": object_generation,
            "object_metadata_hash": object_metadata_hash,
            "item_count": item_count,
            "page_count": page_count,
            "byte_count": byte_count,
            "call_count": call_count,
            "started_at": started_at,
            "completed_at": completed_at,
            "receipt_nonce": receipt_nonce,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.incident_id,j.agent_run_id,j.tool_call_id,j.adapter_key,
                          j.adapter_revision,
                          j.operation,j.source_binding_id,j.source_connection_id,
                          j.source_connection_epoch,j.enrollment_epoch,j.window_start,j.window_end,
                          j.workflow_version,g.object_ref,g.content_hash,g.evidence_manifest_hash,
                          g.redaction_manifest_hash,g.resource_binding_hash,g.classification,
                          g.residency_region,g.content_length
                     FROM solvan_relay.collection_jobs j
                     JOIN solvan_relay.relay_upload_grants g
                       ON (g.organization_id,g.project_id,g.environment_id,g.id,g.grant_digest)=
                          (j.organization_id,j.project_id,j.environment_id,%(upload_grant_id)s,
                           %(upload_grant_digest)s)
                    WHERE j.organization_id=%(organization_id)s AND j.project_id=%(project_id)s
                      AND j.environment_id=%(environment_id)s AND j.id=%(collection_job_id)s
                      AND j.job_digest=%(job_digest)s AND j.enrollment_id=%(enrollment_id)s
                      AND j.state='RESULT_STORED' AND j.claim_token=%(claim_token)s
                    FOR UPDATE OF j,g""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("receipt has no current stored result")
            if any(
                str(row[key]) != str(params[name])
                for key, name in (
                    ("object_ref", "object_ref"),
                    ("content_hash", "content_hash"),
                    ("evidence_manifest_hash", "evidence_manifest_hash"),
                    ("redaction_manifest_hash", "redaction_manifest_hash"),
                    ("resource_binding_hash", "resource_binding_hash"),
                    ("classification", "classification"),
                    ("residency_region", "residency_region"),
                )
            ):
                raise RelayConflict("receipt evidence does not match its durable upload grant")
            if byte_count != int(row["content_length"]):
                raise RelayConflict("receipt byte count does not match its durable upload grant")
            if row["window_start"] is None or row["window_end"] is None:
                raise RelayConflict("receipt requires an exact bounded evidence window")
            receipt_id = new_identifier("rrc")
            evidence_id = new_identifier("evd")
            event_id = new_identifier("evt")
            receipt_hash = canonical_digest(
                {
                    "collection_job_id": collection_job_id,
                    "attempt_id": attempt_id,
                    "attempt_outcome_hash": attempt_outcome_hash,
                    "object_generation": object_generation,
                    "object_metadata_hash": object_metadata_hash,
                    "receipt_nonce": receipt_nonce,
                }
            )
            version = int(row["workflow_version"]) + 1
            receipt = {
                **scope.canonical_dict(),
                "id": receipt_id,
                "collection_job_id": collection_job_id,
                "job_digest": job_digest,
                "attempt_id": attempt_id,
                "attempt_number": attempt_number,
                "claim_token": claim_token,
                "process_boot_id": process_boot_id,
                "receipt_nonce": receipt_nonce,
                "receipt_hash": receipt_hash,
                "result": "SUCCEEDED",
                "error_class": None,
                "input_hash": input_hash,
                "attempt_outcome_hash": attempt_outcome_hash,
                "local_result_hash": local_result_hash,
                "evidence_object_ref": object_ref,
                "evidence_content_hash": content_hash,
                "evidence_manifest_hash": evidence_manifest_hash,
                "redaction_manifest_hash": redaction_manifest_hash,
                "resource_binding_hash": resource_binding_hash,
                "upload_grant_id": upload_grant_id,
                "upload_grant_digest": upload_grant_digest,
                "object_generation": object_generation,
                "object_metadata_hash": object_metadata_hash,
                "classification": classification,
                "residency_region": residency_region,
                "item_count": item_count,
                "page_count": page_count,
                "byte_count": byte_count,
                "call_count": call_count,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
            }
            evidence = {
                **scope.canonical_dict(),
                "id": evidence_id,
                "incident_id": str(row["incident_id"]),
                "source_kind": "SOLVAN_RELAY",
                "source_resource": str(row["source_binding_id"]),
                "query_spec_json": {"operation": str(row["operation"])},
                "window_start": _time_text(row["window_start"]),
                "window_end": _time_text(row["window_end"]),
                "observed_at": completed_at.isoformat(),
                "content_ref": object_ref,
                "content_hash": content_hash,
                "classification": classification,
                "residency": residency_region,
                "armor_verdict_id": None,
                "redaction_manifest_ref": redaction_manifest_hash,
                "provenance_json": {
                    "schema_version": 1,
                    "collection_job_id": collection_job_id,
                    "job_digest": job_digest,
                    "relay_receipt_id": receipt_id,
                    "receipt_hash": receipt_hash,
                    "upload_grant_id": upload_grant_id,
                    "upload_grant_digest": upload_grant_digest,
                    "object_generation": object_generation,
                    "object_metadata_hash": object_metadata_hash,
                    "evidence_manifest_hash": evidence_manifest_hash,
                    "redaction_manifest_hash": redaction_manifest_hash,
                    "resource_binding_hash": resource_binding_hash,
                    "source_binding_id": str(row["source_binding_id"]),
                    "source_connection_id": str(row["source_connection_id"]),
                    "source_connection_epoch": int(row["source_connection_epoch"]),
                    "enrollment_id": enrollment_id,
                    "enrollment_epoch": int(row["enrollment_epoch"]),
                    "adapter_key": str(row["adapter_key"]),
                    "adapter_revision": str(row["adapter_revision"]),
                    "operation": str(row["operation"]),
                },
                "freshness_expires_at": completed_at.isoformat(),
                "created_by_agent_run_id": str(row["agent_run_id"]),
            }
            acceptance = {
                **scope.canonical_dict(),
                "collection_job_id": collection_job_id,
                "relay_receipt_id": receipt_id,
                "evidence_item_id": evidence_id,
                "incident_id": str(row["incident_id"]),
                "accepted_by_principal": "relay-control",
                "acceptance_policy_hash": canonical_digest({"schema_version": 1}),
                "accepted_outbox_event_id": event_id,
            }
            transition = {
                **scope.canonical_dict(),
                "id": new_identifier("rjt"),
                "collection_job_id": collection_job_id,
                "workflow_version": version,
                "machine": "collection_job",
                "from_state": "RESULT_STORED",
                "event": "RECEIPT_ACCEPTED",
                "to_state": "ACCEPTED",
                "reason_code": "OBJECT_VERIFIED_AND_REDACTED",
                "claim_token": claim_token,
                "principal": "relay-control",
                "occurred_at": completed_at.isoformat(),
            }
            outbox = {
                **scope.canonical_dict(),
                "id": event_id,
                "aggregate_type": "RELAY_COLLECTION_JOB",
                "aggregate_id": collection_job_id,
                "aggregate_version": version,
                "topic": "relay.evidence.accepted",
                "event_type": "RELAY_EVIDENCE_ACCEPTED",
                "payload_json": {
                    "collection_job_id": collection_job_id,
                    "relay_receipt_id": receipt_id,
                    "evidence_item_id": evidence_id,
                    "tool_call_id": str(row["tool_call_id"]),
                },
                "idempotency_key": f"relay-evidence-accepted:{collection_job_id}",
            }
            cur.execute(
                """SELECT solvan_relay.relay_commit_success_v1(
                       jsonb_populate_record(NULL::solvan_relay.relay_receipts,%(receipt)s::jsonb),
                       jsonb_populate_record(NULL::solvan.evidence_items,%(evidence)s::jsonb),
                       jsonb_populate_record(NULL::solvan_relay.relay_evidence_acceptances,%(acceptance)s::jsonb),
                       jsonb_populate_record(NULL::solvan_relay.collection_job_transitions,%(transition)s::jsonb),
                       jsonb_populate_record(NULL::solvan.outbox_events,%(outbox)s::jsonb))""",
                {
                    "receipt": json.dumps(receipt),
                    "evidence": json.dumps(evidence),
                    "acceptance": json.dumps(acceptance),
                    "transition": json.dumps(transition),
                    "outbox": json.dumps(outbox),
                },
            )
        return receipt_id

    def record_retryable_attempt_failure(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        collection_job_id: str,
        job_digest: str,
        claim_token: str,
        attempt_id: str,
        attempt_number: int,
        process_boot_id: str,
        input_hash: str,
        attempt_outcome_hash: str,
        error_class: str,
        started_at: datetime,
        completed_at: datetime,
    ) -> RelayRetryOutcome:
        """Persist a closed retryable failure and return only its next safe action.

        A failure never produces a receipt.  The two transition records preserve
        the ``RETRY_WAIT`` decision even when the bounded coordinator policy can
        immediately make the next attempt available.
        """

        if (
            started_at.tzinfo is None
            or completed_at.tzinfo is None
            or completed_at < started_at
            or error_class not in {"UPSTREAM_UNAVAILABLE", "UPSTREAM_RATE_LIMITED"}
        ):
            raise ValueError("retryable Relay outcome is malformed")
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            "enrollment_id": enrollment_id,
            "collection_job_id": collection_job_id,
            "job_digest": job_digest,
            "claim_token": claim_token,
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "process_boot_id": process_boot_id,
            "input_hash": input_hash,
            "attempt_outcome_hash": attempt_outcome_hash,
            "error_class": error_class,
            "started_at": started_at,
            "completed_at": completed_at,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.state,j.workflow_version,j.maximum_attempts,j.claim_token,
                          j.input_hash,a.state AS attempt_state,a.outcome_hash,
                          a.error_class,a.process_boot_id,a.attempt_number
                     FROM solvan_relay.collection_jobs j
                     JOIN solvan_relay.relay_attempts a
                       ON (a.organization_id,a.project_id,a.environment_id,a.id,
                           a.collection_job_id,a.job_digest)=
                          (j.organization_id,j.project_id,j.environment_id,%(attempt_id)s,
                           j.id,j.job_digest)
                    WHERE j.organization_id=%(organization_id)s AND j.project_id=%(project_id)s
                      AND j.environment_id=%(environment_id)s AND j.id=%(collection_job_id)s
                      AND j.job_digest=%(job_digest)s AND j.enrollment_id=%(enrollment_id)s
                    FOR UPDATE OF j,a""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("retryable outcome has no exact Relay attempt")
            if (
                str(row["claim_token"]) != claim_token
                or str(row["input_hash"]) != input_hash
                or str(row["process_boot_id"]) != process_boot_id
                or int(row["attempt_number"]) != attempt_number
            ):
                raise RelayConflict("retryable outcome bindings are stale")
            if str(row["attempt_state"]) == "FAILED_RETRYABLE":
                if (
                    str(row["outcome_hash"]) != attempt_outcome_hash
                    or str(row["error_class"]) != error_class
                ):
                    raise RelayConflict("retryable outcome replay changed covered fields")
                state = str(row["state"])
                return RelayRetryOutcome(
                    collection_job_id,
                    attempt_id,
                    attempt_number,
                    state,
                    "POLL_FOR_RETRY" if state == "PENDING" else "STOP",
                    int(row["workflow_version"]),
                )
            if str(row["state"]) != "EXECUTING" or str(row["attempt_state"]) != "STARTED":
                raise RelayConflict("Relay attempt cannot record a retryable failure now")
            version = int(row["workflow_version"])
            params.update(
                {
                    "retry_wait_version": version + 1,
                    "next_version": version + 2,
                    "retry_wait_transition_id": new_identifier("rjt"),
                    "next_transition_id": new_identifier("rjt"),
                }
            )
            cur.execute(
                """UPDATE solvan_relay.relay_attempts SET state='FAILED_RETRYABLE',
                          outcome_hash=%(attempt_outcome_hash)s,error_class=%(error_class)s,
                          terminal_at=%(completed_at)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(attempt_id)s
                      AND state='STARTED'""",
                params,
            )
            cur.execute(
                """INSERT INTO solvan_relay.collection_job_transitions
                     (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                      from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(retry_wait_transition_id)s,%(collection_job_id)s,%(retry_wait_version)s,
                      'EXECUTING','RETRYABLE_ATTEMPT_FAILED','RETRY_WAIT',%(error_class)s,
                      %(claim_token)s,%(process_boot_id)s,%(completed_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.collection_jobs SET state='RETRY_WAIT',
                          workflow_version=%(retry_wait_version)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                      AND state='EXECUTING' AND workflow_version=%(retry_wait_version)s-1""",
                params,
            )
            exhausted = attempt_number >= int(row["maximum_attempts"])
            if exhausted:
                cur.execute(
                    """INSERT INTO solvan_relay.collection_job_transitions
                         (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                          from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                          %(next_transition_id)s,%(collection_job_id)s,%(next_version)s,
                          'RETRY_WAIT','RETRY_BUDGET_EXHAUSTED','REFUSED','ATTEMPT_BUDGET_EXHAUSTED',
                          %(claim_token)s,'relay-control',%(completed_at)s)""",
                    params,
                )
                cur.execute(
                    """UPDATE solvan_relay.collection_jobs SET state='REFUSED',
                          workflow_version=%(next_version)s,refusal_reason='ATTEMPT_BUDGET_EXHAUSTED',
                          completed_at=%(completed_at)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                          AND state='RETRY_WAIT' AND workflow_version=%(retry_wait_version)s""",
                    params,
                )
                return RelayRetryOutcome(
                    collection_job_id, attempt_id, attempt_number, "REFUSED", "STOP", version + 2
                )
            cur.execute(
                """INSERT INTO solvan_relay.collection_job_transitions
                     (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                      from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(next_transition_id)s,%(collection_job_id)s,%(next_version)s,
                      'RETRY_WAIT','SAFE_RETRY_AUTHORIZED','PENDING','RETRYABLE_ERROR_WITHIN_BUDGET',
                      %(claim_token)s,'relay-control',%(completed_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.collection_jobs SET state='PENDING',
                          workflow_version=%(next_version)s,claim_request_nonce=NULL,
                          claim_token=NULL,lease_owner=NULL,lease_expires_at=NULL
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                      AND state='RETRY_WAIT' AND workflow_version=%(retry_wait_version)s""",
                params,
            )
        return RelayRetryOutcome(
            collection_job_id, attempt_id, attempt_number, "PENDING", "POLL_FOR_RETRY", version + 2
        )

    def get_job_status(
        self, *, scope: Scope, enrollment_id: str, collection_job_id: str
    ) -> RelayJobStatus:
        """Return a minimal, identity-bound reconciliation projection."""

        with self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.id,j.job_digest,j.state,j.cancel_requested_at,
                          a.id AS attempt_id,a.attempt_number,a.local_result_hash
                     FROM solvan_relay.collection_jobs j
                     LEFT JOIN LATERAL (
                       SELECT id,attempt_number,local_result_hash
                         FROM solvan_relay.relay_attempts a
                        WHERE (a.organization_id,a.project_id,a.environment_id,a.collection_job_id)=
                              (j.organization_id,j.project_id,j.environment_id,j.id)
                        ORDER BY a.attempt_number DESC LIMIT 1
                     ) a ON TRUE
                    WHERE j.organization_id=%(organization_id)s AND j.project_id=%(project_id)s
                      AND j.environment_id=%(environment_id)s AND j.id=%(collection_job_id)s
                      AND j.enrollment_id=%(enrollment_id)s
                    FOR SHARE OF j""",
                {
                    **scope.canonical_dict(),
                    "enrollment_id": enrollment_id,
                    "collection_job_id": collection_job_id,
                },
            )
            row = cur.fetchone()
        if row is None:
            raise RelayConflict("Relay job is not visible to this enrollment")
        state = str(row["state"])
        cancelled = row["cancel_requested_at"] is not None
        action = "STOP"
        if cancelled:
            action = "STOP_AND_ACK_CANCEL"
        elif state == "PENDING":
            action = "POLL_FOR_RETRY"
        elif state in {"RESULT_STORED", "AMBIGUOUS"} and row["local_result_hash"] is not None:
            action = "RECONCILE_STORED_RESULT"
        return RelayJobStatus(
            str(row["id"]),
            str(row["job_digest"]),
            state,
            action,
            None if row["attempt_id"] is None else str(row["attempt_id"]),
            None if row["attempt_number"] is None else int(row["attempt_number"]),
            None if row["local_result_hash"] is None else str(row["local_result_hash"]),
            cancelled,
        )

    def request_job_cancellation(
        self,
        *,
        scope: Scope,
        collection_job_id: str,
        principal: str,
        requested_at: datetime,
    ) -> str:
        """Record an administrator cancellation without erasing a possible read."""

        if requested_at.tzinfo is None or not principal:
            raise ValueError("Relay cancellation arguments are invalid")
        params: dict[str, Any] = {
            **scope.canonical_dict(),
            "collection_job_id": collection_job_id,
            "principal": principal,
            "requested_at": requested_at,
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT state,workflow_version,claim_token,cancel_requested_at
                     FROM solvan_relay.collection_jobs
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                    FOR UPDATE""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("Relay job is absent")
            state = str(row["state"])
            if state in {"ACCEPTED", "REFUSED", "EXPIRED", "CANCELLED"}:
                return state
            if state != "PENDING":
                cur.execute(
                    """UPDATE solvan_relay.collection_jobs SET cancel_requested_at=
                          COALESCE(cancel_requested_at,%(requested_at)s)
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(collection_job_id)s""",
                    params,
                )
                return state
            params.update(
                {
                    "transition_id": new_identifier("rjt"),
                    "next_version": int(row["workflow_version"]) + 1,
                }
            )
            cur.execute(
                """INSERT INTO solvan_relay.collection_job_transitions
                     (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                      from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(transition_id)s,%(collection_job_id)s,%(next_version)s,
                     'PENDING','CANCELLED','CANCELLED','ADMIN_CANCELLED_BEFORE_CLAIM',
                     NULL,%(principal)s,%(requested_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.collection_jobs SET state='CANCELLED',
                      workflow_version=%(next_version)s,cancel_requested_at=%(requested_at)s,
                      completed_at=%(requested_at)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                      AND state='PENDING' AND workflow_version=%(next_version)s-1""",
                params,
            )
            if cur.rowcount != 1:
                raise RelayConflict("Relay cancellation compare-and-set lost")
        return "CANCELLED"

    def acknowledge_cancellation(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        collection_job_id: str,
        process_boot_id: str,
    ) -> RelayJobStatus:
        """Acknowledge only an existing cancellation request, never infer one."""

        status = self.get_job_status(
            scope=scope, enrollment_id=enrollment_id, collection_job_id=collection_job_id
        )
        if not status.cancel_requested:
            raise RelayConflict("Relay job has no cancellation request")
        if not process_boot_id:
            raise ValueError("Relay cancellation acknowledgement is malformed")
        return status

    def reconcile_expired_claims(self, *, scope: Scope, now: datetime, limit: int = 25) -> int:
        """Fence lost customer processes without assuming their read never ran.

        A claim has an attempt record before any provider call, so an expired
        claim is conservatively ambiguous.  The coordinator, rather than the
        Relay or a model workload, owns this durable recovery transition.
        """

        if now.tzinfo is None or not 1 <= limit <= 100:
            raise ValueError("Relay reconciliation arguments are invalid")
        reconciled = 0
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.id,j.state,j.workflow_version,j.claim_token
                     FROM solvan_relay.collection_jobs j
                    WHERE j.organization_id=%(organization_id)s AND j.project_id=%(project_id)s
                      AND j.environment_id=%(environment_id)s
                      AND j.state IN ('CLAIMED','EXECUTING')
                      AND j.lease_expires_at <= %(now)s
                    ORDER BY j.lease_expires_at
                    LIMIT %(limit)s FOR UPDATE SKIP LOCKED""",
                {**scope.canonical_dict(), "now": now, "limit": limit},
            )
            rows = cur.fetchall()
            for row in rows:
                state = str(row["state"])
                event = "CLAIM_EXPIRED_AMBIGUOUS" if state == "CLAIMED" else "EXECUTION_AMBIGUOUS"
                params = {
                    **scope.canonical_dict(),
                    "collection_job_id": str(row["id"]),
                    "workflow_version": int(row["workflow_version"]) + 1,
                    "transition_id": new_identifier("rjt"),
                    "claim_token": row["claim_token"],
                    "event": event,
                    "now": now,
                }
                cur.execute(
                    """INSERT INTO solvan_relay.collection_job_transitions
                         (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                          from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                          %(transition_id)s,%(collection_job_id)s,%(workflow_version)s,
                          %(state)s,%(event)s,'AMBIGUOUS','LEASE_EXPIRED_RECONCILIATION',
                          %(claim_token)s,'coordinator',%(now)s)""",
                    {**params, "state": state},
                )
                cur.execute(
                    """UPDATE solvan_relay.collection_jobs SET state='AMBIGUOUS',
                          workflow_version=%(workflow_version)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                          AND state=%(state)s AND workflow_version=%(workflow_version)s-1""",
                    {**params, "state": state},
                )
                if cur.rowcount != 1:
                    raise RelayConflict("Relay lease reconciliation compare-and-set lost")
                reconciled += 1
        return reconciled

    def expire_unclaimed_jobs(self, *, scope: Scope, now: datetime, limit: int = 25) -> int:
        """Terminalize work that no customer process has claimed before expiry.

        ``PENDING`` is the only state in which the control plane can prove no
        customer-side provider call started.  The coordinator therefore owns
        this narrow transition and closes the ordinary Tool-call reservation in
        the same transaction.  Claimed and executing jobs must continue through
        :meth:`reconcile_expired_claims`, where their upstream effect is treated
        as ambiguous rather than discarded.
        """

        if now.tzinfo is None or not 1 <= limit <= 100:
            raise ValueError("Relay expiry arguments are invalid")
        expired = 0
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.id,j.tool_call_id,j.workflow_version
                     FROM solvan_relay.collection_jobs j
                    WHERE j.organization_id=%(organization_id)s AND j.project_id=%(project_id)s
                      AND j.environment_id=%(environment_id)s
                      AND j.state='PENDING' AND j.expires_at <= %(now)s
                    ORDER BY j.expires_at
                    LIMIT %(limit)s FOR UPDATE SKIP LOCKED""",
                {**scope.canonical_dict(), "now": now, "limit": limit},
            )
            for row in cur.fetchall():
                params = {
                    **scope.canonical_dict(),
                    "collection_job_id": str(row["id"]),
                    "tool_call_id": str(row["tool_call_id"]),
                    "workflow_version": int(row["workflow_version"]) + 1,
                    "transition_id": new_identifier("rjt"),
                    "now": now,
                }
                cur.execute(
                    """INSERT INTO solvan_relay.collection_job_transitions
                         (organization_id,project_id,environment_id,id,collection_job_id,workflow_version,
                          from_state,event,to_state,reason_code,claim_token,principal,occurred_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                         %(transition_id)s,%(collection_job_id)s,%(workflow_version)s,
                         'PENDING','EXPIRED','EXPIRED','JOB_EXPIRED_BEFORE_CLAIM',
                         NULL,'coordinator',%(now)s)""",
                    params,
                )
                cur.execute(
                    """UPDATE solvan_relay.collection_jobs SET state='EXPIRED',
                          workflow_version=%(workflow_version)s,completed_at=%(now)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(collection_job_id)s
                          AND state='PENDING' AND workflow_version=%(workflow_version)s-1""",
                    params,
                )
                if cur.rowcount != 1:
                    raise RelayConflict("Relay pending expiry compare-and-set lost")
                cur.execute(
                    """UPDATE solvan.tool_calls SET status='FAILED',error_class='RELAY_JOB_EXPIRED',
                          completed_at=%(now)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(tool_call_id)s
                          AND status='RESERVED'""",
                    params,
                )
                if cur.rowcount != 1:
                    raise RelayConflict("Relay expiry has no reserved Tool call")
                cur.execute(
                    """UPDATE solvan_operability.tool_call_receipts
                          SET output_bytes=0,completed_at=%(now)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND tool_call_id=%(tool_call_id)s
                          AND completed_at IS NULL""",
                    params,
                )
                expired += 1
        return expired

    def claim_job(
        self,
        *,
        scope: Scope,
        enrollment_id: str,
        collection_job_id: str,
        job_digest: str,
        claim_request_nonce: str,
        process_boot_id: str,
        accepted_at: datetime,
        lease_seconds: int = 60,
    ) -> RelayJobClaim:
        """Claim one exact job with replay-safe nonce and server-minted token."""

        if accepted_at.tzinfo is None or not 1 <= lease_seconds <= 90:
            raise ValueError("Relay claim time or lease is invalid")
        params = {
            **scope.canonical_dict(),
            "enrollment_id": enrollment_id,
            "collection_job_id": collection_job_id,
            "job_digest": job_digest,
            "claim_request_nonce": claim_request_nonce,
            "process_boot_id": process_boot_id,
            "accepted_at": accepted_at,
            "lease_seconds": lease_seconds,
            "claim_token": uuid4(),
            "attempt_id": new_identifier("rat"),
            "attempt_number": None,
            "transition_id": new_identifier("rjt"),
        }
        with self._connection.transaction(), self._connection.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT j.state,j.workflow_version,j.claim_request_nonce,
                          j.claim_token,j.lease_expires_at,a.id AS attempt_id,
                          a.attempt_number,
                          COALESCE((SELECT max(previous.attempt_number)
                                      FROM solvan_relay.relay_attempts previous
                                     WHERE (previous.organization_id,previous.project_id,
                                            previous.environment_id,previous.collection_job_id)=
                                           (j.organization_id,j.project_id,
                                            j.environment_id,j.id)),0) AS attempted_count,
                          j.maximum_attempts
                     FROM solvan_relay.collection_jobs j
                     JOIN solvan_relay.relay_enrollments e
                       ON (e.organization_id,e.project_id,e.environment_id,e.id,
                           e.enrollment_epoch,j.cell_id,j.placement_epoch)=
                          (j.organization_id,j.project_id,j.environment_id,j.enrollment_id,
                           j.enrollment_epoch,e.cell_id,e.placement_epoch)
                     LEFT JOIN solvan_relay.relay_attempts a
                       ON (a.organization_id,a.project_id,a.environment_id,a.collection_job_id)=
                          (j.organization_id,j.project_id,j.environment_id,j.id)
                    WHERE j.organization_id=%(organization_id)s
                      AND j.project_id=%(project_id)s
                      AND j.environment_id=%(environment_id)s
                      AND j.id=%(collection_job_id)s AND j.job_digest=%(job_digest)s
                      AND j.enrollment_id=%(enrollment_id)s
                      AND e.lifecycle='READY' AND j.expires_at > %(accepted_at)s
                      AND EXISTS (
                        SELECT 1 FROM solvan_relay.relay_readiness_receipts r
                         WHERE (r.organization_id,r.project_id,r.environment_id,
                                r.enrollment_id,r.enrollment_epoch)=
                               (j.organization_id,j.project_id,j.environment_id,
                                j.enrollment_id,j.enrollment_epoch)
                           AND r.decision='ALLOW' AND r.expires_at > %(accepted_at)s)
                    FOR UPDATE OF j,a""",
                params,
            )
            row = cur.fetchone()
            if row is None:
                raise RelayConflict("Relay job is absent, expired, or no longer eligible")
            if row["state"] == "CLAIMED":
                if row["claim_request_nonce"] != claim_request_nonce:
                    raise RelayConflict("Relay job was claimed by another nonce")
                return RelayJobClaim(
                    collection_job_id,
                    job_digest,
                    str(row["claim_token"]),
                    str(row["attempt_id"]),
                    int(row["attempt_number"]),
                    row["lease_expires_at"],
                    int(row["workflow_version"]),
                )
            if row["state"] != "PENDING":
                raise RelayConflict("Relay job is not claimable")
            attempt_number = int(row.get("attempted_count", 0)) + 1
            if attempt_number > int(row.get("maximum_attempts", 2)):
                raise RelayConflict("Relay job retry budget is exhausted")
            params["attempt_number"] = attempt_number
            params["next_version"] = int(row["workflow_version"]) + 1
            cur.execute(
                """INSERT INTO solvan_relay.collection_job_transitions
                     (organization_id,project_id,environment_id,id,collection_job_id,
                      workflow_version,from_state,event,to_state,reason_code,
                      claim_token,principal,occurred_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(transition_id)s,%(collection_job_id)s,%(next_version)s,'PENDING',
                      'CLAIM_ACCEPTED','CLAIMED','READY_BINDINGS_REVALIDATED',
                      %(claim_token)s,%(process_boot_id)s,%(accepted_at)s)""",
                params,
            )
            cur.execute(
                """UPDATE solvan_relay.collection_jobs
                      SET state='CLAIMED',workflow_version=%(next_version)s,
                          claim_request_nonce=%(claim_request_nonce)s,
                          claim_token=%(claim_token)s,lease_owner=%(process_boot_id)s,
                          lease_expires_at=%(accepted_at)s +
                            (%(lease_seconds)s * interval '1 second')
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(collection_job_id)s AND state='PENDING'
                      AND workflow_version=%(next_version)s-1
                  RETURNING claim_token,lease_expires_at,workflow_version""",
                params,
            )
            claimed = cur.fetchone()
            if claimed is None:
                raise RelayConflict("Relay claim compare-and-set lost")
            cur.execute(
                """INSERT INTO solvan_relay.relay_attempts
                     (organization_id,project_id,environment_id,id,collection_job_id,
                      job_digest,attempt_number,claim_token,process_boot_id,
                      adapter_revision,state,started_at)
                   SELECT %(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(attempt_id)s,j.id,j.job_digest,%(attempt_number)s,
                      %(claim_token)s,%(process_boot_id)s,j.adapter_revision,
                      'STARTED',%(accepted_at)s
                     FROM solvan_relay.collection_jobs j
                    WHERE j.organization_id=%(organization_id)s
                      AND j.project_id=%(project_id)s
                      AND j.environment_id=%(environment_id)s
                      AND j.id=%(collection_job_id)s AND j.job_digest=%(job_digest)s
                      AND j.state='CLAIMED' AND j.claim_token=%(claim_token)s""",
                params,
            )
        return RelayJobClaim(
            collection_job_id,
            job_digest,
            str(claimed["claim_token"]),
            str(params["attempt_id"]),
            attempt_number,
            claimed["lease_expires_at"],
            int(claimed["workflow_version"]),
        )
