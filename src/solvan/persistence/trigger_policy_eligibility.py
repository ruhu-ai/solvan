"""Eligibility authority for independently approved trigger policies."""

from __future__ import annotations

from psycopg.rows import dict_row

from solvan.application.operational_guidance import GuidanceError
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.trigger_policy_base import TriggerPolicyStoreBase
from solvan.persistence.trigger_policy_types import TriggerPolicyLifecycleCommit


class TriggerPolicyEligibilityMixin(TriggerPolicyStoreBase):
    def mark_eligible(
        self,
        *,
        scope: Scope,
        policy_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        decision_request_id: str,
    ) -> TriggerPolicyLifecycleCommit:
        """Append the first lifecycle authority after independent approval."""

        request_hash = canonical_sha256(
            {
                "operation": "MARK_ELIGIBLE",
                "policy_key": policy_key,
                "version": version,
                "policy_hash": expected_digest,
                "expected_prior_lifecycle_epoch": 0,
                "principal": principal,
                "required_role": "TRIGGER_POLICY_LIFECYCLE_MANAGER",
            }
        )
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT owner_department,author_principal,approved_by_principal
                     FROM solvan_operability.trigger_policy_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND version=%(version)s
                      AND policy_hash=%(digest)s""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                },
            )
            authority = cursor.fetchone()
            if authority is None or principal in {
                authority["author_principal"],
                authority["approved_by_principal"],
            }:
                raise GuidanceError("trigger lifecycle actor is not independently authorized")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("TRIGGER_POLICY_LIFECYCLE_MANAGER",),
                department=str(authority["owner_department"]),
            )
            cursor.execute(
                """SELECT id,request_hash FROM
                         solvan_operability.trigger_policy_lifecycle_decisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND idempotency_key=%(request_id)s""",
                {**scope.canonical_dict(), "request_id": decision_request_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise GuidanceError("trigger eligibility idempotency key changed material")
                return TriggerPolicyLifecycleCommit(
                    policy_key, version, "ELIGIBLE", expected_digest, str(existing["id"]), False
                )
            cursor.execute(
                """SELECT lifecycle,policy_hash,owner_department,author_principal,
                          approved_by_principal
                     FROM solvan_operability.trigger_policy_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND version=%(version)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "policy_key": policy_key, "version": version},
            )
            row = cursor.fetchone()
            if (
                row is None
                or row["lifecycle"] != "APPROVED"
                or row["policy_hash"] != expected_digest
            ):
                raise GuidanceError("only the exact approved trigger policy may become eligible")
            decision_id = new_identifier("tpl")
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_lifecycle_decisions
                     (organization_id,project_id,environment_id,id,policy_key,
                      policy_version,policy_hash,lifecycle_epoch,
                      expected_prior_lifecycle_epoch,operation,actor_principal,
                      idempotency_key,request_hash,reason_code)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(policy_key)s,%(version)s,%(digest)s,1,0,'MARK_ELIGIBLE',
                           %(principal)s,%(request_id)s,%(request_hash)s,
                           'APPROVED_POLICY_MARKED_ELIGIBLE')""",
                {
                    **scope.canonical_dict(),
                    "id": decision_id,
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                    "principal": principal,
                    "request_id": decision_request_id,
                    "request_hash": request_hash,
                },
            )
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_current_lifecycles
                     (organization_id,project_id,environment_id,policy_key,
                      policy_version,policy_hash,lifecycle_epoch,availability,
                      decision_id,decision_operation)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(policy_key)s,%(version)s,%(digest)s,1,'ELIGIBLE',
                           %(decision_id)s,'MARK_ELIGIBLE')""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                    "decision_id": decision_id,
                },
            )
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="TRIGGER_POLICY_MARKED_ELIGIBLE",
                entity_ref=f"trigger-policy:{policy_key}@{version}",
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code="APPROVED_POLICY_MARKED_ELIGIBLE",
            )
        return TriggerPolicyLifecycleCommit(
            policy_key, version, "ELIGIBLE", expected_digest, decision_id, True
        )
