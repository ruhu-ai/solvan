"""Activation, deactivation, and retirement of approved trigger policies."""

from __future__ import annotations

from psycopg.rows import dict_row

from solvan.application.operational_guidance import GuidanceError
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.trigger_policy_replacement import TriggerPolicyReplacementMixin
from solvan.persistence.trigger_policy_types import (
    TriggerPolicyLifecycleCommit,
)


class TriggerPolicyLifecycleMixin(TriggerPolicyReplacementMixin):
    def activate(
        self,
        *,
        scope: Scope,
        policy_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        expected_prior_head_epoch: int,
        expected_activation_id: str | None,
        placement_epoch: int,
        decision_request_id: str,
    ) -> TriggerPolicyLifecycleCommit:
        """Append and project one exact approved policy head."""

        if (
            expected_prior_head_epoch < 0
            or placement_epoch < 1
            or (expected_prior_head_epoch == 0) != (expected_activation_id is None)
        ):
            raise GuidanceError("trigger activation epochs are invalid")
        entity_ref = f"trigger-policy-head:{policy_key}"
        request_hash = canonical_sha256(
            {
                "operation": "ACTIVATE",
                "policy_key": policy_key,
                "version": version,
                "policy_hash": expected_digest,
                "expected_prior_head_epoch": expected_prior_head_epoch,
                "expected_activation_id": expected_activation_id,
                "placement_epoch": placement_epoch,
                "principal": principal,
                "required_role": "TRIGGER_POLICY_ACTIVATOR",
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
                raise GuidanceError("trigger activation actor is not independently authorized")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("TRIGGER_POLICY_ACTIVATOR",),
                department=str(authority["owner_department"]),
            )
            cursor.execute(
                """SELECT id,policy_version FROM solvan_operability.trigger_policy_activations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND idempotency_key=%(request_id)s""",
                {**scope.canonical_dict(), "request_id": decision_request_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                cursor.execute(
                    """SELECT request_hash FROM solvan_operability.trigger_policy_activations
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND id=%(id)s""",
                    {**scope.canonical_dict(), "id": existing["id"]},
                )
                stored = cursor.fetchone()
                if stored is None or stored["request_hash"] != request_hash:
                    raise GuidanceError("trigger activation idempotency key changed material")
                return TriggerPolicyLifecycleCommit(
                    policy_key,
                    str(existing["policy_version"]),
                    "ACTIVE",
                    expected_digest,
                    str(existing["id"]),
                    False,
                )
            cursor.execute(
                """SELECT p.*,l.lifecycle_epoch,l.availability
                     FROM solvan_operability.trigger_policy_revisions p
                     JOIN solvan_operability.trigger_policy_current_lifecycles l ON
                       (l.organization_id,l.project_id,l.environment_id,l.policy_key,
                        l.policy_version)=(p.organization_id,p.project_id,p.environment_id,
                                           p.policy_key,p.version)
                    WHERE p.organization_id=%(organization_id)s
                      AND p.project_id=%(project_id)s AND p.environment_id=%(environment_id)s
                      AND p.policy_key=%(policy_key)s AND p.version=%(version)s
                    FOR UPDATE OF p,l""",
                {**scope.canonical_dict(), "policy_key": policy_key, "version": version},
            )
            policy = cursor.fetchone()
            if (
                policy is None
                or policy["lifecycle"] != "APPROVED"
                or policy["availability"] != "ELIGIBLE"
                or policy["policy_hash"] != expected_digest
            ):
                raise GuidanceError("trigger policy is not eligible for activation")
            self._require_policy_dependencies(cursor=cursor, scope=scope, row=policy)
            cursor.execute(
                """SELECT head_epoch,activation_id FROM
                         solvan_operability.trigger_policy_current_heads
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s FOR UPDATE""",
                {**scope.canonical_dict(), "policy_key": policy_key},
            )
            head = cursor.fetchone()
            observed_epoch = 0 if head is None else int(head["head_epoch"])
            observed_activation_id = None if head is None else str(head["activation_id"])
            if (
                observed_epoch != expected_prior_head_epoch
                or observed_activation_id != expected_activation_id
            ):
                raise GuidanceError("trigger activation head epoch is stale")
            activation_id = new_identifier("tpa")
            head_epoch = observed_epoch + 1
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_activations
                     (organization_id,project_id,environment_id,id,policy_key,
                      policy_version,policy_hash,activation_kind,head_epoch,
                      expected_prior_head_epoch,expected_activation_id,evaluation_ref,
                      approval_ref,connection_epoch,placement_epoch,supersession,actor_principal,
                      idempotency_key,request_hash,reason_code)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(policy_key)s,%(version)s,%(digest)s,'ACTIVATE',%(head_epoch)s,
                           %(prior_epoch)s,%(expected_activation_id)s,%(evaluation_ref)s,
                           %(approval_ref)s,%(connection_epoch)s,%(placement_epoch)s,
                           %(supersession)s,
                           %(principal)s,%(request_id)s,%(request_hash)s,'POLICY_ACTIVATED')""",
                {
                    **scope.canonical_dict(),
                    "id": activation_id,
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                    "head_epoch": head_epoch,
                    "prior_epoch": observed_epoch,
                    "expected_activation_id": expected_activation_id,
                    "evaluation_ref": policy["evaluation_ref"],
                    "approval_ref": policy["approval_ref"],
                    "connection_epoch": policy["source_connection_epoch"],
                    "placement_epoch": placement_epoch,
                    "supersession": policy["supersession"],
                    "principal": principal,
                    "request_id": decision_request_id,
                    "request_hash": request_hash,
                },
            )
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_current_heads
                     (organization_id,project_id,environment_id,policy_key,head_epoch,
                      activation_id,policy_version,policy_hash,activation_kind,
                      connection_epoch,placement_epoch,supersession,is_current)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(policy_key)s,%(head_epoch)s,%(activation_id)s,%(version)s,
                           %(digest)s,'ACTIVATE',%(connection_epoch)s,%(placement_epoch)s,
                           %(supersession)s,true)
                   ON CONFLICT (organization_id,project_id,environment_id,policy_key)
                   DO UPDATE SET head_epoch=EXCLUDED.head_epoch,
                                 activation_id=EXCLUDED.activation_id,
                                 policy_version=EXCLUDED.policy_version,
                                 policy_hash=EXCLUDED.policy_hash,
                                 activation_kind=EXCLUDED.activation_kind,
                                 connection_epoch=EXCLUDED.connection_epoch,
                                 placement_epoch=EXCLUDED.placement_epoch,
                                 supersession=EXCLUDED.supersession,
                                 is_current=true
                   WHERE trigger_policy_current_heads.head_epoch=%(prior_epoch)s""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy_key,
                    "head_epoch": head_epoch,
                    "activation_id": activation_id,
                    "version": version,
                    "digest": expected_digest,
                    "connection_epoch": policy["source_connection_epoch"],
                    "placement_epoch": placement_epoch,
                    "supersession": policy["supersession"],
                    "prior_epoch": observed_epoch,
                },
            )
            if cursor.rowcount != 1:
                raise GuidanceError("trigger activation lost its head fence")
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="TRIGGER_POLICY_ACTIVATED",
                entity_ref=entity_ref,
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code="POLICY_ACTIVATED",
            )
        return TriggerPolicyLifecycleCommit(
            policy_key, version, "ACTIVE", expected_digest, activation_id, True
        )

    def disable(
        self,
        *,
        scope: Scope,
        policy_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        expected_head_epoch: int,
        expected_activation_id: str,
        decision_request_id: str,
    ) -> TriggerPolicyLifecycleCommit:
        """Deactivate the current head without mutating its approved revision."""

        request_hash = canonical_sha256(
            {
                "operation": "DEACTIVATE",
                "policy_key": policy_key,
                "version": version,
                "policy_hash": expected_digest,
                "expected_head_epoch": expected_head_epoch,
                "expected_activation_id": expected_activation_id,
                "principal": principal,
                "required_role": "TRIGGER_POLICY_ACTIVATOR",
            }
        )
        entity_ref = f"trigger-policy-head:{policy_key}"
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
                raise GuidanceError("trigger deactivation actor is not independently authorized")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("TRIGGER_POLICY_ACTIVATOR",),
                department=str(authority["owner_department"]),
            )
            cursor.execute(
                """SELECT id,request_hash FROM solvan_operability.trigger_policy_activations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND idempotency_key=%(request_id)s""",
                {**scope.canonical_dict(), "request_id": decision_request_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise GuidanceError("trigger deactivation idempotency key changed material")
                return TriggerPolicyLifecycleCommit(
                    policy_key, version, "DISABLED", expected_digest, str(existing["id"]), False
                )
            cursor.execute(
                """SELECT p.*,h.head_epoch,h.activation_id,h.policy_version AS head_version,
                          h.policy_hash AS head_hash,h.placement_epoch
                     FROM solvan_operability.trigger_policy_revisions p
                     JOIN solvan_operability.trigger_policy_current_heads h ON
                       (h.organization_id,h.project_id,h.environment_id,h.policy_key)=
                       (p.organization_id,p.project_id,p.environment_id,p.policy_key)
                    WHERE p.organization_id=%(organization_id)s
                      AND p.project_id=%(project_id)s AND p.environment_id=%(environment_id)s
                      AND p.policy_key=%(policy_key)s AND p.version=%(version)s
                    FOR UPDATE OF p,h""",
                {**scope.canonical_dict(), "policy_key": policy_key, "version": version},
            )
            row = cursor.fetchone()
            if (
                row is None
                or row["lifecycle"] != "APPROVED"
                or row["policy_hash"] != expected_digest
                or row["head_version"] != version
                or row["head_hash"] != expected_digest
                or int(row["head_epoch"]) != expected_head_epoch
                or row["activation_id"] != expected_activation_id
            ):
                raise GuidanceError("only the exact current trigger-policy head may be disabled")
            activation_id = new_identifier("tpa")
            new_epoch = int(row["head_epoch"]) + 1
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_activations
                     (organization_id,project_id,environment_id,id,policy_key,
                      policy_version,policy_hash,activation_kind,head_epoch,
                      expected_prior_head_epoch,expected_activation_id,evaluation_ref,
                      approval_ref,connection_epoch,placement_epoch,supersession,actor_principal,
                      idempotency_key,request_hash,reason_code)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(policy_key)s,%(version)s,%(digest)s,'DEACTIVATE',%(new_epoch)s,
                           %(prior_epoch)s,%(expected_activation_id)s,%(evaluation_ref)s,
                           %(approval_ref)s,%(connection_epoch)s,%(placement_epoch)s,
                           %(supersession)s,
                           %(principal)s,%(request_id)s,%(request_hash)s,'POLICY_DISABLED')""",
                {
                    **scope.canonical_dict(),
                    "id": activation_id,
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                    "new_epoch": new_epoch,
                    "prior_epoch": row["head_epoch"],
                    "expected_activation_id": row["activation_id"],
                    "evaluation_ref": row["evaluation_ref"],
                    "approval_ref": row["approval_ref"],
                    "connection_epoch": row["source_connection_epoch"],
                    "placement_epoch": row["placement_epoch"],
                    "supersession": row["supersession"],
                    "principal": principal,
                    "request_id": decision_request_id,
                    "request_hash": request_hash,
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.trigger_policy_current_heads
                      SET head_epoch=%(new_epoch)s,activation_id=%(deactivation_id)s,
                          activation_kind='DEACTIVATE',is_current=false
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND head_epoch=%(prior_epoch)s
                      AND activation_id=%(expected_activation_id)s""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy_key,
                    "new_epoch": new_epoch,
                    "deactivation_id": activation_id,
                    "prior_epoch": row["head_epoch"],
                    "expected_activation_id": row["activation_id"],
                },
            )
            if cursor.rowcount != 1:
                raise GuidanceError("trigger deactivation lost its head fence")
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="TRIGGER_POLICY_DISABLED",
                entity_ref=entity_ref,
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code="POLICY_DISABLED",
            )
        return TriggerPolicyLifecycleCommit(
            policy_key, version, "DISABLED", expected_digest, activation_id, True
        )

    def retire(
        self,
        *,
        scope: Scope,
        policy_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        expected_lifecycle_epoch: int,
        expected_head_epoch: int | None,
        expected_activation_id: str | None,
        decision_request_id: str,
    ) -> TriggerPolicyLifecycleCommit:
        """Append a fenced retirement decision; approved material stays immutable."""

        if expected_lifecycle_epoch < 1 or (expected_head_epoch is None) != (
            expected_activation_id is None
        ):
            raise GuidanceError("trigger retirement fences are invalid")

        request_hash = canonical_sha256(
            {
                "operation": "RETIRE",
                "policy_key": policy_key,
                "version": version,
                "policy_hash": expected_digest,
                "expected_lifecycle_epoch": expected_lifecycle_epoch,
                "expected_head_epoch": expected_head_epoch,
                "expected_activation_id": expected_activation_id,
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
                raise GuidanceError("trigger retirement actor is not independently authorized")
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
            entity_ref = f"trigger-policy:{policy_key}@{version}"
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise GuidanceError("trigger retirement idempotency key changed material")
                return TriggerPolicyLifecycleCommit(
                    policy_key, version, "RETIRED", expected_digest, str(existing["id"]), False
                )
            cursor.execute(
                """SELECT p.lifecycle,p.policy_hash,p.owner_department,
                          p.author_principal,p.approved_by_principal,
                          p.evaluation_ref,p.approval_ref,p.source_connection_epoch,
                          p.supersession,
                          l.lifecycle_epoch,l.availability,l.decision_id,
                          l.decision_operation,
                          h.head_epoch,h.activation_id,h.policy_version AS head_version,
                          h.policy_hash AS head_hash,h.placement_epoch,h.is_current
                     FROM solvan_operability.trigger_policy_revisions p
                     JOIN solvan_operability.trigger_policy_current_lifecycles l ON
                       (l.organization_id,l.project_id,l.environment_id,l.policy_key,
                        l.policy_version)=(p.organization_id,p.project_id,p.environment_id,
                                           p.policy_key,p.version)
                     LEFT JOIN solvan_operability.trigger_policy_current_heads h ON
                       (h.organization_id,h.project_id,h.environment_id,h.policy_key)=
                       (p.organization_id,p.project_id,p.environment_id,p.policy_key)
                    WHERE p.organization_id=%(organization_id)s
                      AND p.project_id=%(project_id)s AND p.environment_id=%(environment_id)s
                      AND p.policy_key=%(policy_key)s AND p.version=%(version)s
                    FOR UPDATE OF p,l""",
                {**scope.canonical_dict(), "policy_key": policy_key, "version": version},
            )
            row = cursor.fetchone()
            if (
                row is None
                or row["lifecycle"] != "APPROVED"
                or row["availability"] != "ELIGIBLE"
                or row["policy_hash"] != expected_digest
                or int(row["lifecycle_epoch"]) != expected_lifecycle_epoch
            ):
                raise GuidanceError("trigger policy lifecycle digest is stale")
            decision_id = new_identifier("tpl")
            lifecycle_epoch = int(row["lifecycle_epoch"]) + 1
            if row["is_current"] is True:
                if (
                    row["head_version"] != version
                    or row["head_hash"] != expected_digest
                    or row["head_epoch"] != expected_head_epoch
                    or row["activation_id"] != expected_activation_id
                ):
                    raise GuidanceError("trigger retirement current-head material is stale")
                deactivation_id = new_identifier("tpa")
                deactivation_epoch = int(row["head_epoch"]) + 1
                deactivation_hash = canonical_sha256(
                    {
                        "operation": "RETIRE_DEACTIVATE",
                        "policy_key": policy_key,
                        "version": version,
                        "policy_hash": expected_digest,
                        "expected_prior_head_epoch": row["head_epoch"],
                        "expected_activation_id": row["activation_id"],
                    }
                )
                cursor.execute(
                    """INSERT INTO solvan_operability.trigger_policy_activations
                         (organization_id,project_id,environment_id,id,policy_key,
                          policy_version,policy_hash,activation_kind,head_epoch,
                          expected_prior_head_epoch,expected_activation_id,evaluation_ref,
                          approval_ref,connection_epoch,placement_epoch,supersession,
                          actor_principal,idempotency_key,request_hash,reason_code)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                               %(policy_key)s,%(version)s,%(digest)s,'DEACTIVATE',
                               %(head_epoch)s,%(prior_epoch)s,%(expected_activation_id)s,
                               %(evaluation_ref)s,%(approval_ref)s,%(connection_epoch)s,
                               %(placement_epoch)s,%(supersession)s,%(principal)s,
                               %(head_request_id)s,%(head_request_hash)s,'POLICY_RETIRED')""",
                    {
                        **scope.canonical_dict(),
                        "id": deactivation_id,
                        "policy_key": policy_key,
                        "version": version,
                        "digest": expected_digest,
                        "head_epoch": deactivation_epoch,
                        "prior_epoch": expected_head_epoch,
                        "expected_activation_id": expected_activation_id,
                        "evaluation_ref": row["evaluation_ref"],
                        "approval_ref": row["approval_ref"],
                        "connection_epoch": row["source_connection_epoch"],
                        "placement_epoch": row["placement_epoch"],
                        "supersession": row["supersession"],
                        "principal": principal,
                        "head_request_id": deactivation_hash,
                        "head_request_hash": deactivation_hash,
                    },
                )
                cursor.execute(
                    """UPDATE solvan_operability.trigger_policy_current_heads
                          SET head_epoch=%(head_epoch)s,activation_id=%(deactivation_id)s,
                              activation_kind='DEACTIVATE',is_current=false
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s AND head_epoch=%(prior_epoch)s
                          AND activation_id=%(expected_activation_id)s AND is_current""",
                    {
                        **scope.canonical_dict(),
                        "policy_key": policy_key,
                        "head_epoch": deactivation_epoch,
                        "deactivation_id": deactivation_id,
                        "prior_epoch": expected_head_epoch,
                        "expected_activation_id": expected_activation_id,
                    },
                )
                if cursor.rowcount != 1:
                    raise GuidanceError("trigger retirement lost its current-head fence")
            elif expected_head_epoch is not None or expected_activation_id is not None:
                raise GuidanceError("non-current retirement must not claim a head fence")
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_lifecycle_decisions
                     (organization_id,project_id,environment_id,id,policy_key,
                      policy_version,policy_hash,lifecycle_epoch,
                      expected_prior_lifecycle_epoch,operation,actor_principal,
                      idempotency_key,request_hash,reason_code)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(policy_key)s,%(version)s,%(digest)s,%(lifecycle_epoch)s,
                           %(prior_epoch)s,'RETIRE',%(principal)s,%(request_id)s,
                           %(request_hash)s,'POLICY_RETIRED')""",
                {
                    **scope.canonical_dict(),
                    "id": decision_id,
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                    "lifecycle_epoch": lifecycle_epoch,
                    "prior_epoch": expected_lifecycle_epoch,
                    "principal": principal,
                    "request_id": decision_request_id,
                    "request_hash": request_hash,
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.trigger_policy_current_lifecycles
                      SET lifecycle_epoch=%(lifecycle_epoch)s,availability='RETIRED',
                          decision_id=%(decision_id)s,decision_operation='RETIRE'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND policy_version=%(version)s
                      AND lifecycle_epoch=%(prior_epoch)s AND availability='ELIGIBLE'""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy_key,
                    "version": version,
                    "lifecycle_epoch": lifecycle_epoch,
                    "decision_id": decision_id,
                    "prior_epoch": expected_lifecycle_epoch,
                },
            )
            if cursor.rowcount != 1:
                raise GuidanceError("trigger retirement lost its lifecycle fence")
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="TRIGGER_POLICY_RETIRED",
                entity_ref=entity_ref,
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code="POLICY_RETIRED",
            )
        return TriggerPolicyLifecycleCommit(
            policy_key, version, "RETIRED", expected_digest, decision_id, True
        )
