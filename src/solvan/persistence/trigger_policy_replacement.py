"""Prepared-replacement transactions for a trigger policy head.

Split out of `trigger_policy_lifecycle` under the size ceiling's removal
condition. The public store contract is unchanged: the lifecycle mixin
inherits these methods, so callers still see one transactional store.
"""

from __future__ import annotations

from psycopg.rows import dict_row

from solvan.application.operational_guidance import GuidanceError
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.trigger_policy_eligibility import TriggerPolicyEligibilityMixin
from solvan.persistence.trigger_policy_types import (
    TriggerPolicyLifecycleCommit,
    TriggerPolicyReplacementIntentCommit,
)


class TriggerPolicyReplacementMixin(TriggerPolicyEligibilityMixin):
    """Prepare and consume an exact replacement for a current head."""

    # Consuming a prepared replacement retires the outgoing head and activates
    # the incoming one in the same transaction. Those two transitions stay in
    # the lifecycle mixin that composes this one; declaring them here keeps the
    # dependency explicit instead of relying on a subclass attribute existing.
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
        raise NotImplementedError("composed by TriggerPolicyLifecycleMixin")

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
        raise NotImplementedError("composed by TriggerPolicyLifecycleMixin")

    def prepare_replacement(
        self,
        *,
        scope: Scope,
        retiring_policy_key: str,
        retiring_version: str,
        retiring_digest: str,
        successor_policy_key: str,
        successor_version: str,
        successor_digest: str,
        principal: str,
        expected_head_epoch: int,
        expected_activation_id: str,
        expected_lifecycle_epoch: int,
        placement_epoch: int,
        decision_request_id: str,
    ) -> TriggerPolicyReplacementIntentCommit:
        """Record an immutable, one-use exact replacement intent; change no head."""

        if successor_policy_key != retiring_policy_key:
            raise GuidanceError("a replacement must advance the same policy head")

        request_material = {
            "operation": "PREPARE_REPLACEMENT",
            "retiring_policy_key": retiring_policy_key,
            "retiring_version": retiring_version,
            "retiring_digest": retiring_digest,
            "successor_policy_key": successor_policy_key,
            "successor_version": successor_version,
            "successor_digest": successor_digest,
            "expected_head_epoch": expected_head_epoch,
            "expected_activation_id": expected_activation_id,
            "expected_lifecycle_epoch": expected_lifecycle_epoch,
            "placement_epoch": placement_epoch,
            "principal": principal,
            "required_role": "TRIGGER_POLICY_ACTIVATOR",
        }
        request_hash = canonical_sha256(request_material)
        compound_hash = canonical_sha256({**request_material, "scope": scope.canonical_dict()})
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT retiring.owner_department,
                          retiring.author_principal AS retiring_author,
                          retiring.approved_by_principal AS retiring_approver,
                          successor.owner_department AS successor_department,
                          successor.author_principal AS successor_author,
                          successor.approved_by_principal AS successor_approver
                     FROM solvan_operability.trigger_policy_revisions retiring
                     JOIN solvan_operability.trigger_policy_revisions successor ON
                       (successor.organization_id,successor.project_id,successor.environment_id)=
                       (retiring.organization_id,retiring.project_id,retiring.environment_id)
                    WHERE retiring.organization_id=%(organization_id)s
                      AND retiring.project_id=%(project_id)s
                      AND retiring.environment_id=%(environment_id)s
                      AND retiring.policy_key=%(retiring_key)s
                      AND retiring.version=%(retiring_version)s
                      AND retiring.policy_hash=%(retiring_digest)s
                      AND successor.policy_key=%(successor_key)s
                      AND successor.version=%(successor_version)s
                      AND successor.policy_hash=%(successor_digest)s""",
                {
                    **scope.canonical_dict(),
                    "retiring_key": retiring_policy_key,
                    "retiring_version": retiring_version,
                    "retiring_digest": retiring_digest,
                    "successor_key": successor_policy_key,
                    "successor_version": successor_version,
                    "successor_digest": successor_digest,
                },
            )
            authority = cursor.fetchone()
            if authority is None or principal in {
                authority["retiring_author"],
                authority["retiring_approver"],
                authority["successor_author"],
                authority["successor_approver"],
            }:
                raise GuidanceError("replacement actor is not independently authorized")
            for department in {
                str(authority["owner_department"]),
                str(authority["successor_department"]),
            }:
                self._require_role(
                    scope=scope,
                    principal=principal,
                    roles=("TRIGGER_POLICY_ACTIVATOR",),
                    department=department,
                )
            cursor.execute(
                """SELECT id,compound_request_hash,retiring_policy_key,
                          retiring_policy_version,successor_policy_key,successor_version
                     FROM solvan_operability.trigger_policy_replacement_intents
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND idempotency_key=%(request_id)s""",
                {**scope.canonical_dict(), "request_id": decision_request_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["compound_request_hash"] != compound_hash:
                    raise GuidanceError("replacement intent idempotency key changed material")
                return TriggerPolicyReplacementIntentCommit(
                    str(existing["id"]),
                    str(existing["retiring_policy_key"]),
                    str(existing["retiring_policy_version"]),
                    str(existing["successor_policy_key"]),
                    str(existing["successor_version"]),
                    compound_hash,
                    False,
                )
            cursor.execute(
                """SELECT retiring.owner_department,retiring.author_principal AS retiring_author,
                          retiring.approved_by_principal AS retiring_approver,
                          successor.owner_department AS successor_department,
                          successor.author_principal AS successor_author,
                          successor.approved_by_principal AS successor_approver,
                          successor.evaluation_ref,successor.approval_ref,
                          successor.source_connection_epoch,successor.supersession
                     FROM solvan_operability.trigger_policy_revisions retiring
                     JOIN solvan_operability.trigger_policy_revisions successor ON
                       (successor.organization_id,successor.project_id,successor.environment_id)=
                       (retiring.organization_id,retiring.project_id,retiring.environment_id)
                     JOIN solvan_operability.trigger_policy_current_heads head ON
                       (head.organization_id,head.project_id,head.environment_id,head.policy_key)=
                       (retiring.organization_id,retiring.project_id,
                        retiring.environment_id,retiring.policy_key)
                     JOIN solvan_operability.trigger_policy_current_lifecycles lifecycle ON
                       (lifecycle.organization_id,lifecycle.project_id,
                        lifecycle.environment_id,lifecycle.policy_key,
                        lifecycle.policy_version)=
                       (retiring.organization_id,retiring.project_id,
                        retiring.environment_id,retiring.policy_key,retiring.version)
                    WHERE retiring.organization_id=%(organization_id)s
                      AND retiring.project_id=%(project_id)s
                      AND retiring.environment_id=%(environment_id)s
                      AND retiring.policy_key=%(retiring_key)s
                      AND retiring.version=%(retiring_version)s
                      AND retiring.policy_hash=%(retiring_digest)s
                      AND head.head_epoch=%(head_epoch)s
                      AND head.activation_id=%(activation_id)s AND head.is_current
                      AND head.placement_epoch=%(placement_epoch)s
                      AND lifecycle.lifecycle_epoch=%(lifecycle_epoch)s
                      AND lifecycle.availability='ELIGIBLE'
                      AND successor.policy_key=%(successor_key)s
                      AND successor.version=%(successor_version)s
                      AND successor.policy_hash=%(successor_digest)s
                      AND successor.lifecycle='APPROVED'
                    FOR UPDATE OF retiring,successor,head,lifecycle""",
                {
                    **scope.canonical_dict(),
                    "retiring_key": retiring_policy_key,
                    "retiring_version": retiring_version,
                    "retiring_digest": retiring_digest,
                    "successor_key": successor_policy_key,
                    "successor_version": successor_version,
                    "successor_digest": successor_digest,
                    "head_epoch": expected_head_epoch,
                    "activation_id": expected_activation_id,
                    "lifecycle_epoch": expected_lifecycle_epoch,
                    "placement_epoch": placement_epoch,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise GuidanceError("replacement intent authority material is stale")
            if principal in {
                row["retiring_author"],
                row["retiring_approver"],
                row["successor_author"],
                row["successor_approver"],
            }:
                raise GuidanceError("policy author or approver cannot prepare replacement")
            for department in {str(row["owner_department"]), str(row["successor_department"])}:
                self._require_role(
                    scope=scope,
                    principal=principal,
                    roles=("TRIGGER_POLICY_ACTIVATOR",),
                    department=department,
                )
            intent_id = new_identifier("tpr")
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_replacement_intents
                     (organization_id,project_id,environment_id,id,
                      retiring_policy_key,retiring_policy_version,retiring_policy_hash,
                      expected_head_epoch,expected_activation_id,successor_policy_key,
                      successor_version,successor_hash,successor_evaluation_ref,
                      successor_approval_ref,successor_supersession,connection_epoch,
                      placement_epoch,expected_lifecycle_epoch,actor_principal,
                      idempotency_key,request_hash,compound_request_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(retiring_key)s,%(retiring_version)s,%(retiring_digest)s,
                           %(head_epoch)s,%(activation_id)s,%(successor_key)s,
                           %(successor_version)s,%(successor_digest)s,%(evaluation_ref)s,
                           %(approval_ref)s,%(supersession)s,%(connection_epoch)s,
                           %(placement_epoch)s,%(lifecycle_epoch)s,%(principal)s,
                           %(request_id)s,%(request_hash)s,%(compound_hash)s)
                   ON CONFLICT DO NOTHING RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": intent_id,
                    "retiring_key": retiring_policy_key,
                    "retiring_version": retiring_version,
                    "retiring_digest": retiring_digest,
                    "head_epoch": expected_head_epoch,
                    "activation_id": expected_activation_id,
                    "successor_key": successor_policy_key,
                    "successor_version": successor_version,
                    "successor_digest": successor_digest,
                    "evaluation_ref": row["evaluation_ref"],
                    "approval_ref": row["approval_ref"],
                    "supersession": row["supersession"],
                    "connection_epoch": row["source_connection_epoch"],
                    "placement_epoch": placement_epoch,
                    "lifecycle_epoch": expected_lifecycle_epoch,
                    "principal": principal,
                    "request_id": decision_request_id,
                    "request_hash": request_hash,
                    "compound_hash": compound_hash,
                },
            )
            inserted = cursor.fetchone()
            if inserted is None:
                cursor.execute(
                    """SELECT id,idempotency_key,compound_request_hash,
                              retiring_policy_key,retiring_policy_version,
                              successor_policy_key,successor_version
                         FROM solvan_operability.trigger_policy_replacement_intents
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND (idempotency_key=%(request_id)s OR
                               compound_request_hash=%(compound_hash)s)
                        FOR UPDATE""",
                    {
                        **scope.canonical_dict(),
                        "request_id": decision_request_id,
                        "compound_hash": compound_hash,
                    },
                )
                conflict = cursor.fetchone()
                if (
                    conflict is not None
                    and conflict["idempotency_key"] == decision_request_id
                    and conflict["compound_request_hash"] == compound_hash
                ):
                    return TriggerPolicyReplacementIntentCommit(
                        str(conflict["id"]),
                        str(conflict["retiring_policy_key"]),
                        str(conflict["retiring_policy_version"]),
                        str(conflict["successor_policy_key"]),
                        str(conflict["successor_version"]),
                        compound_hash,
                        False,
                    )
                raise GuidanceError(
                    "replacement intent conflicts with an existing request or material"
                )
        return TriggerPolicyReplacementIntentCommit(
            intent_id,
            retiring_policy_key,
            retiring_version,
            successor_policy_key,
            successor_version,
            compound_hash,
            True,
        )

    def retire_with_prepared_replacement(
        self,
        *,
        scope: Scope,
        replacement_intent_id: str,
        expected_retiring_policy_key: str,
        expected_retiring_version: str,
        principal: str,
        expected_compound_request_hash: str,
        decision_request_id: str,
    ) -> TriggerPolicyLifecycleCommit:
        """Atomically retire the exact head and activate its prepared successor."""

        consumption_hash = canonical_sha256(
            {
                "operation": "RETIRE_WITH_PREPARED_REPLACEMENT",
                "replacement_intent_id": replacement_intent_id,
                "expected_retiring_policy_key": expected_retiring_policy_key,
                "expected_retiring_version": expected_retiring_version,
                "expected_compound_request_hash": expected_compound_request_hash,
                "principal": principal,
                "required_roles": [
                    "TRIGGER_POLICY_LIFECYCLE_MANAGER",
                    "TRIGGER_POLICY_ACTIVATOR",
                ],
            }
        )
        with self._connection.transaction():
            with self._connection.cursor(row_factory=dict_row) as cursor:
                cursor.execute(
                    """SELECT retiring.owner_department,
                              retiring.author_principal AS retiring_author,
                              retiring.approved_by_principal AS retiring_approver,
                              successor.owner_department AS successor_department,
                              successor.author_principal AS successor_author,
                              successor.approved_by_principal AS successor_approver
                         FROM solvan_operability.trigger_policy_replacement_intents intent
                         JOIN solvan_operability.trigger_policy_revisions retiring ON
                           (retiring.organization_id,retiring.project_id,
                            retiring.environment_id,retiring.policy_key,retiring.version)=
                           (intent.organization_id,intent.project_id,intent.environment_id,
                            intent.retiring_policy_key,intent.retiring_policy_version)
                         JOIN solvan_operability.trigger_policy_revisions successor ON
                           (successor.organization_id,successor.project_id,
                            successor.environment_id,successor.policy_key,successor.version)=
                           (intent.organization_id,intent.project_id,intent.environment_id,
                            intent.successor_policy_key,intent.successor_version)
                        WHERE intent.organization_id=%(organization_id)s
                          AND intent.project_id=%(project_id)s
                          AND intent.environment_id=%(environment_id)s
                          AND intent.id=%(intent_id)s
                          AND intent.retiring_policy_key=%(retiring_key)s
                          AND intent.retiring_policy_version=%(retiring_version)s
                          AND intent.compound_request_hash=%(compound_hash)s""",
                    {
                        **scope.canonical_dict(),
                        "intent_id": replacement_intent_id,
                        "retiring_key": expected_retiring_policy_key,
                        "retiring_version": expected_retiring_version,
                        "compound_hash": expected_compound_request_hash,
                    },
                )
                authority = cursor.fetchone()
                if authority is None or principal in {
                    authority["retiring_author"],
                    authority["retiring_approver"],
                    authority["successor_author"],
                    authority["successor_approver"],
                }:
                    raise GuidanceError("replacement consumer is not independently authorized")
                for department in {
                    str(authority["owner_department"]),
                    str(authority["successor_department"]),
                }:
                    for required_role in (
                        "TRIGGER_POLICY_LIFECYCLE_MANAGER",
                        "TRIGGER_POLICY_ACTIVATOR",
                    ):
                        self._require_role(
                            scope=scope,
                            principal=principal,
                            roles=(required_role,),
                            department=department,
                        )
                cursor.execute(
                    """SELECT intent.*
                         FROM solvan_operability.trigger_policy_replacement_intents intent
                        WHERE intent.organization_id=%(organization_id)s
                          AND intent.project_id=%(project_id)s
                          AND intent.environment_id=%(environment_id)s
                          AND intent.id=%(intent_id)s
                          AND intent.retiring_policy_key=%(retiring_key)s
                          AND intent.retiring_policy_version=%(retiring_version)s
                        FOR UPDATE OF intent""",
                    {
                        **scope.canonical_dict(),
                        "intent_id": replacement_intent_id,
                        "retiring_key": expected_retiring_policy_key,
                        "retiring_version": expected_retiring_version,
                    },
                )
                intent = cursor.fetchone()
                if (
                    intent is None
                    or intent["compound_request_hash"] != expected_compound_request_hash
                ):
                    raise GuidanceError("prepared replacement material is absent or stale")
                # Read consumption only after the intent row lock is acquired.
                # A LEFT JOIN in the locking statement can retain the statement's
                # pre-wait snapshot and miss a concurrent consumer's committed row.
                cursor.execute(
                    """SELECT lifecycle_decision_id,consumed_request_hash
                         FROM solvan_operability.trigger_policy_replacement_consumptions
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND replacement_intent_id=%(intent_id)s""",
                    {**scope.canonical_dict(), "intent_id": replacement_intent_id},
                )
                consumption = cursor.fetchone()
                if consumption is not None:
                    if consumption["consumed_request_hash"] != consumption_hash:
                        raise GuidanceError("replacement intent was already consumed differently")
                    cursor.execute(
                        """SELECT id FROM solvan_operability.trigger_policy_activations
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND idempotency_key=%(request_id)s""",
                        {
                            **scope.canonical_dict(),
                            "request_id": f"{decision_request_id}:activate",
                        },
                    )
                    active_row = cursor.fetchone()
                    if active_row is None:
                        raise GuidanceError("replacement consumption lacks its activation")
                    return TriggerPolicyLifecycleCommit(
                        str(intent["successor_policy_key"]),
                        str(intent["successor_version"]),
                        "ACTIVE",
                        str(intent["successor_hash"]),
                        str(active_row["id"]),
                        False,
                    )
            retired = self.retire(
                scope=scope,
                policy_key=str(intent["retiring_policy_key"]),
                version=str(intent["retiring_policy_version"]),
                principal=principal,
                expected_digest=str(intent["retiring_policy_hash"]),
                expected_lifecycle_epoch=int(intent["expected_lifecycle_epoch"]),
                expected_head_epoch=int(intent["expected_head_epoch"]),
                expected_activation_id=str(intent["expected_activation_id"]),
                decision_request_id=f"{decision_request_id}:retire",
            )
            with self._connection.cursor(row_factory=dict_row) as cursor:
                cursor.execute(
                    """SELECT head_epoch,activation_id FROM
                             solvan_operability.trigger_policy_current_heads
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s""",
                    {
                        **scope.canonical_dict(),
                        "policy_key": intent["retiring_policy_key"],
                    },
                )
                retired_head = cursor.fetchone()
                if retired_head is None:
                    raise GuidanceError("retirement did not leave a fenced head projection")
            active = self.activate(
                scope=scope,
                policy_key=str(intent["successor_policy_key"]),
                version=str(intent["successor_version"]),
                principal=principal,
                expected_digest=str(intent["successor_hash"]),
                expected_prior_head_epoch=int(retired_head["head_epoch"]),
                expected_activation_id=str(retired_head["activation_id"]),
                placement_epoch=int(intent["placement_epoch"]),
                decision_request_id=f"{decision_request_id}:activate",
            )
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO solvan_operability.trigger_policy_replacement_consumptions
                         (organization_id,project_id,environment_id,replacement_intent_id,
                          lifecycle_decision_id,consumed_by_principal,consumed_request_hash)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(intent_id)s,%(decision_id)s,%(principal)s,%(request_hash)s)""",
                    {
                        **scope.canonical_dict(),
                        "intent_id": replacement_intent_id,
                        "decision_id": retired.decision_id,
                        "principal": principal,
                        "request_hash": consumption_hash,
                    },
                )
            return active
