"""Durable, fenced trigger matching, claiming, and enqueue."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg.rows import dict_row

from solvan.application.operational_guidance import GuidanceError, VerifiedTriggerEvent
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.trigger_policy_claims import TriggerPolicyClaimMixin
from solvan.persistence.trigger_policy_types import (
    TriggerFiringResult,
)

_CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


class TriggerPolicyRuntimeMixin(TriggerPolicyClaimMixin):
    def current_target_snapshot_hash(self, *, scope: Scope, target_key: str) -> str:
        """Hash the current approved Production Graph target deterministically.

        Source adapters and due-time workers both call this method. A webhook
        body therefore cannot freeze or re-assert the target snapshot used for
        eligibility; Cloud SQL derives it from the current approved graph.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT s.id AS snapshot_id,s.content_hash,s.version,n.node_kind,
                          n.resource_ref,n.external_project_id,n.classification,
                          n.provenance_ref,n.attributes_json
                     FROM solvan.production_graph_snapshots s
                     JOIN solvan.production_graph_nodes n ON
                       (n.organization_id,n.project_id,n.environment_id,n.snapshot_id)=
                       (s.organization_id,s.project_id,s.environment_id,s.id)
                    WHERE s.organization_id=%(organization_id)s
                      AND s.project_id=%(project_id)s
                      AND s.environment_id=%(environment_id)s
                      AND s.status='APPROVED' AND s.superseded_at IS NULL
                      AND n.node_key=%(target_key)s""",
                {**scope.canonical_dict(), "target_key": target_key},
            )
            row = cursor.fetchone()
        if row is None:
            raise GuidanceError("trigger target is absent from the current approved graph")
        return canonical_sha256(
            {
                "snapshot_id": str(row["snapshot_id"]),
                "snapshot_content_hash": str(row["content_hash"]),
                "snapshot_version": int(row["version"]),
                "target_key": target_key,
                "node_kind": str(row["node_kind"]),
                "resource_ref": row["resource_ref"],
                "external_project_id": row["external_project_id"],
                "classification": str(row["classification"]),
                "provenance_ref": str(row["provenance_ref"]),
                "attributes": row["attributes_json"],
            }
        )

    def accept_event(
        self,
        *,
        scope: Scope,
        policy_key: str,
        policy_version: str,
        event: VerifiedTriggerEvent,
    ) -> TriggerFiringResult:
        """Deduplicate, suppress/supersede, and schedule one verified source event."""

        params = {
            **scope.canonical_dict(),
            "policy_key": policy_key,
            "policy_version": policy_version,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.*,h.activation_id,h.activation_kind,h.head_epoch,
                          h.placement_epoch,h.supersession AS activated_supersession,
                          l.lifecycle_epoch,l.availability,
                          l.decision_id AS lifecycle_decision_id,
                          l.decision_operation,l.policy_hash AS lifecycle_policy_hash
                     FROM solvan_operability.trigger_policy_revisions p
                     JOIN solvan_operability.trigger_policy_current_heads h ON
                       (h.organization_id,h.project_id,h.environment_id,h.policy_key,
                        h.policy_version,h.policy_hash)=
                       (p.organization_id,p.project_id,p.environment_id,p.policy_key,
                        p.version,p.policy_hash)
                     JOIN solvan_operability.trigger_policy_current_lifecycles l ON
                       (l.organization_id,l.project_id,l.environment_id,l.policy_key,
                        l.policy_version)=(p.organization_id,p.project_id,p.environment_id,
                                           p.policy_key,p.version)
                    WHERE p.organization_id=%(organization_id)s
                      AND p.project_id=%(project_id)s
                      AND p.environment_id=%(environment_id)s
                      AND p.policy_key=%(policy_key)s AND p.version=%(policy_version)s
                      AND h.is_current AND h.activation_id IS NOT NULL
                    FOR UPDATE OF p,h,l""",
                params,
            )
            policy = cursor.fetchone()
            if (
                policy is None
                or policy["lifecycle"] != "APPROVED"
                or policy["availability"] != "ELIGIBLE"
                or policy["lifecycle_policy_hash"] != policy["policy_hash"]
                or policy["decision_operation"] != "MARK_ELIGIBLE"
                or policy["activated_supersession"] != policy["supersession"]
            ):
                raise GuidanceError("only the active eligible trigger-policy head may match")
            current_target_hash = self.current_target_snapshot_hash(
                scope=scope, target_key=event.target_key
            )
            if event.target_snapshot_hash != current_target_hash:
                raise GuidanceError("trigger target has changed since the source event")
            cursor.execute(
                """SELECT pg_advisory_xact_lock(hashtextextended(%(target_lock_key)s,0))""",
                {
                    "target_lock_key": ":".join(
                        (
                            scope.organization_id,
                            scope.project_id,
                            scope.environment_id,
                            policy_key,
                            policy_version,
                            event.target_key,
                        )
                    )
                },
            )
            self._validate_event(policy, event)
            self._require_connection_capability(scope=scope, policy=policy, event=event)
            cursor.execute(
                """SELECT id,status,policy_hash,activation_id,activation_kind,head_epoch,
                          placement_epoch,supersession,lifecycle_decision_id,
                          lifecycle_operation,lifecycle_epoch,source_sequence,
                          source_event_hash,source_observed_at,connection_id,
                          connection_epoch,target_key,target_snapshot_hash,region,
                          classification
                     FROM solvan_operability.trigger_firings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND policy_version=%(policy_version)s
                      AND source_event_id=%(source_event_id)s""",
                {**params, "source_event_id": event.source_event_id},
            )
            duplicate = cursor.fetchone()
            if duplicate is not None:
                self._require_same_firing_material(existing=duplicate, policy=policy, event=event)
                return TriggerFiringResult(
                    firing_id=str(duplicate["id"]), status=str(duplicate["status"]), created=False
                )
            now = datetime.now(UTC)
            status = "WAITING"
            suppression_kind = suppression_reason = None
            if int(policy["cooldown_ms"]) > 0:
                cursor.execute(
                    """SELECT 1 FROM solvan_operability.trigger_firings
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s AND policy_version=%(policy_version)s
                          AND target_key=%(target_key)s
                          AND status IN ('ENQUEUED','RUNNING','COMPLETED')
                          AND created_at > %(cooldown_after)s LIMIT 1""",
                    {
                        **params,
                        "target_key": event.target_key,
                        "cooldown_after": now - timedelta(milliseconds=int(policy["cooldown_ms"])),
                    },
                )
                if cursor.fetchone() is not None:
                    status = "SUPPRESSED"
                    suppression_kind = "COOLDOWN"
                    suppression_reason = "POLICY_COOLDOWN_ACTIVE"
            if status == "WAITING":
                cursor.execute(
                    """SELECT status,source_sequence
                         FROM solvan_operability.trigger_firings
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s AND policy_version=%(policy_version)s
                          AND target_key=%(target_key)s
                          AND status IN ('WAITING','CLAIMED','RUNNING')""",
                    {**params, "target_key": event.target_key},
                )
                pending_rows = cursor.fetchall()
                if policy["supersession"] == "LATEST_WAITING_PER_TARGET" and any(
                    pending["status"] == "WAITING"
                    and int(pending["source_sequence"]) >= event.source_sequence
                    for pending in pending_rows
                ):
                    status = "SUPPRESSED"
                    suppression_kind = "STALE_SEQUENCE"
                    suppression_reason = "STALE_SOURCE_SEQUENCE"
                pending_count = sum(
                    1
                    for pending in pending_rows
                    if policy["supersession"] != "LATEST_WAITING_PER_TARGET"
                    or pending["status"] != "WAITING"
                    or int(pending["source_sequence"]) >= event.source_sequence
                )
                if status == "WAITING" and pending_count >= int(
                    policy["maximum_pending_per_target"]
                ):
                    status = "SUPPRESSED"
                    suppression_kind = "MAX_PENDING"
                    suppression_reason = "MAXIMUM_PENDING_REACHED"

            firing_id = new_identifier("trf")
            old_firings: list[str] = []
            if status == "WAITING" and policy["supersession"] == "LATEST_WAITING_PER_TARGET":
                cursor.execute(
                    """UPDATE solvan_operability.trigger_firings
                          SET status='SUPERSEDED',decision_reason='NEWER_SOURCE_SEQUENCE',
                              completed_at=%(now)s
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s AND policy_version=%(policy_version)s
                          AND target_key=%(target_key)s AND status='WAITING'
                          AND source_sequence < %(source_sequence)s RETURNING id""",
                    {
                        **params,
                        "target_key": event.target_key,
                        "source_sequence": event.source_sequence,
                        "now": now,
                    },
                )
                old_firings = [str(row["id"]) for row in cursor.fetchall()]
                if old_firings:
                    cursor.execute(
                        """UPDATE solvan_operability.trigger_firing_wakeups
                              SET status='CANCELLED'
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND firing_id=ANY(%(firing_ids)s) AND status='PENDING'""",
                        {**scope.canonical_dict(), "firing_ids": old_firings},
                    )

            due_at = event.observed_at + timedelta(milliseconds=int(policy["delay_ms"]))
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_firings
                     (organization_id,project_id,environment_id,id,policy_key,
                      policy_version,policy_hash,activation_id,activation_kind,
                      head_epoch,placement_epoch,supersession,lifecycle_decision_id,
                      lifecycle_operation,lifecycle_epoch,
                      source_event_id,source_sequence,source_event_hash,
                      source_observed_at,connection_id,connection_epoch,target_key,
                      target_snapshot_hash,
                      region,classification,due_at,status,decision_reason,completed_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(policy_key)s,%(policy_version)s,%(policy_hash)s,
                           %(activation_id)s,%(activation_kind)s,%(head_epoch)s,
                           %(placement_epoch)s,%(activated_supersession)s,
                           %(lifecycle_decision_id)s,%(decision_operation)s,
                           %(lifecycle_epoch)s,%(source_event_id)s,
                           %(source_sequence)s,%(source_event_hash)s,%(source_observed_at)s,
                           %(connection_id)s,
                           %(connection_epoch)s,%(target_key)s,%(target_snapshot_hash)s,
                           %(region)s,%(classification)s,%(due_at)s,%(status)s,
                           %(decision_reason)s,%(completed_at)s)""",
                {
                    **params,
                    "id": firing_id,
                    "source_event_id": event.source_event_id,
                    "policy_hash": policy["policy_hash"],
                    "activation_id": policy["activation_id"],
                    "activation_kind": policy["activation_kind"],
                    "head_epoch": policy["head_epoch"],
                    "placement_epoch": policy["placement_epoch"],
                    "activated_supersession": policy["activated_supersession"],
                    "lifecycle_decision_id": policy["lifecycle_decision_id"],
                    "decision_operation": policy["decision_operation"],
                    "lifecycle_epoch": policy["lifecycle_epoch"],
                    "source_sequence": event.source_sequence,
                    "source_event_hash": event.source_event_hash,
                    "source_observed_at": event.observed_at,
                    "connection_id": event.connection_id,
                    "connection_epoch": event.connection_epoch,
                    "target_key": event.target_key,
                    "target_snapshot_hash": event.target_snapshot_hash,
                    "region": event.region,
                    "classification": event.classification,
                    "due_at": due_at,
                    "status": status,
                    "decision_reason": suppression_reason,
                    "completed_at": now if status == "SUPPRESSED" else None,
                },
            )
            if status == "WAITING":
                cursor.execute(
                    """INSERT INTO solvan_operability.trigger_firing_wakeups
                         (organization_id,project_id,environment_id,id,firing_id,wake_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(id)s,%(firing_id)s,%(wake_at)s)""",
                    {
                        **scope.canonical_dict(),
                        "id": new_identifier("twk"),
                        "firing_id": firing_id,
                        "wake_at": due_at,
                    },
                )
            if suppression_kind is not None:
                self._record_suppression(
                    cursor=cursor,
                    scope=scope,
                    firing_id=firing_id,
                    replacement_firing_id=None,
                    kind=suppression_kind,
                    reason=suppression_reason or "POLICY_SUPPRESSED",
                )
            for old_firing_id in old_firings:
                self._record_suppression(
                    cursor=cursor,
                    scope=scope,
                    firing_id=old_firing_id,
                    replacement_firing_id=firing_id,
                    kind="SUPERSESSION",
                    reason="NEWER_SOURCE_SEQUENCE",
                )
        return TriggerFiringResult(firing_id=firing_id, status=status, created=True)

    @staticmethod
    def _validate_event(policy: dict[str, Any], event: VerifiedTriggerEvent) -> None:
        if event.connection_id != policy["source_connection_id"]:
            raise GuidanceError("trigger event used another connection")
        if event.connection_epoch != policy["source_connection_epoch"]:
            raise GuidanceError("trigger event used a stale connection epoch")
        if event.region != policy["region"]:
            raise GuidanceError("trigger event region does not match policy")
        if (
            _CLASSIFICATION_RANK[event.classification]
            > _CLASSIFICATION_RANK[str(policy["classification_ceiling"])]
        ):
            raise GuidanceError("trigger event exceeds the policy classification ceiling")

    @staticmethod
    def _require_same_firing_material(
        *, existing: dict[str, Any], policy: dict[str, Any], event: VerifiedTriggerEvent
    ) -> None:
        expected = {
            "policy_hash": policy["policy_hash"],
            "activation_id": policy["activation_id"],
            "activation_kind": policy["activation_kind"],
            "head_epoch": policy["head_epoch"],
            "placement_epoch": policy["placement_epoch"],
            "supersession": policy["activated_supersession"],
            "lifecycle_decision_id": policy["lifecycle_decision_id"],
            "lifecycle_operation": policy["decision_operation"],
            "lifecycle_epoch": policy["lifecycle_epoch"],
            "source_sequence": event.source_sequence,
            "source_event_hash": event.source_event_hash,
            "source_observed_at": event.observed_at,
            "connection_id": event.connection_id,
            "connection_epoch": event.connection_epoch,
            "target_key": event.target_key,
            "target_snapshot_hash": event.target_snapshot_hash,
            "region": event.region,
            "classification": event.classification,
        }
        if any(existing[key] != value for key, value in expected.items()):
            raise GuidanceError("trigger source event ID was reused with changed material")

    @staticmethod
    def _record_suppression(
        *,
        cursor: Any,
        scope: Scope,
        firing_id: str,
        replacement_firing_id: str | None,
        kind: str,
        reason: str,
    ) -> None:
        cursor.execute(
            """INSERT INTO solvan_operability.trigger_firing_suppressions
                 (organization_id,project_id,environment_id,id,firing_id,
                  replacement_firing_id,kind,reason_code)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                       %(firing_id)s,%(replacement_firing_id)s,%(kind)s,%(reason)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("tfs"),
                "firing_id": firing_id,
                "replacement_firing_id": replacement_firing_id,
                "kind": kind,
                "reason": reason,
            },
        )
