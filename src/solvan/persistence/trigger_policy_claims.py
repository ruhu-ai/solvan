"""Lease claiming and coordinator-enqueue behavior for trigger firings."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from psycopg.rows import dict_row

from solvan.application.operational_guidance import GuidanceError, VerifiedTriggerEvent
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.trigger_policy_base import TriggerPolicyStoreBase
from solvan.persistence.trigger_policy_types import TriggerEnqueueResult, TriggerWakeClaim

_CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


class TriggerPolicyClaimMixin(TriggerPolicyStoreBase):
    def _require_connection_capability(
        self, *, scope: Scope, policy: dict[str, object], event: VerifiedTriggerEvent
    ) -> None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT availability,last_probe_result,residency_region,classification,
                          connection_epoch,provider
                     FROM solvan.tenant_connections
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(connection_id)s""",
                {**scope.canonical_dict(), "connection_id": event.connection_id},
            )
            connection = cursor.fetchone()
            if connection is None:
                raise GuidanceError("trigger source connection is not registered")
            if int(connection["connection_epoch"]) != event.connection_epoch:
                raise GuidanceError("trigger source connection epoch has changed")
            if connection["availability"] != "READY":
                raise GuidanceError(
                    "trigger source connection is "
                    f"{str(connection['availability']).lower()}, not ready"
                )
            if connection["last_probe_result"] != "SUCCEEDED":
                raise GuidanceError("trigger source connection has no successful probe")
            if connection["residency_region"] != policy["region"]:
                raise GuidanceError(
                    "trigger source control-plane residency does not match the policy"
                )
            if (
                _CLASSIFICATION_RANK[str(connection["classification"])]
                > _CLASSIFICATION_RANK[str(policy["classification_ceiling"])]
            ):
                raise GuidanceError("trigger source connection exceeds classification ceiling")
            cursor.execute(
                """SELECT 1
                     FROM solvan_operability.tool_probe_receipts probe
                     JOIN solvan_operability.tool_revisions tool ON
                       (tool.tool_key,tool.version)=(probe.tool_key,probe.tool_version)
                     JOIN solvan_operability.tool_revision_requesters requester ON
                       (requester.tool_key,requester.tool_version,requester.requester_key)=
                       (probe.tool_key,probe.tool_version,probe.agent_key)
                     JOIN solvan_operability.tool_profile_revisions profile ON
                       profile.profile_key=%(profile_key)s
                      AND profile.version=%(profile_version)s
                      AND profile.allowed_agent_key=probe.agent_key
                     JOIN solvan_operability.tool_profile_members member ON
                       (member.profile_key,member.profile_version,
                        member.tool_key,member.tool_version)=
                       (profile.profile_key,profile.version,probe.tool_key,probe.tool_version)
                     JOIN solvan_operability.tool_profile_connection_requirements requirement ON
                       (requirement.profile_key,requirement.profile_version,
                        requirement.ordinal,requirement.tool_key,requirement.tool_version)=
                       (member.profile_key,member.profile_version,
                        member.ordinal,member.tool_key,member.tool_version)
                     JOIN solvan.production_graph_snapshots snapshot ON
                       snapshot.organization_id=probe.organization_id
                      AND snapshot.project_id=probe.project_id
                      AND snapshot.environment_id=probe.environment_id
                      AND snapshot.status='APPROVED' AND snapshot.superseded_at IS NULL
                     JOIN solvan.production_graph_nodes target ON
                       (target.organization_id,target.project_id,target.environment_id,
                        target.snapshot_id)=(snapshot.organization_id,snapshot.project_id,
                                             snapshot.environment_id,snapshot.id)
                     JOIN solvan_onboarding.connection_external_project_coverage coverage ON
                       (coverage.organization_id,coverage.project_id,coverage.environment_id,
                        coverage.connection_id,coverage.connection_epoch,
                        coverage.external_project_id)=
                       (probe.organization_id,probe.project_id,probe.environment_id,
                        probe.connection_id,probe.connection_epoch,target.external_project_id)
                      AND coverage.workload_region=target.attributes_json->>'region'
                     JOIN solvan_onboarding.environment_external_project_bindings binding ON
                       (binding.organization_id,binding.project_id,binding.environment_id,
                        binding.external_project_id)=
                       (target.organization_id,target.project_id,target.environment_id,
                        target.external_project_id)
                      AND binding.workload_region=coverage.workload_region
                    WHERE probe.organization_id=%(organization_id)s
                      AND probe.project_id=%(project_id)s
                      AND probe.environment_id=%(environment_id)s
                      AND probe.connection_id=%(connection_id)s
                      AND probe.connection_epoch=%(connection_epoch)s
                      AND probe.tool_key=%(source_tool_key)s
                      AND probe.tool_version=%(source_tool_version)s
                      AND probe.agent_key=%(source_agent_key)s
                      AND probe.identity_ref=%(source_identity_ref)s
                      AND probe.registry_resource=tool.registry_resource
                      AND probe.network_policy_hash=tool.network_policy_hash
                      AND requirement.binding_kind='POLICY_SOURCE_CONNECTION'
                      AND requirement.provider=%(connection_provider)s
                      AND requirement.capability_key=%(source_capability_class)s
                      AND requirement.external_project_selector='TARGET_RESOURCE_PROJECT'
                      AND coverage.capability_class=%(source_capability_class)s
                      AND coverage.probe_receipt_ref=probe.receipt_ref
                      AND binding.is_current
                      AND target.node_key=%(target_key)s
                      AND tool.required_connection_providers_json ? %(connection_provider)s
                      AND tool.runtime_regions_json ? %(region)s
                      AND tool.supported_data_classes_json ? %(classification)s
                      AND probe.outcome='PASSED' AND probe.expires_at > now()
                      AND tool.lifecycle='APPROVED'
                      AND profile.lifecycle='APPROVED' LIMIT 1""",
                {
                    **scope.canonical_dict(),
                    "connection_id": event.connection_id,
                    "connection_epoch": event.connection_epoch,
                    "source_tool_key": policy["source_tool_key"],
                    "source_tool_version": policy["source_tool_version"],
                    "source_agent_key": policy["source_agent_key"],
                    "source_identity_ref": policy["source_identity_ref"],
                    "source_capability_class": policy["source_capability_class"],
                    "profile_key": policy["profile_key"],
                    "profile_version": policy["profile_version"],
                    "connection_provider": connection["provider"],
                    "target_key": event.target_key,
                    "region": policy["region"],
                    "classification": event.classification,
                },
            )
            if cursor.fetchone() is None:
                raise GuidanceError("trigger source exact capability proof is stale or missing")

    def claim_due(
        self, *, scope: Scope, owner: str, now: datetime, lease_seconds: int = 60
    ) -> TriggerWakeClaim | None:
        if now.tzinfo is None or not 10 <= lease_seconds <= 300:
            raise GuidanceError("trigger claim requires an aware time and bounded lease")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT w.id AS wakeup_id,f.*
                     FROM solvan_operability.trigger_firing_wakeups w
                     JOIN solvan_operability.trigger_firings f ON
                       (f.organization_id,f.project_id,f.environment_id,f.id)=
                       (w.organization_id,w.project_id,w.environment_id,w.firing_id)
                    WHERE w.organization_id=%(organization_id)s
                      AND w.project_id=%(project_id)s
                      AND w.environment_id=%(environment_id)s
                      AND ((w.status='PENDING' AND w.wake_at <= %(now)s) OR
                           (w.status='CLAIMED' AND w.claim_expires_at <= %(now)s))
                      AND f.status IN ('WAITING','CLAIMED')
                    ORDER BY w.wake_at,w.id FOR UPDATE OF w,f SKIP LOCKED LIMIT 1""",
                {**scope.canonical_dict(), "now": now},
            )
            row = cursor.fetchone()
            if row is None:
                return None
            expiry = now + timedelta(seconds=lease_seconds)
            cursor.execute(
                """UPDATE solvan_operability.trigger_firing_wakeups
                      SET status='CLAIMED',claimed_at=%(now)s,claim_owner=%(owner)s,
                          claim_token=%(token)s,claim_expires_at=%(expiry)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(wakeup_id)s""",
                {
                    **scope.canonical_dict(),
                    "now": now,
                    "owner": owner,
                    "token": token,
                    "expiry": expiry,
                    "wakeup_id": row["wakeup_id"],
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.trigger_firings
                      SET status='CLAIMED',claim_owner=%(owner)s,claim_token=%(token)s,
                          claim_expires_at=%(expiry)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(firing_id)s""",
                {
                    **scope.canonical_dict(),
                    "owner": owner,
                    "token": token,
                    "expiry": expiry,
                    "firing_id": row["id"],
                },
            )
        return TriggerWakeClaim(
            wakeup_id=str(row["wakeup_id"]),
            firing_id=str(row["id"]),
            claim_token=token,
            policy_key=str(row["policy_key"]),
            policy_version=str(row["policy_version"]),
            activation_id=str(row["activation_id"]),
            head_epoch=int(row["head_epoch"]),
            lifecycle_epoch=int(row["lifecycle_epoch"]),
            connection_id=str(row["connection_id"]),
            connection_epoch=int(row["connection_epoch"]),
            target_key=str(row["target_key"]),
            target_snapshot_hash=str(row["target_snapshot_hash"]),
            region=str(row["region"]),
            classification=str(row["classification"]),
        )

    def enqueue_claim(
        self,
        *,
        scope: Scope,
        claim: TriggerWakeClaim,
        observed_target_snapshot_hash: str,
    ) -> TriggerEnqueueResult:
        """Revalidate a fenced claim and write exactly one coordinator inbox event."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT f.*,p.lifecycle AS policy_lifecycle,p.source_connection_epoch,
                          p.region AS policy_region,p.classification_ceiling,
                          p.source_tool_key,p.source_tool_version,p.source_agent_key,
                          p.source_identity_ref,
                          p.source_capability_class,p.profile_key,p.profile_version,
                          h.activation_id AS current_activation_id,
                          h.head_epoch AS current_head_epoch,
                          h.policy_version AS current_policy_version,
                          h.policy_hash AS current_policy_hash,
                          h.activation_kind AS current_activation_kind,
                          h.placement_epoch AS current_placement_epoch,
                          h.supersession AS current_supersession,h.is_current,
                          l.lifecycle_epoch AS current_lifecycle_epoch,
                          l.policy_hash AS current_lifecycle_policy_hash,
                          l.decision_id AS current_lifecycle_decision_id,
                          l.decision_operation AS current_lifecycle_operation,
                          l.availability
                     FROM solvan_operability.trigger_firings f
                     JOIN solvan_operability.trigger_policy_revisions p ON
                       (p.organization_id,p.project_id,p.environment_id,p.policy_key,p.version)=
                       (f.organization_id,f.project_id,f.environment_id,
                        f.policy_key,f.policy_version)
                     LEFT JOIN solvan_operability.trigger_policy_current_heads h ON
                       (h.organization_id,h.project_id,h.environment_id,h.policy_key)=
                       (f.organization_id,f.project_id,f.environment_id,f.policy_key)
                     LEFT JOIN solvan_operability.trigger_policy_current_lifecycles l ON
                       (l.organization_id,l.project_id,l.environment_id,l.policy_key,
                        l.policy_version)=(f.organization_id,f.project_id,f.environment_id,
                                           f.policy_key,f.policy_version)
                    WHERE f.organization_id=%(organization_id)s
                      AND f.project_id=%(project_id)s
                      AND f.environment_id=%(environment_id)s AND f.id=%(firing_id)s
                      AND f.status='CLAIMED' AND f.claim_token=%(claim_token)s
                      AND f.claim_expires_at > now() FOR UPDATE OF f""",
                {
                    **scope.canonical_dict(),
                    "firing_id": claim.firing_id,
                    "claim_token": claim.claim_token,
                },
            )
            row = cursor.fetchone()
            reason = None
            if row is None:
                raise GuidanceError("trigger claim is stale or lost")
            if (
                row["policy_lifecycle"] != "APPROVED"
                or row["availability"] != "ELIGIBLE"
                or row["is_current"] is not True
                or row["current_activation_id"] != claim.activation_id
                or row["current_head_epoch"] != claim.head_epoch
                or row["current_policy_version"] != row["policy_version"]
                or row["current_policy_hash"] != row["policy_hash"]
                or row["current_activation_kind"] != row["activation_kind"]
                or row["current_placement_epoch"] != row["placement_epoch"]
                or row["current_supersession"] != row["supersession"]
                or row["current_lifecycle_epoch"] != claim.lifecycle_epoch
                or row["current_lifecycle_policy_hash"] != row["policy_hash"]
                or row["current_lifecycle_decision_id"] != row["lifecycle_decision_id"]
                or row["current_lifecycle_operation"] != row["lifecycle_operation"]
            ):
                reason = "POLICY_NOT_ACTIVE"
            elif int(row["source_connection_epoch"]) != claim.connection_epoch:
                reason = "CONNECTION_EPOCH_CHANGED"
            elif row["policy_region"] != claim.region:
                reason = "REGION_CHANGED"
            else:
                try:
                    current_target_hash = self.current_target_snapshot_hash(
                        scope=scope, target_key=claim.target_key
                    )
                except GuidanceError:
                    reason = "TARGET_CHANGED"
                else:
                    if (
                        observed_target_snapshot_hash != current_target_hash
                        or claim.target_snapshot_hash != current_target_hash
                    ):
                        reason = "TARGET_CHANGED"
            if reason is None:
                try:
                    self._require_connection_capability(
                        scope=scope,
                        policy={
                            "region": row["policy_region"],
                            "classification_ceiling": row["classification_ceiling"],
                            "source_tool_key": row["source_tool_key"],
                            "source_tool_version": row["source_tool_version"],
                            "source_agent_key": row["source_agent_key"],
                            "source_identity_ref": row["source_identity_ref"],
                            "source_capability_class": row["source_capability_class"],
                            "profile_key": row["profile_key"],
                            "profile_version": row["profile_version"],
                        },
                        event=VerifiedTriggerEvent(
                            source_event_id=str(row["source_event_id"]),
                            source_sequence=int(row["source_sequence"]),
                            source_event_hash=str(row["source_event_hash"]),
                            connection_id=claim.connection_id,
                            connection_epoch=claim.connection_epoch,
                            target_key=claim.target_key,
                            target_snapshot_hash=claim.target_snapshot_hash,
                            region=claim.region,
                            classification=claim.classification,
                            observed_at=row["created_at"],
                        ),
                    )
                except GuidanceError:
                    reason = "CONNECTION_CAPABILITY_INVALID"
            if reason is not None:
                cursor.execute(
                    """UPDATE solvan_operability.trigger_firings
                          SET status='BLOCKED',decision_reason=%(reason)s,completed_at=now(),
                              claim_owner=NULL,claim_token=NULL,claim_expires_at=NULL
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(firing_id)s""",
                    {**scope.canonical_dict(), "firing_id": claim.firing_id, "reason": reason},
                )
                cursor.execute(
                    """UPDATE solvan_operability.trigger_firing_wakeups
                          SET status='CANCELLED'
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(wakeup_id)s""",
                    {**scope.canonical_dict(), "wakeup_id": claim.wakeup_id},
                )
                return TriggerEnqueueResult(
                    firing_id=claim.firing_id,
                    status="BLOCKED",
                    inbox_event_id=None,
                    decision_reason=reason,
                )
            inbox_id = new_identifier("evt")
            payload_ref = f"solvan-operability://trigger-firings/{claim.firing_id}"
            payload_hash = canonical_sha256(
                {
                    "firing_id": claim.firing_id,
                    "policy": f"{claim.policy_key}@{claim.policy_version}",
                    "target_key": claim.target_key,
                    "target_snapshot_hash": claim.target_snapshot_hash,
                }
            )
            cursor.execute(
                """INSERT INTO solvan.inbox_events
                     (organization_id,project_id,environment_id,id,source,
                      source_event_id,event_type,payload_ref,payload_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           'trigger-policy',%(source_event_id)s,'TRIGGER_FIRING_DUE',
                           %(payload_ref)s,%(payload_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": inbox_id,
                    "source_event_id": claim.firing_id,
                    "payload_ref": payload_ref,
                    "payload_hash": payload_hash,
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.trigger_firings
                      SET status='ENQUEUED',coordinator_inbox_event_id=%(inbox_id)s,
                          claim_owner=NULL,claim_token=NULL,claim_expires_at=NULL
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(firing_id)s""",
                {**scope.canonical_dict(), "inbox_id": inbox_id, "firing_id": claim.firing_id},
            )
            cursor.execute(
                """UPDATE solvan_operability.trigger_firing_wakeups
                      SET status='COMPLETED',completed_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(wakeup_id)s AND claim_token=%(claim_token)s""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": claim.wakeup_id,
                    "claim_token": claim.claim_token,
                },
            )
        return TriggerEnqueueResult(
            firing_id=claim.firing_id,
            status="ENQUEUED",
            inbox_event_id=inbox_id,
        )

    def block_claim(
        self,
        *,
        scope: Scope,
        claim: TriggerWakeClaim,
        reason: str,
    ) -> TriggerEnqueueResult:
        """Terminally fence a claimed firing when deterministic revalidation cannot run."""

        if reason not in {"TARGET_UNRESOLVED", "TARGET_STATE_INVALID"}:
            raise GuidanceError("unsupported trigger block reason")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_operability.trigger_firings
                      SET status='BLOCKED',decision_reason=%(reason)s,completed_at=now(),
                          claim_owner=NULL,claim_token=NULL,claim_expires_at=NULL
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(firing_id)s AND status='CLAIMED'
                      AND claim_token=%(claim_token)s AND claim_expires_at > now()""",
                {
                    **scope.canonical_dict(),
                    "firing_id": claim.firing_id,
                    "claim_token": claim.claim_token,
                    "reason": reason,
                },
            )
            if cursor.rowcount != 1:
                raise GuidanceError("trigger claim is stale or lost")
            cursor.execute(
                """UPDATE solvan_operability.trigger_firing_wakeups
                      SET status='CANCELLED'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(wakeup_id)s AND status='CLAIMED'
                      AND claim_token=%(claim_token)s""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": claim.wakeup_id,
                    "claim_token": claim.claim_token,
                },
            )
        return TriggerEnqueueResult(
            firing_id=claim.firing_id,
            status="BLOCKED",
            inbox_event_id=None,
            decision_reason=reason,
        )
