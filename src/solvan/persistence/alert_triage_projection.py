"""Deterministic Alert-policy matching and episode projection."""

from __future__ import annotations

from typing import Any, Literal, cast

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.alert_policy_matching import (
    alert_fingerprint,
    alert_selector_matches,
    canonical_resource_identifier,
)
from solvan.application.alert_triage import (
    AlertGenerationProjectionReceipt,
    AlertPolicyError,
    AlertPolicyRevisionV1,
    CanonicalCloudMonitoringAlert,
    PubSubEnvelopeIdentity,
)
from solvan.domain import Scope, new_identifier


class AlertProjectionPersistenceMixin:
    """Cloud SQL policy-match and provider-generation projection authority."""

    _connection: Connection[Any]

    def project_provider_generation(
        self, *, scope: Scope, provider_generation_id: str
    ) -> AlertGenerationProjectionReceipt:
        """Match one policy-neutral generation and create at most one episode."""

        values: dict[str, Any] = {
            **scope.canonical_dict(),
            "generation_id": provider_generation_id,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (f"{scope.digest()}:{provider_generation_id}:policy-projection",),
            )
            cursor.execute(
                """SELECT generation.*,event.lifecycle_state,event.transition_sequence,
                          event.ended_at,event.observed_at,event.scoping_project_id,
                          event.monitored_resource_project_id,event.resource_type,
                          event.resource_labels_json,event.normalized_labels_json,
                          event.provider_severity,event.canonical_event_hash,
                          event.observed_connection_id,event.observed_connection_epoch
                     FROM solvan_alerts.alert_provider_generations generation
                     JOIN solvan_alerts.alert_events event
                       ON (event.organization_id,event.project_id,event.environment_id,event.id)=
                          (generation.organization_id,generation.project_id,
                           generation.environment_id,generation.last_semantic_event_id)
                    WHERE generation.organization_id=%(organization_id)s
                      AND generation.project_id=%(project_id)s
                      AND generation.environment_id=%(environment_id)s
                      AND generation.id=%(generation_id)s FOR UPDATE OF generation""",
                values,
            )
            generation = cursor.fetchone()
            if generation is None:
                raise AlertPolicyError("provider generation was not found")
            if generation["policy_projection_state"] is not None:
                cursor.execute(
                    """SELECT outcome,selected_policy_match_id
                         FROM solvan_alerts.alert_generation_outcomes
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND provider_generation_id=%(generation_id)s""",
                    values,
                )
                prior_outcome = cursor.fetchone()
                if prior_outcome is None:
                    raise AlertPolicyError("generation projection is internally inconsistent")
                cursor.execute(
                    """SELECT id,policy_key FROM solvan_alerts.alert_episodes
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND provider_generation_id=%(generation_id)s""",
                    values,
                )
                episode = cursor.fetchone()
                return AlertGenerationProjectionReceipt(
                    provider_generation_id=provider_generation_id,
                    outcome=cast(
                        Literal["MATCHED", "UNMATCHED", "POLICY_CONFLICT"],
                        prior_outcome["outcome"],
                    ),
                    episode_id=None if episode is None else str(episode["id"]),
                    selected_policy_key=None if episode is None else str(episode["policy_key"]),
                    created=False,
                )
            alert = _alert_from_generation(generation)
            cursor.execute(
                """SELECT policy.*,subtype.selector_json,subtype.target_mapping_json,
                          subtype.severity_mapping_json,subtype.mode,
                          subtype.triage_profile_ref,subtype.incident_profile_ref,
                          subtype.escalation_expression_json,
                          subtype.full_incident_admission_expression_json,
                          subtype.triage_budget_json,subtype.incident_admission_budget_json,
                          subtype.episode_horizon_ms,subtype.delivery_policy_ref,
                          subtype.retention_policy_revision,
                          subtype.alert_material_hash,head.activation_id,head.head_epoch,
                          head.placement_epoch
                     FROM solvan_alerts.alert_provider_source_current_memberships source
                     JOIN solvan_operability.trigger_policy_current_heads head
                       ON head.organization_id=source.organization_id
                      AND head.project_id=source.project_id
                      AND head.environment_id=source.environment_id AND head.is_current
                      AND head.connection_epoch=source.connection_epoch
                     JOIN solvan_operability.trigger_policy_revisions policy
                       ON (policy.organization_id,policy.project_id,policy.environment_id,
                           policy.policy_key,policy.version,policy.policy_hash)=
                          (head.organization_id,head.project_id,head.environment_id,
                           head.policy_key,head.policy_version,head.policy_hash)
                     JOIN solvan_operability.trigger_policy_current_lifecycles lifecycle
                       ON (lifecycle.organization_id,lifecycle.project_id,
                           lifecycle.environment_id,lifecycle.policy_key,
                           lifecycle.policy_version,lifecycle.policy_hash)=
                          (policy.organization_id,policy.project_id,policy.environment_id,
                           policy.policy_key,policy.version,policy.policy_hash)
                      AND lifecycle.availability='ELIGIBLE'
                     JOIN solvan_alerts.alert_policy_revisions subtype
                       ON (subtype.organization_id,subtype.project_id,subtype.environment_id,
                           subtype.policy_key,subtype.policy_version,subtype.policy_hash)=
                          (policy.organization_id,policy.project_id,policy.environment_id,
                           policy.policy_key,policy.version,policy.policy_hash)
                    WHERE source.organization_id=%(organization_id)s
                      AND source.project_id=%(project_id)s
                      AND source.environment_id=%(environment_id)s
                      AND source.source_identity_id=%(provider_source_identity_id)s
                      AND policy.source_connection_id=source.connection_id
                      AND policy.source_connection_epoch=source.connection_epoch
                      AND policy.trigger_kind='ALERT_OPENED'
                      AND policy.lifecycle='APPROVED'
                    ORDER BY policy.policy_key""",
                {**values, **generation},
            )
            candidates = cursor.fetchall()
            graph = self._current_graph(cursor=cursor, scope=scope)
            match_rows: list[dict[str, Any]] = []
            selected: list[tuple[dict[str, Any], AlertPolicyRevisionV1]] = []
            for candidate in candidates:
                policy = _alert_policy_from_row(candidate)
                selector_result = (
                    "MATCH"
                    if alert_selector_matches(selector=policy.selector, alert=alert)
                    else "NO_MATCH"
                )
                target = None
                reason_codes = ["SELECTOR_MATCHED"]
                mapping_result = "NO_MATCH"
                if selector_result == "NO_MATCH":
                    reason_codes = ["SELECTOR_DID_NOT_MATCH"]
                elif graph is None:
                    mapping_result = "BLOCKED"
                    reason_codes.append("CURRENT_GRAPH_UNAVAILABLE")
                else:
                    target = self._resolve_graph_target(
                        cursor=cursor,
                        scope=scope,
                        graph=graph,
                        policy=policy,
                        alert=alert,
                    )
                    if target is None:
                        mapping_result = "BLOCKED"
                        reason_codes.append("TARGET_MAPPING_UNRESOLVED")
                    elif not graph["assisted_usable"]:
                        target = None
                        mapping_result = "BLOCKED"
                        reason_codes.append("GRAPH_STALE")
                    else:
                        mapping_result = "MATCH"
                        reason_codes.append("TARGET_MAPPING_EXACT")
                match_id = new_identifier("apm")
                match_values = {
                    **values,
                    "match_id": match_id,
                    "policy_key": policy.policy_key,
                    "policy_version": policy.version,
                    "policy_hash": candidate["policy_hash"],
                    "selector_result": selector_result,
                    "mapping_result": mapping_result,
                    "reason_codes": Jsonb(reason_codes),
                    "safe_summary": Jsonb(
                        {
                            "canonical_event_hash": alert.canonical_event_hash,
                            "provider_state": alert.lifecycle_state,
                            "resource_type": alert.resource_type,
                        }
                    ),
                    "classification": candidate["classification_ceiling"],
                    "retention_policy_revision": candidate["retention_policy_revision"],
                    **_nullable_target_values(graph=graph, target=target),
                }
                cursor.execute(
                    """INSERT INTO solvan_alerts.alert_policy_matches (
                          organization_id,project_id,environment_id,id,
                          provider_generation_id,policy_key,policy_version,policy_hash,
                          selector_result,mapping_result,reason_codes_json,cell_id,
                          placement_epoch,graph_snapshot_id,graph_snapshot_version,
                          graph_content_hash,target_node_key,target_node_version,
                          safe_input_summary_json,classification,retention_policy_revision)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                          %(match_id)s,%(generation_id)s,%(policy_key)s,%(policy_version)s,
                          %(policy_hash)s,%(selector_result)s,%(mapping_result)s,
                          %(reason_codes)s,%(cell_id)s,%(placement_epoch)s,
                          %(graph_snapshot_id)s,%(graph_snapshot_version)s,
                          %(graph_content_hash)s,%(target_node_key)s,%(target_node_version)s,
                          %(safe_summary)s,%(classification)s,%(retention_policy_revision)s)""",
                    match_values,
                )
                match_rows.append(match_values)
                if mapping_result == "MATCH":
                    selected.append((match_values, policy))
            projected_outcome: Literal["MATCHED", "UNMATCHED", "POLICY_CONFLICT"] = (
                "MATCHED"
                if len(selected) == 1
                else "POLICY_CONFLICT"
                if len(selected) > 1
                else "UNMATCHED"
            )
            selected_match_id = selected[0][0]["match_id"] if len(selected) == 1 else None
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_generation_outcomes (
                      organization_id,project_id,environment_id,id,provider_generation_id,
                      outcome,candidate_match_ids,selected_policy_match_id,safe_reason_code,
                      classification,retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(outcome_id)s,
                      %(generation_id)s,%(outcome)s,%(candidate_ids)s,%(selected_match_id)s,
                      %(reason_code)s,%(classification)s,%(retention_policy_revision)s)""",
                {
                    **values,
                    "outcome_id": new_identifier("aou"),
                    "outcome": projected_outcome,
                    "candidate_ids": [row["match_id"] for row in match_rows],
                    "selected_match_id": selected_match_id,
                    "reason_code": {
                        "MATCHED": "EXACTLY_ONE_POLICY_MATCHED",
                        "POLICY_CONFLICT": "MULTIPLE_POLICIES_MATCHED",
                        "UNMATCHED": "NO_POLICY_MATCHED",
                    }[projected_outcome],
                    "classification": generation["classification"],
                    "retention_policy_revision": generation["retention_policy_revision"],
                },
            )
            episode_id = None
            selected_policy_key = None
            if len(selected) == 1:
                match, policy = selected[0]
                episode_id = self._create_episode(
                    cursor=cursor,
                    scope=scope,
                    generation=generation,
                    alert=alert,
                    match=match,
                    policy=policy,
                    candidate=candidates[
                        next(
                            index
                            for index, row in enumerate(match_rows)
                            if row["match_id"] == match["match_id"]
                        )
                    ],
                )
                selected_policy_key = policy.policy_key
            cursor.execute(
                """UPDATE solvan_alerts.alert_provider_generations
                      SET policy_projection_state=%(outcome)s,row_version=row_version+1,
                          updated_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(generation_id)s AND policy_projection_state IS NULL""",
                {**values, "outcome": projected_outcome},
            )
            if cursor.rowcount != 1:
                raise AlertPolicyError("generation projection lost its exact fence")
        return AlertGenerationProjectionReceipt(
            provider_generation_id=provider_generation_id,
            outcome=projected_outcome,
            episode_id=episode_id,
            selected_policy_key=selected_policy_key,
            created=True,
        )

    @staticmethod
    def _current_graph(*, cursor: Any, scope: Scope) -> dict[str, Any] | None:
        cursor.execute(
            """SELECT current_graph.snapshot_id,current_graph.snapshot_version,
                      current_graph.cell_id,current_graph.placement_epoch,
                      current_graph.autonomy_eligible,current_graph.assisted_usable,
                      snapshot.content_hash
                 FROM solvan_graph.graph_read_current(
                        %(organization_id)s,%(project_id)s,%(environment_id)s) current_graph
                 JOIN solvan_graph.graph_snapshots snapshot
                   ON (snapshot.organization_id,snapshot.project_id,
                       snapshot.environment_id,snapshot.cell_id,snapshot.placement_epoch,
                       snapshot.snapshot_id,snapshot.snapshot_version)=
                      (%(organization_id)s,%(project_id)s,%(environment_id)s,
                       current_graph.cell_id,current_graph.placement_epoch,
                       current_graph.snapshot_id,current_graph.snapshot_version)""",
            scope.canonical_dict(),
        )
        row = cursor.fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _resolve_graph_target(
        *,
        cursor: Any,
        scope: Scope,
        graph: dict[str, Any],
        policy: AlertPolicyRevisionV1,
        alert: CanonicalCloudMonitoringAlert,
    ) -> dict[str, Any] | None:
        values = {
            **scope.canonical_dict(),
            **graph,
            "external_project_id": alert.monitored_resource_project_id,
        }
        if policy.target_mapping.kind == "EXACT_NODE":
            values["node_key"] = policy.target_mapping.node_key
            condition = "node.node_key=%(node_key)s"
        else:
            resource_ref = canonical_resource_identifier(alert)
            if resource_ref is None:
                return None
            values["resource_ref"] = resource_ref
            values["node_kind"] = policy.target_mapping.node_kind
            condition = "node.resource_ref=%(resource_ref)s AND node.node_kind=%(node_kind)s"
        cursor.execute(
            f"""SELECT node.node_key,node.node_id,node.region,node.external_project_id
                  FROM solvan_graph.graph_nodes node
                 WHERE node.organization_id=%(organization_id)s
                   AND node.project_id=%(project_id)s
                   AND node.environment_id=%(environment_id)s
                   AND node.cell_id=%(cell_id)s
                   AND node.placement_epoch=%(placement_epoch)s
                   AND node.snapshot_id=%(snapshot_id)s
                   AND node.external_project_id=%(external_project_id)s
                   AND node.region=%(region)s AND {condition}
                 ORDER BY node.node_key LIMIT 2""",
            {**values, "region": policy.region},
        )
        rows = cursor.fetchall()
        return dict(rows[0]) if len(rows) == 1 else None

    def _create_episode(
        self,
        *,
        cursor: Any,
        scope: Scope,
        generation: dict[str, Any],
        alert: CanonicalCloudMonitoringAlert,
        match: dict[str, Any],
        policy: AlertPolicyRevisionV1,
        candidate: dict[str, Any],
    ) -> str:
        cursor.execute(
            """SELECT id,episode_generation,state
                 FROM solvan_alerts.alert_episodes
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND provider_source_identity_id=%(source_identity_id)s
                  AND provider_incident_key=%(provider_incident_key)s
                  AND target_node_key=%(target_node_key)s
                  AND provider_generation_id<>%(generation_id)s
                ORDER BY started_at DESC,id DESC LIMIT 1 FOR UPDATE""",
            {
                **scope.canonical_dict(),
                "source_identity_id": generation["provider_source_identity_id"],
                "provider_incident_key": generation["provider_incident_key"],
                "target_node_key": match["target_node_key"],
                "generation_id": generation["id"],
            },
        )
        prior = cursor.fetchone()
        active_states = {"OPEN", "WAITING", "TRIAGING", "TRIAGED", "ESCALATED", "ATTACHED"}
        blocked_by_active = prior is not None and prior["state"] in active_states
        state = (
            "PROVIDER_REPORTED_CLEARED"
            if generation["provider_state_projection"] == "CLOSED"
            else "BLOCKED"
            if blocked_by_active
            else "OPEN"
        )
        episode_id = new_identifier("aep")
        episode_generation = 1 if prior is None else int(prior["episode_generation"]) + 1
        values = {
            **scope.canonical_dict(),
            "episode_id": episode_id,
            "generation_id": generation["id"],
            "source_identity_id": generation["provider_source_identity_id"],
            "provider_incident_key": generation["provider_incident_key"],
            "started_at": generation["started_at"],
            "cell_id": match["cell_id"],
            "placement_epoch": match["placement_epoch"],
            "graph_snapshot_id": match["graph_snapshot_id"],
            "graph_snapshot_version": match["graph_snapshot_version"],
            "graph_content_hash": match["graph_content_hash"],
            "target_node_key": match["target_node_key"],
            "target_node_version": match["target_node_version"],
            "fingerprint": alert_fingerprint(
                policy=policy,
                source_identity_id=str(generation["provider_source_identity_id"]),
                target_node_key=str(match["target_node_key"]),
                alert=alert,
            ),
            "policy_key": policy.policy_key,
            "policy_version": policy.version,
            "policy_hash": candidate["policy_hash"],
            "activation_id": candidate["activation_id"],
            "head_epoch": candidate["head_epoch"],
            "episode_generation": episode_generation,
            "recurrence_id": None if prior is None else prior["id"],
            "state": state,
            "last_event_id": generation["last_semantic_event_id"],
            "provider_state": generation["provider_state_projection"],
            "current_disposition": "BLOCKED" if blocked_by_active else None,
            "last_source_time": alert.observed_at,
            "classification": generation["classification"],
            "retention_policy_revision": generation["retention_policy_revision"],
        }
        cursor.execute(
            """INSERT INTO solvan_alerts.alert_episodes (
                  organization_id,project_id,environment_id,id,provider_generation_id,
                  cell_id,placement_epoch,graph_snapshot_id,graph_snapshot_version,
                  graph_content_hash,target_node_key,target_node_version,
                  provider_source_identity_id,provider_incident_key,started_at,fingerprint,
                  policy_key,policy_version,policy_hash,activation_id,head_epoch,
                  episode_generation,recurrence_of_episode_id,state,first_source_time,
                  last_source_time,last_event_id,provider_state_projection,current_disposition,
                  classification,retention_policy_revision)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(episode_id)s,
                  %(generation_id)s,%(cell_id)s,%(placement_epoch)s,%(graph_snapshot_id)s,
                  %(graph_snapshot_version)s,%(graph_content_hash)s,%(target_node_key)s,
                  %(target_node_version)s,%(source_identity_id)s,%(provider_incident_key)s,
                  %(started_at)s,%(fingerprint)s,%(policy_key)s,%(policy_version)s,
                  %(policy_hash)s,%(activation_id)s,%(head_epoch)s,%(episode_generation)s,
                  %(recurrence_id)s,%(state)s,%(started_at)s,%(last_source_time)s,
                  %(last_event_id)s,%(provider_state)s,%(current_disposition)s,
                  %(classification)s,%(retention_policy_revision)s)""",
            values,
        )
        cursor.execute(
            """SELECT occurrence.delivery_id,occurrence.semantic_event_id,
                      occurrence.observed_at,occurrence.source_state,
                      occurrence.occurrence_kind,occurrence.safe_reason_code
                 FROM solvan_alerts.alert_provider_generation_occurrences occurrence
                WHERE occurrence.organization_id=%(organization_id)s
                  AND occurrence.project_id=%(project_id)s
                  AND occurrence.environment_id=%(environment_id)s
                  AND occurrence.provider_generation_id=%(generation_id)s
                ORDER BY occurrence.observed_at,occurrence.id""",
            values,
        )
        for occurrence in cursor.fetchall():
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_episode_occurrences (
                      organization_id,project_id,environment_id,id,delivery_id,
                      semantic_event_id,episode_id,episode_generation,observed_at,
                      source_state,occurrence_kind,safe_reason_code,classification,
                      retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(occurrence_id)s,%(delivery_id)s,%(semantic_event_id)s,%(episode_id)s,
                      %(episode_generation)s,%(observed_at)s,%(source_state)s,
                      %(occurrence_kind)s,%(safe_reason_code)s,%(classification)s,
                      %(retention_policy_revision)s)""",
                {**values, **occurrence, "occurrence_id": new_identifier("aec")},
            )
        return episode_id


def _alert_from_generation(row: dict[str, Any]) -> CanonicalCloudMonitoringAlert:
    return CanonicalCloudMonitoringAlert(
        envelope=PubSubEnvelopeIdentity(
            message_id="projected-generation",
            subscription_name="projected-generation",
            publish_time=None,
            envelope_hash=str(row["canonical_event_hash"]),
        ),
        provider_incident_key=str(row["provider_incident_key"]),
        lifecycle_state=str(row["lifecycle_state"]),  # type: ignore[arg-type]
        transition_discriminator="projected-generation",
        transition_sequence=int(row["transition_sequence"]),
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        observed_at=row["observed_at"],
        scoping_project_id=str(row["scoping_project_id"]),
        monitored_resource_project_id=str(row["monitored_resource_project_id"]),
        resource_type=str(row["resource_type"]),
        resource_labels=dict(row["resource_labels_json"]),
        normalized_labels=dict(row["normalized_labels_json"]),
        provider_severity=str(row["provider_severity"]),
        canonical_event_hash=str(row["canonical_event_hash"]),
        raw_payload_hash=str(row["canonical_event_hash"]),
    )


def _alert_policy_from_row(row: dict[str, Any]) -> AlertPolicyRevisionV1:
    guidance_revision = (
        None if row["guidance_key"] is None else f"{row['guidance_key']}@{row['guidance_version']}"
    )
    return AlertPolicyRevisionV1.model_validate(
        {
            "policy_key": row["policy_key"],
            "version": row["version"],
            "owner_department": row["owner_department"],
            "source_connection_id": row["source_connection_id"],
            "source_connection_epoch": row["source_connection_epoch"],
            "source_capability_tool_ref": (
                f"{row['source_tool_key']}@{row['source_tool_version']}"
            ),
            "source_capability_agent_key": row["source_agent_key"],
            "source_capability_identity_ref": row["source_identity_ref"],
            "selector": row["selector_json"],
            "target_mapping": row["target_mapping_json"],
            "severity_mapping": row["severity_mapping_json"],
            "incident_class": row["incident_class"],
            "mode": row["mode"],
            "guidance_revision": guidance_revision,
            "triage_profile_ref": row["triage_profile_ref"],
            "incident_profile_ref": row["incident_profile_ref"],
            "escalation_expression": row["escalation_expression_json"],
            "full_incident_admission_expression": row["full_incident_admission_expression_json"],
            "triage_budget": row["triage_budget_json"],
            "incident_admission_budget": row["incident_admission_budget_json"],
            "cooldown_ms": row["cooldown_ms"],
            "maximum_pending_per_target": row["maximum_pending_per_target"],
            "supersession": row["supersession"],
            "episode_horizon_ms": row["episode_horizon_ms"],
            "region": row["region"],
            "classification_ceiling": row["classification_ceiling"],
            "delivery_policy_ref": row["delivery_policy_ref"],
        }
    )


def _nullable_target_values(
    *, graph: dict[str, Any] | None, target: dict[str, Any] | None
) -> dict[str, Any]:
    if graph is None or target is None:
        return {
            "cell_id": None,
            "placement_epoch": None,
            "graph_snapshot_id": None,
            "graph_snapshot_version": None,
            "graph_content_hash": None,
            "target_node_key": None,
            "target_node_version": None,
        }
    return {
        "cell_id": graph["cell_id"],
        "placement_epoch": graph["placement_epoch"],
        "graph_snapshot_id": graph["snapshot_id"],
        "graph_snapshot_version": graph["snapshot_version"],
        "graph_content_hash": graph["content_hash"],
        "target_node_key": target["node_key"],
        "target_node_version": target["node_id"],
    }
