"""Reader-safe Operational Guidance and trigger projections."""

from typing import Any

from psycopg.rows import dict_row

from solvan.domain import Scope
from solvan.persistence.operational_guidance_base import OperationalGuidanceStoreBase


class OperationalGuidanceProjectionMixin(OperationalGuidanceStoreBase):
    def projection(self, *, scope: Scope) -> dict[str, Any]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT d.guidance_key,d.display_name,d.owner_department,
                          r.version,r.description,r.guidance_kind,r.purpose,
                          r.classification,r.eligible_regions_json,r.lifecycle,
                          r.evaluation_ref,r.approval_ref,r.revision_hash,r.created_at,
                          r.source_kind,r.source_ref,r.author_principal,
                          array_agg(DISTINCT a.agent_key) AS agent_keys,
                          array_agg(DISTINCT p.profile_key || '@' || p.profile_version)
                            AS profile_revisions
                      FROM solvan_operability.guidance_definitions d
                      JOIN solvan_operability.guidance_revisions r USING
                        (organization_id,project_id,environment_id,guidance_key)
                      JOIN solvan_operability.guidance_revision_agents a ON
                        (a.organization_id,a.project_id,a.environment_id,a.guidance_key,
                         a.guidance_version)=(r.organization_id,r.project_id,r.environment_id,
                                             r.guidance_key,r.version)
                      JOIN solvan_operability.guidance_revision_profiles p ON
                        (p.organization_id,p.project_id,p.environment_id,p.guidance_key,
                         p.guidance_version)=(r.organization_id,r.project_id,r.environment_id,
                                              r.guidance_key,r.version)
                      LEFT JOIN solvan_operability.guidance_current_heads h ON
                        (h.organization_id,h.project_id,h.environment_id,h.guidance_key)=
                        (d.organization_id,d.project_id,d.environment_id,d.guidance_key)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s
                      AND r.environment_id=%(environment_id)s
                      -- The catalog shows each key's current state, never its
                      -- history: the approved head when one exists, plus any
                      -- in-flight draft. Superseded revisions stay durable and
                      -- queryable; rendering them as separate skills made
                      -- every key look duplicated and deprecated.
                      AND (
                        (h.approved_version IS NOT NULL AND r.version = h.approved_version)
                        OR r.lifecycle IN ('DRAFT','IN_REVIEW')
                      )
                    GROUP BY d.organization_id,d.project_id,d.environment_id,
                             d.guidance_key,d.display_name,d.owner_department,r.version,
                             r.description,r.guidance_kind,r.purpose,r.classification,
                             r.eligible_regions_json,r.lifecycle,r.evaluation_ref,
                             r.approval_ref,r.revision_hash,r.created_at,
                             r.source_kind,r.source_ref,r.author_principal
                    ORDER BY d.display_name,r.created_at DESC""",
                scope.canonical_dict(),
            )
            guidance = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT policy_key,version,owner_department,trigger_kind,
                          source_connection_id,source_connection_epoch,target_selector_ref,
                          guidance_key,guidance_version,profile_key,profile_version,
                          delay_ms,cooldown_ms,maximum_pending_per_target,supersession,
                          region,classification_ceiling,lifecycle,approval_ref,evaluation_ref
                     FROM solvan_operability.trigger_policy_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY policy_key,created_at DESC""",
                scope.canonical_dict(),
            )
            policies = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT id,policy_key,policy_version,source_event_id,source_sequence,
                          connection_id,connection_epoch,target_key,due_at,status,
                          decision_reason,created_at,completed_at
                     FROM solvan_operability.trigger_firings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY created_at DESC LIMIT 100""",
                scope.canonical_dict(),
            )
            firings = [dict(row) for row in cursor.fetchall()]
        return {"guidance": guidance, "trigger_policies": policies, "trigger_firings": firings}
