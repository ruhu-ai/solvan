"""What each Agent may reach, read as records rather than re-derived.

One row per `(Agent, Tool revision)` carrying the material each authority in
`solvan.application.capability_resolution` needs, so the projection above can
state a verdict without inventing a predicate of its own.

Three shapes here are corrections rather than choices:

  * the row set is the union of profile membership and the requester
    declaration. Membership is what dispatch resolves; the declaration is the
    larger set the console used to render as though it were reach. Keeping both
    is what lets a capability say `not registered` — offered to nobody — rather
    than borrowing the word a refusal uses;
  * probe receipts join on all four of `(connection, tool, version, agent)`.
    The console keyed them by Tool alone, so with two Agents holding one Tool
    the last receipt in sort order silently decided both rows;
  * superseded revisions are excluded. `tool_revisions` carries no head
    pointer, so without this every past revision renders as its own row and,
    with no version column on the screen, as a duplicate of the current one.

Profiles and Tool revisions are release-global; probes and connections are
scoped. Only the scoped halves take scope parameters, and the projection labels
which is which rather than fusing them silently.
"""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope

_CAPABILITY_MATRIX_SQL = """
WITH member AS (
  -- One profile per (Agent, Tool). A Tool may sit in more than one approved
  -- profile for the same Agent; the matrix answers whether it is reachable, so
  -- it cites the lowest-keyed grant deterministically instead of emitting a row
  -- per grant and reading as duplicates.
  SELECT DISTINCT ON (f.allowed_agent_key, m.tool_key, m.tool_version)
         f.allowed_agent_key AS agent_key, m.tool_key, m.tool_version,
         f.profile_key, f.version AS profile_version, f.approval_ref AS profile_approval_ref,
         f.runtime_region AS profile_region,
         f.data_classification_ceiling AS profile_ceiling,
         c.binding_kind, c.provider AS required_provider
    FROM solvan_operability.tool_profile_members m
    JOIN solvan_operability.tool_profile_revisions f
      ON (f.profile_key, f.version) = (m.profile_key, m.profile_version)
    LEFT JOIN solvan_operability.tool_profile_connection_requirements c
      ON (c.profile_key, c.profile_version, c.ordinal, c.tool_key, c.tool_version)
       = (m.profile_key, m.profile_version, m.ordinal, m.tool_key, m.tool_version)
   WHERE f.lifecycle = 'APPROVED'
   ORDER BY f.allowed_agent_key, m.tool_key, m.tool_version, f.profile_key, f.version
),
pair AS (
  SELECT agent_key, tool_key, tool_version FROM member
  UNION
  SELECT requester_key, tool_key, tool_version
    FROM solvan_operability.tool_revision_requesters
)
SELECT p.agent_key, p.tool_key, p.tool_version,
       principal.display_name AS agent_display_name,
       d.display_name AS tool_display_name,
       t.permission_class, t.lifecycle AS revision_lifecycle,
       t.approval_ref AS revision_approval_ref, t.gateway_destination,
       t.registry_resource, t.runtime_regions_json, t.supported_data_classes_json,
       (q.requester_key IS NOT NULL) AS declared,
       m.profile_key, m.profile_version, m.profile_approval_ref, m.profile_region,
       m.profile_ceiling, m.binding_kind, m.required_provider,
       bind.connection_id, bind.connection_epoch, bind.outcome AS probe_outcome,
       bind.expires_at AS probe_expires_at, bind.receipt_ref AS probe_receipt_ref,
       bind.reason_code AS probe_reason_code, bind.missing_grant AS probe_missing_grant,
       bind.observed_at AS probe_observed_at
  FROM pair p
  JOIN solvan_operability.tool_revisions t
    ON (t.tool_key, t.version) = (p.tool_key, p.tool_version)
  JOIN solvan_operability.tool_definitions d ON d.tool_key = p.tool_key
  JOIN solvan_operability.catalog_principals principal
    ON principal.principal_key = p.agent_key
  LEFT JOIN member m
    ON (m.agent_key, m.tool_key, m.tool_version)
     = (p.agent_key, p.tool_key, p.tool_version)
  LEFT JOIN solvan_operability.tool_revision_requesters q
    ON (q.tool_key, q.tool_version, q.requester_key)
     = (p.tool_key, p.tool_version, p.agent_key)
  -- A compute-only requirement carries no provider by schema CHECK, so this
  -- matches nothing for one and needs no separate branch. Where a connection is
  -- required, prefer one whose probe currently passes: the question is whether
  -- this Agent can reach the destination through any enrolled connection, not
  -- whether it can through the alphabetically first one.
  LEFT JOIN LATERAL (
    SELECT tc.id AS connection_id, tc.connection_epoch, r.outcome, r.expires_at,
           r.receipt_ref, r.reason_code, r.missing_grant, r.observed_at
      FROM solvan.tenant_connections tc
      LEFT JOIN LATERAL (
        SELECT pr.outcome, pr.expires_at, pr.receipt_ref, pr.reason_code,
               pr.missing_grant, pr.observed_at
          FROM solvan_operability.tool_probe_receipts pr
         WHERE (pr.organization_id, pr.project_id, pr.environment_id)
             = (tc.organization_id, tc.project_id, tc.environment_id)
           AND pr.connection_id = tc.id
           AND pr.tool_key = p.tool_key
           AND pr.tool_version = p.tool_version
           AND pr.agent_key = p.agent_key
         ORDER BY pr.observed_at DESC
         LIMIT 1
      ) r ON true
     WHERE tc.organization_id = %(organization_id)s
       AND tc.project_id = %(project_id)s
       AND tc.environment_id = %(environment_id)s
       AND tc.provider = m.required_provider
       AND tc.lifecycle = 'ENABLED'
       AND tc.availability IN ('READY', 'DEGRADED')
     ORDER BY (r.outcome = 'PASSED' AND r.expires_at > now()) DESC NULLS LAST, tc.id
     LIMIT 1
  ) bind ON true
 WHERE NOT EXISTS (
   SELECT 1 FROM solvan_operability.tool_revisions successor
    WHERE successor.tool_key = t.tool_key
      AND successor.supersedes_version = t.version
 )
 ORDER BY p.agent_key, d.display_name, p.tool_key, p.tool_version
"""


def capability_matrix_rows(connection: Connection[Any], *, scope: Scope) -> list[dict[str, Any]]:
    """Read every governed `(Agent, Tool revision)` pair with its deciding records."""

    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(_CAPABILITY_MATRIX_SQL, scope.canonical_dict())
        return [dict(row) for row in cursor.fetchall()]
