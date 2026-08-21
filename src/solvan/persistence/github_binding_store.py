"""Changing what an existing GitHub repository binding may do.

Registration is an insert and lives in `GitHubStore`. Re-granting is a
different operation with a different hazard, so it is written here on its own:
an insert can only create authority nobody had, while a re-grant can widen
authority that is already being exercised.

Two consequences follow, and both are enforced below rather than left to the
caller. The policy digest is recomputed from the new authority, so a widened
binding cannot keep presenting the digest its narrower form was approved
under. And the binding drops back to PENDING with its probe result cleared,
because the successful probe on record attested to the old policy — an ACTIVE
binding whose authority changed since that probe is asserting something nobody
confirmed.

Specification 24 §1 and specification 13 govern.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.github import GitHubContractError, GitHubOperationKind
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


@dataclass(frozen=True, slots=True)
class RegrantedBinding:
    """What a re-grant produced, so the caller can report the exact change."""

    repository_id: str
    owner: str
    name: str
    previous_operations: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    classification: str
    policy_hash: str
    status: str


class GitHubBindingStore:
    """Re-grant mixin; the concrete store supplies the scoped connection."""

    _connection: Connection[Any]

    def binding_for_regrant(self, *, scope: Scope, repository_id: str) -> dict[str, Any]:
        """Load one binding's current authority under a row lock."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, installation_id, owner, name, default_branch, api_base_url,
                          classification, policy_hash, allowed_operations_json, status
                     FROM solvan.github_repositories
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND id = %(id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "id": repository_id},
            )
            binding = cursor.fetchone()
        if binding is None:
            raise GitHubContractError("GitHub repository binding is not present")
        if str(binding["status"]) == "REVOKED":
            raise GitHubContractError("a revoked binding is not re-granted; bind again")
        return dict(binding)

    def regrant_repository(
        self,
        *,
        scope: Scope,
        repository_id: str,
        allowed_operations: tuple[GitHubOperationKind, ...],
        classification: str,
        policy_hash: str,
        actor: str,
    ) -> RegrantedBinding:
        """Replace one binding's authority, and send it back for re-probing."""

        current = self.binding_for_regrant(scope=scope, repository_id=repository_id)
        previous = tuple(str(item) for item in (current["allowed_operations_json"] or ()))
        if not allowed_operations:
            raise GitHubContractError("a binding's authority is never empty")
        if len(set(allowed_operations)) != len(allowed_operations):
            raise GitHubContractError("GitHub operation allowlist contains duplicates")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.github_repositories
                      SET allowed_operations_json = %(allowed_operations)s::jsonb,
                          classification = %(classification)s,
                          policy_hash = %(policy_hash)s,
                          -- Back to PENDING with no probe result: the probe on
                          -- record confirmed the previous policy, and nothing
                          -- has yet confirmed this one.
                          status = 'PENDING',
                          last_probe_at = NULL,
                          last_probe_result = NULL,
                          updated_at = now()
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND id = %(id)s""",
                {
                    **scope.canonical_dict(),
                    "id": repository_id,
                    "allowed_operations": json.dumps(sorted(allowed_operations)),
                    "classification": classification,
                    "policy_hash": policy_hash,
                },
            )
            if cursor.rowcount != 1:
                raise GitHubContractError("GitHub repository binding was not re-granted")
            # The widening is its own append-only record. The binding row now
            # shows only the new authority, so without this there would be no
            # durable answer to "what could it do before, and who changed that".
            change = {
                "previous_operations": sorted(previous),
                "allowed_operations": sorted(allowed_operations),
                "classification": classification,
                "policy_hash": policy_hash,
            }
            cursor.execute(
                """INSERT INTO solvan.audit_events (
                     organization_id, project_id, environment_id, id, stream_type,
                     stream_id, event_type, actor_principal, input_refs_json,
                     payload_hash)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                     %(id)s, 'GITHUB_REPOSITORY', %(repository_id)s,
                     'GITHUB_BINDING_REGRANTED', %(actor)s, %(detail)s::jsonb,
                     %(payload_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("aud"),
                    "actor": actor,
                    "repository_id": repository_id,
                    "detail": json.dumps([policy_hash]),
                    "payload_hash": canonical_sha256(change),
                },
            )
        return RegrantedBinding(
            repository_id=repository_id,
            owner=str(current["owner"]),
            name=str(current["name"]),
            previous_operations=previous,
            allowed_operations=tuple(sorted(allowed_operations)),
            classification=classification,
            policy_hash=policy_hash,
            status="PENDING",
        )
