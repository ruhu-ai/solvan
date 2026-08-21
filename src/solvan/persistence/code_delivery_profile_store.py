"""Cloud SQL registry for immutable code-delivery policy bundles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.code_delivery_profiles import CodeDeliveryProfileInput
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier


class PolicyReceipt(Protocol):
    @property
    def uri(self) -> str: ...

    @property
    def content_hash(self) -> str: ...


@dataclass(frozen=True, slots=True)
class DeliveryPolicyReceipts:
    required_checks: PolicyReceipt
    reviewer: PolicyReceipt
    pr_creation: PolicyReceipt
    merge: PolicyReceipt
    deployment: PolicyReceipt
    approval: PolicyReceipt


class PostgresCodeDeliveryProfileStore:
    def __init__(self, connection: Connection[Any], *, scope: Scope) -> None:
        self._connection = connection
        self._scope = scope

    def register(
        self,
        *,
        value: CodeDeliveryProfileInput,
        receipts: DeliveryPolicyReceipts,
        principal: str,
    ) -> str:
        params = {**self._scope.canonical_dict(), "repository_id": value.repository_binding_id}
        repository = self._connection.execute(
            """SELECT status FROM solvan.github_repositories
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(repository_id)s FOR UPDATE""",
            params,
        ).fetchone()
        if repository != ("ACTIVE",):
            raise ValueError("CODE_DELIVERY_REPOSITORY_NOT_ACTIVE")
        target = self._connection.execute(
            """SELECT id,profile_hash FROM solvan_delivery.release_target_profiles
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND target_key=%(target_key)s
                  AND status='ACTIVE'""",
            {**params, "target_key": value.deployment_target_profile},
        ).fetchone()
        if target is None:
            raise ValueError("CODE_DELIVERY_RELEASE_TARGET_NOT_ACTIVE")
        existing = self._connection.execute(
            """SELECT id,profile_hash FROM solvan_delivery.code_delivery_profiles
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND repository_binding_id=%(repository_id)s
                  AND status='ACTIVE' FOR UPDATE""",
            params,
        ).fetchone()
        if existing is not None and existing[1] == value.profile_hash:
            return str(existing[0])
        if existing is not None:
            self._connection.execute(
                """UPDATE solvan_delivery.code_delivery_profiles
                      SET status='REVOKED',revoked_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(id)s""",
                {**params, "id": existing[0]},
            )
        version_row = self._connection.execute(
            """SELECT COALESCE(max(profile_version),0)+1
                 FROM solvan_delivery.code_delivery_profiles
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND repository_binding_id=%(repository_id)s""",
            params,
        ).fetchone()
        version = int(version_row[0]) if version_row else 1
        profile_id = new_identifier("cdp")
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_delivery_profiles
                 (organization_id,project_id,environment_id,id,repository_binding_id,profile_version,
                  maximum_request_lifetime_minutes,
                  allowed_paths_json,allowed_paths_hash,required_checks_policy_ref,
                  required_checks_policy_hash,required_check_definition_paths_json,
                  required_check_definition_paths_hash,reviewer_policy_ref,reviewer_policy_hash,
                  pr_creation_policy_ref,pr_creation_policy_hash,merge_policy_ref,merge_policy_hash,
                  deployment_policy_ref,deployment_policy_hash,profile_hash,approval_ref,approval_hash,
                  release_target_profile_id,release_target_profile_hash,
                  status,activated_at,created_by_principal)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                       %(repository_id)s,%(version)s,%(maximum_lifetime)s,
                       %(allowed_paths)s,%(allowed_paths_hash)s,
                       %(checks_ref)s,%(checks_hash)s,%(definition_paths)s,%(definition_paths_hash)s,
                       %(reviewer_ref)s,%(reviewer_hash)s,%(pr_ref)s,%(pr_hash)s,
                       %(merge_ref)s,%(merge_hash)s,%(deployment_ref)s,%(deployment_hash)s,
                       %(profile_hash)s,%(approval_ref)s,%(approval_hash)s,
                       %(target_id)s,%(target_hash)s,'ACTIVE',now(),%(principal)s)""",
            {
                **params,
                "id": profile_id,
                "version": version,
                "maximum_lifetime": value.maximum_request_lifetime_minutes,
                "allowed_paths": Jsonb(sorted(value.allowed_paths)),
                "allowed_paths_hash": canonical_sha256(sorted(value.allowed_paths)),
                "checks_ref": receipts.required_checks.uri,
                "checks_hash": receipts.required_checks.content_hash,
                "definition_paths": Jsonb(sorted(value.required_check_definition_paths)),
                "definition_paths_hash": canonical_sha256(
                    sorted(value.required_check_definition_paths)
                ),
                "reviewer_ref": receipts.reviewer.uri,
                "reviewer_hash": receipts.reviewer.content_hash,
                "pr_ref": receipts.pr_creation.uri,
                "pr_hash": receipts.pr_creation.content_hash,
                "merge_ref": receipts.merge.uri,
                "merge_hash": receipts.merge.content_hash,
                "deployment_ref": receipts.deployment.uri,
                "deployment_hash": receipts.deployment.content_hash,
                "profile_hash": value.profile_hash,
                "approval_ref": receipts.approval.uri,
                "approval_hash": receipts.approval.content_hash,
                "principal": principal,
                "target_id": target[0],
                "target_hash": target[1],
            },
        )
        return profile_id

    def list(self) -> list[dict[str, Any]]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,repository_binding_id,profile_version,allowed_paths_json,
                          required_check_definition_paths_json,reviewer_policy_hash,
                          profile_hash,status,activated_at,revoked_at
                     FROM solvan_delivery.code_delivery_profiles
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY created_at DESC LIMIT 100""",
                self._scope.canonical_dict(),
            )
            return [dict(row) for row in cursor.fetchall()]
