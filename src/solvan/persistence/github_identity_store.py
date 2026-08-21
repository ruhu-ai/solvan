"""Cloud SQL authority for the GitHub reviewer-link ceremony."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.github_identity import OAuthClientProfile, requested_permission_hash
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier


class GitHubIdentityStoreError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LinkAuthority:
    profile: OAuthClientProfile
    repository_binding_id: str
    reviewer_policy_hash: str


@dataclass(frozen=True, slots=True)
class ConsumedLink:
    transaction_id: str
    profile: OAuthClientProfile
    repository_binding_id: str
    principal: str
    session_binding_hash: str
    reviewer_policy_hash: str
    encrypted_verifier: str
    pkce_key_version: str


class PostgresGitHubIdentityStore:
    def __init__(self, connection: Connection[Any], *, scope: Scope) -> None:
        self._connection = connection
        self._scope = scope

    @property
    def _params(self) -> dict[str, str]:
        return self._scope.canonical_dict()

    def authority(self, *, repository_binding_id: str, principal: str) -> LinkAuthority:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id AS repository_binding_id, d.reviewer_policy_hash,
                          p.id, p.github_app_client_id, p.client_secret_ref,
                          p.authorization_endpoint, p.token_endpoint, p.api_base_url,
                          p.callback_uri, p.protocol_version, p.configuration_hash
                     FROM solvan.github_repositories r
                     JOIN solvan_delivery.github_oauth_client_profiles p
                       ON p.organization_id=r.organization_id AND p.project_id=r.project_id
                      AND p.environment_id=r.environment_id AND p.status='ACTIVE'
                     JOIN solvan_delivery.code_delivery_profiles d
                       ON d.organization_id=r.organization_id AND d.project_id=r.project_id
                      AND d.environment_id=r.environment_id AND d.repository_binding_id=r.id
                      AND d.status='ACTIVE'
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s
                      AND r.environment_id=%(environment_id)s
                      AND r.id=%(repository_binding_id)s AND r.status='ACTIVE'
                      AND EXISTS (
                        SELECT 1 FROM solvan.actor_role_bindings b
                         WHERE b.organization_id=r.organization_id
                           AND b.project_id=r.project_id
                           AND b.environment_id=r.environment_id
                           AND b.principal=%(principal)s
                           AND b.role='CODE_CHANGE_APPROVER'
                           AND (b.expires_at IS NULL OR b.expires_at > now()))""",
                {
                    **self._params,
                    "repository_binding_id": repository_binding_id,
                    "principal": principal,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise GitHubIdentityStoreError("GITHUB_REVIEWER_LINK_AUTHORITY_REFUSED")
        return LinkAuthority(
            profile=OAuthClientProfile(
                id=row["id"],
                client_id=row["github_app_client_id"],
                client_secret_ref=row["client_secret_ref"],
                authorization_endpoint=row["authorization_endpoint"],
                token_endpoint=row["token_endpoint"],
                api_base_url=row["api_base_url"],
                callback_uri=row["callback_uri"],
                protocol_version=row["protocol_version"],
                configuration_hash=row["configuration_hash"],
            ),
            repository_binding_id=row["repository_binding_id"],
            reviewer_policy_hash=row["reviewer_policy_hash"],
        )

    def create_transaction(
        self,
        *,
        transaction_id: str,
        authority: LinkAuthority,
        principal: str,
        session_binding_hash: str,
        state_hash: str,
        encrypted_verifier: str,
        pkce_key_version: str,
        requested_permission_hash: str,
    ) -> str:
        self._connection.execute(
            """INSERT INTO solvan_delivery.github_identity_link_transactions
                 (organization_id,project_id,environment_id,id,oauth_client_profile_id,
                  repository_binding_id,solvan_principal,solvan_session_binding_hash,
                  state_hash,pkce_verifier_ciphertext,pkce_key_version,
                  requested_permission_hash,status,expires_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                       %(profile_id)s,%(repository_binding_id)s,%(principal)s,
                       %(session_binding_hash)s,%(state_hash)s,%(encrypted_verifier)s,
                       %(pkce_key_version)s,%(requested_permission_hash)s,'PENDING',
                       now()+interval '10 minutes')""",
            {
                **self._params,
                "id": transaction_id,
                "profile_id": authority.profile.id,
                "repository_binding_id": authority.repository_binding_id,
                "principal": principal,
                "session_binding_hash": session_binding_hash,
                "state_hash": state_hash,
                "encrypted_verifier": encrypted_verifier,
                "pkce_key_version": pkce_key_version,
                "requested_permission_hash": requested_permission_hash,
            },
        )
        return transaction_id

    def consume(
        self, *, transaction_id: str, state_hash: str, session_binding_hash: str
    ) -> ConsumedLink:
        """Consume once and erase the only durable copy of the PKCE verifier."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT t.*, d.reviewer_policy_hash AS current_policy_hash,
                          r.status AS repository_status, p.github_app_client_id,
                          p.client_secret_ref,p.authorization_endpoint,p.token_endpoint,
                          p.api_base_url,p.callback_uri,p.protocol_version,p.configuration_hash,
                          p.status AS profile_status
                     FROM solvan_delivery.github_identity_link_transactions t
                     JOIN solvan.github_repositories r
                       ON r.organization_id=t.organization_id AND r.project_id=t.project_id
                      AND r.environment_id=t.environment_id AND r.id=t.repository_binding_id
                     JOIN solvan_delivery.github_oauth_client_profiles p
                       ON p.organization_id=t.organization_id AND p.project_id=t.project_id
                      AND p.environment_id=t.environment_id AND p.id=t.oauth_client_profile_id
                     JOIN solvan_delivery.code_delivery_profiles d
                       ON d.organization_id=t.organization_id AND d.project_id=t.project_id
                      AND d.environment_id=t.environment_id
                      AND d.repository_binding_id=t.repository_binding_id AND d.status='ACTIVE'
                    WHERE t.organization_id=%(organization_id)s
                      AND t.project_id=%(project_id)s
                      AND t.environment_id=%(environment_id)s AND t.id=%(id)s
                    FOR UPDATE OF t""",
                {**self._params, "id": transaction_id},
            )
            row = cursor.fetchone()
            if (
                row is None
                or row["status"] != "PENDING"
                or row["expires_at"] <= datetime.now(UTC)
                or row["state_hash"] != state_hash
                or row["solvan_session_binding_hash"] != session_binding_hash
                or row["repository_status"] != "ACTIVE"
                or row["profile_status"] != "ACTIVE"
                or row["pkce_verifier_ciphertext"] is None
                or row["requested_permission_hash"]
                != requested_permission_hash(
                    repository_binding_id=row["repository_binding_id"],
                    reviewer_policy_hash=row["current_policy_hash"],
                )
            ):
                raise GitHubIdentityStoreError("GITHUB_REVIEWER_LINK_CALLBACK_REFUSED")
            cursor.execute(
                """UPDATE solvan_delivery.github_identity_link_transactions
                      SET status='CONSUMED',consumed_at=now(),pkce_verifier_ciphertext=NULL
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(id)s AND status='PENDING'""",
                {**self._params, "id": transaction_id},
            )
        return ConsumedLink(
            transaction_id=transaction_id,
            profile=OAuthClientProfile(
                id=row["oauth_client_profile_id"],
                client_id=row["github_app_client_id"],
                client_secret_ref=row["client_secret_ref"],
                authorization_endpoint=row["authorization_endpoint"],
                token_endpoint=row["token_endpoint"],
                api_base_url=row["api_base_url"],
                callback_uri=row["callback_uri"],
                protocol_version=row["protocol_version"],
                configuration_hash=row["configuration_hash"],
            ),
            repository_binding_id=row["repository_binding_id"],
            principal=row["solvan_principal"],
            session_binding_hash=row["solvan_session_binding_hash"],
            reviewer_policy_hash=row["current_policy_hash"],
            encrypted_verifier=row["pkce_verifier_ciphertext"],
            pkce_key_version=row["pkce_key_version"],
        )

    def pending_session_binding(self, *, transaction_id: str, state_hash: str) -> str:
        row = self._connection.execute(
            """SELECT solvan_session_binding_hash
                 FROM solvan_delivery.github_identity_link_transactions
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(id)s
                  AND state_hash=%(state_hash)s AND status='PENDING' AND expires_at > now()""",
            {**self._params, "id": transaction_id, "state_hash": state_hash},
        ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise GitHubIdentityStoreError("GITHUB_REVIEWER_LINK_CALLBACK_REFUSED")
        return row[0]

    def refuse_pending(self, *, transaction_id: str, state_hash: str, failure_code: str) -> str:
        row = self._connection.execute(
            """UPDATE solvan_delivery.github_identity_link_transactions
                  SET status='REFUSED',consumed_at=now(),pkce_verifier_ciphertext=NULL,
                      failure_code=%(failure_code)s
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(id)s
                  AND state_hash=%(state_hash)s AND status='PENDING' AND expires_at > now()
              RETURNING solvan_principal""",
            {
                **self._params,
                "id": transaction_id,
                "state_hash": state_hash,
                "failure_code": failure_code[:128],
            },
        ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise GitHubIdentityStoreError("GITHUB_REVIEWER_LINK_CALLBACK_REFUSED")
        return row[0]

    def expire_pending(self) -> int:
        cursor = self._connection.execute(
            """UPDATE solvan_delivery.github_identity_link_transactions
                  SET status='EXPIRED',consumed_at=now(),pkce_verifier_ciphertext=NULL,
                      failure_code='GITHUB_REVIEWER_LINK_EXPIRED'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND status='PENDING'
                  AND expires_at <= now()""",
            self._params,
        )
        return cursor.rowcount

    def create_binding(
        self,
        *,
        link: ConsumedLink,
        github_account_node_id: str,
        github_login: str,
        proof_ref: str,
        proof_hash: str,
        actor_identity: str,
    ) -> str:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,solvan_principal,github_account_node_id
                     FROM solvan_delivery.github_reviewer_bindings
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND repository_binding_id=%(repository_binding_id)s AND status='ACTIVE'
                      AND (solvan_principal=%(principal)s
                           OR github_account_node_id=%(account_id)s)
                    FOR UPDATE""",
                {
                    **self._params,
                    "repository_binding_id": link.repository_binding_id,
                    "principal": link.principal,
                    "account_id": github_account_node_id,
                },
            )
            prior = cursor.fetchall()
            if any(item["solvan_principal"] != link.principal for item in prior):
                raise GitHubIdentityStoreError("GITHUB_ACCOUNT_ALREADY_LINKED")
            for item in prior:
                self._insert_event(
                    binding_id=item["id"],
                    event_kind="REPLACED",
                    actor_kind="GITHUB_IDENTITY_BROKER",
                    actor_identity=actor_identity,
                    input_hash=canonical_sha256(
                        {"schema_version": 1, "replacement_transaction_id": link.transaction_id}
                    ),
                    receipt_ref=proof_ref,
                    receipt_hash=proof_hash,
                )
            binding_id = new_identifier("grb")
            cursor.execute(
                """INSERT INTO solvan_delivery.github_reviewer_bindings
                     (organization_id,project_id,environment_id,id,repository_binding_id,
                      solvan_principal,github_account_node_id,github_login,binding_proof_ref,
                      binding_proof_hash,reviewer_policy_hash,status,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(repository_binding_id)s,%(principal)s,%(account_id)s,%(login)s,
                           %(proof_ref)s,%(proof_hash)s,%(policy_hash)s,'ACTIVE',
                           now()+interval '30 days')""",
                {
                    **self._params,
                    "id": binding_id,
                    "repository_binding_id": link.repository_binding_id,
                    "principal": link.principal,
                    "account_id": github_account_node_id,
                    "login": github_login,
                    "proof_ref": proof_ref,
                    "proof_hash": proof_hash,
                    "policy_hash": link.reviewer_policy_hash,
                },
            )
            self._insert_event(
                binding_id=binding_id,
                event_kind="LINKED",
                actor_kind="GITHUB_IDENTITY_BROKER",
                actor_identity=actor_identity,
                input_hash=canonical_sha256(
                    {
                        "schema_version": 1,
                        "transaction_id": link.transaction_id,
                        "github_account_node_id": github_account_node_id,
                        "reviewer_policy_hash": link.reviewer_policy_hash,
                    }
                ),
                receipt_ref=proof_ref,
                receipt_hash=proof_hash,
            )
        return binding_id

    def disconnect(
        self, *, binding_id: str, principal: str, receipt_ref: str, receipt_hash: str
    ) -> None:
        row = self._connection.execute(
            """SELECT status FROM solvan_delivery.github_reviewer_bindings
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(id)s
                  AND solvan_principal=%(principal)s FOR UPDATE""",
            {**self._params, "id": binding_id, "principal": principal},
        ).fetchone()
        if row != ("ACTIVE",):
            raise GitHubIdentityStoreError("GITHUB_REVIEWER_BINDING_NOT_ACTIVE")
        self._insert_event(
            binding_id=binding_id,
            event_kind="REVOKED",
            actor_kind="HUMAN",
            actor_identity=principal,
            input_hash=canonical_sha256({"schema_version": 1, "binding_id": binding_id}),
            receipt_ref=receipt_ref,
            receipt_hash=receipt_hash,
        )

    def list_for_principal(self, *, principal: str) -> list[dict[str, Any]]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT b.id,b.repository_binding_id,b.github_login,b.status,b.expires_at,
                          b.created_at,r.owner,r.name
                     FROM solvan_delivery.github_reviewer_bindings b
                     JOIN solvan.github_repositories r
                       ON r.organization_id=b.organization_id AND r.project_id=b.project_id
                      AND r.environment_id=b.environment_id AND r.id=b.repository_binding_id
                    WHERE b.organization_id=%(organization_id)s AND b.project_id=%(project_id)s
                      AND b.environment_id=%(environment_id)s
                      AND b.solvan_principal=%(principal)s
                    ORDER BY b.created_at DESC LIMIT 100""",
                {**self._params, "principal": principal},
            )
            return [dict(row) for row in cursor.fetchall()]

    def _insert_event(
        self,
        *,
        binding_id: str,
        event_kind: str,
        actor_kind: str,
        actor_identity: str,
        input_hash: str,
        receipt_ref: str,
        receipt_hash: str,
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_delivery.github_reviewer_binding_events
                 (organization_id,project_id,environment_id,id,github_reviewer_binding_id,
                  sequence_no,event_kind,actor_kind,actor_identity,input_hash,receipt_ref,receipt_hash)
               SELECT %(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,%(binding_id)s,
                      COALESCE(max(sequence_no),0)+1,%(event_kind)s,%(actor_kind)s,%(actor_identity)s,
                      %(input_hash)s,%(receipt_ref)s,%(receipt_hash)s
                 FROM solvan_delivery.github_reviewer_binding_events
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND github_reviewer_binding_id=%(binding_id)s""",
            {
                **self._params,
                "id": new_identifier("gre"),
                "binding_id": binding_id,
                "event_kind": event_kind,
                "actor_kind": actor_kind,
                "actor_identity": actor_identity,
                "input_hash": input_hash,
                "receipt_ref": receipt_ref,
                "receipt_hash": receipt_hash,
            },
        )

    def append_audit(
        self,
        *,
        stream_id: str,
        event_type: str,
        actor_principal: str,
        payload: dict[str, Any],
    ) -> None:
        payload_hash = canonical_sha256(payload)
        self._connection.execute(
            """INSERT INTO solvan.audit_events
                 (organization_id,project_id,environment_id,id,stream_type,stream_id,
                  event_type,actor_principal,input_refs_json,payload_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                       'GITHUB_REVIEWER_LINK',%(stream_id)s,%(event_type)s,
                       %(actor_principal)s,%(input_refs)s,%(payload_hash)s)""",
            {
                **self._params,
                "id": new_identifier("aud"),
                "stream_id": stream_id,
                "event_type": event_type,
                "actor_principal": actor_principal,
                "input_refs": Jsonb(payload),
                "payload_hash": payload_hash,
            },
        )
