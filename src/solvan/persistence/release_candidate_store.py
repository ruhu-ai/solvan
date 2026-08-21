"""Atomic persistence of independently verified signed release candidates."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.application.release_candidates import ReleaseCandidateEnvelope, envelope_hash
from solvan.domain import Scope, new_identifier


class ReleaseCandidateConflict(ValueError):
    pass


class PostgresReleaseCandidateStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def expected(self, *, scope: Scope, request_id: str) -> dict[str, object]:
        row = self._connection.execute(
            """SELECT request.id,request.repository_binding_id,request.proposed_tree_hash,
                      request.deployment_policy_hash,request.sequence_no,request.expires_at,
                      observation.merge_commit_sha,signer.signer_identity,signer.key_version
                 FROM solvan_delivery.code_change_requests request
                 JOIN LATERAL (
                   SELECT merge_commit_sha FROM solvan_delivery.code_change_github_observations item
                    WHERE item.organization_id=request.organization_id
                      AND item.project_id=request.project_id
                      AND item.environment_id=request.environment_id
                      AND item.code_change_request_id=request.id
                      AND item.observation_kind='MERGED'
                    ORDER BY item.sequence_no DESC LIMIT 1
                 ) observation ON true
                 JOIN solvan_delivery.release_signer_keys signer
                   ON signer.organization_id=request.organization_id
                  AND signer.project_id=request.project_id
                  AND signer.environment_id=request.environment_id AND signer.status='ACTIVE'
                WHERE request.organization_id=%(organization_id)s
                  AND request.project_id=%(project_id)s
                  AND request.environment_id=%(environment_id)s AND request.id=%(request_id)s
                  AND request.state='MERGED' AND request.expires_at>now()
                LIMIT 1 FOR SHARE OF request,signer""",
            {**scope.canonical_dict(), "request_id": request_id},
        ).fetchone()
        if row is None:
            raise ReleaseCandidateConflict("release candidate authority is unavailable")
        return {
            "code_change_request_id": str(row[0]),
            "repository_binding_id": str(row[1]),
            "source_tree_hash": str(row[2]),
            "release_policy_hash": str(row[3]),
            "sequence_no": int(row[4]),
            "expires_at": row[5],
            "merged_commit_sha": str(row[6]),
            "signer_identity": str(row[7]),
            "signer_key_version": str(row[8]),
        }

    def record_verified(
        self,
        *,
        scope: Scope,
        envelope: ReleaseCandidateEnvelope,
        envelope_ref: str,
        envelope_receipt_hash: str,
        coordinator_identity: str,
    ) -> str:
        material_hash = envelope_hash(envelope)
        if material_hash != envelope_receipt_hash:
            raise ReleaseCandidateConflict("release candidate envelope receipt differs")
        existing = self._connection.execute(
            """SELECT id FROM solvan_delivery.release_candidates
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                  AND build_artifact_hash=%(artifact_hash)s""",
            {
                **scope.canonical_dict(),
                "request_id": envelope.code_change_request_id,
                "artifact_hash": envelope.build_artifact_hash,
            },
        ).fetchone()
        if existing is not None:
            return str(existing[0])
        request = self.expected(scope=scope, request_id=envelope.code_change_request_id)
        if any(
            (
                envelope.repository_binding_id != request["repository_binding_id"],
                envelope.merged_commit_sha != request["merged_commit_sha"],
                envelope.source_tree_hash != request["source_tree_hash"],
                envelope.release_policy_hash != request["release_policy_hash"],
                envelope.signer_identity != request["signer_identity"],
                envelope.signer_key_version != request["signer_key_version"],
            )
        ):
            raise ReleaseCandidateConflict("verified release candidate is no longer current")
        candidate_id = new_identifier("rlc")
        self._connection.execute(
            """INSERT INTO solvan_delivery.release_candidates
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  repository_binding_id,merged_commit_sha,source_tree_hash,
                  build_definition_ref,build_definition_hash,builder_identity,
                  build_invocation_ref,build_invocation_hash,build_artifact_ref,
                  build_artifact_hash,sbom_ref,sbom_hash,provenance_predicate_type,
                  provenance_predicate_version,provenance_ref,provenance_hash,
                  release_signature_ref,release_signature_hash,signer_identity,
                  signer_key_version,deployment_manifest_ref,deployment_manifest_hash,
                  release_policy_hash,candidate_envelope_ref,candidate_envelope_hash,issued_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(request_id)s,%(repository_id)s,%(merge_sha)s,%(tree_hash)s,
                  %(build_ref)s,%(build_hash)s,%(builder)s,%(invocation_ref)s,
                  %(invocation_hash)s,%(artifact_ref)s,%(artifact_hash)s,%(sbom_ref)s,
                  %(sbom_hash)s,%(predicate_type)s,%(predicate_version)s,%(provenance_ref)s,
                  %(provenance_hash)s,%(signature_ref)s,%(signature_hash)s,%(signer)s,
                  %(key_version)s,%(manifest_ref)s,%(manifest_hash)s,%(policy_hash)s,
                  %(envelope_ref)s,%(envelope_hash)s,%(issued_at)s)""",
            {
                **scope.canonical_dict(),
                "id": candidate_id,
                "request_id": envelope.code_change_request_id,
                "repository_id": envelope.repository_binding_id,
                "merge_sha": envelope.merged_commit_sha,
                "tree_hash": envelope.source_tree_hash,
                "build_ref": envelope.build_definition_ref,
                "build_hash": envelope.build_definition_hash,
                "builder": envelope.builder_identity,
                "invocation_ref": envelope.build_invocation_ref,
                "invocation_hash": envelope.build_invocation_hash,
                "artifact_ref": envelope.build_artifact_ref,
                "artifact_hash": envelope.build_artifact_hash,
                "sbom_ref": envelope.sbom_ref,
                "sbom_hash": envelope.sbom_hash,
                "predicate_type": envelope.provenance_predicate_type,
                "predicate_version": envelope.provenance_predicate_version,
                "provenance_ref": envelope.provenance_ref,
                "provenance_hash": envelope.provenance_hash,
                "signature_ref": envelope.release_signature_ref,
                "signature_hash": envelope.release_signature_hash,
                "signer": envelope.signer_identity,
                "key_version": envelope.signer_key_version,
                "manifest_ref": envelope.deployment_manifest_ref,
                "manifest_hash": envelope.deployment_manifest_hash,
                "policy_hash": envelope.release_policy_hash,
                "envelope_ref": envelope_ref,
                "envelope_hash": envelope_receipt_hash,
                "issued_at": envelope.issued_at,
            },
        )
        current_sequence = request["sequence_no"]
        if type(current_sequence) is not int:
            raise ReleaseCandidateConflict("release candidate sequence is malformed")
        sequence = current_sequence + 1
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                  idempotency_key,actor_kind,actor_identity,receipt_ref,receipt_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(transition_id)s,
                  %(request_id)s,%(sequence)s,'MERGED','RELEASE_CANDIDATE',
                  %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,'COORDINATOR',
                  %(identity)s,%(receipt_ref)s,%(receipt_hash)s)""",
            {
                **scope.canonical_dict(),
                "transition_id": new_identifier("cct"),
                "request_id": envelope.code_change_request_id,
                "sequence": sequence,
                "expected_sequence": request["sequence_no"],
                "input_hash": material_hash,
                "idempotency_key": f"release-candidate:{candidate_id}",
                "identity": coordinator_identity,
                "receipt_ref": envelope_ref,
                "receipt_hash": envelope_receipt_hash,
            },
        )
        return candidate_id
