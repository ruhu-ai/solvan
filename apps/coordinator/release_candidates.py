"""Import and verify the deterministic signed release-candidate inbox."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from solvan.application.release_candidates import (
    ReleaseCandidateEnvelope,
    ReleaseCandidateExpected,
    envelope_hash,
    verify_release_candidate,
)
from solvan.application.workspace_hashing import canonical_json_bytes
from solvan.persistence.release_candidate_store import PostgresReleaseCandidateStore
from solvan.platform.evidence_objects import GcsEvidenceReader
from solvan.platform.google_rest import GoogleRestSession, authorized_session
from solvan.platform.workspace_attestation import GoogleKmsPublicKeyReader


def advance_release_candidates(
    *, settings: CoordinatorSettings, connection: Connection[Any]
) -> None:
    rows = connection.execute(
        """SELECT request.id,observation.merge_commit_sha
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
            WHERE request.organization_id=%(organization_id)s
              AND request.project_id=%(project_id)s
              AND request.environment_id=%(environment_id)s AND request.state='MERGED'
              AND request.expires_at>now()
              AND NOT EXISTS (
                SELECT 1 FROM solvan_delivery.release_candidates candidate
                 WHERE candidate.organization_id=request.organization_id
                   AND candidate.project_id=request.project_id
                   AND candidate.environment_id=request.environment_id
                   AND candidate.code_change_request_id=request.id)
            ORDER BY request.created_at LIMIT 20""",
        settings.scope.canonical_dict(),
    ).fetchall()
    if not rows:
        return
    session = authorized_session()
    evidence = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    kms = GoogleKmsPublicKeyReader(session)
    for request_id, merge_sha in rows:
        object_name = (
            f"{settings.scope.organization_id}/{settings.scope.project_id}/"
            f"{settings.scope.environment_id}/release-candidate-inbox/"
            f"{request_id}/{merge_sha}/candidate.json"
        )
        loaded = _read_candidate(
            session=session, bucket=settings.runtime_bucket, object_name=object_name
        )
        if loaded is None:
            continue
        envelope, envelope_ref = loaded
        store = PostgresReleaseCandidateStore(connection)
        with connection.transaction():
            current = store.expected(scope=settings.scope, request_id=str(request_id))
        expected = ReleaseCandidateExpected(
            code_change_request_id=str(current["code_change_request_id"]),
            repository_binding_id=str(current["repository_binding_id"]),
            merged_commit_sha=str(current["merged_commit_sha"]),
            source_tree_hash=str(current["source_tree_hash"]),
            release_policy_hash=str(current["release_policy_hash"]),
            signer_identity=str(current["signer_identity"]),
            signer_key_version=str(current["signer_key_version"]),
            maximum_age_seconds=86400,
            now=datetime.now(UTC),
        )
        verify_release_candidate(envelope, expected=expected, evidence=evidence, kms=kms)
        with connection.transaction():
            store.record_verified(
                scope=settings.scope,
                envelope=envelope,
                envelope_ref=envelope_ref,
                envelope_receipt_hash=envelope_hash(envelope),
                coordinator_identity=settings.coordinator_principal,
            )


def _read_candidate(
    *, session: GoogleRestSession, bucket: str, object_name: str
) -> tuple[ReleaseCandidateEnvelope, str] | None:
    url = (
        f"https://storage.googleapis.com/storage/v1/b/{quote(bucket)}/o/"
        f"{quote(object_name, safe='')}?alt=media"
    )
    response = session.get(url, timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    if not response.content or len(response.content) > 128_000:
        raise ValueError("release candidate inbox object is empty or oversized")
    value = json.loads(response.content)
    if not isinstance(value, dict):
        raise ValueError("release candidate inbox object is not a JSON object")
    envelope = ReleaseCandidateEnvelope.model_validate(value)
    if response.content != canonical_json_bytes(envelope.model_dump(mode="json")):
        raise ValueError("release candidate inbox object is not canonical JSON")
    return envelope, f"gs://{bucket}/{object_name}"
