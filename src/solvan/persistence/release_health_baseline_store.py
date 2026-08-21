"""Durable verifier-owned pre-canary health baseline authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.release_verification import ReleaseHealthSnapshot
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class ReleaseHealthBaselineConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseHealthBaselineCandidate:
    request_id: str
    verification_profile_hash: str
    target_observation_hash: str
    material_hash: str
    deadline: datetime


@dataclass(frozen=True, slots=True)
class ReleaseHealthBaselineMaterial:
    request_id: str
    release_candidate_id: str
    release_target_profile_id: str
    target_observation_hash: str
    verification_profile_ref: str
    verification_profile_hash: str
    target_version: str
    target_assignment_hash: str
    external_project_id: str
    service_name: str
    window_start: datetime
    window_end: datetime
    verifier_identity: str
    verifier_key_version: str


@dataclass(frozen=True, slots=True)
class RecordedHealthBaseline:
    baseline_id: str
    baseline_ref: str
    baseline_hash: str


class PostgresReleaseHealthBaselineStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def candidates(
        self, *, scope: Scope, now: datetime, limit: int = 20
    ) -> tuple[ReleaseHealthBaselineCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.id,request.expires_at,target.verification_profile_hash,
                          target.observation_windows_seconds,observation.observation_hash,
                          observation.observed_at
                     FROM solvan_delivery.code_change_requests request
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=request.organization_id
                      AND candidate.project_id=request.project_id
                      AND candidate.environment_id=request.environment_id
                      AND candidate.code_change_request_id=request.id
                     JOIN solvan_delivery.code_delivery_profiles delivery
                       ON delivery.organization_id=request.organization_id
                      AND delivery.project_id=request.project_id
                      AND delivery.environment_id=request.environment_id
                      AND delivery.id=request.code_delivery_profile_id AND delivery.status='ACTIVE'
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=delivery.organization_id
                      AND target.project_id=delivery.project_id
                      AND target.environment_id=delivery.environment_id
                      AND target.id=delivery.release_target_profile_id
                      AND target.profile_hash=delivery.release_target_profile_hash
                      AND target.status='ACTIVE'
                     JOIN LATERAL (
                       SELECT * FROM solvan_delivery.release_target_observations item
                        WHERE item.organization_id=request.organization_id
                          AND item.project_id=request.project_id
                          AND item.environment_id=request.environment_id
                          AND item.code_change_request_id=request.id
                          AND item.release_candidate_id=candidate.id
                          AND item.release_target_profile_id=target.id
                        ORDER BY item.observed_at DESC,item.id DESC LIMIT 1
                     ) observation ON true
                    WHERE request.organization_id=%(organization_id)s
                      AND request.project_id=%(project_id)s
                      AND request.environment_id=%(environment_id)s
                      AND request.state='DEPLOYMENT_APPROVAL_PENDING'
                      AND request.expires_at>%(now)s
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.release_health_baselines baseline
                         WHERE baseline.organization_id=request.organization_id
                           AND baseline.project_id=request.project_id
                           AND baseline.environment_id=request.environment_id
                           AND baseline.code_change_request_id=request.id
                           AND baseline.target_observation_hash=observation.observation_hash
                           AND baseline.verification_profile_hash=
                               target.verification_profile_hash)
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=request.organization_id
                           AND command.project_id=request.project_id
                           AND command.environment_id=request.environment_id
                           AND command.command_kind='OBSERVE_RELEASE_BASELINE'
                           AND command.subject_id=request.id
                           AND command.status IN ('PREPARED','ISSUED','RECONCILING'))
                    ORDER BY observation.observed_at,request.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "now": now, "limit": limit},
            )
            candidates: list[ReleaseHealthBaselineCandidate] = []
            for row in cursor.fetchall():
                material_hash = self._material_hash(
                    request_id=str(row["id"]),
                    verification_profile_hash=str(row["verification_profile_hash"]),
                    target_observation_hash=str(row["observation_hash"]),
                )
                candidates.append(
                    ReleaseHealthBaselineCandidate(
                        request_id=str(row["id"]),
                        verification_profile_hash=str(row["verification_profile_hash"]),
                        target_observation_hash=str(row["observation_hash"]),
                        material_hash=material_hash,
                        deadline=min(row["expires_at"], now + timedelta(minutes=10)),
                    )
                )
            return tuple(candidates)

    def dispatchable_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        rows = self._connection.execute(
            """SELECT id FROM solvan_delivery.private_command_dispatches
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND command_kind='OBSERVE_RELEASE_BASELINE'
                  AND status IN ('PREPARED','ISSUED','RECONCILING') AND deadline>now()
                ORDER BY created_at,id LIMIT %(limit)s""",
            {**scope.canonical_dict(), "limit": limit},
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    @staticmethod
    def _material_hash(
        *, request_id: str, verification_profile_hash: str, target_observation_hash: str
    ) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "command_kind": "OBSERVE_RELEASE_BASELINE",
                "code_change_request_id": request_id,
                "verification_profile_hash": verification_profile_hash,
                "target_observation_hash": target_observation_hash,
            }
        )

    def load(
        self, *, scope: Scope, request_id: str, material_hash: str
    ) -> ReleaseHealthBaselineMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.id,candidate.id AS candidate_id,target.id AS target_id,
                          target.verification_profile_ref,target.verification_profile_hash,
                          target.external_project_id,target.service_name,
                          target.observation_windows_seconds,target.verifier_identity,
                          target.verifier_key_version,observation.observation_hash,
                          observation.target_version,observation.assignment_hash,
                          observation.observed_at
                     FROM solvan_delivery.code_change_requests request
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=request.organization_id
                      AND candidate.project_id=request.project_id
                      AND candidate.environment_id=request.environment_id
                      AND candidate.code_change_request_id=request.id
                     JOIN solvan_delivery.code_delivery_profiles delivery
                       ON delivery.organization_id=request.organization_id
                      AND delivery.project_id=request.project_id
                      AND delivery.environment_id=request.environment_id
                      AND delivery.id=request.code_delivery_profile_id AND delivery.status='ACTIVE'
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=delivery.organization_id
                      AND target.project_id=delivery.project_id
                      AND target.environment_id=delivery.environment_id
                      AND target.id=delivery.release_target_profile_id
                      AND target.profile_hash=delivery.release_target_profile_hash
                      AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_verifier_keys verifier_key
                       ON verifier_key.organization_id=target.organization_id
                      AND verifier_key.project_id=target.project_id
                      AND verifier_key.environment_id=target.environment_id
                      AND verifier_key.verifier_identity=target.verifier_identity
                      AND verifier_key.key_version=target.verifier_key_version
                      AND verifier_key.status='ACTIVE'
                     JOIN LATERAL (
                       SELECT * FROM solvan_delivery.release_target_observations item
                        WHERE item.organization_id=request.organization_id
                          AND item.project_id=request.project_id
                          AND item.environment_id=request.environment_id
                          AND item.code_change_request_id=request.id
                          AND item.release_candidate_id=candidate.id
                          AND item.release_target_profile_id=target.id
                        ORDER BY item.observed_at DESC,item.id DESC LIMIT 1
                     ) observation ON true
                    WHERE request.organization_id=%(organization_id)s
                      AND request.project_id=%(project_id)s
                      AND request.environment_id=%(environment_id)s
                      AND request.id=%(request_id)s
                      AND request.state='DEPLOYMENT_APPROVAL_PENDING'
                    FOR SHARE OF request,candidate,delivery,target,verifier_key,observation""",
                {**scope.canonical_dict(), "request_id": request_id},
            )
            row = cursor.fetchone()
        windows = row["observation_windows_seconds"] if row is not None else None
        if row is None or not isinstance(windows, list) or not windows:
            raise ReleaseHealthBaselineConflict("release health baseline authority is stale")
        expected = self._material_hash(
            request_id=request_id,
            verification_profile_hash=str(row["verification_profile_hash"]),
            target_observation_hash=str(row["observation_hash"]),
        )
        if expected != material_hash:
            raise ReleaseHealthBaselineConflict("release health baseline material changed")
        window_end = row["observed_at"]
        return ReleaseHealthBaselineMaterial(
            request_id=request_id,
            release_candidate_id=str(row["candidate_id"]),
            release_target_profile_id=str(row["target_id"]),
            target_observation_hash=str(row["observation_hash"]),
            verification_profile_ref=str(row["verification_profile_ref"]),
            verification_profile_hash=str(row["verification_profile_hash"]),
            target_version=str(row["target_version"]),
            target_assignment_hash=str(row["assignment_hash"]),
            external_project_id=str(row["external_project_id"]),
            service_name=str(row["service_name"]),
            window_start=window_end - timedelta(seconds=int(windows[0])),
            window_end=window_end,
            verifier_identity=str(row["verifier_identity"]),
            verifier_key_version=str(row["verifier_key_version"]),
        )

    def record(
        self,
        *,
        scope: Scope,
        material: ReleaseHealthBaselineMaterial,
        snapshot: ReleaseHealthSnapshot,
        baseline_ref: str,
        baseline_hash: str,
        signature_ref: str,
        signature_hash: str,
    ) -> str:
        if baseline_hash != canonical_sha256(snapshot.model_dump(mode="json")):
            raise ReleaseHealthBaselineConflict("release baseline hash differs")
        baseline_id = new_identifier("rhb")
        row = self._connection.execute(
            """INSERT INTO solvan_delivery.release_health_baselines
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  release_candidate_id,release_target_profile_id,target_observation_hash,
                  verification_profile_hash,target_version,target_assignment_hash,
                  window_start,window_end,signal_results_hash,baseline_ref,baseline_hash,
                  verifier_identity,verifier_key_version,signature_ref,signature_hash,observed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(candidate_id)s,%(target_id)s,%(observation_hash)s,
                 %(profile_hash)s,%(target_version)s,%(assignment_hash)s,%(window_start)s,
                 %(window_end)s,%(signals_hash)s,%(baseline_ref)s,%(baseline_hash)s,
                 %(verifier)s,%(key_version)s,%(signature_ref)s,%(signature_hash)s,
                 %(observed_at)s)
               ON CONFLICT (organization_id,project_id,environment_id,code_change_request_id,
                            target_observation_hash,verification_profile_hash)
               DO NOTHING RETURNING id""",
            {
                **scope.canonical_dict(),
                "id": baseline_id,
                "request_id": material.request_id,
                "candidate_id": material.release_candidate_id,
                "target_id": material.release_target_profile_id,
                "observation_hash": material.target_observation_hash,
                "profile_hash": material.verification_profile_hash,
                "target_version": material.target_version,
                "assignment_hash": material.target_assignment_hash,
                "window_start": snapshot.window_start,
                "window_end": snapshot.window_end,
                "signals_hash": snapshot.signal_results_hash,
                "baseline_ref": baseline_ref,
                "baseline_hash": baseline_hash,
                "verifier": material.verifier_identity,
                "key_version": material.verifier_key_version,
                "signature_ref": signature_ref,
                "signature_hash": signature_hash,
                "observed_at": snapshot.observed_at,
            },
        ).fetchone()
        if row is not None:
            return str(row[0])
        existing = self._connection.execute(
            """SELECT id,baseline_hash,signature_hash
                 FROM solvan_delivery.release_health_baselines
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                  AND target_observation_hash=%(observation_hash)s
                  AND verification_profile_hash=%(profile_hash)s""",
            {
                **scope.canonical_dict(),
                "request_id": material.request_id,
                "observation_hash": material.target_observation_hash,
                "profile_hash": material.verification_profile_hash,
            },
        ).fetchone()
        if existing is None or tuple(existing[1:]) != (baseline_hash, signature_hash):
            raise ReleaseHealthBaselineConflict("release baseline replay conflicts")
        return str(existing[0])

    def existing(
        self, *, scope: Scope, material: ReleaseHealthBaselineMaterial
    ) -> RecordedHealthBaseline | None:
        row = self._connection.execute(
            """SELECT id,baseline_ref,baseline_hash
                 FROM solvan_delivery.release_health_baselines
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                  AND release_candidate_id=%(candidate_id)s
                  AND release_target_profile_id=%(target_id)s
                  AND target_observation_hash=%(observation_hash)s
                  AND verification_profile_hash=%(profile_hash)s""",
            {
                **scope.canonical_dict(),
                "request_id": material.request_id,
                "candidate_id": material.release_candidate_id,
                "target_id": material.release_target_profile_id,
                "observation_hash": material.target_observation_hash,
                "profile_hash": material.verification_profile_hash,
            },
        ).fetchone()
        return (
            RecordedHealthBaseline(str(row[0]), str(row[1]), str(row[2]))
            if row is not None
            else None
        )
