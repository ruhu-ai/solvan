"""Target-only outcome-quality ledger and derived-receipt repository.

Episode/declaration/falsification rows are immutable observations.  Population,
quality, competence, and earned-autonomy rows are intentionally reachable only
through the target SQL derivation functions; this module exposes those
functions without reimplementing their predicates in Python.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import Connection

from solvan.domain import Scope


class OutcomeQualityError(ValueError):
    """The caller supplied an invalid or incomplete quality record."""


class OutcomeQualityRepository:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def record_episode(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        episode_id: str,
        incident_ref: str,
        incident_generation: int,
        action_class: str,
        service_key: str,
        catalog_version: int,
        scenario_key: str,
        scenario_version: int,
        eligible_at: datetime,
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_quality.recovery_episodes
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  episode_id,incident_ref,incident_generation,action_class,service_key,
                  catalog_version,scenario_key,scenario_version,eligible_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(episode_id)s,%(incident_ref)s,
                       %(incident_generation)s,%(action_class)s,%(service_key)s,
                       %(catalog_version)s,%(scenario_key)s,%(scenario_version)s,
                       %(eligible_at)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "episode_id": episode_id,
                "incident_ref": incident_ref,
                "incident_generation": incident_generation,
                "action_class": action_class,
                "service_key": service_key,
                "catalog_version": catalog_version,
                "scenario_key": scenario_key,
                "scenario_version": scenario_version,
                "eligible_at": eligible_at,
            },
        )

    def record_declaration(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        declaration_id: str,
        episode_id: str,
        declaration_kind: str,
        producer_principal: str,
        producer_service_revision: str,
        subject_ref: str,
        declared_at: datetime,
        falsification_window_seconds: int,
    ) -> None:
        if not 1_800 <= falsification_window_seconds <= 86_400:
            raise OutcomeQualityError("falsification window must be 30 minutes to 24 hours")
        self._connection.execute(
            """INSERT INTO solvan_quality.recovery_declarations
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  declaration_id,episode_id,declaration_kind,producer_principal,
                  producer_service_revision,subject_ref,declared_at,
                  falsification_window_seconds,window_closes_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(declaration_id)s,%(episode_id)s,
                       %(declaration_kind)s,%(producer_principal)s,
                       %(producer_service_revision)s,%(subject_ref)s,%(declared_at)s,
                       %(falsification_window_seconds)s,
                       %(declared_at)s + make_interval(secs=>%(falsification_window_seconds)s))""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "declaration_id": declaration_id,
                "episode_id": episode_id,
                "declaration_kind": declaration_kind,
                "producer_principal": producer_principal,
                "producer_service_revision": producer_service_revision,
                "subject_ref": subject_ref,
                "declared_at": declared_at,
                "falsification_window_seconds": falsification_window_seconds,
            },
        )

    def record_isolation_receipt(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        values: dict[str, Any],
    ) -> None:
        required = {
            "isolation_receipt_id",
            "declaration_id",
            "producer_principal",
            "oracle_principal",
            "producer_service_revision",
            "oracle_service_revision",
            "producer_process_boot_id",
            "oracle_process_boot_id",
            "producer_provider_request_id",
            "oracle_provider_request_id",
            "producer_context_hash",
            "oracle_context_hash",
            "producer_policy_hash",
            "oracle_policy_hash",
            "producer_evidence_partitions",
            "oracle_evidence_partitions",
            "attested_by",
            "receipt_hash",
        }
        if set(values) != required:
            raise OutcomeQualityError("isolation receipt fields are not the closed contract")
        self._connection.execute(
            """INSERT INTO solvan_quality.verification_isolation_receipts
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  isolation_receipt_id,declaration_id,producer_principal,oracle_principal,
                  producer_service_revision,oracle_service_revision,producer_process_boot_id,
                  oracle_process_boot_id,producer_provider_request_id,oracle_provider_request_id,
                  producer_context_hash,oracle_context_hash,producer_policy_hash,
                  oracle_policy_hash,producer_evidence_partitions,oracle_evidence_partitions,
                  attested_by,receipt_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(isolation_receipt_id)s,%(declaration_id)s,
                       %(producer_principal)s,%(oracle_principal)s,%(producer_service_revision)s,
                       %(oracle_service_revision)s,%(producer_process_boot_id)s,
                       %(oracle_process_boot_id)s,%(producer_provider_request_id)s,
                       %(oracle_provider_request_id)s,%(producer_context_hash)s,
                       %(oracle_context_hash)s,%(producer_policy_hash)s,%(oracle_policy_hash)s,
                       %(producer_evidence_partitions)s,%(oracle_evidence_partitions)s,
                       %(attested_by)s,%(receipt_hash)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                **values,
            },
        )

    def record_falsification(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        falsification_id: str,
        declaration_id: str,
        isolation_receipt_id: str,
        oracle_kind: str,
        timing_class: str,
        evidence_ref: str,
        observed_at: datetime,
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_quality.recovery_falsifications
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  falsification_id,declaration_id,isolation_receipt_id,oracle_kind,
                  timing_class,evidence_ref,observed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(falsification_id)s,%(declaration_id)s,
                       %(isolation_receipt_id)s,%(oracle_kind)s,%(timing_class)s,
                       %(evidence_ref)s,%(observed_at)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "falsification_id": falsification_id,
                "declaration_id": declaration_id,
                "isolation_receipt_id": isolation_receipt_id,
                "oracle_kind": oracle_kind,
                "timing_class": timing_class,
                "evidence_ref": evidence_ref,
                "observed_at": observed_at,
            },
        )

    def approve_catalog(self, *, catalog_version: int, principal: str) -> None:
        self._connection.execute(
            "SELECT solvan_quality.quality_approve_catalog(%(catalog_version)s,%(principal)s)",
            {"catalog_version": catalog_version, "principal": principal},
        )

    def build_population(
        self, *, scope: Scope, cell_id: str, placement_epoch: int, population_id: str
    ) -> None:
        self._connection.execute(
            "SELECT solvan_quality.quality_build_population(%(organization_id)s,%(project_id)s,"
            "%(environment_id)s,%(cell_id)s,%(placement_epoch)s,%(population_id)s)",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "population_id": population_id,
            },
        )

    def publish_receipt(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        population_id: str,
        receipt_id: str,
    ) -> None:
        self._connection.execute(
            "SELECT solvan_quality.quality_publish_receipt(%(organization_id)s,%(project_id)s,"
            "%(environment_id)s,%(cell_id)s,%(placement_epoch)s,%(population_id)s,%(receipt_id)s)",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "population_id": population_id,
                "receipt_id": receipt_id,
            },
        )

    def derive_competence(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        action_class: str,
        quality_receipt_id: str,
        competence_receipt_id: str,
    ) -> None:
        self._connection.execute(
            "SELECT solvan_quality.quality_derive_competence(%(organization_id)s,%(project_id)s,"
            "%(environment_id)s,%(cell_id)s,%(placement_epoch)s,%(action_class)s,"
            "%(quality_receipt_id)s,%(competence_receipt_id)s)",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "action_class": action_class,
                "quality_receipt_id": quality_receipt_id,
                "competence_receipt_id": competence_receipt_id,
            },
        )
