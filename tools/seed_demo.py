"""Seed the isolated payments fault-drill policy from a measured calibration receipt.

Plan-only is the default. Applying requires the migration-admin connection and
refuses thresholds that do not strictly separate healthy and fault samples.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import psycopg
from psycopg import Connection
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.domain import Scope
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from tools.workspace_fixture import (
    REGRESSION_COMMAND_DEFINITION_ID,
    REPRODUCTION_COMMAND_DEFINITION_ID,
    repository_policy,
    upload_repository_snapshot,
)

SERVICE_ID = "svc_00000000000000000000000001"
GRAPH_ID = "pgs_00000000000000000000000001"
SERVICE_NODE_ID = "pgn_00000000000000000000000001"
DEPLOYMENT_NODE_ID = "pgn_00000000000000000000000002"
DATABASE_NODE_ID = "pgn_00000000000000000000000003"
PROFILE_NODE_ID = "pgn_00000000000000000000000004"
REPOSITORY_NODE_ID = "pgn_00000000000000000000000005"
DEPLOYMENT_EDGE_ID = "pge_00000000000000000000000001"
DATABASE_EDGE_ID = "pge_00000000000000000000000002"
PROFILE_EDGE_ID = "pge_00000000000000000000000003"
REPOSITORY_EDGE_ID = "pge_00000000000000000000000004"
PROFILE_ID = "payments-availability-v1"
PREAUTH_ID = "payments-pool-recycle-v1"
ACTUATOR_CONNECTION_ID = "con_00000000000000000000000001"
ACTUATOR_ID = "atr_00000000000000000000000001"
INCIDENT_CLASS = "connection_exhaustion"


class SignalCalibration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal_kind: Literal["HTTP_5XX_RATIO", "HTTP_P95_LATENCY"]
    baseline_max: float = Field(ge=0)
    fault_min: float = Field(gt=0)
    detection_threshold: float = Field(gt=0)
    recovery_threshold: float = Field(gt=0)
    sustained_windows: int = Field(ge=1, le=6)
    sample_hashes: tuple[str, ...] = Field(min_length=4)

    @model_validator(mode="after")
    def separated(self) -> SignalCalibration:
        if not self.baseline_max < self.detection_threshold < self.fault_min:
            raise ValueError("detection threshold must strictly separate baseline and fault")
        if not self.baseline_max <= self.recovery_threshold < self.fault_min:
            raise ValueError("recovery threshold must preserve measured healthy/fault separation")
        if any(re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in self.sample_hashes):
            raise ValueError("calibration samples require sha256 hashes")
        return self


class CalibrationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    release_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
    region: Literal["europe-west1"]
    payments_service_name: str = Field(pattern=r"^[a-z][a-z0-9-]{2,62}$")
    known_good_revision: str = Field(pattern=r"^[a-z][a-z0-9-]{2,62}$")
    fault_revision: str = Field(pattern=r"^[a-z][a-z0-9-]{2,62}$")
    cloud_sql_database_id: str = Field(min_length=1, max_length=200)
    evidence_ref: str
    approved_by: str = Field(min_length=3, max_length=300)
    approved_at: datetime
    signals: tuple[SignalCalibration, ...]

    @model_validator(mode="after")
    def exact_signals(self) -> CalibrationReceipt:
        if not self.evidence_ref.startswith("gs://"):
            raise ValueError("calibration receipt must be stored in durable GCS evidence")
        if self.approved_at.tzinfo is None or self.approved_at.utcoffset() is None:
            raise ValueError("calibration approval time must be timezone-aware")
        if self.known_good_revision == self.fault_revision:
            raise ValueError("known-good and fault revisions must be distinct")
        expected_sql = f"{self.project_id}:{self.region}:"
        sql_instance = self.cloud_sql_database_id.removeprefix(expected_sql)
        if not self.cloud_sql_database_id.startswith(expected_sql) or not sql_instance:
            raise ValueError(
                "Cloud SQL connection name must match the calibrated project and region"
            )
        kinds = {item.signal_kind for item in self.signals}
        if kinds != {"HTTP_5XX_RATIO", "HTTP_P95_LATENCY"} or len(self.signals) != 2:
            raise ValueError("exactly one 5xx and one p95 calibration are required")
        return self

    def signal(self, kind: str) -> SignalCalibration:
        return next(item for item in self.signals if item.signal_kind == kind)


def load_receipt(path: Path) -> tuple[CalibrationReceipt, str]:
    return parse_receipt_bytes(path.read_bytes())


def parse_receipt_bytes(raw: bytes) -> tuple[CalibrationReceipt, str]:
    value = json.loads(raw)
    receipt = CalibrationReceipt.model_validate(value)
    return receipt, "sha256:" + hashlib.sha256(raw).hexdigest()


def apply_seed(
    connection: Connection[Any],
    *,
    scope: Scope,
    receipt: CalibrationReceipt,
    receipt_hash: str,
    repository_policy: dict[str, Any],
    actuator_principal_email: str = "actuator@customer.example",
    actuator_expected_audience: str = "https://actuator.internal.solvan",
    actuator_image_digest: str = "sha256:" + "0" * 64,
) -> None:
    if set(repository_policy) != {
        "repository_binding_id",
        "repository_snapshot_uri",
        "repository_snapshot_hash",
        "base_commit_sha",
        "reproduction_command_definition_id",
        "regression_command_definition_id",
        "allowed_file_globs",
        "artifact_output_uri",
        "provider",
    }:
        raise ValueError("repository policy has an unsupported schema")
    ratio = receipt.signal("HTTP_5XX_RATIO")
    latency = receipt.signal("HTTP_P95_LATENCY")
    profile_signals = [
        {
            "signal_key": "http_5xx_ratio",
            "provider_signal_kind": "HTTP_5XX_RATIO",
            "comparator": "LTE",
            "threshold": ratio.recovery_threshold,
            "sustained_samples": ratio.sustained_windows,
        },
        {
            "signal_key": "http_p95_latency",
            "provider_signal_kind": "HTTP_P95_LATENCY",
            "comparator": "LTE",
            "threshold": latency.recovery_threshold,
            "sustained_samples": latency.sustained_windows,
        },
    ]
    profile_hash = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(profile_signals, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    scope_values = scope.canonical_dict()
    service_resource = (
        f"projects/{receipt.project_id}/locations/{receipt.region}/services/"
        f"{receipt.payments_service_name}"
    )
    cloud_sql_instance = receipt.cloud_sql_database_id.rsplit(":", 1)[-1]
    database_resource = f"projects/{receipt.project_id}/instances/{cloud_sql_instance}"
    deployment_target_key = (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        f"cloud-run/payments-api/deployment"
    )
    with connection.cursor() as cursor:
        seed_repair_command_authority(
            cursor,
            scope_values=scope_values,
            approved_by=receipt.approved_by,
            repository_policy=repository_policy,
        )
        cursor.execute(
            """INSERT INTO solvan.services
              (organization_id, project_id, environment_id, id, service_key,
               display_name, platform_kind, platform_resource, owner_department)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                %(service_id)s, 'payments-api', 'Payments API', 'CLOUD_RUN_SERVICE',
                %(platform_resource)s, 'Payments Reliability')
              ON CONFLICT DO NOTHING""",
            {
                **scope_values,
                "service_id": SERVICE_ID,
                "platform_resource": service_resource,
            },
        )
        cursor.execute(
            """INSERT INTO solvan.production_graph_snapshots
              (organization_id, project_id, environment_id, id, version, status,
               source_manifest_ref, content_hash, effective_at, approved_by, approved_at)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                %(graph_id)s, 1, 'APPROVED', %(receipt_ref)s, %(receipt_hash)s,
                %(approved_at)s, %(approved_by)s, %(approved_at)s)
              ON CONFLICT DO NOTHING""",
            {
                **scope_values,
                "graph_id": GRAPH_ID,
                "receipt_ref": receipt.evidence_ref,
                "receipt_hash": receipt_hash,
                "approved_at": receipt.approved_at,
                "approved_by": receipt.approved_by,
            },
        )
        nodes: tuple[tuple[str, str, str, str, dict[str, Any], str], ...] = (
            (
                SERVICE_NODE_ID,
                "service:payments-api",
                "SERVICE",
                service_resource,
                {},
                "INTERNAL",
            ),
            (
                DEPLOYMENT_NODE_ID,
                "deployment:payments-api",
                "DEPLOYMENT",
                service_resource,
                {
                    "service_id": SERVICE_ID,
                    "active_revision": receipt.fault_revision,
                    "known_good_revision": receipt.known_good_revision,
                    "target_key": deployment_target_key,
                },
                "INTERNAL",
            ),
            (
                DATABASE_NODE_ID,
                "database:payments-control",
                "DATABASE",
                database_resource,
                {},
                "INTERNAL",
            ),
            (
                PROFILE_NODE_ID,
                f"verification:{PROFILE_ID}",
                "VERIFICATION_PROFILE",
                PROFILE_ID,
                {},
                "INTERNAL",
            ),
            (
                REPOSITORY_NODE_ID,
                "repository:payments-public-synthetic",
                "REPOSITORY",
                str(repository_policy["repository_snapshot_uri"]),
                repository_policy,
                "PUBLIC",
            ),
        )
        for node_id, node_key, node_kind, resource_ref, attributes, classification in nodes:
            cursor.execute(
                """INSERT INTO solvan.production_graph_nodes
                  (organization_id, project_id, environment_id, id, snapshot_id,
                   node_key, node_kind, resource_ref, external_project_id, attributes_json,
                   classification, provenance_ref)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(node_id)s, %(graph_id)s, %(node_key)s, %(node_kind)s,
                    %(resource_ref)s, %(external_project_id)s, %(attributes)s, %(classification)s,
                    %(provenance_ref)s)
                  ON CONFLICT DO NOTHING""",
                {
                    **scope_values,
                    "node_id": node_id,
                    "graph_id": GRAPH_ID,
                    "node_key": node_key,
                    "node_kind": node_kind,
                    "resource_ref": resource_ref,
                    # Specification 13 §4.2: only the Google Cloud node kinds
                    # name a project. A REPOSITORY names a git snapshot and a
                    # VERIFICATION_PROFILE names a Solvan record; neither has
                    # one. The demo estate is a single project, but the column
                    # is per node so a second one needs no migration.
                    "external_project_id": (
                        receipt.project_id
                        if node_kind in ("SERVICE", "DEPLOYMENT", "DATABASE", "QUEUE")
                        else None
                    ),
                    "attributes": Jsonb(attributes),
                    "classification": classification,
                    "provenance_ref": (
                        str(repository_policy["repository_snapshot_uri"])
                        if node_kind == "REPOSITORY"
                        else receipt.evidence_ref
                    ),
                },
            )
        for edge_id, target, kind in (
            (DEPLOYMENT_EDGE_ID, DEPLOYMENT_NODE_ID, "DEPLOYED_AS"),
            (DATABASE_EDGE_ID, DATABASE_NODE_ID, "STORES_IN"),
            (PROFILE_EDGE_ID, PROFILE_NODE_ID, "VERIFIED_BY"),
            (REPOSITORY_EDGE_ID, REPOSITORY_NODE_ID, "IMPLEMENTED_BY"),
        ):
            cursor.execute(
                """INSERT INTO solvan.production_graph_edges
                  (organization_id, project_id, environment_id, id, snapshot_id,
                   source_node_id, target_node_id, edge_kind, provenance_ref)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(edge_id)s, %(graph_id)s, %(source)s, %(target)s, %(kind)s,
                    %(provenance_ref)s) ON CONFLICT DO NOTHING""",
                {
                    **scope_values,
                    "edge_id": edge_id,
                    "graph_id": GRAPH_ID,
                    "source": SERVICE_NODE_ID,
                    "target": target,
                    "kind": kind,
                    "provenance_ref": receipt.evidence_ref,
                },
            )
        for rule_id, signal, dedup in (
            ("payments-http-5xx-v1", ratio, "availability"),
            ("payments-p95-latency-v1", latency, "latency"),
        ):
            cursor.execute(
                """INSERT INTO solvan.detection_rules
                  (organization_id, project_id, environment_id, id, version,
                   service_id, incident_class, signal_kind, query_json,
                   evaluation_interval_ms, comparator, threshold, sustained_windows,
                   severity, deduplication_dimension, action_budget,
                   repeated_action_limit, status, calibration_receipt_ref,
                   approved_by, approved_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(rule_id)s, 1, %(service_id)s, %(incident_class)s,
                    %(signal_kind)s, %(query)s, 25000, 'GT', %(threshold)s,
                    %(sustained)s, 'SEV2', %(dedup)s, 2, 1, 'APPROVED',
                    %(receipt_ref)s, %(approved_by)s, %(approved_at)s)
                  ON CONFLICT DO NOTHING""",
                {
                    **scope_values,
                    "rule_id": rule_id,
                    "service_id": SERVICE_ID,
                    "incident_class": INCIDENT_CLASS,
                    "signal_kind": signal.signal_kind,
                    "query": Jsonb(
                        {
                            "gcp_project_id": receipt.project_id,
                            "resource_name": receipt.payments_service_name,
                            "window_ms": 60_000,
                            # The Alert predicate compiler accepts this marker
                            # only on the exact approved S1 rule. It is not
                            # inferred from an environment name or model text.
                            "synthetic_fixture": True,
                        }
                    ),
                    "threshold": signal.detection_threshold,
                    "sustained": signal.sustained_windows,
                    "dedup": dedup,
                    "receipt_ref": receipt.evidence_ref,
                    "approved_by": receipt.approved_by,
                    "approved_at": receipt.approved_at,
                },
            )
        _seed_governance(
            cursor,
            scope_values=scope_values,
            receipt=receipt,
            profile_signals=profile_signals,
            profile_hash=profile_hash,
            deployment_target_key=deployment_target_key,
            actuator_principal_email=actuator_principal_email,
            actuator_expected_audience=actuator_expected_audience,
            actuator_image_digest=actuator_image_digest,
        )
        _verify_seed(
            cursor,
            scope_values=scope_values,
            receipt=receipt,
            service_resource=service_resource,
            database_resource=database_resource,
            deployment_target_key=deployment_target_key,
            repository_policy=repository_policy,
        )


def seed_repair_command_authority(
    cursor: Any,
    *,
    scope_values: dict[str, str],
    approved_by: str,
    repository_policy: dict[str, Any],
) -> None:
    """Register the fixture repository and literal no-egress commands.

    Even the public-synthetic drill uses the production authority shape. The
    production-graph node refers to these identifiers; it never embeds a shell
    command that later becomes executable by being copied into a plan.
    """

    cursor.execute(
        """INSERT INTO solvan.github_repositories
          (organization_id,project_id,environment_id,id,installation_id,owner,name,
           default_branch,api_base_url,classification,credential_secret_ref,
           webhook_secret_ref,policy_hash,allowed_operations_json,status,
           last_probe_at,last_probe_result,created_by_principal)
          VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
            %(repository_binding_id)s,1,'solvan-fixtures','payments-leak','main',
            'https://api.github.com','PUBLIC',
            'projects/solvan-test/secrets/github-app-key/versions/1',
            'projects/solvan-test/secrets/github-webhook/versions/1',
            %(policy_hash)s,'["SYNC_PULL_REQUEST"]'::jsonb,'ACTIVE',now(),
            'SUCCEEDED',%(approved_by)s) ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "repository_binding_id": repository_policy["repository_binding_id"],
            "policy_hash": "sha256:" + hashlib.sha256(b"fixture-github-policy-v1").hexdigest(),
            "approved_by": approved_by,
        },
    )
    definitions = (
        (
            REPRODUCTION_COMMAND_DEFINITION_ID,
            "REPRODUCTION",
            ["python", "-m", "unittest", "-q", "tests.test_payments"],
        ),
        (
            REGRESSION_COMMAND_DEFINITION_ID,
            "REGRESSION",
            ["python", "-m", "unittest", "-q", "tests.test_payments"],
        ),
    )
    for definition_id, command_kind, argv in definitions:
        declared_inputs = list(repository_policy["allowed_file_globs"])
        declared_outputs: list[str] = []
        material = {
            "repository_binding_id": repository_policy["repository_binding_id"],
            "command_kind": command_kind,
            "argv": argv,
            "working_directory": ".",
            "declared_inputs": declared_inputs,
            "declared_outputs": declared_outputs,
            "limits": {
                "timeout_ms": 30_000,
                "cpu_millis": 1_000,
                "memory_mib": 256,
                "output_byte_limit": 65_536,
            },
            "network_mode": "NONE",
        }
        command_hash = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        cursor.execute(
            """INSERT INTO solvan_delivery.repair_plan_command_definitions
              (organization_id,project_id,environment_id,id,repository_binding_id,
               command_hash,command_kind,argv_json,working_directory,
               declared_inputs_hash,declared_outputs_hash,timeout_ms,cpu_millis,
               memory_mib,output_byte_limit,network_mode,catalog_hash,lifecycle,
               approved_ref,declared_inputs_json,declared_outputs_json)
              VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                %(definition_id)s,%(repository_binding_id)s,%(command_hash)s,
                %(command_kind)s,%(argv)s,'.',%(inputs_hash)s,%(outputs_hash)s,
                30000,1000,256,65536,'NONE',%(catalog_hash)s,'APPROVED',
                'fixture://approved-repair-command',%(declared_inputs)s,
                %(declared_outputs)s) ON CONFLICT DO NOTHING""",
            {
                **scope_values,
                "definition_id": definition_id,
                "repository_binding_id": repository_policy["repository_binding_id"],
                "command_hash": command_hash,
                "command_kind": command_kind,
                "argv": Jsonb(argv),
                "inputs_hash": "sha256:"
                + hashlib.sha256(
                    json.dumps(declared_inputs, separators=(",", ":")).encode()
                ).hexdigest(),
                "outputs_hash": "sha256:"
                + hashlib.sha256(
                    json.dumps(declared_outputs, separators=(",", ":")).encode()
                ).hexdigest(),
                "declared_inputs": Jsonb(declared_inputs),
                "declared_outputs": Jsonb(declared_outputs),
                "catalog_hash": "sha256:"
                + hashlib.sha256((command_hash + ":catalog-v1").encode()).hexdigest(),
            },
        )


def _seed_governance(
    cursor: Any,
    *,
    scope_values: dict[str, str],
    receipt: CalibrationReceipt,
    profile_signals: list[dict[str, object]],
    profile_hash: str,
    deployment_target_key: str,
    actuator_principal_email: str,
    actuator_expected_audience: str,
    actuator_image_digest: str,
) -> None:
    confirmation = {
        "normalized_cause_key": "payments-connection-pool-exhaustion",
        "statement": "The defective payments revision exhausted its bounded SQL pool.",
        "all_required": [
            {
                "source_kind": "CLOUD_LOGGING",
                "tool_name": "cloud_logging_query",
                "argument_equals": {
                    "signature_key": "connection-exhaustion",
                    "log_view_id": "payments-errors",
                },
            },
            {
                "source_kind": "CLOUD_RUN",
                "tool_name": "cloud_run_read",
                "argument_equals": {"service_id": SERVICE_ID},
            },
        ],
    }
    cursor.execute(
        """INSERT INTO solvan.confirmation_rules
          (organization_id, project_id, environment_id, id, version, incident_class,
           required_observations_json, contradiction_policy, status, approved_by, approved_at)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            'rollback-correlation-v1', 1, %(incident_class)s, %(observations)s,
            'ESCALATE', 'APPROVED', %(approved_by)s, %(approved_at)s)
          ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "incident_class": INCIDENT_CLASS,
            "observations": Jsonb(confirmation),
            "approved_by": receipt.approved_by,
            "approved_at": receipt.approved_at,
        },
    )
    cursor.execute(
        """INSERT INTO solvan.verification_profiles
          (organization_id, project_id, environment_id, id, version, status,
           owner, warmup_ms, observation_ms, required_signals_json,
           guardrails_json, inconclusive_policy, content_hash, approved_by, approved_at)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            %(profile_id)s, 1, 'APPROVED', 'Payments Reliability', 30000, 120000,
            %(signals)s, %(guardrails)s, 'ESCALATE', %(profile_hash)s,
            %(approved_by)s, %(approved_at)s) ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "profile_id": PROFILE_ID,
            "signals": Jsonb(profile_signals),
            "guardrails": Jsonb({"synthetic_payment": {"amount_minor": 100, "required": True}}),
            "profile_hash": profile_hash,
            "approved_by": receipt.approved_by,
            "approved_at": receipt.approved_at,
        },
    )
    cursor.execute(
        """INSERT INTO solvan.verification_profile_bindings
          (organization_id, project_id, environment_id,
           production_graph_snapshot_id, service_id, incident_class,
           profile_id, profile_version, effective_at, policy_owner)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            %(graph_id)s, %(service_id)s, %(incident_class)s, %(profile_id)s,
            1, %(approved_at)s, 'Payments Reliability') ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "graph_id": GRAPH_ID,
            "service_id": SERVICE_ID,
            "incident_class": INCIDENT_CLASS,
            "profile_id": PROFILE_ID,
            "approved_at": receipt.approved_at,
        },
    )
    cursor.execute(
        """INSERT INTO solvan.standing_preauthorizations
          (organization_id, project_id, environment_id, id, version, action_type,
           service_id, incident_class, maximum_risk_class, payload_constraints_json,
           maximum_attempts, cooldown_ms, valid_from, valid_until, status,
           approved_by, approved_at)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            %(preauth_id)s, 1, 'PAYMENTS_POOL_RECYCLE', %(service_id)s,
            %(incident_class)s, 'MEDIUM', %(payload)s, 1, 600000,
            %(valid_from)s, %(valid_from)s + interval '30 days', 'APPROVED',
            %(approved_by)s, %(valid_from)s) ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "preauth_id": PREAUTH_ID,
            "service_id": SERVICE_ID,
            "incident_class": INCIDENT_CLASS,
            "payload": Jsonb({"admin_operation": "RECYCLE_DB_POOL", "drain_timeout_ms": 5_000}),
            "valid_from": receipt.approved_at,
            "approved_by": receipt.approved_by,
        },
    )
    target_key = (
        f"{scope_values['organization_id']}/{scope_values['project_id']}/"
        f"{scope_values['environment_id']}/payments-admin/payments-api/connection-pool"
    )
    cursor.execute(
        """INSERT INTO solvan.target_epochs
          (organization_id, project_id, environment_id, target_key, epoch,
           last_observed_version) VALUES (%(organization_id)s, %(project_id)s,
            %(environment_id)s, %(target_key)s, 0, 'pool-generation-1')
          ON CONFLICT DO NOTHING""",
        {**scope_values, "target_key": target_key},
    )
    cursor.execute(
        """INSERT INTO solvan.target_epochs
          (organization_id, project_id, environment_id, target_key, epoch,
           last_observed_version) VALUES (%(organization_id)s, %(project_id)s,
            %(environment_id)s, %(target_key)s, 0, %(known_good_revision)s)
          ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "target_key": deployment_target_key,
            "known_good_revision": receipt.known_good_revision,
        },
    )
    actuator_policy_hash = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                {
                    "action_type": "PAYMENTS_POOL_RECYCLE",
                    "maximum_attempts": 1,
                    "payload": {
                        "admin_operation": "RECYCLE_DB_POOL",
                        "drain_timeout_ms": 5_000,
                    },
                    "scope": scope_values,
                    "target_key": target_key,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )
    cursor.execute(
        """INSERT INTO solvan.tenant_connections
          (organization_id, project_id, environment_id, id, display_name,
           kind, provider, credential_posture, residency_region,
           classification, lifecycle, availability, availability_reason_code,
           availability_explanation, availability_remediation_kind,
           availability_receipt_ref, last_probe_at,
           last_probe_result, last_success_at, created_by_principal)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            %(connection_id)s, 'Competition customer actuator', 'COLLECTOR',
            'SOLVAN_ACTUATOR', 'CUSTOMER_SIDE_NONE', %(region)s, 'INTERNAL',
            'ENABLED', 'READY', NULL, NULL, NULL, 'probe://seed',
            now(), 'SUCCEEDED', now(), %(approved_by)s)
          ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "connection_id": ACTUATOR_CONNECTION_ID,
            "region": receipt.region,
            "approved_by": receipt.approved_by,
        },
    )
    cursor.execute(
        """INSERT INTO solvan.actuator_registrations
          (organization_id, project_id, environment_id, id, connection_id,
           host_kind, production_eligible, principal_email, expected_audience,
           posture, image_digest, actuator_version, policy_hash,
           policy_source_ref, customer_audit_sink_ref, status,
           registered_by_principal)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            %(actuator_id)s, %(connection_id)s, 'CLOUD_RUN', true,
            %(principal_email)s, %(expected_audience)s, 'REMEDIATE',
            %(image_digest)s, 'competition-v1', %(policy_hash)s,
            %(policy_source_ref)s, %(audit_sink)s, 'ACTIVE', %(approved_by)s)
          ON CONFLICT DO NOTHING""",
        {
            **scope_values,
            "actuator_id": ACTUATOR_ID,
            "connection_id": ACTUATOR_CONNECTION_ID,
            "principal_email": actuator_principal_email,
            "expected_audience": actuator_expected_audience,
            "image_digest": actuator_image_digest,
            "policy_hash": actuator_policy_hash,
            "policy_source_ref": receipt.evidence_ref,
            "audit_sink": f"projects/{receipt.project_id}/logs/solvan-actuator-audit",
            "approved_by": receipt.approved_by,
        },
    )


def _verify_seed(
    cursor: Any,
    *,
    scope_values: dict[str, str],
    receipt: CalibrationReceipt,
    service_resource: str,
    database_resource: str,
    deployment_target_key: str,
    repository_policy: dict[str, Any],
) -> None:
    cursor.execute(
        """SELECT id, signal_kind, threshold FROM solvan.detection_rules
          WHERE organization_id = %(organization_id)s AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s AND status = 'APPROVED'
          ORDER BY id""",
        scope_values,
    )
    actual = [(str(row[0]), str(row[1]), float(row[2])) for row in cursor.fetchall()]
    expected = sorted(
        [
            (
                "payments-http-5xx-v1",
                "HTTP_5XX_RATIO",
                receipt.signal("HTTP_5XX_RATIO").detection_threshold,
            ),
            (
                "payments-p95-latency-v1",
                "HTTP_P95_LATENCY",
                receipt.signal("HTTP_P95_LATENCY").detection_threshold,
            ),
        ]
    )
    if actual != expected:
        raise RuntimeError("existing approved detection policy conflicts with calibration receipt")
    cursor.execute(
        """SELECT node_kind, resource_ref, attributes_json
          FROM solvan.production_graph_nodes
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND snapshot_id = %(graph_id)s
            AND node_kind IN ('DEPLOYMENT', 'DATABASE')
          ORDER BY node_kind""",
        {**scope_values, "graph_id": GRAPH_ID},
    )
    graph_rows = cursor.fetchall()
    expected_graph = [
        ("DATABASE", database_resource, {}),
        (
            "DEPLOYMENT",
            service_resource,
            {
                "service_id": SERVICE_ID,
                "active_revision": receipt.fault_revision,
                "known_good_revision": receipt.known_good_revision,
                "target_key": deployment_target_key,
            },
        ),
    ]
    if [(str(row[0]), str(row[1]), row[2]) for row in graph_rows] != expected_graph:
        raise RuntimeError("existing Production Graph conflicts with calibrated release revisions")
    cursor.execute(
        """SELECT resource_ref, attributes_json, classification
          FROM solvan.production_graph_nodes
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND snapshot_id = %(graph_id)s AND node_kind = 'REPOSITORY'""",
        {**scope_values, "graph_id": GRAPH_ID},
    )
    repository = cursor.fetchall()
    if repository != [
        (
            repository_policy["repository_snapshot_uri"],
            repository_policy,
            "PUBLIC",
        )
    ]:
        raise RuntimeError("existing repository policy conflicts with the public fixture")
    cursor.execute(
        """SELECT target_key, last_observed_version FROM solvan.target_epochs
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND target_key = %(target_key)s""",
        {**scope_values, "target_key": deployment_target_key},
    )
    target = cursor.fetchone()
    if target is None or (str(target[0]), str(target[1])) != (
        deployment_target_key,
        receipt.known_good_revision,
    ):
        raise RuntimeError("existing deployment epoch conflicts with calibrated fault revision")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calibration-receipt", required=True, type=Path)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--scope-project-id", required=True)
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--runtime-bucket", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument(
        "--actuator-principal-email",
        default=os.environ.get("SOLVAN_ACTUATOR_PRINCIPAL_EMAIL", "actuator@customer.example"),
    )
    parser.add_argument(
        "--actuator-expected-audience",
        default=os.environ.get(
            "SOLVAN_ACTUATOR_EXPECTED_AUDIENCE", "https://actuator.internal.solvan"
        ),
    )
    parser.add_argument(
        "--actuator-image-digest",
        default=os.environ.get("SOLVAN_ACTUATOR_IMAGE_DIGEST", "sha256:" + "0" * 64),
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    receipt, receipt_hash = load_receipt(args.calibration_receipt)
    scope = Scope(args.organization_id, args.scope_project_id, args.environment_id)
    if not args.apply:
        print(
            json.dumps(
                {
                    "status": "PLAN_ONLY",
                    "scope": scope.canonical_dict(),
                    "calibration_receipt_hash": receipt_hash,
                    "approved_rules": ["payments-http-5xx-v1", "payments-p95-latency-v1"],
                    "verification_profile": PROFILE_ID,
                    "standing_preauthorization": PREAUTH_ID,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    database_url = os.environ.get("SOLVAN_MIGRATION_DATABASE_URL")
    if not database_url:
        raise RuntimeError("SOLVAN_MIGRATION_DATABASE_URL is required with --apply")
    with psycopg.connect(database_url) as connection, connection.transaction():
        snapshot_receipt = upload_repository_snapshot(
            writer=GcsEvidenceWriter(
                bucket=args.runtime_bucket,
                session=authorized_session(),
            ),
            scope=scope,
            release_commit=args.release_commit,
        )
        apply_seed(
            connection,
            scope=scope,
            receipt=receipt,
            receipt_hash=receipt_hash,
            repository_policy=repository_policy(
                receipt=snapshot_receipt,
                release_commit=args.release_commit,
                runtime_bucket=args.runtime_bucket,
                scope=scope,
            ),
            actuator_principal_email=args.actuator_principal_email,
            actuator_expected_audience=args.actuator_expected_audience,
            actuator_image_digest=args.actuator_image_digest,
        )
    print("APPLIED_UNVERIFIED: calibrated immutable fault-drill policy seeded; run preflight next")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
