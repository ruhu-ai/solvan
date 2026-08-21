"""Immutable connection authority for polling detection rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope


class DetectionConnectionBindingError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DetectionConnectionBinding:
    detection_rule_id: str
    detection_rule_version: int
    connection_id: str
    connection_epoch: int


class PostgresDetectionConnectionStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def bind(
        self,
        *,
        scope: Scope,
        detection_rule_id: str,
        detection_rule_version: int,
        connection_id: str,
        expected_connection_epoch: int,
        actor: str,
        decision_ref: str,
        idempotency_key: str,
        request_hash: str,
    ) -> DetectionConnectionBinding:
        parameters = {
            **scope.canonical_dict(),
            "detection_rule_id": detection_rule_id,
            "detection_rule_version": detection_rule_version,
            "connection_id": connection_id,
            "connection_epoch": expected_connection_epoch,
            "actor": actor,
            "decision_ref": decision_ref,
            "idempotency_key": idempotency_key,
            "request_hash": request_hash,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.status,r.signal_kind,r.query_json,c.provider,c.kind,
                          c.authentication_mode,c.connection_epoch,c.lifecycle,
                          c.availability,x.resource_kind,x.resource_id
                     FROM solvan.detection_rules r
                     JOIN solvan.tenant_connections c
                       ON (c.organization_id,c.project_id,c.environment_id,c.id)=
                          (r.organization_id,r.project_id,r.environment_id,%(connection_id)s)
                     JOIN solvan_onboarding.connection_external_resource_scopes x
                       ON (x.organization_id,x.project_id,x.environment_id,x.connection_id)=
                          (c.organization_id,c.project_id,c.environment_id,c.id)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s
                      AND r.environment_id=%(environment_id)s
                      AND r.id=%(detection_rule_id)s
                      AND r.version=%(detection_rule_version)s
                    FOR UPDATE OF r,c""",
                parameters,
            )
            row = cursor.fetchone()
            if row is None:
                raise DetectionConnectionBindingError("rule or connection is unavailable")
            expected = (
                "APPROVED",
                "CLOUD_MONITORING",
                "GCP_NATIVE",
                "GCP_SERVICE_ACCOUNT_IMPERSONATION",
                expected_connection_epoch,
                "ENABLED",
                "READY",
                "GCP_PROJECT",
            )
            observed = (
                row["status"],
                row["provider"],
                row["kind"],
                row["authentication_mode"],
                int(row["connection_epoch"]),
                row["lifecycle"],
                row["availability"],
                row["resource_kind"],
            )
            query = row["query_json"]
            if observed != expected or not isinstance(query, dict):
                raise DetectionConnectionBindingError(
                    "rule requires one current READY direct Cloud Monitoring connection"
                )
            if query.get("gcp_project_id") != row["resource_id"]:
                raise DetectionConnectionBindingError(
                    "rule project does not match the connection resource scope"
                )
            cursor.execute(
                """SELECT detection_rule_id,detection_rule_version,connection_id,
                          connection_epoch,request_hash
                     FROM solvan_onboarding.detection_rule_connection_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND detection_rule_id=%(detection_rule_id)s
                      AND detection_rule_version=%(detection_rule_version)s""",
                parameters,
            )
            existing = cursor.fetchone()
            if existing is not None:
                exact = (
                    str(existing["detection_rule_id"]),
                    int(existing["detection_rule_version"]),
                    str(existing["connection_id"]),
                    int(existing["connection_epoch"]),
                )
                requested = (
                    detection_rule_id,
                    detection_rule_version,
                    connection_id,
                    expected_connection_epoch,
                )
                if exact != requested or existing["request_hash"] != request_hash:
                    raise DetectionConnectionBindingError(
                        "detection rule already has different immutable connection material"
                    )
                return DetectionConnectionBinding(*exact)
            cursor.execute(
                """INSERT INTO solvan_onboarding.detection_rule_connection_bindings
                     (organization_id,project_id,environment_id,detection_rule_id,
                      detection_rule_version,connection_id,connection_epoch,
                      bound_by_principal,decision_ref,idempotency_key,request_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(detection_rule_id)s,%(detection_rule_version)s,%(connection_id)s,
                      %(connection_epoch)s,%(actor)s,%(decision_ref)s,
                      %(idempotency_key)s,%(request_hash)s)
                   ON CONFLICT DO NOTHING""",
                parameters,
            )
            cursor.execute(
                """SELECT detection_rule_id,detection_rule_version,connection_id,
                          connection_epoch,request_hash
                     FROM solvan_onboarding.detection_rule_connection_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND idempotency_key=%(idempotency_key)s""",
                parameters,
            )
            bound = cursor.fetchone()
        if bound is None or bound["request_hash"] != request_hash:
            raise DetectionConnectionBindingError("binding idempotency key was reused")
        exact = (
            str(bound["detection_rule_id"]),
            int(bound["detection_rule_version"]),
            str(bound["connection_id"]),
            int(bound["connection_epoch"]),
        )
        requested = (
            detection_rule_id,
            detection_rule_version,
            connection_id,
            expected_connection_epoch,
        )
        if exact != requested:
            raise DetectionConnectionBindingError("binding retry does not match stored material")
        return DetectionConnectionBinding(*exact)
