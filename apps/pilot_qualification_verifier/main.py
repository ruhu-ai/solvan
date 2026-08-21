"""Independent direct-GCP pilot qualification verifier process.

It intentionally has no producer-facing route. Qualification execution is a
separately scheduled/internal command once immutable deployment, ingress,
triage, and operator-continuation evidence have been recorded. This process is
kept distinct from the action verifier so neither service can confirm its own
work.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Response, status
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field

from solvan.domain import Scope, new_identifier
from solvan.observability import instrument_fastapi
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.relay_signing import GoogleKmsSigner
from solvan.platform.service_identity import ServiceIdentityError, verify_service_caller


class QualificationCommand(BaseModel):
    """A request names existing evidence only; it cannot supply evidence."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    source_binding_id: str = Field(pattern=r"^asb_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    source_binding_epoch: int = Field(ge=1)


class QualificationResult(BaseModel):
    receipt_id: str
    receipt_hash: str
    expires_at: datetime


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"{name} is not configured")
    return value


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _authorize(authorization: str | None) -> None:
    try:
        caller = verify_service_caller(
            authorization, audience_variable="SOLVAN_PILOT_QUALIFICATION_AUDIENCE"
        )
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
    expected = _required("SOLVAN_PILOT_QUALIFICATION_CALLER")
    if caller.email != expected:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not the scoped control-plane API")


def _deployment() -> dict[str, str]:
    """Deployment evidence is injected by Terraform; missing values never qualify."""

    return {
        "control_project_id": _required("SOLVAN_GCP_PROJECT"),
        "region": _required("SOLVAN_REGION"),
        "source_commit": _required("SOLVAN_RELEASE_COMMIT"),
        "alert_ingress_revision": _required("SOLVAN_ALERT_INGRESS_REVISION"),
        "api_revision": _required("SOLVAN_API_REVISION"),
        "coordinator_revision": _required("SOLVAN_COORDINATOR_REVISION"),
        "qualification_verifier_revision": _required("K_REVISION"),
    }


def _validate_receipt(value: dict[str, Any]) -> None:
    """The persisted object must conform to the reviewed public receipt contract."""

    artifact = (
        Path(__file__).resolve().parents[2]
        / "specs/artifacts/direct-gcp-pilot-qualification-receipt.schema.json"
    )
    try:
        schema = json.loads(artifact.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(value)
    except OSError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "qualification receipt schema is unavailable"
        ) from error
    except ValidationError as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "recomputed qualification material does not satisfy its contract",
        ) from error


def _evidence(*, scope: Scope, command: QualificationCommand) -> dict[str, Any]:
    """Recompute all positive predicates from durable, independently-readable rows."""

    values = {**scope.canonical_dict(), **command.model_dump()}
    with connect_database() as connection, connection.cursor() as cursor:
        cursor.execute(
            """SELECT c.connection_epoch,c.authentication_mode,c.solvan_delegator_principal,
                      c.customer_reader_principal,c.delegation_condition_digest,
                      c.availability_receipt_ref,b.binding_epoch,b.configuration_digest,
                      b.subscription_name,b.push_service_account,b.oidc_audience,
                      b.qualification_delivery_id,q.envelope_hash
                 FROM solvan.tenant_connections c
                 JOIN solvan_alerts.alert_source_bindings b
                   ON (b.organization_id,b.project_id,b.environment_id,b.connection_id)=
                      (c.organization_id,c.project_id,c.environment_id,c.id)
                 JOIN solvan_alerts.alert_source_qualification_deliveries q
                   ON (q.organization_id,q.project_id,q.environment_id,q.id)=
                      (b.organization_id,b.project_id,b.environment_id,b.qualification_delivery_id)
                WHERE c.organization_id=%(organization_id)s AND c.project_id=%(project_id)s
                  AND c.environment_id=%(environment_id)s AND c.id=%(connection_id)s
                  AND b.id=%(source_binding_id)s AND b.binding_epoch=%(source_binding_epoch)s
                  AND b.connection_epoch=c.connection_epoch
                  AND c.lifecycle='ENABLED' AND c.availability='READY'
                  AND b.status='QUALIFIED'
                  AND c.authentication_mode='GCP_SERVICE_ACCOUNT_IMPERSONATION'""",
            values,
        )
        binding = cursor.fetchone()
        if binding is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "qualification prerequisites are not current"
            )
        cursor.execute(
            """SELECT delivery.id,run.id,request.id,request.actor_principal
                 FROM solvan_alerts.alert_ingress_deliveries delivery
                 JOIN solvan_alerts.alert_events event
                   ON (event.organization_id,event.project_id,event.environment_id,event.id)=
                      (delivery.organization_id,delivery.project_id,delivery.environment_id,delivery.semantic_event_id)
                 JOIN solvan_alerts.alert_provider_generations generation
                   ON (generation.organization_id,generation.project_id,generation.environment_id,
                       generation.provider_source_identity_id,generation.provider_incident_key)=
                      (event.organization_id,event.project_id,event.environment_id,
                       event.provider_source_identity_id,event.provider_incident_key)
                 JOIN solvan_alerts.alert_episodes episode
                   ON (episode.organization_id,episode.project_id,episode.environment_id,
                       episode.provider_generation_id)=
                      (generation.organization_id,generation.project_id,generation.environment_id,generation.id)
                 JOIN solvan_alerts.alert_triage_runs run
                   ON (run.organization_id,run.project_id,run.environment_id,run.episode_id)=
                      (episode.organization_id,episode.project_id,episode.environment_id,episode.id)
                 JOIN solvan_alerts.alert_operator_requests request
                   ON (request.organization_id,request.project_id,request.environment_id,
                       request.episode_id)=
                      (episode.organization_id,episode.project_id,episode.environment_id,episode.id)
                WHERE delivery.organization_id=%(organization_id)s
                  AND delivery.project_id=%(project_id)s
                  AND delivery.environment_id=%(environment_id)s
                  AND delivery.connection_id=%(connection_id)s
                  AND delivery.connection_epoch=%(connection_epoch)s
                  AND delivery.provider_source_identity_id=%(source_identity_id)s
                  AND delivery.outcome='COMMITTED' AND run.status='SUCCEEDED'
                  AND episode.current_disposition IN ('TRIAGED_HOLD','MANUAL_REVIEW')
                  AND request.request_kind='INCIDENT_CONTINUATION' AND request.outcome='ACCEPTED'
                ORDER BY request.created_at DESC, request.id DESC LIMIT 1""",
            {
                **values,
                "connection_epoch": binding[0],
                "source_identity_id": _source_identity(cursor, values),
            },
        )
        demonstration = cursor.fetchone()
    if demonstration is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "no complete read-only triage and continuation evidence exists",
        )
    return {"binding": binding, "demonstration": demonstration}


def _source_identity(cursor: Any, values: dict[str, Any]) -> str:
    cursor.execute(
        """SELECT source_identity_id FROM solvan_alerts.alert_source_bindings
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(source_binding_id)s""",
        values,
    )
    row = cursor.fetchone()
    if row is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "source binding disappeared during qualification"
        )
    return str(row[0])


def _current_receipt(*, scope: Scope, command: QualificationCommand) -> QualificationResult | None:
    """Return the one still-current receipt for this immutable source epoch.

    Qualification is evidence publication, not a command with a new effect on
    every click. Reusing the signed receipt avoids duplicate KMS signatures and
    prevents a retry from making two equally-current deployment claims.
    """

    with connect_database() as connection, connection.cursor() as cursor:
        cursor.execute(
            """SELECT id,receipt_hash,expires_at
                 FROM solvan_alerts.direct_gcp_pilot_qualification_receipts
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND source_binding_id=%(source_binding_id)s
                  AND source_binding_epoch=%(source_binding_epoch)s
                  AND superseded_at IS NULL AND expires_at > now()
                ORDER BY issued_at DESC LIMIT 1""",
            {**scope.canonical_dict(), **command.model_dump()},
        )
        row = cursor.fetchone()
    if row is None:
        return None
    return QualificationResult(receipt_id=str(row[0]), receipt_hash=str(row[1]), expires_at=row[2])


def _issue(*, scope: Scope, command: QualificationCommand) -> QualificationResult:
    # PostgreSQL advisory locking is deliberately held on a dedicated session
    # across independent recomputation, signing, object publication and the
    # durable receipt insert. The unique target-schema index remains the final
    # guard should an operator bypass this verifier with a second revision.
    lock_key = ":".join(
        (
            "direct-gcp-pilot-qualification",
            scope.organization_id,
            scope.project_id,
            scope.environment_id,
            command.source_binding_id,
            str(command.source_binding_epoch),
        )
    )
    with connect_database() as lock_connection:
        lock_connection.execute("SELECT pg_advisory_lock(hashtext(%s))", (lock_key,))
        try:
            existing = _current_receipt(scope=scope, command=command)
            if existing is not None:
                return existing
            return _issue_locked(scope=scope, command=command)
        finally:
            lock_connection.execute("SELECT pg_advisory_unlock(hashtext(%s))", (lock_key,))


def _issue_locked(*, scope: Scope, command: QualificationCommand) -> QualificationResult:
    """Issue once while the caller holds the source-epoch advisory lock."""

    proof = _evidence(scope=scope, command=command)
    binding = proof["binding"]
    delivery_id, triage_run_id, continuation_id, operator_principal = proof["demonstration"]
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(days=7)
    receipt_id = new_identifier("pgq")
    verifier_principal = (
        f"serviceAccount:{_required('SOLVAN_PILOT_QUALIFICATION_VERIFIER_SERVICE_ACCOUNT')}"
    )
    key_version = _required("SOLVAN_PILOT_QUALIFICATION_KMS_KEY_VERSION")
    unsigned = {
        "schema_version": 1,
        "kind": "SOLVAN_DIRECT_GCP_PILOT_QUALIFICATION",
        "receipt_id": receipt_id,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "deployment": _deployment(),
        "direct_connection": {
            "connection_id": command.connection_id,
            "connection_epoch": int(binding[0]),
            "authentication_mode": binding[1],
            "solvan_delegator_principal": binding[2],
            "customer_reader_principal": binding[3],
            "delegation_condition_digest": binding[4],
            "capability_receipt_ref": binding[5],
        },
        "alert_source": {
            "source_binding_id": command.source_binding_id,
            "source_binding_epoch": command.source_binding_epoch,
            "configuration_digest": binding[7],
            "subscription": binding[8],
            "push_service_account": binding[9],
            "oidc_audience": binding[10],
            "qualification_delivery_ref": f"sql://alert-source-qualification-deliveries/{binding[11]}",
        },
        "results": {
            "delegation_verified": True,
            "ingress_isolation_verified": True,
            "authenticated_delivery_verified": True,
            "read_only_triage_verified": True,
            "operator_continuation_verified": True,
        },
        "manual_continuation": {
            "operator_principal_ref": f"principal://{operator_principal}",
            "continuation_receipt_ref": f"sql://alert-operator-requests/{continuation_id}",
        },
    }
    canonical_unsigned = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    signature = GoogleKmsSigner().sign_sha256(
        hashlib.sha256(canonical_unsigned).digest(), key_version=key_version
    )
    signature_digest = f"sha256:{hashlib.sha256(signature).hexdigest()}"
    writer = GcsEvidenceWriter(
        bucket=_required("SOLVAN_PILOT_QUALIFICATION_RECEIPT_BUCKET"), session=authorized_session()
    )
    signature_receipt = writer.put_bytes(
        object_name=f"direct-gcp-pilot/{receipt_id}/signature.der",
        content=signature,
        content_type="application/octet-stream",
    )
    verifier_revision = _deployment()["qualification_verifier_revision"]
    receipt = {
        **unsigned,
        "independent_verification": {
            "verifier_principal": verifier_principal,
            "verifier_revision": verifier_revision,
            "kms_key_version": key_version,
            "signature_digest": signature_digest,
            "evidence_refs": [
                signature_receipt.uri,
                f"sql://alert-ingress-deliveries/{delivery_id}",
                f"sql://alert-triage-runs/{triage_run_id}",
                f"sql://alert-operator-requests/{continuation_id}",
            ],
        },
    }
    _validate_receipt(receipt)
    object_receipt = writer.put_json(
        object_name=f"direct-gcp-pilot/{receipt_id}/receipt.json", value=receipt
    )
    with connect_database() as connection, connection.transaction(), connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan_alerts.direct_gcp_pilot_qualification_receipts
                (organization_id,project_id,environment_id,id,receipt_hash,source_binding_id,
                 source_binding_epoch,connection_id,connection_epoch,verifier_principal,
                 verifier_revision,kms_key_version,signature_digest,immutable_object_ref,issued_at,expires_at)
                VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                        %(receipt_hash)s,
                        %(source_binding_id)s,%(source_binding_epoch)s,%(connection_id)s,
                        %(connection_epoch)s,%(verifier_principal)s,%(verifier_revision)s,
                        %(kms_key_version)s,%(signature_digest)s,%(immutable_object_ref)s,
                        %(issued_at)s,%(expires_at)s)""",
            {
                **scope.canonical_dict(),
                "id": receipt_id,
                "receipt_hash": object_receipt.content_hash,
                "source_binding_id": command.source_binding_id,
                "source_binding_epoch": command.source_binding_epoch,
                "connection_id": command.connection_id,
                "connection_epoch": int(binding[0]),
                "verifier_principal": verifier_principal,
                "verifier_revision": verifier_revision,
                "kms_key_version": key_version,
                "signature_digest": signature_digest,
                "immutable_object_ref": object_receipt.uri,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )
    return QualificationResult(
        receipt_id=receipt_id, receipt_hash=object_receipt.content_hash, expires_at=expires_at
    )


app = FastAPI(
    title="Solvan Direct GCP Pilot Qualification Verifier",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
instrument_fastapi(app, service_name="solvan-pilot-qualification-verifier")


@app.get("/healthz", include_in_schema=False)
def healthz() -> Response:
    """Liveness only; it never asserts qualification."""

    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})


@app.post("/internal/v1/direct-gcp-pilot:qualify", response_model=QualificationResult)
def qualify(
    command: QualificationCommand, authorization: str | None = Header(default=None)
) -> QualificationResult:
    _authorize(authorization)
    return _issue(scope=_scope(), command=command)
