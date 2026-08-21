"""Cloud-only release fixture and deterministic oracle job operations.

These operations run as identities that are deliberately outside Agent Runtime.
The injector can change only the isolated payments fixture; the oracle is
read-only. Neither operation accepts a model-authored resource or query.
"""

from __future__ import annotations

import hashlib
import os
import time
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import quote

import httpx
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.id_token import fetch_id_token

from solvan.domain import Scope
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import GoogleRestSession, authorized_session
from tools.seed_demo import CalibrationReceipt, parse_receipt_bytes


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value or value == "UNCONFIGURED":
        raise RuntimeError(f"required scenario setting {name} is missing")
    return value


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _read_calibration(session: GoogleRestSession) -> CalibrationReceipt:
    uri = _required("SOLVAN_CALIBRATION_RECEIPT_URI")
    if not uri.startswith("gs://") or "/" not in uri.removeprefix("gs://"):
        raise RuntimeError("calibration receipt is not a complete GCS URI")
    bucket, object_name = uri.removeprefix("gs://").split("/", 1)
    response = session.get(
        "https://storage.googleapis.com/storage/v1/b/"
        f"{quote(bucket, safe='')}/o/{quote(object_name, safe='')}?alt=media",
        timeout=30,
    )
    response.raise_for_status()
    receipt, actual_hash = parse_receipt_bytes(response.content)
    expected_hash = _required("SOLVAN_CALIBRATION_RECEIPT_HASH")
    if actual_hash != expected_hash:
        raise RuntimeError("calibration receipt changed after release approval")
    if (
        receipt.project_id != _required("SOLVAN_GCP_PROJECT")
        or receipt.region != _required("SOLVAN_GCP_REGION")
        or receipt.release_commit != _required("SOLVAN_RELEASE_COMMIT")
    ):
        raise RuntimeError("calibration receipt is not bound to this release")
    return receipt


def _single_revision(service: dict[str, Any]) -> str:
    statuses = service.get("trafficStatuses")
    if not isinstance(statuses, list):
        raise RuntimeError("Cloud Run returned no traffic status")
    active = [
        str(item.get("revision"))
        for item in statuses
        if isinstance(item, dict)
        and item.get("type") == "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"
        and item.get("percent") == 100
        and isinstance(item.get("revision"), str)
    ]
    if len(active) != 1:
        raise RuntimeError("payments traffic is not one exact 100-percent revision")
    return active[0]


def _cloud_run_service(session: GoogleRestSession, receipt: CalibrationReceipt) -> dict[str, Any]:
    resource = (
        f"projects/{receipt.project_id}/locations/{receipt.region}/services/"
        f"{receipt.payments_service_name}"
    )
    response = session.get(f"https://run.googleapis.com/v2/{resource}", timeout=30)
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict) or value.get("name") != resource:
        raise RuntimeError("Cloud Run returned another payments resource")
    return cast(dict[str, Any], value)


def _shift_revision(
    session: GoogleRestSession,
    receipt: CalibrationReceipt,
    *,
    target_revision: str,
) -> tuple[str, str]:
    if target_revision not in {receipt.known_good_revision, receipt.fault_revision}:
        raise RuntimeError("requested traffic target is outside the calibration receipt")
    before = _cloud_run_service(session, receipt)
    before_revision = _single_revision(before)
    if before_revision not in {receipt.known_good_revision, receipt.fault_revision}:
        raise RuntimeError("payments is not on an approved calibration revision")
    if before_revision != target_revision:
        etag = before.get("etag")
        if not isinstance(etag, str) or not etag:
            raise RuntimeError("Cloud Run service has no concurrency etag")
        response = session.patch(
            f"https://run.googleapis.com/v2/{before['name']}?updateMask=traffic",
            json={
                "name": before["name"],
                "etag": etag,
                "traffic": [
                    {
                        "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                        "revision": target_revision,
                        "percent": 100,
                    }
                ],
            },
            timeout=30,
        )
        response.raise_for_status()
    after_revision = ""
    for _attempt in range(24):
        after_revision = _single_revision(_cloud_run_service(session, receipt))
        if after_revision == target_revision:
            break
        time.sleep(5)
    if after_revision != target_revision:
        raise RuntimeError("requested revision did not become the sole traffic target")
    return before_revision, after_revision


def _shift_to_fault(session: GoogleRestSession, receipt: CalibrationReceipt) -> tuple[str, str]:
    return _shift_revision(session, receipt, target_revision=receipt.fault_revision)


def _record_fault_epoch(receipt: CalibrationReceipt) -> tuple[int, int]:
    scope = _scope()
    target_key = (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        "cloud-run/payments-api/deployment"
    )
    scope_values = (
        scope.organization_id,
        scope.project_id,
        scope.environment_id,
    )
    with connect_database() as connection, connection.transaction():
        row = connection.execute(
            """SELECT epoch, last_observed_version FROM solvan.target_epochs
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND target_key = %s FOR UPDATE""",
            (*scope_values, target_key),
        ).fetchone()
        if row is None:
            raise RuntimeError("deployment target epoch is not seeded")
        before_epoch, before_revision = int(row[0]), str(row[1])
        if before_revision == receipt.known_good_revision:
            updated = connection.execute(
                """UPDATE solvan.target_epochs
                  SET epoch = epoch + 1, last_observed_version = %s, updated_at = now()
                  WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                    AND target_key = %s AND epoch = %s AND last_observed_version = %s
                  RETURNING epoch""",
                (
                    receipt.fault_revision,
                    *scope_values,
                    target_key,
                    before_epoch,
                    receipt.known_good_revision,
                ),
            ).fetchone()
            if updated is None:
                raise RuntimeError("deployment target epoch changed during injection")
            return before_epoch, int(updated[0])
        if before_revision == receipt.fault_revision:
            return before_epoch, before_epoch
        raise RuntimeError("deployment target epoch contains an unapproved revision")


def _restore_known_good_epoch(receipt: CalibrationReceipt) -> tuple[int, int]:
    scope = _scope()
    target_key = (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        "cloud-run/payments-api/deployment"
    )
    scope_values = (scope.organization_id, scope.project_id, scope.environment_id)
    with connect_database() as connection, connection.transaction():
        row = connection.execute(
            """SELECT epoch, last_observed_version FROM solvan.target_epochs
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND target_key = %s FOR UPDATE""",
            (*scope_values, target_key),
        ).fetchone()
        if row is None:
            raise RuntimeError("deployment target epoch is not seeded")
        before_epoch, before_revision = int(row[0]), str(row[1])
        if before_revision == receipt.known_good_revision:
            return before_epoch, before_epoch
        if before_revision != receipt.fault_revision:
            raise RuntimeError("deployment target epoch contains an unapproved revision")
        updated = connection.execute(
            """UPDATE solvan.target_epochs
              SET epoch = epoch + 1, last_observed_version = %s, updated_at = now()
              WHERE organization_id = %s AND project_id = %s AND environment_id = %s
                AND target_key = %s AND epoch = %s AND last_observed_version = %s
              RETURNING epoch""",
            (
                receipt.known_good_revision,
                *scope_values,
                target_key,
                before_epoch,
                receipt.fault_revision,
            ),
        ).fetchone()
        if updated is None:
            raise RuntimeError("deployment target epoch changed during compensation")
        return before_epoch, int(updated[0])


def _identity_token(audience: str) -> str:
    return str(fetch_id_token(GoogleRequest(), audience))  # type: ignore[no-untyped-call]


def _synthetic_fault_load(receipt: CalibrationReceipt) -> dict[str, Any]:
    base_url = _required("SOLVAN_PAYMENTS_URL").rstrip("/")
    token = _identity_token(base_url)
    run_key = hashlib.sha256(
        f"{_required('SOLVAN_DEPLOYMENT_ID')}:{datetime.now(UTC).isoformat()}".encode()
    ).hexdigest()[:20]
    statuses: list[int] = []
    trace_ids: list[str] = []
    with httpx.Client(timeout=10) as client:
        for index in range(12):
            response = client.post(
                f"{base_url}/v1/synthetic/payments",
                headers={
                    "authorization": f"Bearer {token}",
                    "idempotency-key": f"fixture-{run_key}-{index:02d}",
                },
                json={
                    "schema_version": 1,
                    "payment_id": f"fixture-{run_key}-{index:02d}",
                    "amount_minor": 100,
                },
            )
            statuses.append(response.status_code)
            trace_id = response.headers.get("x-solvan-trace-id")
            if trace_id:
                trace_ids.append(trace_id)
    if statuses.count(503) < 4 or not any(status < 400 for status in statuses):
        raise RuntimeError("fault load did not produce the calibrated partial success/exhaustion")
    return {
        "request_count": len(statuses),
        "success_count": sum(status < 400 for status in statuses),
        "unavailable_count": statuses.count(503),
        "status_histogram": {
            str(status): statuses.count(status) for status in sorted(set(statuses))
        },
        "trace_ids": sorted(set(trace_ids)),
    }


def inject_s1() -> bool:
    """Shift to the measured fault, fence its target epoch, and run real traffic."""

    session = authorized_session()
    receipt = _read_calibration(session)
    started_at = datetime.now(UTC)
    object_name = _required("SOLVAN_SCENARIO_OBJECT_NAME")
    writer = GcsEvidenceWriter(bucket=_required("SOLVAN_EVIDENCE_BUCKET"), session=session)
    before_revision: str | None = None
    after_revision: str | None = None
    before_epoch: int | None = None
    after_epoch: int | None = None
    try:
        before_revision, after_revision = _shift_to_fault(session, receipt)
        before_epoch, after_epoch = _record_fault_epoch(receipt)
        load = _synthetic_fault_load(receipt)
    except Exception as error:
        compensation_errors: list[str] = []
        try:
            _shift_revision(session, receipt, target_revision=receipt.known_good_revision)
        except Exception as compensation_error:
            compensation_errors.append(f"traffic:{type(compensation_error).__name__}")
        try:
            _restore_known_good_epoch(receipt)
        except Exception as compensation_error:
            compensation_errors.append(f"epoch:{type(compensation_error).__name__}")
        failure = {
            "schema_version": 1,
            "kind": "SOLVAN_S1_FAULT_INJECTION_FAILED",
            "project_id": receipt.project_id,
            "release_commit": receipt.release_commit,
            "deployment_id": _required("SOLVAN_DEPLOYMENT_ID"),
            "injector_identity": _required("SOLVAN_INJECTOR_IDENTITY"),
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "error_class": type(error).__name__,
            "compensation_status": (
                "SUCCEEDED" if not compensation_errors else "REQUIRES_OPERATOR_RECONCILIATION"
            ),
            "compensation_errors": compensation_errors,
            "observed_before_revision": before_revision,
            "observed_after_revision": after_revision,
            "observed_target_epoch_before": before_epoch,
            "observed_target_epoch_after": after_epoch,
            "agent_visible": False,
        }
        written = writer.put_json(object_name=object_name, value=failure)
        raise RuntimeError(f"S1 injection failed; durable receipt: {written.uri}") from error
    document = {
        "schema_version": 1,
        "kind": "SOLVAN_S1_FAULT_INJECTION",
        "project_id": receipt.project_id,
        "release_commit": receipt.release_commit,
        "deployment_id": _required("SOLVAN_DEPLOYMENT_ID"),
        "fixture_version": "competition-release-v1",
        "injector_identity": _required("SOLVAN_INJECTOR_IDENTITY"),
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "service_name": receipt.payments_service_name,
        "before_revision": before_revision,
        "fault_revision": after_revision,
        "target_epoch_before": before_epoch,
        "target_epoch_after": after_epoch,
        "synthetic_load": load,
        "agent_visible": False,
    }
    written = writer.put_json(object_name=object_name, value=document)
    print(f"S1_FAULT_INJECTED:{written.uri}")
    return True


def cleanup_demo() -> bool:
    """Restore the sole approved known-good revision and its fenced target epoch."""

    session = authorized_session()
    receipt = _read_calibration(session)
    started_at = datetime.now(UTC)
    before_revision, after_revision = _shift_revision(
        session, receipt, target_revision=receipt.known_good_revision
    )
    before_epoch, after_epoch = _restore_known_good_epoch(receipt)
    observed_revision = _single_revision(_cloud_run_service(session, receipt))
    passed = observed_revision == receipt.known_good_revision
    document = {
        "schema_version": 1,
        "kind": "SOLVAN_DEMO_CLEANUP",
        "status": "RESTORED" if passed else "FAILED",
        "project_id": receipt.project_id,
        "release_commit": receipt.release_commit,
        "deployment_id": _required("SOLVAN_DEPLOYMENT_ID"),
        "injector_identity": _required("SOLVAN_INJECTOR_IDENTITY"),
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "before_revision": before_revision,
        "after_revision": after_revision,
        "observed_revision": observed_revision,
        "known_good_revision": receipt.known_good_revision,
        "target_epoch_before": before_epoch,
        "target_epoch_after": after_epoch,
        "agent_visible": False,
    }
    written = GcsEvidenceWriter(
        bucket=_required("SOLVAN_EVIDENCE_BUCKET"), session=session
    ).put_json(object_name=_required("SOLVAN_SCENARIO_OBJECT_NAME"), value=document)
    print(f"DEMO_CLEANUP_WRITTEN:{written.uri}")
    return passed
