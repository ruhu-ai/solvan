"""One bounded, customer-local Relay collection attempt.

This module deliberately owns no HTTP listener, SQL connection, mutation
connector, or generic request surface. It consumes a signed job from the
control plane and may execute only a closed, policy-approved read operation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from apps.solvant_relay.ledger import AttemptRecord, EncryptedAttemptLedger
from apps.solvant_relay.policy import RelayPolicy, RelayPolicyError
from apps.solvant_relay.redaction import RedactionError, evidence_envelope
from solvan.domain import canonical_digest, require_digest


class RelayRuntimeError(RuntimeError):
    """A Relay attempt cannot safely start, upload, or settle."""


class RelayControl(Protocol):
    def claim(
        self, *, collection_job_id: str, job_digest: str, process_boot_id: str
    ) -> Mapping[str, Any]: ...

    def upload_grant(
        self, *, collection_job_id: str, body: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def receipt(self, *, collection_job_id: str, body: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def retryable_outcome(
        self, *, collection_job_id: str, body: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def status(self, *, collection_job_id: str) -> Mapping[str, Any]: ...


class ObjectUploader(Protocol):
    def upload(
        self,
        *,
        url: str,
        content: bytes,
        content_type: str,
        required_headers: Mapping[str, str],
    ) -> Mapping[str, str]: ...


class RelayReadAdapter(Protocol):
    def read(
        self,
        *,
        adapter: Mapping[str, Any],
        parameters: Mapping[str, Any],
        maximum_pages: int,
        maximum_items: int,
        maximum_bytes: int,
        maximum_calls: int,
    ) -> Sequence[Mapping[str, Any]]: ...


class JobVerifier(Protocol):
    """Verifies the control-plane signature before any local policy or provider use."""

    def verify(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class RelayJob:
    collection_job_id: str
    job_digest: str
    adapter_key: str
    adapter_revision: str
    source_connection_id: str
    source_connection_epoch: int
    operation: str
    typed_parameters: Mapping[str, Any]
    parameters_hash: str
    resource_binding_id: str
    resource_binding_hash: str
    window_start: datetime | None
    window_end: datetime | None
    maximum_pages: int
    maximum_items: int
    maximum_bytes: int
    maximum_calls: int
    maximum_attempts: int
    redaction_revision: str
    classification_ceiling: str
    residency_region: str
    input_hash: str

    @classmethod
    def from_envelope(cls, value: Mapping[str, Any]) -> RelayJob:
        job = value.get("job")
        if not isinstance(job, Mapping):
            raise RelayRuntimeError("control-plane poll response has no job envelope")
        known = {
            "schema_version",
            "canonicalization_version",
            "scope_hash",
            "collection_job_id",
            "enrollment_id",
            "enrollment_epoch",
            "relay_connection_id",
            "relay_connection_epoch",
            "source_binding_id",
            "job_digest",
            "adapter_key",
            "adapter_revision",
            "source_connection_id",
            "source_connection_epoch",
            "placement_epoch",
            "cell_id",
            "agent_run_id",
            "tool_call_id",
            "tool_arguments_hash",
            "incident_id",
            "profile_key",
            "profile_version",
            "profile_material_hash",
            "profile_ordinal",
            "tool_key",
            "tool_version",
            "capability_receipt_id",
            "capability_receipt_hash",
            "connector_catalog_key",
            "connector_catalog_revision",
            "connector_catalog_digest",
            "operation",
            "typed_parameters",
            "parameters_hash",
            "resource_binding_id",
            "graph_snapshot_id",
            "resource_binding_hash",
            "window_start",
            "window_end",
            "maximum_pages",
            "maximum_items",
            "maximum_bytes",
            "maximum_calls",
            "maximum_attempts",
            "redaction_revision",
            "classification_ceiling",
            "residency_region",
            "input_hash",
            "issued_at",
            "expires_at",
            "job_nonce",
            "signing_key_id",
        }
        if set(job) != known:
            raise RelayRuntimeError("control-plane job envelope has unrecognized or missing fields")
        typed_parameters = job["typed_parameters"]
        if not isinstance(typed_parameters, Mapping):
            raise RelayRuntimeError("control-plane job parameters are malformed")
        parsed = cls(
            collection_job_id=str(job["collection_job_id"]),
            job_digest=str(job["job_digest"]),
            adapter_key=str(job["adapter_key"]),
            adapter_revision=str(job["adapter_revision"]),
            source_connection_id=str(job["source_connection_id"]),
            source_connection_epoch=int(job["source_connection_epoch"]),
            operation=str(job["operation"]),
            typed_parameters=dict(typed_parameters),
            parameters_hash=str(job["parameters_hash"]),
            resource_binding_id=str(job["resource_binding_id"]),
            resource_binding_hash=str(job["resource_binding_hash"]),
            window_start=_optional_time(job["window_start"], field="window_start"),
            window_end=_optional_time(job["window_end"], field="window_end"),
            maximum_pages=int(job["maximum_pages"]),
            maximum_items=int(job["maximum_items"]),
            maximum_bytes=int(job["maximum_bytes"]),
            maximum_calls=int(job["maximum_calls"]),
            maximum_attempts=int(job["maximum_attempts"]),
            redaction_revision=str(job["redaction_revision"]),
            classification_ceiling=str(job["classification_ceiling"]),
            residency_region=str(job["residency_region"]),
            input_hash=str(job["input_hash"]),
        )
        for digest, field in (
            (parsed.job_digest, "job_digest"),
            (parsed.resource_binding_hash, "resource_binding_hash"),
            (parsed.parameters_hash, "parameters_hash"),
            (parsed.input_hash, "input_hash"),
        ):
            require_digest(digest, field=field)
        if canonical_digest(parsed.typed_parameters) != parsed.parameters_hash:
            raise RelayRuntimeError("job parameter hash does not bind typed parameters")
        if job["schema_version"] != 1 or job["canonicalization_version"] != 1:
            raise RelayRuntimeError("customer Relay only accepts collection job schema v1")
        supported_operations = {
            "monitoring.time-series.read.v1": "cloud-monitoring.v1",
            "prometheus.registered-range.read.v1": "managed-prometheus.v1",
            "logging.entries.read.v1": "cloud-logging.v1",
            "trace.spans.read.v1": "cloud-trace.v1",
            "kubernetes.metadata.list.v1": "kubernetes-metadata.v1",
        }
        if supported_operations.get(parsed.operation) != parsed.adapter_key:
            raise RelayRuntimeError("customer Relay has no adapter for this operation")
        if (
            not 1 <= parsed.maximum_pages <= 20
            or not 1 <= parsed.maximum_items <= 1000
            or not 1 <= parsed.maximum_bytes <= 1_048_576
            or not 1 <= parsed.maximum_calls <= 20
            or not 1 <= parsed.maximum_attempts <= 2
        ):
            raise RelayRuntimeError("job bounds are outside the closed local limits")
        return parsed


@dataclass(slots=True)
class RelayAttemptRunner:
    control: RelayControl
    job_verifier: JobVerifier
    monitoring: RelayReadAdapter
    uploader: ObjectUploader
    ledger: EncryptedAttemptLedger
    process_boot_id: str
    adapters: Mapping[str, RelayReadAdapter] | None = None

    def execute(self, *, policy: RelayPolicy, envelope: Mapping[str, Any], now: datetime) -> str:
        """Run one read-only collection attempt and settle it through the control plane."""

        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        job = RelayJob.from_envelope(self.job_verifier.verify(envelope))
        if job.redaction_revision != policy.redaction_revision:
            raise RelayRuntimeError("job redaction revision is not the current local policy")
        if job.residency_region != policy.region:
            raise RelayRuntimeError("job residency region is not the local policy region")
        if _classification_rank(job.classification_ceiling) > _classification_rank(
            policy.classification_ceiling
        ):
            raise RelayRuntimeError("job classification exceeds the local policy ceiling")
        try:
            adapter = policy.adapter_for(
                adapter_key=job.adapter_key,
                source_connection_id=job.source_connection_id,
                source_connection_epoch=job.source_connection_epoch,
                operation=job.operation,
            )
        except RelayPolicyError as error:
            raise RelayRuntimeError("job is not authorized by current local policy") from error
        claim = self.control.claim(
            collection_job_id=job.collection_job_id,
            job_digest=job.job_digest,
            process_boot_id=self.process_boot_id,
        )
        claim_token = claim.get("claim_token")
        attempt_id = claim.get("attempt_id")
        attempt_number = claim.get("attempt_number")
        if (
            not isinstance(claim_token, str)
            or not isinstance(attempt_id, str)
            or not isinstance(attempt_number, int)
            or not 1 <= attempt_number <= job.maximum_attempts
        ):
            raise RelayRuntimeError("control-plane claim has no exact attempt binding")
        started = now.astimezone(UTC)
        self.ledger.upsert(
            AttemptRecord(
                collection_job_id=job.collection_job_id,
                attempt_id=attempt_id,
                attempt_number=attempt_number,
                job_digest=job.job_digest,
                claim_token=claim_token,
                process_boot_id=self.process_boot_id,
                state="STARTED",
                input_hash=job.input_hash,
                outcome_hash=None,
                local_result_hash=None,
                created_at=started,
                updated_at=started,
            )
        )
        try:
            reader = self._reader_for(job)
            records = reader.read(
                adapter=adapter,
                parameters=job.typed_parameters,
                maximum_pages=job.maximum_pages,
                maximum_items=job.maximum_items,
                maximum_bytes=job.maximum_bytes,
                maximum_calls=job.maximum_calls,
            )
            evidence, content_hash, manifest_hash = evidence_envelope(
                collection_job_id=job.collection_job_id,
                job_digest=job.job_digest,
                adapter_key=job.adapter_key,
                adapter_revision=job.adapter_revision,
                operation=job.operation,
                resource_binding_id=job.resource_binding_id,
                resource_binding_hash=job.resource_binding_hash,
                window_start=job.window_start,
                window_end=job.window_end,
                classification=job.classification_ceiling,
                residency_region=job.residency_region,
                redaction_revision=job.redaction_revision,
                records=records,
                observed_at=now,
            )
        except (RedactionError, RelayRuntimeError):
            raise
        except Exception as error:
            self._record_retryable_failure(
                job=job,
                attempt_id=attempt_id,
                attempt_number=attempt_number,
                claim_token=claim_token,
                now=now,
            )
            raise RelayRuntimeError(
                "Relay provider read failed; retry outcome was recorded"
            ) from error
        content = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
        local_result_hash = "sha256:" + hashlib.sha256(content).hexdigest()
        outcome_hash = canonical_digest(
            {"result": "SUCCEEDED", "content_hash": content_hash, "attempt_id": attempt_id}
        )
        stored_record = AttemptRecord(
            collection_job_id=job.collection_job_id,
            attempt_id=attempt_id,
            attempt_number=attempt_number,
            job_digest=job.job_digest,
            claim_token=claim_token,
            process_boot_id=self.process_boot_id,
            state="LOCAL_RESULT_STORED",
            input_hash=job.input_hash,
            outcome_hash=outcome_hash,
            local_result_hash=local_result_hash,
            created_at=started,
            updated_at=now.astimezone(UTC),
        )
        self.ledger.upsert(stored_record, result_bytes=content)
        grant = self.control.upload_grant(
            collection_job_id=job.collection_job_id,
            body={
                "schema_version": 1,
                "job_digest": job.job_digest,
                "claim_token": claim_token,
                "attempt_id": attempt_id,
                "attempt_number": attempt_number,
                "process_boot_id": self.process_boot_id,
                "attempt_outcome_hash": outcome_hash,
                "local_result_hash": local_result_hash,
                "content_hash": content_hash,
                "manifest_hash": manifest_hash,
                "redaction_manifest_hash": manifest_hash,
                "resource_binding_hash": job.resource_binding_hash,
                "classification": job.classification_ceiling,
                "residency_region": job.residency_region,
                "content_type": "application/json",
                "content_length": len(content),
            },
        )
        url = grant.get("put_url")
        headers = grant.get("required_headers")
        if not isinstance(url, str) or not isinstance(headers, Mapping):
            raise RelayRuntimeError("upload grant response is malformed")
        metadata = self.uploader.upload(
            url=url,
            content=content,
            content_type="application/json",
            required_headers={str(key): str(value) for key, value in headers.items()},
        )
        generation = metadata.get("object_generation")
        metadata_hash = metadata.get("object_metadata_hash")
        if generation is not None and not isinstance(generation, str):
            raise RelayRuntimeError("uploaded object generation is malformed")
        if metadata_hash is not None and not isinstance(metadata_hash, str):
            raise RelayRuntimeError("uploaded object metadata digest is malformed")
        evidence_projection: dict[str, object] = {
            "object_ref": grant.get("object_ref"),
            "content_hash": content_hash,
            "manifest_hash": manifest_hash,
            "redaction_manifest_hash": manifest_hash,
            "resource_binding_hash": job.resource_binding_hash,
            "classification": job.classification_ceiling,
            "residency_region": job.residency_region,
            "upload_grant_id": grant.get("upload_grant_id"),
            "upload_grant_digest": grant.get("upload_grant_digest"),
        }
        if generation is not None:
            evidence_projection["object_generation"] = generation
        if metadata_hash is not None:
            evidence_projection["object_metadata_hash"] = metadata_hash
        self.control.receipt(
            collection_job_id=job.collection_job_id,
            body={
                "schema_version": 1,
                "job_digest": job.job_digest,
                "claim_token": claim_token,
                "attempt_id": attempt_id,
                "attempt_number": attempt_number,
                "process_boot_id": self.process_boot_id,
                "input_hash": job.input_hash,
                "attempt_outcome_hash": outcome_hash,
                "local_result_hash": local_result_hash,
                "result": "SUCCEEDED",
                "error_class": None,
                "safe_measurements": {
                    "items": len(records),
                    "pages": 1,
                    "bytes": len(content),
                    "calls": 1,
                },
                "evidence": evidence_projection,
                "started_at": started.isoformat(),
                "completed_at": now.astimezone(UTC).isoformat(),
                "receipt_nonce": f"receipt:{attempt_id}",
            },
        )
        self.ledger.acknowledge(stored_record, at=now)
        return attempt_id

    def _reader_for(self, job: RelayJob) -> RelayReadAdapter:
        """Resolve only a compiled-in adapter; policy cannot load code or URLs."""

        if job.adapter_key == "cloud-monitoring.v1":
            return self.monitoring
        adapter = (self.adapters or {}).get(job.adapter_key)
        if adapter is None:
            raise RelayRuntimeError("customer Relay image has no compiled adapter for this job")
        return adapter

    def acknowledge_terminal_outcomes(self, *, now: datetime) -> int:
        """Retain local evidence until the control plane has a terminal receipt.

        This bounded recovery pass never replays a provider call or uploads
        evidence.  A later reconciliation command may resume a locally stored
        result; this pass merely frees customer-local retention after a status
        projection proves the workflow is terminal.
        """

        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        acknowledged = 0
        terminal_states = {"ACCEPTED", "REFUSED", "EXPIRED", "CANCELLED"}
        for record in self.ledger.pending_reconciliation(now=now):
            status = self.control.status(collection_job_id=record.collection_job_id)
            if (
                status.get("collection_job_id") != record.collection_job_id
                or status.get("job_digest") != record.job_digest
            ):
                raise RelayRuntimeError("control-plane reconciliation projection is malformed")
            if status.get("state") in terminal_states:
                self.ledger.acknowledge(record, at=now)
                acknowledged += 1
        return acknowledged

    def _record_retryable_failure(
        self,
        *,
        job: RelayJob,
        attempt_id: str,
        attempt_number: int,
        claim_token: str,
        now: datetime,
    ) -> None:
        completed = now.astimezone(UTC)
        outcome_hash = canonical_digest(
            {"result": "FAILED_RETRYABLE", "error_class": "UPSTREAM_UNAVAILABLE"}
        )
        self.control.retryable_outcome(
            collection_job_id=job.collection_job_id,
            body={
                "schema_version": 1,
                "job_digest": job.job_digest,
                "claim_token": claim_token,
                "attempt_id": attempt_id,
                "attempt_number": attempt_number,
                "process_boot_id": self.process_boot_id,
                "input_hash": job.input_hash,
                "attempt_outcome_hash": outcome_hash,
                "error_class": "UPSTREAM_UNAVAILABLE",
                "safe_measurements": {"items": 0, "pages": 0, "bytes": 0, "calls": 1},
                "started_at": completed.isoformat(),
                "completed_at": completed.isoformat(),
            },
        )


def _optional_time(value: object, *, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RelayRuntimeError(f"{field} is not an RFC-3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RelayRuntimeError(f"{field} is not an RFC-3339 timestamp") from error
    if parsed.tzinfo is None:
        raise RelayRuntimeError(f"{field} is not timezone-aware")
    return parsed.astimezone(UTC)


def _classification_rank(value: str) -> int:
    ranks = {"PUBLIC": 1, "INTERNAL": 2, "CONFIDENTIAL": 3, "RESTRICTED": 4}
    try:
        return ranks[value]
    except KeyError as error:
        raise RelayRuntimeError("classification is outside the closed vocabulary") from error
