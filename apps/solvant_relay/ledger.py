"""Encrypted, bounded local attempt ledger for an outbound-only Relay."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from solvan.domain import require_digest


class RelayLedgerError(RuntimeError):
    """The local Relay ledger cannot safely accept or settle an attempt."""


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """Content-free state; encrypted evidence bytes are kept in a sibling file."""

    collection_job_id: str
    attempt_id: str
    attempt_number: int
    job_digest: str
    claim_token: str
    process_boot_id: str
    state: str
    input_hash: str
    outcome_hash: str | None
    local_result_hash: str | None
    created_at: datetime
    updated_at: datetime
    terminal_at: datetime | None = None
    acknowledged_at: datetime | None = None

    def __post_init__(self) -> None:
        for value, prefix in ((self.collection_job_id, "rcj_"), (self.attempt_id, "rat_")):
            if not value.startswith(prefix) or len(value) != 30:
                raise RelayLedgerError("attempt record identifier is invalid")
        if not 1 <= self.attempt_number <= 2:
            raise RelayLedgerError("attempt number is outside the closed bound")
        require_digest(self.job_digest, field="job_digest")
        require_digest(self.input_hash, field="input_hash")
        if self.outcome_hash is not None:
            require_digest(self.outcome_hash, field="outcome_hash")
        if self.local_result_hash is not None:
            require_digest(self.local_result_hash, field="local_result_hash")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise RelayLedgerError("attempt record timestamps must be timezone-aware")
        if self.updated_at < self.created_at:
            raise RelayLedgerError("attempt record update precedes creation")


class EncryptedAttemptLedger:
    """An atomically-written, capacity-bounded local ledger.

    The caller supplies a customer-managed 32-byte key. The ledger never stores
    policy bytes, credential references, provider errors, or plaintext evidence
    in its index. Evidence, when present, is encrypted under the same key and
    addressed only by its verified local result hash.
    """

    def __init__(self, *, directory: Path, key: bytes, max_records: int = 256) -> None:
        if len(key) != 32:
            raise RelayLedgerError("local attempt ledger key must be exactly 32 bytes")
        if not 1 <= max_records <= 4096:
            raise RelayLedgerError("local attempt ledger capacity is outside the closed bound")
        self._directory = directory
        self._key = key
        self._max_records = max_records
        self._index = directory / "attempts.json"

    def upsert(self, record: AttemptRecord, *, result_bytes: bytes | None = None) -> None:
        rows = self._load()
        existing = rows.get(record.attempt_id)
        if existing is None and len(rows) >= self._max_records:
            raise RelayLedgerError("local attempt ledger is full; refusing a new claim")
        if existing is not None:
            prior = self._record(existing)
            if (
                prior.collection_job_id != record.collection_job_id
                or prior.job_digest != record.job_digest
                or prior.claim_token != record.claim_token
            ):
                raise RelayLedgerError("attempt identifier is already bound to different authority")
        if result_bytes is not None:
            if not record.local_result_hash:
                raise RelayLedgerError("encrypted result requires a local result hash")
            self._write_result(record.attempt_id, result_bytes)
        rows[record.attempt_id] = self._encode(record)
        self._write(rows)

    def read_result(self, attempt_id: str) -> bytes | None:
        path = self._result_path(attempt_id)
        if not path.exists():
            return None
        try:
            raw = base64.b64decode(path.read_bytes(), validate=True)
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(self._key).decrypt(nonce, ciphertext, attempt_id.encode("ascii"))
        except Exception as error:
            raise RelayLedgerError("local attempt result cannot be decrypted") from error

    def pending_reconciliation(self, *, now: datetime) -> tuple[AttemptRecord, ...]:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return tuple(
            record
            for record in (self._record(value) for value in self._load().values())
            if record.acknowledged_at is None
            and (
                record.terminal_at is None
                or now.astimezone(UTC) - record.terminal_at <= timedelta(days=7)
            )
        )

    def purge(self, *, now: datetime, legal_hold: bool) -> int:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        if legal_hold:
            return 0
        rows = self._load()
        removed = 0
        for attempt_id, value in tuple(rows.items()):
            record = self._record(value)
            cutoff = record.acknowledged_at or record.updated_at
            window = timedelta(hours=24) if record.acknowledged_at else timedelta(days=7)
            if now.astimezone(UTC) - cutoff >= window:
                rows.pop(attempt_id)
                self._result_path(attempt_id).unlink(missing_ok=True)
                removed += 1
        if removed:
            self._write(rows)
        return removed

    def acknowledge(self, record: AttemptRecord, *, at: datetime) -> None:
        """Mark only a committed terminal control-plane outcome as acknowledged."""

        if at.tzinfo is None:
            raise ValueError("acknowledgement time must be timezone-aware")
        self.upsert(
            replace(
                record,
                state="ACKNOWLEDGED",
                terminal_at=record.terminal_at or at.astimezone(UTC),
                acknowledged_at=at.astimezone(UTC),
                updated_at=at.astimezone(UTC),
            )
        )

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self._index.exists():
            return {}
        try:
            value = json.loads(self._index.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RelayLedgerError("local attempt ledger index cannot be read") from error
        if not isinstance(value, dict) or any(not isinstance(row, dict) for row in value.values()):
            raise RelayLedgerError("local attempt ledger index is malformed")
        return value

    def _write(self, rows: dict[str, dict[str, Any]]) -> None:
        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self._index.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(rows, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(self._index)

    def _write_result(self, attempt_id: str, result_bytes: bytes) -> None:
        if not result_bytes or len(result_bytes) > 1_048_576:
            raise RelayLedgerError("local result bytes are outside the closed bound")
        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        nonce = os.urandom(12)
        encrypted = nonce + AESGCM(self._key).encrypt(
            nonce, result_bytes, attempt_id.encode("ascii")
        )
        temporary = self._result_path(attempt_id).with_suffix(".tmp")
        temporary.write_bytes(base64.b64encode(encrypted))
        os.chmod(temporary, 0o600)
        temporary.replace(self._result_path(attempt_id))

    def _result_path(self, attempt_id: str) -> Path:
        if not attempt_id.startswith("rat_") or len(attempt_id) != 30:
            raise RelayLedgerError("attempt identifier is invalid")
        return self._directory / f"{attempt_id}.bin"

    @staticmethod
    def _encode(record: AttemptRecord) -> dict[str, Any]:
        value = asdict(record)
        for field in ("created_at", "updated_at", "terminal_at", "acknowledged_at"):
            current = value[field]
            value[field] = current.isoformat() if current is not None else None
        return value

    @staticmethod
    def _record(value: dict[str, Any]) -> AttemptRecord:
        fields = dict(value)
        for field in ("created_at", "updated_at", "terminal_at", "acknowledged_at"):
            current = fields[field]
            fields[field] = datetime.fromisoformat(current) if current is not None else None
        return AttemptRecord(**fields)
