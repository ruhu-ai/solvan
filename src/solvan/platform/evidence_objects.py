"""Regional GCS object writer returning content-addressed evidence receipts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from solvan.platform.google_rest import GoogleRestSession


@dataclass(frozen=True, slots=True)
class ObjectReceipt:
    uri: str
    content_hash: str
    generation: str


class GcsEvidenceWriter:
    def __init__(self, *, bucket: str, session: GoogleRestSession) -> None:
        if not bucket or "/" in bucket:
            raise ValueError("evidence bucket must be a bucket name")
        self._bucket = bucket
        self._session = session

    def put_json(self, *, object_name: str, value: dict[str, Any]) -> ObjectReceipt:
        content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return self.put_bytes(
            object_name=object_name, content=content, content_type="application/json"
        )

    def put_bytes(
        self,
        *,
        object_name: str,
        content: bytes,
        content_type: str,
        allow_empty: bool = False,
    ) -> ObjectReceipt:
        if not object_name or object_name.startswith("/") or ".." in object_name.split("/"):
            raise ValueError("evidence object name is unsafe")
        if (not content and not allow_empty) or len(content) > 4_194_304:
            raise ValueError("evidence object bytes are empty or exceed the write ceiling")
        if not content_type or "\r" in content_type or "\n" in content_type:
            raise ValueError("evidence content type is invalid")
        digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        response = self._session.post(
            f"https://storage.googleapis.com/upload/storage/v1/b/{quote(self._bucket)}/o",
            params={"uploadType": "media", "name": object_name, "ifGenerationMatch": "0"},
            headers={"Content-Type": content_type},
            data=content,
            timeout=30,
        )
        if response.status_code == 412:
            metadata = self._session.get(
                "https://storage.googleapis.com/storage/v1/b/"
                f"{quote(self._bucket)}/o/{quote(object_name, safe='')}",
                timeout=30,
            )
            metadata.raise_for_status()
            existing = self._session.get(
                "https://storage.googleapis.com/storage/v1/b/"
                f"{quote(self._bucket)}/o/{quote(object_name, safe='')}?alt=media",
                timeout=30,
            )
            existing.raise_for_status()
            if existing.content != content:
                raise RuntimeError("existing evidence object content does not match retry")
            response = metadata
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("generation"), str):
            raise RuntimeError("Cloud Storage returned no object generation")
        return ObjectReceipt(
            uri=f"gs://{self._bucket}/{object_name}",
            content_hash=digest,
            generation=payload["generation"],
        )


class GcsEvidenceDeleter:
    """Generation-fenced deletion for retention workers.

    A 404 is treated as an idempotent, already-absent result.  Any other
    response is refused; callers must not mark the Cloud SQL retention row
    deleted without the returned provider receipt.
    """

    def __init__(self, *, allowed_buckets: frozenset[str], session: GoogleRestSession) -> None:
        if not allowed_buckets or any(not bucket or "/" in bucket for bucket in allowed_buckets):
            raise ValueError("at least one valid evidence bucket is required")
        self._allowed_buckets = allowed_buckets
        self._session = session

    def delete(self, *, uri: str, expected_generation: str | None = None) -> str:
        bucket, object_name = _parse_gcs_uri(uri)
        if bucket not in self._allowed_buckets:
            raise ValueError("evidence URI bucket is outside the approved boundary")
        params: dict[str, str] = {}
        if expected_generation is not None:
            if not expected_generation.isdigit():
                raise ValueError("object generation is invalid")
            params["ifGenerationMatch"] = expected_generation
        response = self._session.delete(
            f"https://storage.googleapis.com/storage/v1/b/{quote(bucket)}/o/"
            f"{quote(object_name, safe='')}",
            params=params,
            timeout=30,
        )
        if response.status_code not in (200, 204, 404):
            response.raise_for_status()
        return f"{uri}#deleted-status={response.status_code}"


class GcsEvidenceReader:
    """Read a bounded JSON object and verify its authoritative content hash."""

    def __init__(self, *, allowed_buckets: frozenset[str], session: GoogleRestSession) -> None:
        if not allowed_buckets or any(not bucket or "/" in bucket for bucket in allowed_buckets):
            raise ValueError("at least one valid evidence bucket is required")
        self._allowed_buckets = allowed_buckets
        self._session = session

    def get_json(
        self, *, uri: str, expected_hash: str, max_bytes: int = 1_048_576
    ) -> dict[str, Any]:
        content = self.get_bytes(uri=uri, expected_hash=expected_hash, max_bytes=max_bytes)
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError("evidence object must be a JSON object")
        return value

    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int = 1_048_576) -> bytes:
        bucket, object_name = _parse_gcs_uri(uri)
        if bucket not in self._allowed_buckets:
            raise ValueError("evidence URI bucket is outside the approved boundary")
        if max_bytes < 1 or max_bytes > 4_194_304:
            raise ValueError("evidence read ceiling is outside policy")
        response = self._session.get(
            f"https://storage.googleapis.com/storage/v1/b/{quote(bucket)}/o/"
            f"{quote(object_name, safe='')}?alt=media",
            timeout=30,
        )
        response.raise_for_status()
        content = response.content
        if len(content) > max_bytes:
            raise ValueError("evidence object exceeds the byte ceiling")
        actual_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if actual_hash != expected_hash:
            raise ValueError("evidence object hash does not match the durable ledger")
        return content


def _parse_gcs_uri(uri: str) -> tuple[str, str]:
    if not uri.startswith("gs://"):
        raise ValueError("evidence reference must be a GCS URI")
    remainder = uri[5:]
    bucket, separator, object_name = remainder.partition("/")
    if not separator or not bucket or not object_name or ".." in object_name.split("/"):
        raise ValueError("evidence GCS URI is invalid")
    return bucket, object_name
