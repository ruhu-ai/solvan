"""Generation-pinned GCS verifier for governed guidance evaluations."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from solvan.application.guidance_evaluation import (
    VerifiedGuidanceEvaluation,
    verify_evaluation_binding,
)
from solvan.domain import Scope

_GCS_RECEIPT = re.compile(
    r"^gs://(?P<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])/(?P<object>[^#]+)#generation=(?P<generation>[0-9]+)$"
)
_MAX_RECEIPT_BYTES = 1_048_576


class GcsGuidanceEvaluationVerifier:
    """Read an immutable object generation and validate its exact binding."""

    def __init__(
        self,
        *,
        authorized_session: Any,
        allowed_buckets: frozenset[str],
        timeout_seconds: float = 15.0,
        media_get: Callable[[str, dict[str, str], float], bytes] | None = None,
    ) -> None:
        if not allowed_buckets:
            raise ValueError("at least one evaluation receipt bucket is required")
        self._session = authorized_session
        self._allowed_buckets = allowed_buckets
        self._timeout = timeout_seconds
        self._media_get = media_get

    def _read(self, bucket: str, object_name: str, generation: str) -> bytes:
        url = (
            "https://storage.googleapis.com/storage/v1/b/"
            f"{quote(bucket, safe='')}/o/{quote(object_name, safe='')}"
        )
        params = {"alt": "media", "generation": generation}
        if self._media_get is not None:
            return self._media_get(url, params, self._timeout)
        response = self._session.get(url, params=params, timeout=self._timeout)
        response.raise_for_status()
        body = bytes(response.content)
        if len(body) > _MAX_RECEIPT_BYTES:
            raise ValueError("evaluation receipt exceeds the maximum size")
        return body

    def verify(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        expected_digest: str,
        receipt_ref: str,
    ) -> VerifiedGuidanceEvaluation:
        del scope
        match = _GCS_RECEIPT.fullmatch(receipt_ref)
        if match is None:
            raise ValueError("evaluation receipt must be a generation-pinned GCS URI")
        bucket = match.group("bucket")
        if bucket not in self._allowed_buckets:
            raise ValueError("evaluation receipt bucket is not registered")
        body = self._read(bucket, match.group("object"), match.group("generation"))
        if len(body) > _MAX_RECEIPT_BYTES:
            raise ValueError("evaluation receipt exceeds the maximum size")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("evaluation receipt is not valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("evaluation receipt must be a JSON object")
        receipt_hash = f"sha256:{hashlib.sha256(body).hexdigest()}"
        return verify_evaluation_binding(
            value,
            receipt_ref=receipt_ref,
            receipt_hash=receipt_hash,
            object_generation=match.group("generation"),
            guidance_key=guidance_key,
            version=version,
            expected_digest=expected_digest,
        )
