"""Generation-fenced GCS verification for guidance evaluation receipts."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import quote

from solvan.application.guidance_evaluation import (
    VerifiedGuidanceEvaluation,
    verify_evaluation_binding,
)
from solvan.domain import Scope
from solvan.platform.google_rest import GoogleRestSession


class GcsGuidanceEvaluationVerifier:
    def __init__(self, *, allowed_buckets: frozenset[str], session: GoogleRestSession) -> None:
        if not allowed_buckets or any(not bucket or "/" in bucket for bucket in allowed_buckets):
            raise ValueError("at least one valid evaluation bucket is required")
        self._allowed_buckets = allowed_buckets
        self._session = session

    @staticmethod
    def _binding(receipt_ref: str) -> tuple[str, str, str]:
        if not receipt_ref.startswith("gs://") or "#generation=" not in receipt_ref:
            raise ValueError("evaluation receipt must name an exact GCS generation")
        location, generation = receipt_ref.rsplit("#generation=", 1)
        remainder = location.removeprefix("gs://")
        bucket, separator, object_name = remainder.partition("/")
        if (
            not separator
            or not bucket
            or not object_name
            or not generation.isdigit()
            or ".." in object_name.split("/")
        ):
            raise ValueError("evaluation receipt reference is invalid")
        return bucket, object_name, generation

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
        bucket, object_name, generation = self._binding(receipt_ref)
        if bucket not in self._allowed_buckets:
            raise ValueError("evaluation receipt bucket is outside the approved boundary")
        response = self._session.get(
            "https://storage.googleapis.com/storage/v1/b/"
            f"{quote(bucket)}/o/{quote(object_name, safe='')}?alt=media&generation={generation}",
            timeout=30,
        )
        response.raise_for_status()
        if len(response.content) > 1_048_576:
            raise ValueError("evaluation receipt exceeds the byte ceiling")
        try:
            value: Any = json.loads(response.content)
        except json.JSONDecodeError as error:
            raise ValueError("evaluation receipt is not valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("evaluation receipt must be a JSON object")
        receipt_hash = f"sha256:{hashlib.sha256(response.content).hexdigest()}"
        return verify_evaluation_binding(
            value,
            receipt_ref=receipt_ref,
            receipt_hash=receipt_hash,
            object_generation=generation,
            guidance_key=guidance_key,
            version=version,
            expected_digest=expected_digest,
        )
