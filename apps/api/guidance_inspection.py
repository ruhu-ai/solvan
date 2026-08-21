"""Bounded, hash-bound guidance inspection for the operational catalog."""

from __future__ import annotations

import os

from apps.api.operational_guidance_admin import GuidanceContentInspection
from solvan.application.operational_guidance import GuidanceRevision
from solvan.application.tool_output_security import secure_tool_output
from solvan.platform.evidence_objects import GcsEvidenceReader
from solvan.platform.google_rest import authorized_session


def inspect_guidance_content(revision: GuidanceRevision) -> GuidanceContentInspection:
    """Hash-bind and scan one bounded JSON guidance object before catalog ingestion."""

    bucket = os.environ.get("SOLVAN_GUIDANCE_BUCKET")
    if not bucket:
        return GuidanceContentInspection(False, ("GUIDANCE_BUCKET_NOT_CONFIGURED",))
    try:
        document = GcsEvidenceReader(
            allowed_buckets=frozenset({bucket}), session=authorized_session()
        ).get_json(
            uri=revision.content_ref,
            expected_hash=revision.content_hash,
            max_bytes=262_144,
        )
        secured = secure_tool_output(document)
    except Exception:
        return GuidanceContentInspection(False, ("CONTENT_RETRIEVAL_OR_HASH_FAILED",))
    if secured.reason_codes:
        return GuidanceContentInspection(False, secured.reason_codes)
    return GuidanceContentInspection(True, ("STRUCTURE_AND_SECURITY_VALIDATED",))
