"""Independent Google Cloud Deploy verification for catalog publication."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from solvan.platform.google_rest import GoogleRestSession

_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


@dataclass(frozen=True, slots=True)
class CatalogCloudDeployGate:
    release_ref: str
    evaluation_ref: str
    approval_ref: str


def _resource_ref(document: dict[str, Any], *, kind: str) -> str:
    name = document.get("name")
    uid = document.get("uid")
    if not isinstance(name, str) or not name or not isinstance(uid, str) or not uid:
        raise RuntimeError(f"Cloud Deploy {kind} has no immutable name and UID")
    return f"//clouddeploy.googleapis.com/{name}?uid={quote(uid, safe='')}"


def verify_catalog_publication_gate(
    *,
    session: GoogleRestSession,
    project_id: str,
    location: str,
    pipeline_id: str,
    release_id: str,
    publication_rollout_id: str,
    evaluation_target_id: str,
    publication_target_id: str,
    expected_annotations: dict[str, str],
) -> CatalogCloudDeployGate:
    """Re-read the exact release and rollouts; refuse on any ambiguity or drift."""

    for label, value in (
        ("pipeline", pipeline_id),
        ("release", release_id),
        ("publication rollout", publication_rollout_id),
        ("evaluation target", evaluation_target_id),
        ("publication target", publication_target_id),
    ):
        if _ID.fullmatch(value) is None:
            raise RuntimeError(f"Cloud Deploy {label} ID is invalid")
    base = (
        "https://clouddeploy.googleapis.com/v1/projects/"
        f"{quote(project_id, safe='')}/locations/{quote(location, safe='')}/"
        f"deliveryPipelines/{quote(pipeline_id, safe='')}/releases/{quote(release_id, safe='')}"
    )
    release_response = session.get(base, timeout=30)
    release_response.raise_for_status()
    release = release_response.json()
    if not isinstance(release, dict):
        raise RuntimeError("Cloud Deploy release response is malformed")
    if release.get("annotations") != expected_annotations:
        raise RuntimeError("Cloud Deploy release annotations do not match the catalog subject")

    list_response = session.get(f"{base}/rollouts?pageSize=100", timeout=30)
    list_response.raise_for_status()
    listed = list_response.json()
    if not isinstance(listed, dict) or listed.get("nextPageToken"):
        raise RuntimeError("Cloud Deploy rollout set is malformed or unexpectedly paginated")
    rollouts = listed.get("rollouts")
    if not isinstance(rollouts, list):
        raise RuntimeError("Cloud Deploy release has no rollout set")
    evaluations = [
        item
        for item in rollouts
        if isinstance(item, dict) and item.get("targetId") == evaluation_target_id
    ]
    if len(evaluations) != 1 or evaluations[0].get("state") != "SUCCEEDED":
        raise RuntimeError("catalog evaluation rollout is not uniquely SUCCEEDED")

    publication_response = session.get(
        f"{base}/rollouts/{quote(publication_rollout_id, safe='')}", timeout=30
    )
    publication_response.raise_for_status()
    publication = publication_response.json()
    if not isinstance(publication, dict):
        raise RuntimeError("Cloud Deploy publication rollout response is malformed")
    if publication.get("targetId") != publication_target_id:
        raise RuntimeError("Cloud Deploy publication rollout targets another stage")
    if publication.get("approvalState") != "APPROVED":
        raise RuntimeError("Cloud Deploy publication rollout lacks human approval")
    if publication.get("state") not in {"IN_PROGRESS", "SUCCEEDED"}:
        raise RuntimeError("Cloud Deploy publication rollout is not executing an approved stage")
    return CatalogCloudDeployGate(
        release_ref=_resource_ref(release, kind="release"),
        evaluation_ref=_resource_ref(evaluations[0], kind="evaluation rollout"),
        approval_ref=_resource_ref(publication, kind="publication rollout"),
    )
