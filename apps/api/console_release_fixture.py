"""Clearly labeled non-authoritative release data for local console development."""

from __future__ import annotations

from typing import Any


def scripted_release_fixture() -> dict[str, Any]:
    return {
        "scenarios": [
            {
                "id": "S1",
                "name": "Detect → mitigate → verify",
                "status": "NOT RUN · LIVE GCP REQUIRED",
            },
            {
                "id": "S2",
                "name": "Duplicate delivery and stale Agent",
                "status": "LOCAL CONTRACT PASSED",
            },
            {
                "id": "S3",
                "name": "Agent budget and fallback",
                "status": "LOCAL CONTRACT PASSED",
            },
            {
                "id": "S4",
                "name": "Stale approval and target",
                "status": "LOCAL CONTRACT PASSED",
            },
            {
                "id": "S5",
                "name": "Injection and memory poisoning",
                "status": "LOCAL CONTRACT PASSED",
            },
            {
                "id": "S6",
                "name": "Isolation, Gateway, and region",
                "status": "LOCAL CONTRACT PASSED · NOT CLOUD-RUN",
            },
        ],
        "commit": "working tree · not submission evidence",
        "cloud": "No cloud release receipt yet",
        "gate": "Minimum Submittable Release: in progress",
    }
