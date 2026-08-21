"""Reader-safe projection for the operator-facing Skills catalog."""

from __future__ import annotations

from typing import Any


def guidance_projection(item: dict[str, Any]) -> dict[str, Any]:
    lifecycle = str(item["lifecycle"])
    approved = lifecycle == "APPROVED"
    return {
        "key": str(item["guidance_key"]),
        "version": str(item["version"]),
        "name": str(item["display_name"]),
        "description": str(item["description"]),
        "owner": str(item["owner_department"]),
        "source_kind": str(item["source_kind"]),
        "source_ref": str(item["source_ref"]),
        "author_principal": str(item["author_principal"]),
        "recorded_at": item["created_at"].isoformat() if item["created_at"] else "",
        "kind": str(item["guidance_kind"]).replace("_", " ").title(),
        "purpose": str(item["purpose"]).replace("_", " ").title(),
        "classification": str(item["classification"]),
        "regions": [str(value) for value in item["eligible_regions_json"]],
        "agent_keys": [str(value) for value in item["agent_keys"]],
        "profile_revisions": [str(value) for value in item["profile_revisions"]],
        "lifecycle": lifecycle.replace("_", " ").title(),
        "availability": "Available" if approved else "Unavailable",
        "evidence": "Evaluated" if item["evaluation_ref"] else "Not evaluated",
        "why": (
            "The exact immutable revision is approved and evaluated."
            if approved
            else "This revision is not approved for new work."
        ),
        "next_step": (
            "No action required; selection still needs exact scope and profile."
            if approved
            else "Complete evaluation and independent approval of the exact digest."
        ),
        "revision_hash": str(item["revision_hash"])[:10] + "…" + str(item["revision_hash"])[-8:],
    }
