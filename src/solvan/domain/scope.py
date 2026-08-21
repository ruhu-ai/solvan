"""Tenant and environment scope used by every authoritative operation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from solvan.domain.identifiers import validate_identifier


@dataclass(frozen=True, slots=True)
class Scope:
    organization_id: str
    project_id: str
    environment_id: str

    def __post_init__(self) -> None:
        validate_identifier(self.organization_id, expected_prefix="org")
        validate_identifier(self.project_id, expected_prefix="prj")
        validate_identifier(self.environment_id, expected_prefix="env")

    def canonical_dict(self) -> dict[str, str]:
        return {
            "environment_id": self.environment_id,
            "organization_id": self.organization_id,
            "project_id": self.project_id,
        }

    def digest(self) -> str:
        payload = json.dumps(self.canonical_dict(), separators=(",", ":"), sort_keys=True).encode()
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"
