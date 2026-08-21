"""Fail-closed release-evidence contracts for S1-S6 and the MSR gate."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class EvidenceMode(StrEnum):
    LOCAL_CONTRACT = "LOCAL_CONTRACT"
    LIVE_GCP = "LIVE_GCP"
    SCRIPTED_GCP = "SCRIPTED_GCP"


class EvidenceStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"


_SCENARIOS = frozenset({f"S{number}" for number in range(1, 7)})


@dataclass(frozen=True, slots=True)
class ScenarioReceipt:
    scenario_id: str
    mode: EvidenceMode
    status: EvidenceStatus
    release_commit: str
    project_id: str | None
    region: str
    deployment_id: str | None
    started_at: datetime
    completed_at: datetime
    assertions: tuple[tuple[str, bool], ...]
    evidence_refs: tuple[str, ...]
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        scenario_id: str,
        mode: EvidenceMode,
        status: EvidenceStatus,
        release_commit: str,
        project_id: str | None,
        region: str,
        deployment_id: str | None,
        started_at: datetime,
        completed_at: datetime,
        assertions: dict[str, bool],
        evidence_refs: tuple[str, ...],
    ) -> ScenarioReceipt:
        if scenario_id not in _SCENARIOS:
            raise ValueError("release scenario must be S1 through S6")
        if len(release_commit) != 40:
            raise ValueError("release evidence requires a full git commit")
        try:
            int(release_commit, 16)
        except ValueError as error:
            raise ValueError("release evidence requires a full git commit") from error
        if region != "europe-west1":
            raise ValueError("release evidence must be regional to europe-west1")
        if completed_at < started_at:
            raise ValueError("release evidence completion precedes its start")
        if not assertions:
            raise ValueError("release evidence requires named assertions")
        if status is EvidenceStatus.PASS and not all(assertions.values()):
            raise ValueError("a passing receipt cannot contain a failed assertion")
        if mode is not EvidenceMode.LOCAL_CONTRACT and (
            not project_id or not deployment_id or not evidence_refs
        ):
            raise ValueError("GCP evidence requires project, deployment, and durable refs")
        if mode is EvidenceMode.LOCAL_CONTRACT and (project_id or deployment_id):
            raise ValueError("local evidence cannot claim a cloud project or deployment")
        if (
            scenario_id == "S1"
            and status is EvidenceStatus.PASS
            and mode is not EvidenceMode.LIVE_GCP
        ):
            raise ValueError("S1 can pass the release gate only as LIVE_GCP")
        canonical = {
            "schema_version": 1,
            "scenario_id": scenario_id,
            "mode": mode.value,
            "status": status.value,
            "release_commit": release_commit,
            "project_id": project_id,
            "region": region,
            "deployment_id": deployment_id,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "assertions": dict(sorted(assertions.items())),
            "evidence_refs": list(evidence_refs),
        }
        content_hash = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        return cls(
            scenario_id=scenario_id,
            mode=mode,
            status=status,
            release_commit=release_commit,
            project_id=project_id,
            region=region,
            deployment_id=deployment_id,
            started_at=started_at,
            completed_at=completed_at,
            assertions=tuple(sorted(assertions.items())),
            evidence_refs=evidence_refs,
            content_hash=content_hash,
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "scenario_id": self.scenario_id,
            "mode": self.mode.value,
            "status": self.status.value,
            "release_commit": self.release_commit,
            "project_id": self.project_id,
            "region": self.region,
            "deployment_id": self.deployment_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "assertions": dict(self.assertions),
            "evidence_refs": list(self.evidence_refs),
            "content_hash": self.content_hash,
        }


def parse_scenario_receipt(value: object) -> ScenarioReceipt:
    """Validate one untrusted receipt document and its canonical content hash."""

    expected = {
        "schema_version",
        "scenario_id",
        "mode",
        "status",
        "release_commit",
        "project_id",
        "region",
        "deployment_id",
        "started_at",
        "completed_at",
        "assertions",
        "evidence_refs",
        "content_hash",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise ValueError("scenario receipt schema is invalid")
    assertions = value["assertions"]
    refs = value["evidence_refs"]
    if not isinstance(assertions, dict) or not all(
        isinstance(name, str) and isinstance(passed, bool) for name, passed in assertions.items()
    ):
        raise ValueError("scenario receipt assertions are invalid")
    if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
        raise ValueError("scenario receipt evidence references are invalid")
    try:
        receipt = ScenarioReceipt.create(
            scenario_id=str(value["scenario_id"]),
            mode=EvidenceMode(str(value["mode"])),
            status=EvidenceStatus(str(value["status"])),
            release_commit=str(value["release_commit"]),
            project_id=(None if value["project_id"] is None else str(value["project_id"])),
            region=str(value["region"]),
            deployment_id=(None if value["deployment_id"] is None else str(value["deployment_id"])),
            started_at=datetime.fromisoformat(str(value["started_at"])),
            completed_at=datetime.fromisoformat(str(value["completed_at"])),
            assertions={str(name): passed for name, passed in assertions.items()},
            evidence_refs=tuple(str(item) for item in refs),
        )
    except (TypeError, ValueError) as error:
        raise ValueError("scenario receipt values are invalid") from error
    if value["content_hash"] != receipt.content_hash:
        raise ValueError("scenario receipt content hash is invalid")
    return receipt


@dataclass(frozen=True, slots=True)
class MinimumReleaseDecision:
    passed: bool
    reason_codes: tuple[str, ...]


def evaluate_minimum_release(
    *,
    release_commit: str,
    project_id: str,
    deployment_id: str,
    preflight_passed: bool,
    receipts: tuple[ScenarioReceipt, ...],
    open_p0_count: int,
    unsafe_actions: int,
    duplicate_mutations: int,
    isolation_violations: int,
) -> MinimumReleaseDecision:
    reasons: list[str] = []
    if not preflight_passed:
        reasons.append("PLATFORM_PREFLIGHT_NOT_PASSED")
    if open_p0_count:
        reasons.append("OPEN_P0")
    if any(value for value in (unsafe_actions, duplicate_mutations, isolation_violations)):
        reasons.append("SECURITY_OR_DUPLICATE_EFFECT_FAILURE")
    by_scenario: dict[str, ScenarioReceipt] = {}
    for receipt in receipts:
        if receipt.scenario_id in by_scenario:
            reasons.append(f"DUPLICATE_RECEIPT:{receipt.scenario_id}")
        by_scenario[receipt.scenario_id] = receipt
        if (
            receipt.release_commit != release_commit
            or receipt.project_id != project_id
            or receipt.deployment_id != deployment_id
        ):
            reasons.append(f"RELEASE_BINDING_MISMATCH:{receipt.scenario_id}")
    for scenario_id in sorted(_SCENARIOS):
        scenario_receipt = by_scenario.get(scenario_id)
        if scenario_receipt is None:
            reasons.append(f"MISSING_RECEIPT:{scenario_id}")
            continue
        expected_mode = EvidenceMode.LIVE_GCP if scenario_id == "S1" else EvidenceMode.SCRIPTED_GCP
        if (
            scenario_receipt.status is not EvidenceStatus.PASS
            or scenario_receipt.mode is not expected_mode
        ):
            reasons.append(f"SCENARIO_NOT_RELEASE_PASS:{scenario_id}")
    return MinimumReleaseDecision(not reasons, tuple(reasons))
