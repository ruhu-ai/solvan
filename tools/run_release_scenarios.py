"""Run deterministic local S1-S6 contracts and emit non-promotable receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from solvan.application import EvidenceMode, EvidenceStatus, ScenarioReceipt

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class LocalScenario:
    scenario_id: str
    commands: tuple[tuple[str, ...], ...]
    assertions: tuple[str, ...]


LOCAL_SCENARIOS = (
    LocalScenario("S1", (), ("live_gcp_required",)),
    LocalScenario(
        "S2",
        (("./scripts/check-contracts",),),
        ("duplicate_ingress_deduplicated", "single_target_reservation"),
    ),
    LocalScenario(
        "S3",
        (
            ("./scripts/check-contracts",),
            (
                "uv",
                "run",
                "pytest",
                "-q",
                "tests/unit/test_investigation_coordinator.py",
                "tests/unit/test_agent_runtime.py",
            ),
        ),
        (
            "attempt_committed_before_dispatch",
            "cached_call_budget_enforced",
            "single_declared_fallback_attempt",
            "stale_output_fenced",
        ),
    ),
    LocalScenario(
        "S4",
        (
            (
                "uv",
                "run",
                "pytest",
                "-q",
                "tests/unit/test_action_policy.py",
                "tests/unit/test_actuator.py",
            ),
        ),
        ("stale_approval_denied", "changed_target_zero_effect"),
    ),
    LocalScenario(
        "S5",
        (
            (
                "uv",
                "run",
                "pytest",
                "-q",
                "tests/unit/test_safety.py",
                "tests/unit/test_memory.py",
                "tests/unit/test_memory_bank.py",
            ),
        ),
        ("instruction_control_blocked", "poisoned_memory_not_promoted"),
    ),
    LocalScenario(
        "S6",
        (
            ("./scripts/check-contracts",),
            ("uv", "run", "pytest", "-q", "tests/unit/test_release_contracts.py"),
        ),
        ("cross_scope_row_policy_denied", "gateway_and_region_fail_closed"),
    ),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--scenario", action="append", choices=[f"S{i}" for i in range(1, 7)])
    args = parser.parse_args()
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    started = datetime.now(UTC)
    output_dir = args.output_dir or (
        ROOT / ".solvan" / "release-evidence" / "local" / started.strftime("%Y%m%dT%H%M%SZ")
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    selected = set(args.scenario or [item.scenario_id for item in LOCAL_SCENARIOS])
    command_results: dict[tuple[str, ...], tuple[bool, str]] = {}
    receipts: list[ScenarioReceipt] = []
    for scenario in LOCAL_SCENARIOS:
        if scenario.scenario_id not in selected:
            continue
        if scenario.scenario_id == "S1":
            receipt = ScenarioReceipt.create(
                scenario_id="S1",
                mode=EvidenceMode.LOCAL_CONTRACT,
                status=EvidenceStatus.NOT_RUN,
                release_commit=commit,
                project_id=None,
                region="europe-west1",
                deployment_id=None,
                started_at=started,
                completed_at=datetime.now(UTC),
                assertions={"live_gcp_required": False},
                evidence_refs=(),
            )
        else:
            assertions: dict[str, bool] = {}
            refs: list[str] = []
            for command in scenario.commands:
                if command not in command_results:
                    result = subprocess.run(
                        command,
                        cwd=ROOT,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    output = result.stdout + result.stderr
                    command_results[command] = (result.returncode == 0, output)
                passed, output = command_results[command]
                digest = hashlib.sha256(output.encode()).hexdigest()
                log_name = f"command-{digest}.log"
                log_path = output_dir / log_name
                if not log_path.exists():
                    log_path.write_text(output, encoding="utf-8")
                refs.append(f"local://{log_name}#sha256:{digest}")
                for name in scenario.assertions:
                    assertions[name] = assertions.get(name, True) and passed
            status = EvidenceStatus.PASS if all(assertions.values()) else EvidenceStatus.FAIL
            receipt = ScenarioReceipt.create(
                scenario_id=scenario.scenario_id,
                mode=EvidenceMode.LOCAL_CONTRACT,
                status=status,
                release_commit=commit,
                project_id=None,
                region="europe-west1",
                deployment_id=None,
                started_at=started,
                completed_at=datetime.now(UTC),
                assertions=assertions,
                evidence_refs=tuple(refs),
            )
        (output_dir / f"{scenario.scenario_id}.json").write_text(
            json.dumps(receipt.canonical_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        receipts.append(receipt)
    summary = {
        "schema_version": 1,
        "authority": "LOCAL_CONTRACT_ONLY",
        "release_eligible": False,
        "reason": "S1 requires LIVE_GCP and S2-S6 require the same deployed GCP release.",
        "release_commit": commit,
        "working_tree_dirty": bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        ),
        "receipts": [item.canonical_dict() for item in receipts],
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(output_dir)
    return (
        0
        if all(item.status in {EvidenceStatus.PASS, EvidenceStatus.NOT_RUN} for item in receipts)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
