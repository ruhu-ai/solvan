"""Safe scripted console projection for local UI and demo-path testing.

The data is visibly labeled and grants no workflow or mutation authority.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from apps.api.console_fleet_fixture import fleet_fixture
from apps.api.console_incident_fixture import incident_fixtures, scripted_patch_diff
from apps.api.console_integration_fixture import integration_fixture
from apps.api.console_release_fixture import scripted_release_fixture
from apps.api.overview_history import (
    awaiting_approval_detail,
    open_incidents_detail,
    reliability_cases_detail,
    tile,
    verified_mitigations_detail,
)

#: The instant this projection claims to have been generated at. Every caption
#: below is measured from it, so the fixture is deterministic across runs.
_GENERATED_AT = datetime(2026, 8, 8, 12, 8, tzinfo=UTC)

#: The scripted incident's own clock, matching `console_incident_fixture`.
#: Every scripted instant below is offset from it, so the tile captions, the
#: incident's stated age, and its impact window cannot contradict each other.
_DETECTED_AT = datetime(2026, 8, 8, 11, 50, 3, tzinfo=UTC)


def _scripted_metrics() -> list[dict[str, Any]]:
    """The four stat tiles, captioned by the live path's own derivations.

    The figures and trends are scripted — that is what a fixture is for — but
    the captions are not written here. They are read from scripted *records*
    through the same functions `overview_tiles` uses, so this projection cannot
    display a caption the product is unable to produce, and a change to a
    caption form shows up here rather than drifting away from the live path.
    """
    # Triage, investigation, and diagnosis precede the approval gate; the
    # mitigation is verified once the scripted 8m 10s impact window has closed.
    waiting_since = _DETECTED_AT + timedelta(minutes=4)
    verified_at = _DETECTED_AT + timedelta(minutes=8, seconds=10)
    return [
        tile(
            "Open incidents",
            open_incidents_detail([{"severity": "SEV2"}]),
            [0, 0, 0, 0, 1, 1, 2, 2, 1, 1, 1, 1],
            1,
        ),
        tile(
            "Reliability Cases",
            reliability_cases_detail(
                [{"next_action_at": datetime(2026, 8, 9, 9, 0, tzinfo=UTC)}], _GENERATED_AT
            ),
            [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1],
            1,
        ),
        tile(
            "Awaiting approval",
            awaiting_approval_detail(
                [{"id": "inc_scripted", "state": "AWAITING_APPROVAL"}],
                {"inc_scripted": [(waiting_since, "AWAITING_APPROVAL", "MITIGATION_PROPOSED")]},
                _GENERATED_AT,
            ),
            [1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1],
            1,
        ),
        tile(
            "Verified mitigations",
            verified_mitigations_detail(
                [{"id": "inc_1042", "state": "MITIGATED"}],
                {"inc_1042": [(verified_at, "MITIGATED", "VERIFYING_MITIGATION")]},
                {"MITIGATED", "RESOLVED"},
                _GENERATED_AT,
            ),
            [0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
            1,
        ),
    ]


def console_snapshot() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
        "generated_at": _GENERATED_AT.isoformat().replace("+00:00", "Z"),
        # The local console is a development environment, not a product tenant.
        # The fault injection remains a separately enabled acceptance scenario.
        "environment": {"name": "development", "region": "europe-west1"},
        "overview": {
            "metrics": _scripted_metrics(),
            "queue": {"ready": 2, "running": 1, "sleeping": 3, "overdue": 0, "fenced": 1},
        },
        "incidents": incident_fixtures(),
        "cases": [
            {
                "id": "REL-0042",
                "service": "payments-api",
                "state": "AWAITING_REVIEW",
                "incident": "INC-1042",
                "age": "2d",
                "repair": "Sandbox-tested patch awaiting exact review",
                "repair_plan": "rep_…DEMO",
                "provider": "GEMINI_ADK_AGENT_ENGINE",
                "commit": "demo snapshot · not a cloud receipt",
                "patch_status": "scripted fixture only",
                "patch_artifact": "pat_…DEMO",
                "patch_digest": f"sha256:{'0' * 64}",
                "patch_ref": "fixture://repair.patch",
                # The reviewer approves a change, so the change is shown. The
                # digest above proves which change this is; this is what it does.
                "patch_diff": scripted_patch_diff(),
                "test_ref": "fixture://test-output.txt",
                "residual_risks": ["Scripted fixture; not a production patch."],
                "next": "2026-08-09 09:00 UTC",
                "owner": "payments-platform",
                "phases": [
                    "Root cause",
                    "Repair",
                    "Review",
                    "Canary",
                    "Rollout",
                    "Observation",
                    "Closed",
                ],
                "checkpoints": [
                    {
                        "day": "Day 1 · Aug 8",
                        "events": [
                            "12:06 case opened from verified mitigation",
                            "12:07 wake-up wak_…21B scheduled",
                            "No process running · next wake-up 09:00",
                        ],
                    },
                    {
                        "day": "Day 2 · Aug 9",
                        "events": [
                            "09:00 scheduler claimed wak_…21B",
                            "09:01 case lease acquired by coordinator",
                            "09:02 plan version 1 committed",
                            "09:04 next wake-up scheduled for owner review",
                        ],
                    },
                ],
                "workspace": {
                    "id": "wsp_…DEMO",
                    "kind": "INCIDENT",
                    "status": "OPEN",
                    "provider": "GEMINI_ADK_AGENT_ENGINE",
                    "implementation_sdk": "google-adk",
                    "implementation_sdk_version": "2.7.1",
                    "provider_revision": "scripted · not deployed",
                    "registry_agent_key": "workspace-agent",
                    "classification": "INTERNAL",
                    "synthetic": True,
                    "eligibility_decision": "pol_…DEMO",
                    "input_manifest_hash": f"sha256:{'1' * 64}",
                    "network_policy_hash": f"sha256:{'2' * 64}",
                    "task_runs": [
                        {
                            "id": "run_…DEMO",
                            "task": "REPAIR",
                            "status": "SUCCEEDED",
                            "attempt": 1,
                            "request_hash": f"sha256:{'3' * 64}",
                            "output_hash": f"sha256:{'4' * 64}",
                            "provider_boot_hash": f"sha256:{'5' * 64}",
                            "provider_service_revision": "scripted · not deployed",
                        }
                    ],
                    "checkpoints": [
                        {
                            "id": "wck_…DEMO",
                            "event": "REHYDRATION",
                            "sequence": 2,
                            "artifact_manifest_hash": f"sha256:{'6' * 64}",
                            "provider_boot_hash": f"sha256:{'7' * 64}",
                        }
                    ],
                    "repair_cognition": {
                        "patch_artifact_id": "pat_…DEMO",
                        "status": "TESTS_PASSED",
                        "trust_class": "PROPOSED",
                        "mechanism": (
                            "A leaked payment database connection exhausts the bounded pool."
                        ),
                        "hypotheses": [
                            {
                                "hypothesis_key": "connection-leak",
                                "statement": "The error path does not release its connection.",
                                "supporting_citations": ["src/payments.py:84"],
                                "contradicting_citations": ["src/payments.py:51"],
                                "leading": True,
                            },
                            {
                                "hypothesis_key": "pool-too-small",
                                "statement": "Normal concurrency exceeds the configured pool.",
                                "supporting_citations": ["config/runtime.yaml:22"],
                                "contradicting_citations": ["tests/load/result.json"],
                                "leading": False,
                            },
                        ],
                        "artifact_ref": "gs://scripted-demo/repair/cognition.json",
                        "artifact_hash": f"sha256:{'8' * 64}",
                        "reproduction": {
                            "command": "pytest -q tests/test_connection_leak.py",
                            "exit_code": 1,
                            "output_ref": "gs://scripted-demo/repair/reproduction-output.txt",
                            "output_hash": f"sha256:{'9' * 64}",
                        },
                        "regression": {
                            "command": "pytest -q tests/test_connection_leak.py",
                            "exit_code": 0,
                            "output_ref": "gs://scripted-demo/repair/test-output.txt",
                            "output_hash": f"sha256:{'a' * 64}",
                        },
                    },
                    "denied_authorities": [
                        "root-cause confirmation",
                        "patch approval or repository merge",
                        "deployment or production mutation",
                        "verification adjudication",
                        "incident resolution or case closure",
                        "Memory or Production Graph promotion",
                    ],
                },
            }
        ],
        "fleet": fleet_fixture(),
        "integration": integration_fixture(),
        "release": scripted_release_fixture(),
    }
