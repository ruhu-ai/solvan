from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from apps.coordinator.contracts import GovernedAgentBinding
from solvan.application.catalog_release_governance import (
    catalog_release_subject,
    evaluate_network_policy,
)
from solvan.application.default_tool_catalog import AGENT_PROFILE_KEYS
from solvan.domain import Scope
from solvan.platform.cloud_deploy_catalog import verify_catalog_publication_gate

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "specs" / "artifacts" / "catalog-network-policy.v1.json"


def _bindings() -> dict[str, GovernedAgentBinding]:
    return {
        agent: GovernedAgentBinding(
            profile_key=profile,
            profile_version="1",
            identity_ref=f"principal://example/{agent}",
            accepted_tool_ordinals=(),
            connection_epochs={},
            gateway_destinations=frozenset(),
            data_classification="CONFIDENTIAL",
        )
        for agent, profile in AGENT_PROFILE_KEYS.items()
    }


def test_checked_in_catalog_network_policy_exactly_covers_every_tool() -> None:
    raw = POLICY.read_bytes()
    digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    result = evaluate_network_policy(raw_policy=raw, expected_hash=digest)
    assert result["result"] == "PASSED"
    assert result["tool_revision_count"] == 34

    with pytest.raises(RuntimeError, match="hash"):
        evaluate_network_policy(raw_policy=raw + b"\n", expected_hash=digest)


def test_catalog_subject_is_stable_and_requires_every_agent() -> None:
    values = dict(
        scope=Scope(
            "org_01H00000000000000000000000",
            "prj_01H00000000000000000000000",
            "env_01H00000000000000000000000",
        ),
        release_commit="a" * 40,
        deployment_id="staging-20260821",
        manifest_hash="sha256:" + "b" * 64,
        network_policy_hash="sha256:" + "c" * 64,
    )
    first = catalog_release_subject(bindings=_bindings(), **values)
    second = catalog_release_subject(bindings=dict(reversed(list(_bindings().items()))), **values)
    assert first == second
    missing = _bindings()
    missing.pop("workspace-agent")
    with pytest.raises(RuntimeError, match="all canonical"):
        catalog_release_subject(bindings=missing, **values)


class _Response:
    def __init__(self, value: dict[str, Any]) -> None:
        self._value = value
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self.content = b""

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._value


class _Session:
    def __init__(self, values: list[dict[str, Any]]) -> None:
        self.values = values

    def get(self, _url: str, **_kwargs: Any) -> _Response:
        return _Response(self.values.pop(0))


def test_publication_gate_requires_succeeded_evaluation_and_google_approval() -> None:
    annotations = {
        "solvan-catalog-subject": "sha256:" + "a" * 64,
        "solvan-deployment-id": "staging-20260821",
        "solvan-network-policy": "sha256:" + "b" * 64,
        "solvan-release-commit": "c" * 40,
    }
    session = _Session(
        [
            {
                "name": "projects/p/locations/r/deliveryPipelines/pipe/releases/rel",
                "uid": "release-uid",
                "annotations": annotations,
            },
            {
                "rollouts": [
                    {
                        "name": "evaluation",
                        "uid": "evaluation-uid",
                        "targetId": "evaluation",
                        "state": "SUCCEEDED",
                    }
                ]
            },
            {
                "name": "publication",
                "uid": "publication-uid",
                "targetId": "publication",
                "state": "IN_PROGRESS",
                "approvalState": "APPROVED",
            },
        ]
    )
    result = verify_catalog_publication_gate(
        session=session,  # type: ignore[arg-type]
        project_id="project-id",
        location="europe-west1",
        pipeline_id="pipeline",
        release_id="release",
        publication_rollout_id="rollout",
        evaluation_target_id="evaluation",
        publication_target_id="publication",
        expected_annotations=annotations,
    )
    assert "release-uid" in result.release_ref
    assert "evaluation-uid" in result.evaluation_ref
    assert "publication-uid" in result.approval_ref


def test_publication_gate_refuses_unapproved_rollout() -> None:
    session = _Session(
        [
            {"name": "release", "uid": "release-uid", "annotations": {}},
            {
                "rollouts": [
                    {
                        "name": "evaluation",
                        "uid": "evaluation-uid",
                        "targetId": "evaluation",
                        "state": "SUCCEEDED",
                    }
                ]
            },
            {
                "name": "publication",
                "uid": "publication-uid",
                "targetId": "publication",
                "state": "PENDING_APPROVAL",
                "approvalState": "NEEDS_APPROVAL",
            },
        ]
    )
    with pytest.raises(RuntimeError, match="lacks human approval"):
        verify_catalog_publication_gate(
            session=session,  # type: ignore[arg-type]
            project_id="project-id",
            location="europe-west1",
            pipeline_id="pipeline",
            release_id="release",
            publication_rollout_id="rollout",
            evaluation_target_id="evaluation",
            publication_target_id="publication",
            expected_annotations={},
        )
