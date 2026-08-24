from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

import pytest

from solvan.application import EvidenceMode, EvidenceStatus, ScenarioReceipt
from solvan.platform import ReleaseTopology, evaluate_platform_preflight
from solvan.platform.google_rest import JsonResponse
from solvan.platform.preflight import _REQUIRED_APIS, _REQUIRED_PROOFS
from solvan.platform.release_projection import (
    PLATFORM_RECEIPT_HORIZON,
    CloudReleaseBinding,
    GcsReleaseProjection,
)

PROJECT = "solvan-demo"
COMMIT = "a" * 40
DEPLOYMENT = "deploy-20260808"
BUCKET = "solvan-demo-evidence"
NOW = datetime(2026, 8, 8, tzinfo=UTC)
AGENTS = (
    "workspace_agent",
    "evidence_agent",
    "execution_agent",
    "incident_supervisor",
    "infrastructure_agent",
    "verification_agent",
)


class FakeResponse:
    def __init__(self, value: Any) -> None:
        self._value = value
        self.status_code = 200
        self.headers: Mapping[str, str] = {}
        self.content = json.dumps(value, sort_keys=True).encode()

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._value


class FakeSession:
    def __init__(self, objects: dict[str, dict[str, Any]]) -> None:
        self.objects = objects

    def get(self, url: str, **kwargs: Any) -> JsonResponse:
        params = kwargs.get("params")
        if isinstance(params, dict):
            prefix = str(params["prefix"])
            return FakeResponse(
                {"items": [{"name": name} for name in self.objects if name.startswith(prefix)]}
            )
        object_name = unquote(url.split("/o/", maxsplit=1)[1].split("?", maxsplit=1)[0])
        return FakeResponse(self.objects[object_name])

    def post(self, url: str, **kwargs: Any) -> JsonResponse:
        raise AssertionError(f"unexpected POST {url} {kwargs}")

    def patch(self, url: str, **kwargs: Any) -> JsonResponse:
        raise AssertionError(f"unexpected PATCH {url} {kwargs}")


def _topology() -> ReleaseTopology:
    services = tuple(
        sorted(
            (
                name,
                (f"https://solvan-{name.replace('_', '-')}-123456789012.europe-west1.run.app"),
            )
            for name in (
                "actuator",
                "api",
                "console",
                "coordinator",
                "detector",
                "evidence",
                "memory",
                "payments",
                "publisher",
                "verifier",
                "workspace_sandbox",
            )
        )
    )
    agents = tuple(
        (name, f"projects/{PROJECT}/locations/europe-west1/reasoningEngines/{name}-1")
        for name in AGENTS
    )
    principals = tuple(
        (
            name,
            "principal://agents.global.project-123456789012.system.id.goog/resources/"
            f"aiplatform/projects/123456789012/locations/europe-west1/reasoningEngines/{name}-1",
        )
        for name in AGENTS
    )
    registered_names = (
        "actuator",
        "aiplatform",
        "aiplatform_mtls",
        "aiplatform_rep",
        "aiplatform_eu_rep",
        "evidence",
        "logging",
        "monitoring",
        "payments",
        "resource_manager",
        "resource_manager_mtls",
        "storage",
        "telemetry",
        "telemetry_mtls",
        "verifier",
    )
    return ReleaseTopology(
        region="europe-west1",
        required_services=tuple(sorted(_REQUIRED_APIS)),
        cloud_sql_connection_name=f"{PROJECT}:europe-west1:control",
        service_uris=services,
        evidence_bucket=BUCKET,
        runtime_bucket="solvan-demo-runtime",
        gateway_resources=tuple(
            (name, f"projects/{PROJECT}/locations/europe-west1/gateways/{name}")
            for name in ("egress", "ingress")
        ),
        gateway_policy_resources=tuple(
            (name, f"projects/{PROJECT}/locations/europe-west1/policies/{name}")
            for name in (
                "iap_extension",
                "iap_egress_policy",
                "iap_ingress_policy",
                "model_armor_extension",
                "model_armor_policy",
            )
        ),
        gateway_policy_status=(
            ("iap", "ENFORCED"),
            ("in_process_model_armor", "ENFORCED_FAIL_CLOSED"),
            ("inline_model_armor", "ENFORCED"),
        ),
        model_armor_template=f"projects/{PROJECT}/locations/europe-west1/templates/boundary",
        fast_fleet_model_resource="gemini-3.6-flash",
        fast_fleet_model_location="eu",
        fast_fleet_model_endpoint="https://aiplatform.eu.rep.googleapis.com",
        registered_endpoints=tuple(
            (name, f"projects/{PROJECT}/locations/europe-west1/services/{name}")
            for name in registered_names
        ),
        agent_resources=agents,
        agent_revisions=tuple((name, f"release-{COMMIT[:12]}") for name in AGENTS),
        agent_principals=principals,
        scenario_identities=(
            ("injector", f"solvan-injector@{PROJECT}.iam.gserviceaccount.com"),
            ("oracle", f"solvan-oracle@{PROJECT}.iam.gserviceaccount.com"),
        ),
    )


def _objects() -> dict[str, dict[str, Any]]:
    preflight = evaluate_platform_preflight(
        topology=_topology(),
        release_commit=COMMIT,
        project_id=PROJECT,
        project_number="123456789012",
        deployment_id=DEPLOYMENT,
        observed_at=NOW,
        billing_enabled=True,
        enabled_apis=_REQUIRED_APIS,
        proof_results={proof: True for proof in _REQUIRED_PROOFS},
        evidence_refs=(f"gs://{BUCKET}/preflight/proofs.json",),
    )
    objects = {f"preflight/{DEPLOYMENT}/receipt.json": preflight.canonical_dict()}
    for number in range(1, 7):
        scenario_id = f"S{number}"
        receipt = ScenarioReceipt.create(
            scenario_id=scenario_id,
            mode=EvidenceMode.LIVE_GCP if number == 1 else EvidenceMode.SCRIPTED_GCP,
            status=EvidenceStatus.PASS,
            release_commit=COMMIT,
            project_id=PROJECT,
            region="europe-west1",
            deployment_id=DEPLOYMENT,
            started_at=NOW,
            completed_at=NOW + timedelta(minutes=number),
            assertions={"oracle": True},
            evidence_refs=(f"gs://{BUCKET}/scenarios/{scenario_id}/oracle.json",),
        )
        objects[f"scenarios/{DEPLOYMENT}/{scenario_id}/receipts/{receipt.content_hash}.json"] = (
            receipt.canonical_dict()
        )
    return objects


def _projection(
    objects: dict[str, dict[str, Any]], *, now: datetime = NOW
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    # The clock is a parameter so the receipt's age is part of the case under
    # test rather than a function of when the suite happens to run.
    return GcsReleaseProjection(
        binding=CloudReleaseBinding(
            project_id=PROJECT,
            release_commit=COMMIT,
            deployment_id=DEPLOYMENT,
            evidence_bucket=BUCKET,
        ),
        session=FakeSession(objects),
    ).load(now=now)


def test_projection_promotes_only_the_exact_bound_preflight_and_six_receipts() -> None:
    platform, release = _projection(_objects())
    assert all(item["health"] == "HEALTHY" for item in platform)
    assert all(item["evidence"] == "CLOUD_VERIFIED" for item in platform)
    assert release["cloud"] == "BOUND_GCP_EVIDENCE_COMPLETE"
    assert release["invalid_receipt_count"] == 0
    assert [item["status"] for item in release["scenarios"]] == [
        "PASS · LIVE_GCP",
        *("PASS · SCRIPTED_GCP" for _ in range(5)),
    ]
    assert all(item["last_checked"] == NOW.isoformat() for item in platform)


def test_a_receipt_past_its_horizon_stops_supporting_a_health_claim() -> None:
    """Verification is observed, never inherited.

    The receipt stays exactly bound to its release commit, so nothing here is
    tampered or mismatched. What changed is only how long ago the topology was
    observed, and past the horizon that is no longer evidence that the platform
    is healthy now.
    """

    platform, release = _projection(
        _objects(), now=NOW + PLATFORM_RECEIPT_HORIZON + timedelta(seconds=1)
    )
    assert all(item["health"] == "UNKNOWN" for item in platform)
    assert all(item["evidence"] == "UNVERIFIED" for item in platform)
    assert all("past its 24h horizon" in item["detail"] for item in platform)
    assert release["cloud"] == "PENDING_RECEIPTS"
    assert release["gate"] == "NOT_EVALUATED"

    fresh, _ = _projection(_objects(), now=NOW + PLATFORM_RECEIPT_HORIZON)
    assert all(item["health"] == "HEALTHY" for item in fresh)


def test_projection_fails_closed_for_tampered_or_unbound_receipts() -> None:
    objects = _objects()
    s6_name = next(name for name in objects if f"/{DEPLOYMENT}/S6/" in name)
    objects[s6_name]["completed_at"] = (NOW + timedelta(hours=1)).isoformat()
    local = ScenarioReceipt.create(
        scenario_id="S2",
        mode=EvidenceMode.LOCAL_CONTRACT,
        status=EvidenceStatus.NOT_RUN,
        release_commit=COMMIT,
        project_id=None,
        region="europe-west1",
        deployment_id=None,
        started_at=NOW,
        completed_at=NOW,
        assertions={"local": True},
        evidence_refs=(),
    )
    objects[f"scenarios/{DEPLOYMENT}/S2/receipts/local.json"] = local.canonical_dict()

    _platform, release = _projection(objects)
    assert release["cloud"] == "PENDING_RECEIPTS"
    assert release["invalid_receipt_count"] == 2
    assert release["scenarios"][5]["status"] == "NOT_RUN_ON_GCP"


@pytest.mark.parametrize(
    "changes",
    (
        {"project_id": "bad"},
        {"release_commit": "not-a-sha"},
        {"deployment_id": "BAD"},
        {"evidence_bucket": "bad/bucket"},
    ),
)
def test_release_binding_rejects_ambiguous_identifiers(changes: dict[str, str]) -> None:
    values = {
        "project_id": PROJECT,
        "release_commit": COMMIT,
        "deployment_id": DEPLOYMENT,
        "evidence_bucket": BUCKET,
        **changes,
    }
    with pytest.raises(ValueError, match="release projection"):
        CloudReleaseBinding(**values)


class ListingSession(FakeSession):
    def __init__(self, listing: object) -> None:
        super().__init__({})
        self.listing = listing

    def get(self, url: str, **kwargs: Any) -> JsonResponse:
        if "params" in kwargs:
            return FakeResponse(self.listing)
        return super().get(url, **kwargs)


def test_projection_rejects_malformed_or_unbounded_object_listings() -> None:
    binding = CloudReleaseBinding(PROJECT, COMMIT, DEPLOYMENT, BUCKET)
    malformed = GcsReleaseProjection(binding=binding, session=ListingSession({"items": {}}))
    with pytest.raises(RuntimeError, match="malformed"):
        malformed._list_names("scenarios/x/")

    unbounded = GcsReleaseProjection(
        binding=binding,
        session=ListingSession({"items": [{"name": f"scenarios/x/{n}"} for n in range(100)]}),
    )
    with pytest.raises(RuntimeError, match="bounded release view"):
        unbounded._list_names("scenarios/x/")
