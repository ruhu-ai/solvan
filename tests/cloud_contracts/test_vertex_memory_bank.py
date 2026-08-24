"""Provider contracts: what Vertex Memory Bank actually does.

Every failure in the 2026-08-23/24 staging campaign crossed the same seam:
Google behavior no local harness models. Scope maximum of five key-value
pairs, resources named with the project number, a distinct permission for
the follow-up get. Each cost a full deploy cycle to discover; each is
pinned here as a laptop-runnable test against the real API, so the next
change to the memory path learns the provider's rules before any deploy.

Gated on SOLVAN_CLOUD_CONTRACT_PROJECT; runs under the operator's ADC.
Never part of scripts/check: these calls cost real quota and need real
credentials. Run through scripts/check-cloud-contracts, which refuses a
run in which everything skipped.
"""

from __future__ import annotations

import os
import uuid

import pytest

PROJECT = os.environ.get("SOLVAN_CLOUD_CONTRACT_PROJECT")
REGION = os.environ.get("SOLVAN_CLOUD_CONTRACT_REGION", "europe-west1")

pytestmark = pytest.mark.skipif(
    not PROJECT, reason="requires SOLVAN_CLOUD_CONTRACT_PROJECT and operator ADC"
)


@pytest.fixture(scope="module")
def engine_resource() -> str:
    """One live Solvan reasoning engine, discovered rather than configured."""

    import google.auth
    import google.auth.transport.requests
    import requests

    credentials, _ = google.auth.default()
    credentials.refresh(google.auth.transport.requests.Request())
    listing = requests.get(
        f"https://{REGION}-aiplatform.googleapis.com/v1/projects/{PROJECT}/"
        f"locations/{REGION}/reasoningEngines?pageSize=50",
        headers={"Authorization": f"Bearer {credentials.token}"},
        timeout=30,
    )
    listing.raise_for_status()
    engines = [
        item["name"]
        for item in listing.json().get("reasoningEngines", [])
        if "solvan-incident-supervisor" in item.get("displayName", "")
    ]
    if not engines:
        pytest.skip("no deployed solvan supervisor engine to test against")
    return sorted(engines)[-1]


def _bank(engine_resource: str):
    from solvan.platform.memory_bank import (
        GeminiMemoryBank,
        MemoryBankConfiguration,
        VertexMemoryAPI,
    )

    project_number = engine_resource.split("/")[1]
    engine_id = engine_resource.rsplit("/", 1)[-1]
    config = MemoryBankConfiguration(PROJECT, REGION, engine_id, project_number=project_number)
    return GeminiMemoryBank(config=config, api=VertexMemoryAPI(project=PROJECT, location=REGION))


def test_scope_of_six_pairs_is_refused_on_create_not_retrieve(engine_resource: str) -> None:
    """The five-pair maximum, pinned where it actually binds. First live run
    of this tier taught the precise shape: retrieve accepts six pairs (200);
    only create refuses them -- which is exactly the operation the staging
    memory probe died on (staging-20260823-09). Solvan folds classification
    and region into one composite pair because of this create-side limit."""

    import google.auth
    import google.auth.transport.requests
    import requests

    credentials, _ = google.auth.default()
    credentials.refresh(google.auth.transport.requests.Request())
    headers = {"Authorization": f"Bearer {credentials.token}"}
    base = f"https://{REGION}-aiplatform.googleapis.com/v1/{engine_resource}"
    six = {f"key_{i}": "v" for i in range(6)}

    retrieve = requests.post(
        f"{base}/memories:retrieve", headers=headers, json={"scope": six}, timeout=30
    )
    assert retrieve.status_code == 200, (
        "retrieve now also enforces the pair limit; update the platform note: "
        + retrieve.text[:200]
    )

    create = requests.post(
        f"{base}/memories",
        headers=headers,
        json={"fact": "provider contract pin: pair limit", "scope": six},
        timeout=30,
    )
    assert create.status_code == 400, create.text[:200]
    assert "5" in create.json()["error"]["message"]


def test_created_memories_are_named_with_the_project_number(engine_resource: str) -> None:
    """The number-vs-ID spelling, pinned where it actually bit: a created
    memory's resource name. Three layers of Solvan validation tripped on this
    one behavior across two days."""

    from solvan.domain import Scope
    from solvan.domain.memory import MemoryScope

    bank = _bank(engine_resource)
    scope = MemoryScope(
        Scope(
            "org_00000000000000000000000000",
            "prj_00000000000000000000000000",
            "env_00000000000000000000000000",
        ),
        f"cloud-contract-{uuid.uuid4().hex[:8]}",
        "INTERNAL",
        REGION,
    )
    receipt = bank.upsert_exact(
        exact_scope=scope, fact_text="provider contract pin: naming spelling"
    )
    number = engine_resource.split("/")[1]
    assert receipt.memory_resource.startswith(f"projects/{number}/"), receipt.memory_resource
    assert number.isdigit(), "engine listing itself returned the ID spelling"
