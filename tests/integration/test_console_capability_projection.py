"""Phase 0: what the Capabilities & Policy projection must say, against real PostgreSQL 16.

The shipped table renders one row per *declared requester* and one verdict per
*Tool*, derived from `lifecycle == APPROVED and a fresh probe exists`. Three
things follow, and all three are visible on the screen an operator consults to
learn what is actually allowed:

  * a `COMPUTE_ONLY` Tool can never obtain a probe — `tool_probe_receipts`
    references `tenant_connections` and an internal provider has no connection —
    so nine rows, `execute_authorized_action` among them, read `Denied` forever;
  * five further rows are in no approved profile at all, which is a different
    fact wearing the same word;
  * probe receipts are keyed by `(connection, tool, version, agent)` in the
    schema and by `(tool, version)` in the projection, so one Agent's evidence
    silently decides another Agent's row.

Each test below states what the projection must answer instead. The contract is
`snapshot["fleet"]["capabilities"]`: one decision per `(agent, tool revision)`
carrying the ordered layer chain that produced it, so the cell can name the
layer that decided rather than reprinting the destination host.

These carried `xfail(strict=True)` while the projection was being built, so
the contract was recorded executably without turning the shared worktree's one
authoritative gate red for lanes that did not cause the defect. Strict is what
ended that state: the moment the projection satisfied them, the unexpected pass
failed the suite and the markers came off.

Governing records: specification 06 §Capabilities & Policy, specification 16 §5
and §10, PR-031, PR-032, PR-033.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest

from apps.api.console_projection import live_console_snapshot
from solvan.application.default_tool_catalog import (
    AGENT_PROFILE_KEYS,
    catalog_principals,
    catalog_profile,
    catalog_tools,
)
from solvan.application.tool_catalog import (
    CapabilityProbe,
    CatalogLifecycle,
    EvidenceKind,
    IdempotencyKind,
    ImplementationKind,
    ModelArmorCoverage,
    NoDataSemantics,
    PermissionClass,
    ToolConnectionBindingKind,
    ToolConnectionRequirement,
    ToolProfileRevision,
    ToolRevision,
)
from solvan.domain import Scope
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
CONNECTION_ID = "con_01J4QZK8Q4J8Q6B95KQY4M9R2S"
HASH = f"sha256:{'a' * 64}"
MANIFEST_HASH = f"sha256:{'e' * 64}"
LOCAL_APPROVAL_REF = "approval://local/phase-0"
LOCAL_EVALUATION_REF = "evaluation://local/phase-0"

#: The one row whose wrong answer matters most. It is `PROPOSE` against the
#: private actuator, it binds no external connection, and the console will keep
#: calling it `Denied` after the actuator is deployed and its profile is live —
#: a safety claim about production mutation that no record supports.
ACTUATOR_TOOL = "execute_authorized_action"
#: Registered in the catalog and, by `profile_eligible`, in no profile: there is
#: no closed provider/capability pair for GitHub, so the requirement cannot be
#: stated exactly and the Tool stays out of every profile by design.
UNPROFILED_TOOL = "github_pr_diff_read"


@pytest.fixture
def connection() -> Iterator[psycopg.Connection[Any]]:
    assert DATABASE_URL is not None
    with (
        psycopg.connect(DATABASE_URL) as database,
        database.transaction(force_rollback=True),
    ):
        database.execute(
            """INSERT INTO solvan.organizations(id,display_name)
               VALUES (%s,'Test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id,),
        )
        database.execute(
            """INSERT INTO solvan.projects
                 (organization_id,id,display_name,gcp_project_id)
               VALUES (%s,%s,'Test','solvan-test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        database.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Test','europe-west1','INTERNAL')
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        database.execute(
            """INSERT INTO solvan.tenant_connections
                 (organization_id,project_id,environment_id,id,display_name,kind,
                  provider,credential_posture,residency_region,classification,
                  lifecycle,availability,availability_reason_code,
                  availability_explanation,availability_remediation_kind,
                  availability_receipt_ref,last_probe_at,last_probe_result,
                  created_by_principal)
               VALUES (%s,%s,%s,%s,'Ruhu metrics','GCP_NATIVE',
                       'CLOUD_MONITORING','CUSTOMER_SIDE_NONE','europe-west1',
                       'INTERNAL','ENABLED','READY',NULL,NULL,NULL,'probe://seed',
                       now(),'SUCCEEDED','user:test@example.com')
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, CONNECTION_ID),
        )
        yield database


def _publish_release_catalog(database: psycopg.Connection[Any]) -> None:
    """Publish exactly what a deployment publishes: same material, same store.

    `tools/release_admin.py` and `tools/bootstrap_local_database.py` both call
    these three functions, so the state under test is the state on the screen
    rather than a fixture shaped to agree with the assertion.
    """

    store = PostgresToolCatalogStore(database)
    for principal in catalog_principals(manifest_hash=MANIFEST_HASH):
        store.register_principal(principal)
    for tool in catalog_tools(
        network_policy_hash=HASH,
        approval_ref=LOCAL_APPROVAL_REF,
        evaluation_ref=LOCAL_EVALUATION_REF,
    ):
        store.publish_tool(tool)
    for agent_key in AGENT_PROFILE_KEYS:
        store.publish_profile(
            scope=SCOPE,
            profile=catalog_profile(
                agent_key=agent_key,
                approval_ref=LOCAL_APPROVAL_REF,
                evaluation_ref=LOCAL_EVALUATION_REF,
                classification_ceiling="INTERNAL",
            ),
        )


def _capabilities(database: psycopg.Connection[Any]) -> list[dict[str, Any]]:
    snapshot = live_console_snapshot(database, scope=SCOPE)
    rows = snapshot["fleet"].get("capabilities")
    assert isinstance(rows, list), (
        "the fleet projection exposes no capability decisions; the console still "
        "derives an operator-facing permission from probe freshness alone"
    )
    return rows


def _decision(rows: list[dict[str, Any]], *, agent_key: str, tool_key: str) -> dict[str, Any]:
    matches = [row for row in rows if (row["agent_key"], row["tool_key"]) == (agent_key, tool_key)]
    assert len(matches) == 1, f"expected exactly one decision for {agent_key}/{tool_key}"
    return matches[0]


def _layer(decision: dict[str, Any], layer: str) -> dict[str, Any]:
    matches = [item for item in decision["layers"] if item["layer"] == layer]
    assert len(matches) == 1, f"expected exactly one {layer} observation"
    return matches[0]


def test_a_compute_only_capability_is_not_denied_for_want_of_a_probe(
    connection: psycopg.Connection[Any],
) -> None:
    _publish_release_catalog(connection)
    decision = _decision(
        _capabilities(connection), agent_key="execution-agent", tool_key=ACTUATOR_TOOL
    )
    assert decision["verdict"] != "DENIED"
    assert _layer(decision, "CAPABILITY_PROBE")["state"] == "NOT_APPLICABLE"
    assert _layer(decision, "CONNECTION_BINDING")["state"] == "NOT_APPLICABLE"


def test_a_tool_outside_every_profile_reads_not_registered(
    connection: psycopg.Connection[Any],
) -> None:
    _publish_release_catalog(connection)
    rows = _capabilities(connection)
    unprofiled = _decision(rows, agent_key="infrastructure-agent", tool_key=UNPROFILED_TOOL)
    actuator = _decision(rows, agent_key="execution-agent", tool_key=ACTUATOR_TOOL)
    assert unprofiled["verdict"] == "NOT_REGISTERED"
    assert unprofiled["winning_layer"] == "PROFILE_MEMBERSHIP"
    # Two different facts must not print the same word: one Tool is offered to
    # nobody, the other is offered and simply not yet observed end to end.
    assert unprofiled["verdict"] != actuator["verdict"]


def test_the_matrix_counts_reach_rather_than_declaration(
    connection: psycopg.Connection[Any],
) -> None:
    """The same page must not answer this question twice, differently.

    The Agents tab already projects both numbers and shows the gap, because a
    Tool revision may name an Agent as an allowed requester while sitting in no
    approved profile. The capability matrix is built from the larger number.
    """

    _publish_release_catalog(connection)
    rows = _capabilities(connection)
    reachable = [
        row
        for row in rows
        if row["agent_key"] == "infrastructure-agent" and row["verdict"] != "NOT_REGISTERED"
    ]
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT count(*) FROM solvan_operability.tool_profile_members m
                 JOIN solvan_operability.tool_profile_revisions f
                   ON (f.profile_key, f.version) = (m.profile_key, m.profile_version)
                WHERE f.allowed_agent_key = 'infrastructure-agent'
                  AND f.lifecycle = 'APPROVED'"""
        )
        row = cursor.fetchone()
    assert row is not None
    assert len(reachable) == int(row[0])


def test_a_probe_decides_only_the_agent_it_was_written_for(
    connection: psycopg.Connection[Any],
) -> None:
    """Receipts are per `(connection, tool, version, agent)`; the console keys on two of the four.

    With two Agents holding the same Tool, one passing receipt currently decides
    both rows — the matrix answers a per-Agent question with another Agent's
    evidence.
    """

    store = PostgresToolCatalogStore(connection)
    for principal in catalog_principals(manifest_hash=MANIFEST_HASH):
        store.register_principal(principal)
    store.publish_tool(_dual_requester_tool())
    for agent_key, profile_key in (
        ("evidence-agent", "evidence.dual-requester.v1"),
        ("infrastructure-agent", "infrastructure.dual-requester.v1"),
    ):
        store.publish_profile(
            scope=SCOPE, profile=_dual_requester_profile(agent_key=agent_key, key=profile_key)
        )
    observed = datetime.now(UTC) - timedelta(minutes=1)
    receipt = "receipt://probe/evidence-agent"
    store.record_probe(
        scope=SCOPE,
        probe=CapabilityProbe(
            connection_id=CONNECTION_ID,
            tool_revision="fixture_dual_requester_read@1",
            agent_key="evidence-agent",
            connection_provider="CLOUD_MONITORING",
            capabilities=frozenset({"monitoring.timeSeries.list"}),
            connection_epoch=1,
            identity_ref="identity://evidence-agent/1",
            registry_resource="registry://fixture/dual-requester/1",
            gateway_policy_ref="gateway://policy/1",
            network_policy_hash=HASH,
            region="europe-west1",
            classification_ceiling="INTERNAL",
            outcome="PASSED",
            observed_at=observed,
            expires_at=observed + timedelta(minutes=30),
            receipt_ref=receipt,
            receipt_hash=HASH,
        ),
    )
    rows = _capabilities(connection)
    borrower = _decision(
        rows, agent_key="infrastructure-agent", tool_key="fixture_dual_requester_read"
    )
    assert borrower["verdict"] != "ALLOWED"
    assert _layer(borrower, "CAPABILITY_PROBE")["reference"] != receipt


def test_an_expired_passing_probe_never_renders_none_as_its_reason(
    connection: psycopg.Connection[Any],
) -> None:
    """A `PASSED` receipt carries no reason by schema CHECK, so the fallback prints `str(None)`.

    An operator reading `Why: None` beside a refused capability is being shown a
    Python repr where a reason belongs. This one is red against the code as it
    stands rather than against a projection that does not exist yet.
    """

    _publish_release_catalog(connection)
    observed = datetime.now(UTC) - timedelta(hours=2)
    PostgresToolCatalogStore(connection).record_probe(
        scope=SCOPE,
        probe=CapabilityProbe(
            connection_id=CONNECTION_ID,
            tool_revision="cloud_monitoring_query@1",
            agent_key="evidence-agent",
            connection_provider="CLOUD_MONITORING",
            capabilities=frozenset({"monitoring.timeSeries.list"}),
            connection_epoch=1,
            identity_ref="identity://evidence-agent/1",
            registry_resource="registry://solvan/tools/cloud_monitoring_query@1",
            gateway_policy_ref="gateway://policy/1",
            network_policy_hash=HASH,
            region="europe-west1",
            classification_ceiling="INTERNAL",
            outcome="PASSED",
            observed_at=observed,
            expires_at=observed + timedelta(hours=1),
            receipt_ref="receipt://probe/expired",
            receipt_hash=HASH,
        ),
    )
    snapshot = live_console_snapshot(connection, scope=SCOPE)
    stale = [tool for tool in snapshot["fleet"]["tools"] if tool["key"] == "cloud_monitoring_query"]
    assert stale, "the seeded catalog must project cloud_monitoring_query"
    for tool in stale:
        assert tool["why"] != "None"
        assert tool["next_step"] != "None"


def test_no_capability_reads_allowed_without_cloud_evidence(
    connection: psycopg.Connection[Any],
) -> None:
    """The invariant the whole phase protects, asserted over the real catalog.

    Nothing in this scope has a Gateway route receipt or a deployed Agent
    Identity, so no capability may claim `ALLOWED` — whatever else the fix
    changes, it must not widen the screen's claim to close the gap it opens by
    removing the false denials.
    """

    _publish_release_catalog(connection)
    for decision in _capabilities(connection):
        assert decision["verdict"] != "ALLOWED"
        assert decision["winning_layer"], "every decision names the layer that decided it"


def _dual_requester_tool() -> ToolRevision:
    return ToolRevision(
        tool_key="fixture_dual_requester_read",
        version="1",
        display_name="Fixture dual requester read",
        description="Read one bounded metric series on behalf of two Agents.",
        use_cases=("Read service telemetry",),
        anti_use_cases=("Execute arbitrary PromQL",),
        owner_department="Reliability Platform",
        permission_class=PermissionClass.READ,
        implementation_kind=ImplementationKind.CONNECTOR,
        allowed_requester_keys=("evidence-agent", "infrastructure-agent"),
        required_capabilities=("monitoring.timeSeries.list",),
        required_connection_providers=("CLOUD_MONITORING",),
        input_schema_ref="schema://fixture/dual-requester/input/1",
        input_schema_hash=HASH,
        output_schema_ref="schema://fixture/dual-requester/output/1",
        output_schema_hash=HASH,
        evidence_kind=EvidenceKind.METRICS,
        output_semantics=("bounded time series",),
        supported_retrieval_controls=("bounded_window",),
        no_data_semantics=NoDataSemantics.UNKNOWN,
        failure_taxonomy=("NO_DATA", "PERMISSION_DENIED"),
        supported_data_classes=("INTERNAL",),
        runtime_regions=("europe-west1",),
        gateway_destination="monitoring.googleapis.com",
        registry_resource="registry://fixture/dual-requester/1",
        model_armor_coverage=ModelArmorCoverage.NOT_APPLICABLE,
        network_policy_hash=HASH,
        timeout_ms=10_000,
        max_input_bytes=4096,
        max_output_bytes=65_536,
        default_call_budget=3,
        idempotency=IdempotencyKind.NOT_APPLICABLE,
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref=LOCAL_APPROVAL_REF,
        evaluation_ref=LOCAL_EVALUATION_REF,
    )


def _dual_requester_profile(*, agent_key: str, key: str) -> ToolProfileRevision:
    return ToolProfileRevision(
        profile_key=key,
        version="1",
        purpose="Read bounded telemetry for one investigation step",
        allowed_agent_key=agent_key,
        tool_revisions=("fixture_dual_requester_read@1",),
        maximum_total_calls=3,
        maximum_parallel_calls=1,
        tool_connection_requirements=(
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="fixture_dual_requester_read@1",
                binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                provider="CLOUD_MONITORING",
                capability_key="METRIC_READ",
                external_project_selector="TARGET_RESOURCE_PROJECT",
            ),
        ),
        data_classification_ceiling="INTERNAL",
        runtime_region="europe-west1",
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref=LOCAL_APPROVAL_REF,
        evaluation_ref=LOCAL_EVALUATION_REF,
    )
