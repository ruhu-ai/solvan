import copy
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from solvan.application.default_tool_catalog import (
    AGENT_PROFILE_KEYS,
    INTERNAL_PROVIDERS,
    TOOL_SEEDS,
    alert_triage_profile,
    catalog_principals,
    catalog_profile,
    catalog_tools,
)
from solvan.application.effective_tool_set import (
    EffectiveToolSetError,
    EffectiveToolSetV1,
    validate_effective_tool_set_at_boundary,
)
from solvan.application.tool_catalog import (
    SOURCE_CONNECTION_PAIRS,
    CapabilityProbe,
    CatalogLifecycle,
    CatalogPrincipal,
    EvidenceKind,
    ExecutionRole,
    IdempotencyKind,
    ImplementationKind,
    ModelArmorCoverage,
    NoDataSemantics,
    PermissionClass,
    ProfileResolutionContext,
    RegistryKind,
    ToolCatalog,
    ToolCatalogError,
    ToolConnectionBindingKind,
    ToolConnectionRequirement,
    ToolProfileRevision,
    ToolRevision,
)
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore
from tools.generate_alert_hash_vectors import _replacement, _set_path

HASH = f"sha256:{'1' * 64}"
NOW = datetime(2026, 8, 10, tzinfo=UTC)


def tool(**changes: object) -> ToolRevision:
    values: dict[str, object] = {
        "tool_key": "managed_prometheus_query",
        "version": "1",
        "display_name": "Managed Prometheus query",
        "description": "Run one registered metric template.",
        "use_cases": ("Read a bounded service metric",),
        "anti_use_cases": ("Arbitrary PromQL",),
        "owner_department": "Reliability Platform",
        "permission_class": PermissionClass.READ,
        "implementation_kind": ImplementationKind.CONNECTOR,
        "allowed_requester_keys": ("evidence-agent",),
        "required_capabilities": ("METRIC_READ",),
        "required_connection_providers": ("CLOUD_MONITORING",),
        "input_schema_ref": "schema://managed-prometheus/input/1",
        "input_schema_hash": HASH,
        "output_schema_ref": "schema://managed-prometheus/output/1",
        "output_schema_hash": HASH,
        "evidence_kind": EvidenceKind.METRICS,
        "output_semantics": ("bounded time series",),
        "supported_retrieval_controls": ("registered_template", "bounded_window"),
        "no_data_semantics": NoDataSemantics.UNKNOWN,
        "failure_taxonomy": ("NO_DATA", "PERMISSION_DENIED"),
        "supported_data_classes": ("INTERNAL",),
        "runtime_regions": ("europe-west1",),
        "gateway_destination": "monitoring.googleapis.com",
        "registry_resource": "projects/p/locations/europe-west1/tools/managed-prometheus",
        "model_armor_coverage": ModelArmorCoverage.NOT_APPLICABLE,
        "network_policy_hash": HASH,
        "timeout_ms": 10_000,
        "max_input_bytes": 4096,
        "max_output_bytes": 65_536,
        "default_call_budget": 3,
        "idempotency": IdempotencyKind.NOT_APPLICABLE,
        "lifecycle": CatalogLifecycle.APPROVED,
        "approval_ref": "approval://tool/1",
        "evaluation_ref": "evaluation://tool/1",
    }
    values.update(changes)
    return ToolRevision.model_validate(values)


def profile(**changes: object) -> ToolProfileRevision:
    values: dict[str, object] = {
        "profile_key": "evidence.ruhu-observability.v1",
        "version": "1",
        "purpose": "Investigate Ruhu telemetry",
        "allowed_agent_key": "evidence-agent",
        "tool_revisions": ("managed_prometheus_query@1",),
        "maximum_total_calls": 3,
        "maximum_parallel_calls": 1,
        "tool_connection_requirements": (
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="managed_prometheus_query@1",
                binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                provider="CLOUD_MONITORING",
                capability_key="METRIC_READ",
                external_project_selector="TARGET_RESOURCE_PROJECT",
            ),
        ),
        "data_classification_ceiling": "INTERNAL",
        "runtime_region": "europe-west1",
        "lifecycle": CatalogLifecycle.APPROVED,
        "approval_ref": "approval://profile/1",
        "evaluation_ref": "evaluation://profile/1",
    }
    values.update(changes)
    return ToolProfileRevision.model_validate(values)


def catalog(*, expiry: datetime | None = None) -> ToolCatalog:
    principal = CatalogPrincipal(
        principal_key="evidence-agent",
        display_name="Evidence Agent",
        registry_kind=RegistryKind.AGENT,
        execution_role=ExecutionRole.SPECIALIST,
        model_backed=True,
        manifest_hash=HASH,
    )
    probe = CapabilityProbe(
        connection_id="ruhu-prod-europe-west1",
        tool_revision="managed_prometheus_query@1",
        agent_key="evidence-agent",
        connection_provider="CLOUD_MONITORING",
        capabilities=frozenset({"METRIC_READ"}),
        connection_epoch=7,
        identity_ref="identity://evidence-agent/21",
        registry_resource="registry://managed-prometheus/1",
        gateway_policy_ref="gateway://policy/12",
        network_policy_hash=HASH,
        region="europe-west1",
        classification_ceiling="INTERNAL",
        outcome="PASSED",
        observed_at=NOW - timedelta(minutes=1),
        expires_at=expiry or NOW + timedelta(minutes=4),
        receipt_ref="receipt://probe/1",
        receipt_hash=HASH,
    )
    return ToolCatalog(principals=(principal,), tools=(tool(),), probes=(probe,))


def context(**changes: object) -> ProfileResolutionContext:
    values: dict[str, object] = {
        "agent_key": "evidence-agent",
        "agent_revision": "evidence-agent@1",
        "scope": {
            "organization_id": "org_a",
            "project_id": "project_a",
            "environment_id": "env_prod",
        },
        "identity_ref": "identity://evidence-agent/21",
        "identity_verified": True,
        "runtime_region": "europe-west1",
        "data_classification": "INTERNAL",
        "connection_epochs": {"ruhu-prod-europe-west1": 7},
        "registered_gateway_destinations": frozenset({"monitoring.googleapis.com"}),
        "target_external_project_id": "project_a",
        "placement_epoch": 1,
        "accepted_step_budget_hash": HASH,
        "now": NOW,
    }
    values.update(changes)
    return ProfileResolutionContext.model_validate(values)


def test_resolves_exact_approved_profile_and_hash() -> None:
    resolved = catalog().resolve(profile=profile(), context=context())
    assert resolved.ordered_tool_revisions == ("managed_prometheus_query@1",)
    assert resolved.effective_tool_set_hash.startswith("sha256:")


def _compute_tool() -> ToolRevision:
    return tool(
        tool_key="evidence_window_compare",
        description="Compare two bounded evidence windows.",
        gateway_destination="solvan-evidence.internal",
    )


def test_a_mixed_source_and_compute_profile_resolves() -> None:
    """The canonical profiles mix one source-bound Tool with compute-only ones.

    Refusing the compute half whenever connections exist rejected every real
    profile, while the production SQL binder accepts exactly this shape.
    """

    base = catalog()
    mixed_catalog = ToolCatalog(
        principals=tuple(base._principals.values()),
        tools=(tool(), _compute_tool()),
        probes=tuple(base._probes.values()),
    )
    mixed = profile(
        tool_revisions=("managed_prometheus_query@1", "evidence_window_compare@1"),
        tool_connection_requirements=(
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="managed_prometheus_query@1",
                binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                provider="CLOUD_MONITORING",
                capability_key="METRIC_READ",
                external_project_selector="TARGET_RESOURCE_PROJECT",
            ),
            ToolConnectionRequirement(
                ordinal=2,
                tool_revision="evidence_window_compare@1",
                binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
            ),
        ),
    )
    resolved = mixed_catalog.resolve(
        profile=mixed,
        context=context(
            registered_gateway_destinations=frozenset(
                {"monitoring.googleapis.com", "solvan-evidence.internal"}
            )
        ),
    )
    assert resolved.ordered_tool_revisions == (
        "managed_prometheus_query@1",
        "evidence_window_compare@1",
    )


def test_a_policy_bound_profile_matches_the_run_region() -> None:
    """POLICY_BOUND takes its region from the bound connection, not the run."""

    bound = profile(runtime_region="POLICY_BOUND")
    resolved = catalog().resolve(profile=bound, context=context())
    assert resolved.ordered_tool_revisions == ("managed_prometheus_query@1",)


def test_effective_tool_set_v1_reproduces_the_published_alert_vector() -> None:
    vectors = yaml.safe_load(
        Path("specs/artifacts/alert-triage-profile-hash-vectors.yaml").read_text()
    )
    published = next(item for item in vectors["vectors"] if item["kind"] == "effective_tool_set")
    material = EffectiveToolSetV1.model_validate(json.loads(published["canonical_json"]))
    assert material.effective_tool_set_hash == published["expected_hash"]


def test_gateway_rejects_every_published_effective_set_mutation() -> None:
    vectors = yaml.safe_load(
        Path("specs/artifacts/alert-triage-profile-hash-vectors.yaml").read_text()
    )
    published = next(item for item in vectors["vectors"] if item["kind"] == "effective_tool_set")
    base = json.loads(published["canonical_json"])
    expected_hash = str(published["expected_hash"])
    accepted = validate_effective_tool_set_at_boundary(
        material=base,
        expected_hash=expected_hash,
        expected_agent_key="evidence-agent",
        expected_tool_key="cloud_monitoring_query",
    )
    assert accepted.effective_tool_set_hash == expected_hash

    configured = vectors["mutation_values"]["effective_tool_set"]
    for vector in (
        item for item in vectors["mutation_vectors"] if item["base"] == "effective_tool_set"
    ):
        field = str(vector["field"])
        mutated = copy.deepcopy(base)
        _set_path(mutated, field, _replacement(field, configured))
        with pytest.raises(EffectiveToolSetError, match="effective Tool set"):
            validate_effective_tool_set_at_boundary(
                material=mutated,
                expected_hash=expected_hash,
                expected_agent_key="evidence-agent",
                expected_tool_key="cloud_monitoring_query",
            )


@pytest.mark.parametrize(
    ("profile_changes", "message"),
    [
        ({"tool_revisions": ("*",)}, "exact Tool revision"),
    ],
)
def test_profile_rejects_wildcard_or_implicit_connection(
    profile_changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        profile(**profile_changes)


def test_model_profile_rejects_mutation_revision() -> None:
    mutation = tool(
        permission_class=PermissionClass.MUTATE,
        implementation_kind=ImplementationKind.DETERMINISTIC_SERVICE,
    )
    base = catalog()
    base._tools[mutation.revision_ref] = mutation  # type: ignore[attr-defined]
    with pytest.raises(ToolCatalogError, match="cannot contain MUTATE"):
        base.resolve(profile=profile(), context=context())


def test_tool_less_profile_is_an_explicit_zero_budget_binding() -> None:
    resolved = catalog().resolve(
        profile=profile(
            tool_revisions=(),
            tool_connection_requirements=(),
            maximum_total_calls=0,
            maximum_parallel_calls=0,
        ),
        context=context(connection_epochs={}),
    )
    assert resolved.ordered_tool_revisions == ()
    assert resolved.connection_epochs == {}


def test_stale_probe_or_connection_epoch_refuses_dispatch() -> None:
    with pytest.raises(ToolCatalogError, match="stale or failed"):
        catalog(expiry=NOW).resolve(profile=profile(), context=context())
    with pytest.raises(ToolCatalogError, match="stale connection epoch"):
        catalog().resolve(
            profile=profile(), context=context(connection_epochs={"ruhu-prod-europe-west1": 8})
        )


def test_unregistered_gateway_and_wrong_identity_refuse_dispatch() -> None:
    with pytest.raises(ToolCatalogError, match="Gateway route"):
        catalog().resolve(
            profile=profile(),
            context=context(registered_gateway_destinations=frozenset()),
        )
    with pytest.raises(ToolCatalogError, match="another identity"):
        catalog().resolve(profile=profile(), context=context(identity_ref="identity://wrong"))


def test_run_classification_cannot_exceed_the_profile_ceiling() -> None:
    with pytest.raises(ToolCatalogError, match="exceeds the Tool profile ceiling"):
        catalog().resolve(
            profile=profile(),
            context=context(data_classification="CONFIDENTIAL"),
        )


def test_compute_only_tools_still_require_classification_region_and_gateway() -> None:
    compute = tool(
        tool_key="metric_baseline_compare",
        permission_class=PermissionClass.COMPUTE,
        implementation_kind=ImplementationKind.DETERMINISTIC_SERVICE,
        required_capabilities=("COMPUTE",),
        required_connection_providers=("SOLVAN_INTERNAL",),
        gateway_destination="compute.internal",
        supported_data_classes=("INTERNAL",),
    )
    compute_profile = profile(
        tool_revisions=("metric_baseline_compare@1",),
        tool_connection_requirements=(
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="metric_baseline_compare@1",
                binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
            ),
        ),
        maximum_total_calls=1,
        maximum_parallel_calls=1,
        data_classification_ceiling="CONFIDENTIAL",
    )
    base = catalog()
    base._tools[compute.revision_ref] = compute  # type: ignore[attr-defined]
    compute_context = context(
        connection_epochs={},
        registered_gateway_destinations=frozenset({"compute.internal"}),
    )
    resolved = base.resolve(profile=compute_profile, context=compute_context)
    assert resolved.ordered_tool_revisions == ("metric_baseline_compare@1",)
    with pytest.raises(ToolCatalogError, match="does not support the run classification"):
        base.resolve(
            profile=compute_profile,
            context=context(
                connection_epochs={},
                data_classification="CONFIDENTIAL",
                registered_gateway_destinations=frozenset({"compute.internal"}),
            ),
        )
    with pytest.raises(ToolCatalogError, match="registered Gateway route"):
        base.resolve(
            profile=compute_profile,
            context=context(connection_epochs={}, registered_gateway_destinations=frozenset()),
        )


def test_default_catalog_is_exact_complete_and_requires_connections() -> None:
    principals = catalog_principals(manifest_hash=HASH)
    tools = catalog_tools(
        network_policy_hash=HASH,
        approval_ref="approval://catalog/1",
        evaluation_ref="evaluation://catalog/1",
    )
    assert {principal.principal_key for principal in principals} == set(AGENT_PROFILE_KEYS)
    assert {revision.tool_key for revision in tools} == {seed.key for seed in TOOL_SEEDS}
    assert len(tools) == len({revision.content_hash for revision in tools})
    supervisor = catalog_profile(
        agent_key="incident-supervisor",
        approval_ref="approval://catalog/1",
        evaluation_ref="evaluation://catalog/1",
    )
    assert supervisor.tool_revisions == ()
    assert supervisor.maximum_total_calls == supervisor.maximum_parallel_calls == 0
    workspace = catalog_profile(
        agent_key="workspace-agent",
        approval_ref="approval://catalog/1",
        evaluation_ref="evaluation://catalog/1",
    )
    assert workspace.profile_ref == "workspace.code-repair.v1@1"
    assert workspace.tool_revisions == (
        "workspace.code-repair.read-artifact@1",
        "workspace.code-repair.write-candidate-artifact@1",
        "workspace.code-repair.run-in-sandbox@1",
    )
    assert workspace.maximum_total_calls == 104
    assert workspace.maximum_parallel_calls == 1
    assert workspace.maximum_read_window_ms == 0
    alert_profile = alert_triage_profile(
        approval_ref="approval://catalog/1",
        evaluation_ref="evaluation://catalog/1",
    )
    assert alert_profile.profile_ref == "alert-triage-read-compute-v1@1"
    assert alert_profile.tool_revisions == (
        "cloud_monitoring_query@1",
        "metric_baseline_compare@1",
        "metric_change_point_detect@1",
        "metric_correlate@1",
    )
    assert alert_profile.runtime_region == "POLICY_BOUND"


def test_later_release_gate_reuses_only_identical_tool_revision_material() -> None:
    original = catalog_tools(
        network_policy_hash=HASH,
        approval_ref="approval://catalog/1",
        evaluation_ref="evaluation://catalog/1",
    )[0]
    later_release = original.model_copy(
        update={
            "approval_ref": "approval://catalog/2",
            "evaluation_ref": "evaluation://catalog/2",
        }
    )

    assert PostgresToolCatalogStore._same_tool_revision_material(
        later_release,
        content_hash=original.content_hash,
        approval_ref=original.approval_ref,
        evaluation_ref=original.evaluation_ref,
    )
    assert not PostgresToolCatalogStore._same_tool_revision_material(
        later_release.model_copy(update={"description": "changed immutable meaning"}),
        content_hash=original.content_hash,
        approval_ref=original.approval_ref,
        evaluation_ref=original.evaluation_ref,
    )


def _ddl_source_connection_pairs() -> set[tuple[str, str]]:
    """Read the pairs the authoritative CHECK constraint actually admits."""

    ddl = (
        Path(__file__).resolve().parents[2]
        / "specs"
        / "artifacts"
        / "operability-schema.target.sql"
    ).read_text(encoding="utf-8")
    _, _, after = ddl.partition("CREATE TABLE tool_profile_connection_requirements")
    _, _, pairs = after.partition("(provider,capability_key) IN")
    clause, _, _ = pairs.partition("external_project_selector = 'TARGET_RESOURCE_PROJECT'")
    return set(re.findall(r"\('([A-Z_]+)','([A-Z_]+)'\)", clause))


def test_source_connection_pairs_match_the_authoritative_ddl() -> None:
    """One closed pair table, or a profile this layer accepts cannot be stored.

    These lists drifted in opposite directions: the typed model admitted
    MANAGED_PROMETHEUS/PROMQL_READ and KUBERNETES/KUBERNETES_METADATA_READ,
    which the schema refuses, and omitted four pairs the schema admits, so the
    canonical catalog could neither be published nor state the bindings it
    needed. Comparing them here fails the drift rather than the deployment.
    """

    assert set(SOURCE_CONNECTION_PAIRS.items()) == _ddl_source_connection_pairs()


def test_canonical_profiles_never_publish_unfenced_external_reach() -> None:
    """A connector Tool is either source-bound or absent, never compute-only.

    A COMPUTE_ONLY effective binding carries no connection, epoch, capability
    receipt, or external project, so declaring an external connector that way
    publishes reach that nothing fences. A connector whose provider has no
    admissible closed pair stays registered in the catalog and out of every
    profile instead.
    """

    seed_by_key = {seed.key: seed for seed in TOOL_SEEDS}
    published: set[str] = set()
    for agent_key in AGENT_PROFILE_KEYS:
        profile = catalog_profile(
            agent_key=agent_key,
            approval_ref="approval://catalog/1",
            evaluation_ref="evaluation://catalog/1",
        )
        assert len(profile.tool_connection_requirements) == len(profile.tool_revisions)
        for requirement in profile.tool_connection_requirements:
            seed = seed_by_key[requirement.tool_revision.removesuffix("@1")]
            published.add(seed.key)
            if requirement.binding_kind is ToolConnectionBindingKind.COMPUTE_ONLY:
                assert (
                    seed.permission is PermissionClass.COMPUTE
                    or seed.provider in INTERNAL_PROVIDERS
                ), f"{seed.key} reaches {seed.provider} with no connection fence"
            else:
                assert requirement.provider == seed.provider
                assert requirement.capability_key == SOURCE_CONNECTION_PAIRS[seed.provider]
    unpublishable = {
        seed.key
        for seed in TOOL_SEEDS
        if seed.permission is not PermissionClass.COMPUTE
        and seed.provider not in INTERNAL_PROVIDERS
        and seed.provider not in SOURCE_CONNECTION_PAIRS
    }
    assert published.isdisjoint(unpublishable)
    assert unpublishable == {
        "cloud_asset_inventory_search",
        "cloud_build_history_read",
        "github_commit_history_read",
        "github_commit_range_read",
        "github_deployments_read",
        "github_discussions_read",
        "github_issue_read",
        "github_merge_queue_read",
        "github_pr_diff_read",
        "github_repository_tree_read",
        "github_search_read",
        "github_workflow_runs_read",
        "github_workflow_run_read",
    }
