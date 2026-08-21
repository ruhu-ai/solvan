"""Checked-in Solvan Tool catalog material used to seed immutable revisions.

This module contains capability metadata only.  It grants no connection,
identity, Gateway route, lifecycle approval, or Runtime authority.  Production
profiles are constructed separately from exact tenant connection instances and
external evaluation/approval receipts.
"""

from __future__ import annotations

from solvan.application.effective_tool_set import ToolConnectionBindingKind
from solvan.application.github_tool_seeds import GITHUB_TOOL_SEEDS
from solvan.application.tool_catalog import (
    SOURCE_CONNECTION_PAIRS,
    CatalogLifecycle,
    CatalogPrincipal,
    EvidenceKind,
    ExecutionRole,
    IdempotencyKind,
    ImplementationKind,
    ModelArmorCoverage,
    NoDataSemantics,
    PermissionClass,
    RegistryKind,
    ToolConnectionRequirement,
    ToolProfileRevision,
    ToolRevision,
)
from solvan.application.tool_seed import ToolSeed
from solvan.application.workspace_hashing import canonical_sha256

_READ = PermissionClass.READ
_COMPUTE = PermissionClass.COMPUTE
_CONNECTOR = ImplementationKind.CONNECTOR
_APPLICATION = ImplementationKind.APPLICATION_SERVICE

TOOL_SEEDS: tuple[ToolSeed, ...] = (
    ToolSeed(
        "cloud_monitoring_query",
        "evidence-agent",
        _READ,
        _CONNECTOR,
        "CLOUD_MONITORING",
        "monitoring.timeSeries.list",
        "monitoring.googleapis.com",
        EvidenceKind.METRICS,
        "Read one allowlisted service signal in a bounded window.",
        "bounded_window",
    ),
    ToolSeed(
        "managed_prometheus_query",
        "evidence-agent",
        _READ,
        _CONNECTOR,
        "MANAGED_PROMETHEUS",
        "monitoring.prometheus.query",
        "monitoring.googleapis.com",
        EvidenceKind.METRICS,
        "Run one registered PromQL template in a bounded window.",
        "registered_template",
    ),
    ToolSeed(
        "cloud_logging_query",
        "evidence-agent",
        _READ,
        _CONNECTOR,
        "CLOUD_LOGGING",
        "logging.entries.list",
        "logging.googleapis.com",
        EvidenceKind.LOGS,
        "Read one registered log signature.",
        "registered_signature",
    ),
    ToolSeed(
        "cloud_trace_read",
        "evidence-agent",
        _READ,
        _CONNECTOR,
        "CLOUD_TRACE",
        "cloudtrace.traces.get",
        "cloudtrace.googleapis.com",
        EvidenceKind.TRACES,
        "Read one incident-bound trace.",
        "exact_trace",
    ),
    ToolSeed(
        "kubernetes_metadata_read",
        "evidence-agent",
        _READ,
        _CONNECTOR,
        "KUBERNETES",
        "metadata.list",
        "customer Kubernetes API",
        EvidenceKind.TOPOLOGY,
        "Read namespace-bounded Kubernetes workload metadata only.",
        "policy_namespace_and_kind",
    ),
    ToolSeed(
        "cloud_audit_log_query",
        "evidence-agent",
        _READ,
        _CONNECTOR,
        "CLOUD_AUDIT",
        "logging.entries.list",
        "logging.googleapis.com",
        EvidenceKind.EVENTS,
        "Read bounded Admin Activity events.",
        "bounded_window",
    ),
    ToolSeed(
        "error_reporting_query",
        "evidence-agent",
        _READ,
        _CONNECTOR,
        "ERROR_REPORTING",
        "clouderrorreporting.groups.list",
        "clouderrorreporting.googleapis.com",
        EvidenceKind.LOGS,
        "Read bounded grouped error signatures.",
        "bounded_window",
    ),
    ToolSeed(
        "metric_baseline_compare",
        "evidence-agent",
        _COMPUTE,
        _APPLICATION,
        "CLOUD_MONITORING",
        "evidence.metric.compute",
        "solvan-evidence.internal",
        EvidenceKind.METRICS,
        "Compare two committed metric series.",
        "evidence_refs",
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
    ),
    ToolSeed(
        "metric_change_point_detect",
        "evidence-agent",
        _COMPUTE,
        _APPLICATION,
        "CLOUD_MONITORING",
        "evidence.metric.compute",
        "solvan-evidence.internal",
        EvidenceKind.METRICS,
        "Detect bounded mean-shift candidates.",
        "evidence_refs",
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
    ),
    ToolSeed(
        "metric_correlate",
        "evidence-agent",
        _COMPUTE,
        _APPLICATION,
        "CLOUD_MONITORING",
        "evidence.metric.compute",
        "solvan-evidence.internal",
        EvidenceKind.METRICS,
        "Correlate timestamp-aligned committed series.",
        "evidence_refs",
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
    ),
    ToolSeed(
        "log_pattern_summary",
        "evidence-agent",
        _COMPUTE,
        _APPLICATION,
        "CLOUD_LOGGING",
        "evidence.log.compute",
        "solvan-evidence.internal",
        EvidenceKind.LOGS,
        "Count registered signatures in committed logs.",
        "evidence_refs",
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
    ),
    ToolSeed(
        "log_sample_bounded",
        "evidence-agent",
        _COMPUTE,
        _APPLICATION,
        "CLOUD_LOGGING",
        "evidence.log.compute",
        "solvan-evidence.internal",
        EvidenceKind.LOGS,
        "Produce a stable bounded log sample.",
        "evidence_refs",
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
    ),
    ToolSeed(
        "cloud_run_read",
        "infrastructure-agent",
        _READ,
        _CONNECTOR,
        "CLOUD_RUN",
        "run.services.get",
        "run.googleapis.com",
        EvidenceKind.DEPLOYMENT_METADATA,
        "Read one graph-bound Cloud Run service.",
        "exact_service",
    ),
    ToolSeed(
        "cloud_sql_metadata_read",
        "infrastructure-agent",
        _READ,
        _CONNECTOR,
        "CLOUD_SQL",
        "cloudsql.instances.get",
        "sqladmin.googleapis.com",
        EvidenceKind.TOPOLOGY,
        "Read configuration metadata without database data.",
        "exact_graph_node",
    ),
    ToolSeed(
        "production_graph_read",
        "infrastructure-agent",
        _READ,
        _CONNECTOR,
        "PRODUCTION_GRAPH",
        "production_graph.read",
        "solvan-control.internal",
        EvidenceKind.TOPOLOGY,
        "Read one immutable graph slice.",
        "exact_snapshot",
    ),
    ToolSeed(
        "cloud_asset_inventory_search",
        "infrastructure-agent",
        _READ,
        _CONNECTOR,
        "ASSET_INVENTORY",
        "cloudasset.resources.search",
        "cloudasset.googleapis.com",
        EvidenceKind.TOPOLOGY,
        "Find bounded candidates for graph review.",
        "bounded_candidates",
    ),
    ToolSeed(
        "cloud_run_revision_compare",
        "infrastructure-agent",
        _COMPUTE,
        _APPLICATION,
        "CLOUD_RUN",
        "evidence.revision.compute",
        "solvan-evidence.internal",
        EvidenceKind.DEPLOYMENT_METADATA,
        "Compare normalized revision projections.",
        "evidence_refs",
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
    ),
    *GITHUB_TOOL_SEEDS,
    ToolSeed(
        "cloud_build_history_read",
        "infrastructure-agent",
        _READ,
        _CONNECTOR,
        "CLOUD_BUILD",
        "cloudbuild.builds.list",
        "cloudbuild.googleapis.com",
        EvidenceKind.DEPLOYMENT_METADATA,
        "Read bounded build history for one trigger.",
        "bounded_window",
    ),
    ToolSeed(
        "execute_authorized_action",
        "execution-agent",
        PermissionClass.PROPOSE,
        _CONNECTOR,
        "SOLVAN_ACTUATOR",
        "authorized_action.execute",
        "solvan-actuator.internal",
        EvidenceKind.NONE,
        "Submit one already-authorized stored action to the deterministic actuator.",
        "exact_stored_action",
        no_data=NoDataSemantics.NOT_APPLICABLE,
        timeout_ms=210_000,
        max_output_bytes=16_384,
    ),
    ToolSeed(
        "run_bound_verification",
        "verification-agent",
        _READ,
        _CONNECTOR,
        "SOLVAN_VERIFIER",
        "verification.run",
        "solvan-verifier.internal",
        EvidenceKind.NONE,
        "Run one immutable policy-bound verification.",
        "exact_stored_action",
        no_data=NoDataSemantics.NOT_APPLICABLE,
        timeout_ms=240_000,
        max_output_bytes=32_768,
    ),
    ToolSeed(
        "workspace.code-repair.read-artifact",
        "workspace-agent",
        _READ,
        _APPLICATION,
        "SOLVAN_WORKSPACE_ADAPTER",
        "workspace.artifact.read",
        "solvan-workspace-adapter.internal",
        EvidenceKind.ARTIFACT,
        "Read one opaque, same-run repair artifact in a bounded UTF-8 slice.",
        "same_run_opaque_handle",
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
        max_input_bytes=256,
        max_output_bytes=65_536,
        default_call_budget=64,
    ),
    ToolSeed(
        "workspace.code-repair.write-candidate-artifact",
        "workspace-agent",
        PermissionClass.PROPOSE,
        _APPLICATION,
        "SOLVAN_WORKSPACE_ADAPTER",
        "workspace.candidate.propose",
        "solvan-workspace-adapter.internal",
        EvidenceKind.ARTIFACT,
        "Append one immutable candidate-tree generation under the frozen path policy.",
        "same_run_candidate_cas",
        no_data=NoDataSemantics.NOT_APPLICABLE,
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
        max_input_bytes=65_536,
        max_output_bytes=1_024,
        default_call_budget=32,
    ),
    ToolSeed(
        "workspace.code-repair.run-in-sandbox",
        "workspace-agent",
        _COMPUTE,
        _APPLICATION,
        "SOLVAN_WORKSPACE_ADAPTER",
        "workspace.sandbox.explore",
        "solvan-workspace-adapter.internal",
        EvidenceKind.ARTIFACT,
        "Run one frozen non-shell catalog command against a same-run candidate tree.",
        "resolved_command_catalog",
        no_data=NoDataSemantics.NOT_APPLICABLE,
        model_armor=ModelArmorCoverage.NOT_APPLICABLE,
        timeout_ms=120_000,
        max_input_bytes=256,
        max_output_bytes=131_072,
        default_call_budget=8,
    ),
)

AGENT_PROFILE_KEYS: dict[str, str] = {
    "incident-supervisor": "supervisor.plan.v1",
    "evidence-agent": "evidence.ruhu-observability.v1",
    "infrastructure-agent": "infrastructure.ruhu-change.v1",
    "execution-agent": "execution.authorized-action.v1",
    "verification-agent": "verification.payments.v1",
    "workspace-agent": "workspace.code-repair.v1",
}


def catalog_principals(*, manifest_hash: str) -> tuple[CatalogPrincipal, ...]:
    roles = {
        "incident-supervisor": ExecutionRole.SUPERVISOR,
        "workspace-agent": ExecutionRole.WORKSPACE,
    }
    displays = {
        "incident-supervisor": "Incident Supervisor Agent",
        "evidence-agent": "Evidence Agent",
        "infrastructure-agent": "Infrastructure Agent",
        "execution-agent": "Execution Agent",
        "verification-agent": "Verification Agent",
        "workspace-agent": "Workspace Agent",
    }
    return tuple(
        CatalogPrincipal(
            principal_key=key,
            display_name=display,
            registry_kind=RegistryKind.AGENT,
            execution_role=roles.get(key, ExecutionRole.SPECIALIST),
            model_backed=True,
            manifest_hash=manifest_hash,
        )
        for key, display in displays.items()
    )


def catalog_tools(
    *, network_policy_hash: str, approval_ref: str, evaluation_ref: str
) -> tuple[ToolRevision, ...]:
    revisions = []
    for seed in TOOL_SEEDS:
        input_material = {"tool": seed.key, "version": "1", "direction": "input"}
        output_material = {"tool": seed.key, "version": "1", "direction": "output"}
        revisions.append(
            ToolRevision(
                tool_key=seed.key,
                version="1",
                display_name=seed.key.replace("_", " ").title(),
                description=seed.use_case,
                use_cases=(seed.use_case,),
                anti_use_cases=(
                    "Arbitrary URL, query language, shell, SQL, credential, or cross-scope use.",
                ),
                owner_department="Reliability Platform",
                permission_class=seed.permission,
                implementation_kind=seed.implementation,
                allowed_requester_keys=(seed.agent_key,),
                required_capabilities=(seed.capability,),
                required_connection_providers=(seed.provider,),
                input_schema_ref=f"schema://solvan/tools/{seed.key}/input/1",
                input_schema_hash=canonical_sha256(input_material),
                output_schema_ref=f"schema://solvan/tools/{seed.key}/output/1",
                output_schema_hash=canonical_sha256(output_material),
                evidence_kind=seed.evidence_kind,
                output_semantics=("Typed, bounded, provenance-bearing result.",),
                supported_retrieval_controls=(seed.retrieval_control,),
                no_data_semantics=seed.no_data,
                failure_taxonomy=(
                    "NO_DATA",
                    "PERMISSION_DENIED",
                    "STALE_BINDING",
                    "PROVIDER_UNAVAILABLE",
                ),
                supported_data_classes=("PUBLIC", "INTERNAL", "CONFIDENTIAL"),
                runtime_regions=("europe-west1",),
                gateway_destination=seed.destination,
                registry_resource=f"registry://solvan/tools/{seed.key}@1",
                model_armor_coverage=seed.model_armor,
                network_policy_hash=network_policy_hash,
                timeout_ms=seed.timeout_ms,
                max_input_bytes=seed.max_input_bytes,
                max_output_bytes=seed.max_output_bytes,
                default_call_budget=seed.default_call_budget,
                idempotency=IdempotencyKind.SOLVAN_RECONCILED,
                lifecycle=CatalogLifecycle.APPROVED,
                approval_ref=approval_ref,
                evaluation_ref=evaluation_ref,
            )
        )
    return tuple(revisions)


#: Providers reached through Solvan's own typed services rather than a tenant
#: source connection. There is no external source to bind, so these are
#: genuinely `COMPUTE_ONLY` rather than an unexpressed binding.
INTERNAL_PROVIDERS: frozenset[str] = frozenset(
    {
        "PRODUCTION_GRAPH",
        "SOLVAN_ACTUATOR",
        "SOLVAN_VERIFIER",
        "SOLVAN_WORKSPACE_ADAPTER",
    }
)


def profile_eligible(seed: ToolSeed) -> bool:
    """Whether a Tool's connection requirement can be stated exactly.

    A `COMPUTE` Tool operates on evidence a source-bound read already
    retrieved, and an internal provider has no external source, so both bind to
    no connection. Every other Tool reaches an external system and must name a
    closed provider/capability pair. When specification 16 has no pair for that
    provider the requirement cannot be expressed, and the Tool stays registered
    in the catalog but out of every profile: declaring it `COMPUTE_ONLY` would
    publish external reach that no source connection, epoch, or coverage
    receipt gates.
    """

    return (
        seed.permission is _COMPUTE
        or seed.provider in INTERNAL_PROVIDERS
        or seed.provider in SOURCE_CONNECTION_PAIRS
    )


def _connection_requirement(*, ordinal: int, seed: ToolSeed) -> ToolConnectionRequirement:
    source_bound = seed.permission is not _COMPUTE and seed.provider in SOURCE_CONNECTION_PAIRS
    return ToolConnectionRequirement(
        ordinal=ordinal,
        tool_revision=f"{seed.key}@1",
        binding_kind=(
            ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION
            if source_bound
            else ToolConnectionBindingKind.COMPUTE_ONLY
        ),
        provider=seed.provider if source_bound else None,
        capability_key=SOURCE_CONNECTION_PAIRS[seed.provider] if source_bound else None,
        external_project_selector="TARGET_RESOURCE_PROJECT" if source_bound else None,
    )


def catalog_profile(
    *,
    agent_key: str,
    approval_ref: str,
    evaluation_ref: str,
    classification_ceiling: str = "CONFIDENTIAL",
) -> ToolProfileRevision:
    try:
        profile_key = AGENT_PROFILE_KEYS[agent_key]
    except KeyError as error:
        raise ValueError(f"unknown canonical Agent {agent_key}") from error
    seeds = tuple(
        seed for seed in TOOL_SEEDS if seed.agent_key == agent_key and profile_eligible(seed)
    )
    tool_refs = tuple(f"{seed.key}@1" for seed in seeds)
    requirements = tuple(
        _connection_requirement(ordinal=ordinal, seed=seed)
        for ordinal, seed in enumerate(seeds, start=1)
    )
    workspace_profile = agent_key == "workspace-agent"
    profile_limits = (
        {"maximum_read_window_ms": 0, "maximum_aggregate_evidence_bytes": 1_048_576}
        if workspace_profile
        else {}
    )
    return ToolProfileRevision(
        profile_key=profile_key,
        version="1",
        purpose=f"Canonical bounded capability profile for {agent_key}.",
        allowed_agent_key=agent_key,
        tool_revisions=tool_refs,
        maximum_total_calls=(104 if workspace_profile else len(tool_refs) * 3),
        maximum_parallel_calls=(1 if workspace_profile else min(3, len(tool_refs))),
        tool_connection_requirements=requirements,
        data_classification_ceiling=classification_ceiling,
        runtime_region="europe-west1",
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref=approval_ref,
        evaluation_ref=evaluation_ref,
        **profile_limits,
    )


def alert_triage_profile(*, approval_ref: str, evaluation_ref: str) -> ToolProfileRevision:
    """Return the one frozen read/compute profile from specification 21."""

    tools = (
        "cloud_monitoring_query@1",
        "metric_baseline_compare@1",
        "metric_change_point_detect@1",
        "metric_correlate@1",
    )
    return ToolProfileRevision(
        profile_key="alert-triage-read-compute-v1",
        version="1",
        purpose="ALERT_TRIAGE",
        allowed_agent_key="evidence-agent",
        tool_revisions=tools,
        maximum_total_calls=12,
        maximum_parallel_calls=2,
        maximum_read_window_ms=86_400_000,
        maximum_aggregate_evidence_bytes=1_048_576,
        tool_connection_requirements=(
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="cloud_monitoring_query@1",
                binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                provider="CLOUD_MONITORING",
                capability_key="METRIC_READ",
                external_project_selector="TARGET_RESOURCE_PROJECT",
            ),
            *tuple(
                ToolConnectionRequirement(
                    ordinal=ordinal,
                    tool_revision=tool,
                    binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
                )
                for ordinal, tool in enumerate(tools[1:], start=2)
            ),
        ),
        data_classification_ceiling="CONFIDENTIAL",
        runtime_region="POLICY_BOUND",
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref=approval_ref,
        evaluation_ref=evaluation_ref,
    )
