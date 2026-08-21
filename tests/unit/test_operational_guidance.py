from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from solvan.application.operational_guidance import (
    GuidanceError,
    GuidanceLifecycle,
    GuidanceRevision,
    GuidanceSelectionContext,
    GuidanceSourceKind,
    PredicateRegistry,
    eligible_guidance,
    validate_guidance_approval,
)
from solvan.application.tool_catalog import (
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
from solvan.domain import Scope, new_identifier
from solvan.persistence.operational_guidance_runtime import OperationalGuidanceRuntimeMixin

HASH = f"sha256:{'1' * 64}"


class _PredicateCursor:
    def __init__(self, rows: list[dict[str, object] | None]) -> None:
        self.rows = rows

    def execute(self, *_args: object) -> None:
        return None

    def fetchone(self) -> dict[str, object] | None:
        return self.rows.pop(0)


class _PredicateStore(OperationalGuidanceRuntimeMixin):
    pass


def guidance(**changes: object) -> GuidanceRevision:
    values: dict[str, object] = {
        "guidance_key": "payments.connection-exhaustion",
        "version": "1",
        "display_name": "Payment connection exhaustion",
        "description": "Gather bounded evidence for exhausted pools.",
        "owner_department": "Payments SRE",
        "discoverable_departments": ("Payments", "Reliability"),
        "guidance_kind": "DIAGNOSTIC_PROCEDURE",
        "applicable_service_kinds": ("CLOUD_RUN",),
        "applicable_incident_classes": ("CONNECTION_EXHAUSTION",),
        "symptom_tags": ("http-503", "pool-saturation"),
        "purpose": "INCIDENT_INVESTIGATION",
        "classification": "INTERNAL",
        "eligible_regions": ("europe-west1",),
        "allowed_agent_keys": ("evidence-agent",),
        "required_profile_revisions": ("evidence.ruhu-observability.v1@1",),
        "steps": (
            {
                "step_key": "observe-errors",
                "ordinal": 1,
                "title": "Observe bounded errors",
                "objective": "Measure the registered error signature during the incident window.",
                "step_kind": "OBSERVE",
                "allowed_tool_revisions": ("managed_prometheus_query@1",),
                "prerequisite_step_keys": (),
                "completion_predicate_key": "evidence-kind-present",
                "completion_predicate_version": "1",
                "required_evidence_kinds": ("METRICS",),
                "maximum_tool_requests": 1,
                "on_blocked": "STOP_INCONCLUSIVE",
            },
        ),
        "content_ref": "gs://guidance/payments/connection-exhaustion/1.json",
        "content_hash": HASH,
        "source_kind": "SOLVAN_AUTHORED",
        "source_ref": "solvan://guidance/payments/connection-exhaustion",
        "evaluation_ref": "evaluation://guidance/1",
        "approval_ref": "approval://guidance/1",
        "author_principal": "user:author@example.com",
        "approved_by_principal": "user:approver@example.com",
        "approved_at": datetime(2026, 8, 10, tzinfo=UTC),
        "lifecycle": "APPROVED",
    }
    values.update(changes)
    return GuidanceRevision.model_validate(values)


def tool(**changes: object) -> ToolRevision:
    values: dict[str, object] = {
        "tool_key": "managed_prometheus_query",
        "version": "1",
        "display_name": "Managed Prometheus query",
        "description": "Run one registered metric template.",
        "use_cases": ("Bounded metric read",),
        "anti_use_cases": ("Arbitrary PromQL",),
        "owner_department": "Reliability Platform",
        "permission_class": PermissionClass.READ,
        "implementation_kind": ImplementationKind.CONNECTOR,
        "allowed_requester_keys": ("evidence-agent",),
        "required_capabilities": ("promql.read",),
        "required_connection_providers": ("MANAGED_PROMETHEUS",),
        "input_schema_ref": "schema://input/1",
        "input_schema_hash": HASH,
        "output_schema_ref": "schema://output/1",
        "output_schema_hash": HASH,
        "evidence_kind": EvidenceKind.METRICS,
        "output_semantics": ("bounded series",),
        "supported_retrieval_controls": ("registered_template",),
        "no_data_semantics": NoDataSemantics.UNKNOWN,
        "failure_taxonomy": ("NO_DATA",),
        "supported_data_classes": ("INTERNAL",),
        "runtime_regions": ("europe-west1",),
        "gateway_destination": "monitoring.googleapis.com",
        "registry_resource": "registry://managed-prometheus/1",
        "model_armor_coverage": ModelArmorCoverage.NOT_APPLICABLE,
        "network_policy_hash": HASH,
        "timeout_ms": 10_000,
        "max_input_bytes": 4_096,
        "max_output_bytes": 65_536,
        "default_call_budget": 2,
        "idempotency": IdempotencyKind.NOT_APPLICABLE,
        "lifecycle": CatalogLifecycle.APPROVED,
        "approval_ref": "approval://tool/1",
        "evaluation_ref": "evaluation://tool/1",
    }
    values.update(changes)
    return ToolRevision.model_validate(values)


def profile() -> ToolProfileRevision:
    return ToolProfileRevision(
        profile_key="evidence.ruhu-observability.v1",
        version="1",
        purpose="Incident investigation",
        allowed_agent_key="evidence-agent",
        tool_revisions=("managed_prometheus_query@1",),
        maximum_total_calls=3,
        maximum_parallel_calls=1,
        tool_connection_requirements=(
            ToolConnectionRequirement(
                ordinal=1,
                tool_revision="managed_prometheus_query@1",
                binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
            ),
        ),
        data_classification_ceiling="INTERNAL",
        runtime_region="europe-west1",
        lifecycle=CatalogLifecycle.APPROVED,
        approval_ref="approval://profile/1",
        evaluation_ref="evaluation://profile/1",
    )


def test_guidance_rejects_cycles_and_author_self_approval() -> None:
    cyclic = guidance().steps[0].model_copy(update={"prerequisite_step_keys": ("observe-errors",)})
    with pytest.raises(ValidationError, match="cannot depend on itself"):
        guidance(steps=(cyclic,))
    with pytest.raises(ValidationError, match="cannot approve"):
        guidance(approved_by_principal="user:author@example.com")


def test_imported_guidance_requires_license_but_can_follow_lifecycle() -> None:
    with pytest.raises(ValidationError, match="source license"):
        guidance(source_kind=GuidanceSourceKind.IMPORTED)
    imported = guidance(
        source_kind=GuidanceSourceKind.IMPORTED,
        source_license="Apache-2.0",
        lifecycle=GuidanceLifecycle.DRAFT,
        evaluation_ref=None,
        approval_ref=None,
        approved_by_principal=None,
        approved_at=None,
    )
    assert imported.lifecycle is GuidanceLifecycle.DRAFT
    approved = guidance(
        source_kind=GuidanceSourceKind.IMPORTED,
        source_license="Apache-2.0",
    )
    assert approved.lifecycle is GuidanceLifecycle.APPROVED


def test_approval_requires_known_predicate_and_profile_subset() -> None:
    predicates = PredicateRegistry(predicates=frozenset({"evidence-kind-present@1"}))
    validate_guidance_approval(
        revision=guidance(), profiles=(profile(),), tools=(tool(),), predicates=predicates
    )
    with pytest.raises(GuidanceError, match="unknown completion predicate"):
        validate_guidance_approval(
            revision=guidance(),
            profiles=(profile(),),
            tools=(tool(),),
            predicates=PredicateRegistry(predicates=frozenset()),
        )
    with pytest.raises(GuidanceError, match="outside a required"):
        step = (
            guidance().steps[0].model_copy(update={"allowed_tool_revisions": ("another_tool@1",)})
        )
        validate_guidance_approval(
            revision=guidance(steps=(step,)),
            profiles=(profile(),),
            tools=(tool(tool_key="another_tool"),),
            predicates=predicates,
        )
    with pytest.raises(GuidanceError, match="unknown evidence kinds"):
        step = (
            guidance().steps[0].model_copy(update={"required_evidence_kinds": ("NOT_REGISTERED",)})
        )
        validate_guidance_approval(
            revision=guidance(steps=(step,)),
            profiles=(profile(),),
            tools=(tool(),),
            predicates=predicates,
        )


def test_candidate_filter_is_metadata_only_and_fail_closed() -> None:
    context = GuidanceSelectionContext(
        department="Payments",
        service_kind="CLOUD_RUN",
        incident_class="CONNECTION_EXHAUSTION",
        symptom_tags=frozenset({"http-503"}),
        purpose="INCIDENT_INVESTIGATION",
        classification_ceiling="INTERNAL",
        region="europe-west1",
        agent_key="evidence-agent",
        profile_revision="evidence.ruhu-observability.v1@1",
    )
    candidates = eligible_guidance((guidance(),), context=context)
    assert len(candidates) == 1
    assert "content_ref" not in candidates[0].model_fields_set
    assert (
        eligible_guidance(
            (guidance(),), context=context.model_copy(update={"region": "us-central1"})
        )
        == ()
    )


def test_guidance_content_fetched_predicate_requires_exact_selection_and_receipt() -> None:
    scope = Scope(new_identifier("org"), new_identifier("prj"), new_identifier("env"))
    run_id = new_identifier("run")
    selection_id = new_identifier("gsl")
    exact_audit = {
        "id": new_identifier("goa"),
        "entity_ref": f"guidance-selection:{selection_id}",
        "material_digest": HASH,
        "principal": "service:coordinator",
        "event_type": "GUIDANCE_FETCH_ALLOWED",
    }
    cursor = _PredicateCursor(
        [
            {"incident_id": new_identifier("inc")},
            {"agent_run_id": run_id, "content_hash": HASH},
            exact_audit,
        ]
    )
    verdict, citations, reason = _PredicateStore(object())._evaluate_registered_predicate(
        cursor=cursor,
        scope=scope,
        predicate_ref="guidance-content-fetched@1",
        selection_id=selection_id,
        agent_run_id=run_id,
        required_evidence_kinds=("GUIDANCE_FETCH_RECEIPT",),
    )
    assert (verdict, reason) == ("SATISFIED", None)
    assert citations == (
        f"db://solvan-operability/guidance-selections/{selection_id}",
        f"db://solvan-operability/operability-audit-events/{exact_audit['id']}",
    )

    missing = _PredicateCursor(
        [
            {"incident_id": new_identifier("inc")},
            {"agent_run_id": run_id, "content_hash": HASH},
            None,
        ]
    )
    assert (
        _PredicateStore(object())._evaluate_registered_predicate(
            cursor=missing,
            scope=scope,
            predicate_ref="guidance-content-fetched@1",
            selection_id=selection_id,
            agent_run_id=run_id,
            required_evidence_kinds=("GUIDANCE_FETCH_RECEIPT",),
        )[0]
        == "NOT_SATISFIED"
    )
