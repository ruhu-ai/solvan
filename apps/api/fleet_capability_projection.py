"""One operator-facing decision per `(Agent, Tool revision)`, and its provenance.

This is the half of the Capabilities & Policy surface that reads records. It
observes each authority named in `solvan.application.capability_resolution`,
hands the complete chain to that rule, and serializes what comes back. It
decides nothing itself: a predicate that lives only here would be the second
rule all over again.

The states it can report are deliberately four rather than two. The console used
to print `Denied` for anything short of a fresh probe, which made fourteen of
twenty-three capabilities permanently wrong — nine of them because a
compute-only Tool binds no connection and so can hold no probe receipt at all,
and five because they sit in no approved profile and were never offered to
anyone. `NOT_APPLICABLE` and `NOT_EVALUATED` are what let those two say what
they actually are.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from psycopg import Connection

from solvan.application.capability_resolution import (
    CapabilityLayer,
    LayerOutcome,
    LayerState,
    resolve_capability,
)
from solvan.application.tool_catalog import DATA_CLASSIFICATION_RANKS
from solvan.domain import Scope
from solvan.persistence.capability_matrix import capability_matrix_rows


def capability_projection(
    connection: Connection[Any],
    *,
    scope: Scope,
    environment_region: str,
    environment_classification: str | None,
    registered_gateway_destinations: frozenset[str] | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Project every governed capability with the chain that decided it.

    `registered_gateway_destinations` is the routed set a platform preflight
    receipt attests. It is `None` until a cloud receipt binds, and that absence
    is reported as an unobserved authority rather than assumed either way —
    which is why nothing reads `ALLOWED` in a scope with no receipt.
    """

    observed_at = now or datetime.now(UTC)
    projected: list[dict[str, Any]] = []
    for row in capability_matrix_rows(connection, scope=scope):
        outcomes, details = _observe(
            row,
            environment_region=environment_region,
            environment_classification=environment_classification,
            registered_gateway_destinations=registered_gateway_destinations,
            now=observed_at,
        )
        decision = resolve_capability(layers=outcomes)
        projected.append(
            {
                "agent_key": str(row["agent_key"]),
                "agent": str(row["agent_display_name"]),
                "tool_key": str(row["tool_key"]),
                "version": str(row["tool_version"]),
                "tool": str(row["tool_display_name"]),
                "destination": str(row["gateway_destination"]),
                "registry_resource": str(row["registry_resource"]),
                "permission_class": str(row["permission_class"]),
                "verdict": decision.verdict.value,
                "winning_layer": decision.winning_layer.value,
                "winning_reference": decision.winning_reference,
                "layers": [
                    {
                        "layer": item.layer.value,
                        "state": item.state.value,
                        "reference": item.reference,
                        "observed_at": (item.observed_at.isoformat() if item.observed_at else None),
                        "detail": details[item.layer],
                    }
                    for item in decision.layers
                ],
            }
        )
    return projected


def _observe(
    row: dict[str, Any],
    *,
    environment_region: str,
    environment_classification: str | None,
    registered_gateway_destinations: frozenset[str] | None,
    now: datetime,
) -> tuple[list[LayerOutcome], dict[CapabilityLayer, str]]:
    """Read each authority from the records, in the order the binder applies them."""

    outcomes: list[LayerOutcome] = []
    details: dict[CapabilityLayer, str] = {}

    def record(
        layer: CapabilityLayer,
        state: LayerState,
        detail: str,
        reference: str = "",
        seen: datetime | None = None,
    ) -> None:
        outcomes.append(
            LayerOutcome(layer=layer, state=state, reference=reference, observed_at=seen)
        )
        details[layer] = detail

    revision = f"{row['tool_key']}@{row['tool_version']}"
    profile = f"{row['profile_key']}@{row['profile_version']}" if row["profile_key"] else ""
    binding = row["binding_kind"]

    if profile:
        record(
            CapabilityLayer.PROFILE_MEMBERSHIP,
            LayerState.SATISFIED,
            f"An approved profile offers this capability to {row['agent_key']}.",
            profile,
        )
    else:
        record(
            CapabilityLayer.PROFILE_MEMBERSHIP,
            LayerState.REFUSED,
            "No approved capability profile contains this Tool for this Agent, "
            "so dispatch could never select it.",
        )

    if row["declared"]:
        record(
            CapabilityLayer.REQUESTER_DECLARATION,
            LayerState.SATISFIED,
            "The Tool revision names this Agent as an allowed requester.",
            revision,
        )
    else:
        record(
            CapabilityLayer.REQUESTER_DECLARATION,
            LayerState.REFUSED,
            "The Tool revision does not name this Agent as an allowed requester.",
        )

    lifecycle = str(row["revision_lifecycle"])
    if lifecycle != "APPROVED":
        record(
            CapabilityLayer.REVISION_LIFECYCLE,
            LayerState.REFUSED,
            f"This revision is {lifecycle.lower()} and may not enter new work.",
            revision,
        )
    elif str(row["permission_class"]) == "MUTATE":
        record(
            CapabilityLayer.REVISION_LIFECYCLE,
            LayerState.REFUSED,
            "A model-backed Agent profile cannot contain a MUTATE capability.",
            revision,
        )
    else:
        record(
            CapabilityLayer.REVISION_LIFECYCLE,
            LayerState.SATISFIED,
            f"Revision approved as a {row['permission_class']} capability.",
            str(row["revision_approval_ref"] or revision),
        )

    _record_placement(
        record,
        row,
        environment_region=environment_region,
        environment_classification=environment_classification,
        profile=profile,
    )

    destination = str(row["gateway_destination"])
    if registered_gateway_destinations is None:
        record(
            CapabilityLayer.GATEWAY_ROUTE,
            LayerState.NOT_EVALUATED,
            "No platform preflight receipt is bound in this scope, so no record "
            "says whether this destination is a registered Gateway route.",
        )
    elif destination in registered_gateway_destinations:
        record(
            CapabilityLayer.GATEWAY_ROUTE,
            LayerState.SATISFIED,
            "A bound preflight receipt registers this destination.",
            destination,
        )
    else:
        record(
            CapabilityLayer.GATEWAY_ROUTE,
            LayerState.REFUSED,
            "The bound preflight receipt registers no route to this destination.",
            destination,
        )

    _record_binding(record, row, binding=binding)
    _record_probe(record, row, binding=binding, now=now)
    return outcomes, details


def _record_placement(
    record: Any,
    row: dict[str, Any],
    *,
    environment_region: str,
    environment_classification: str | None,
    profile: str,
) -> None:
    """Compare this environment against the ceilings the profile and revision carry."""

    if not profile:
        record(
            CapabilityLayer.CLASSIFICATION_AND_REGION,
            LayerState.NOT_EVALUATED,
            "No profile bounds this capability, so there is no ceiling to compare.",
        )
        return
    if environment_classification is None:
        record(
            CapabilityLayer.CLASSIFICATION_AND_REGION,
            LayerState.NOT_EVALUATED,
            "This environment declares no data classification, so no ceiling comparison "
            "is possible.",
        )
        return
    regions = [str(value) for value in row["runtime_regions_json"]]
    classes = [str(value) for value in row["supported_data_classes_json"]]
    ceiling = str(row["profile_ceiling"])
    profile_region = str(row["profile_region"])
    if profile_region not in {environment_region, "POLICY_BOUND"}:
        refusal = f"The profile is bound to {profile_region}, not {environment_region}."
    elif environment_region not in regions:
        refusal = f"This revision does not run in {environment_region}."
    elif environment_classification not in classes:
        refusal = f"This revision does not support {environment_classification} data."
    elif DATA_CLASSIFICATION_RANKS[environment_classification] > DATA_CLASSIFICATION_RANKS[ceiling]:
        refusal = f"{environment_classification} data exceeds the profile ceiling of {ceiling}."
    else:
        record(
            CapabilityLayer.CLASSIFICATION_AND_REGION,
            LayerState.SATISFIED,
            f"Permitted in {environment_region} at {environment_classification}, "
            f"within the profile ceiling of {ceiling}.",
            profile,
        )
        return
    record(CapabilityLayer.CLASSIFICATION_AND_REGION, LayerState.REFUSED, refusal, profile)


def _record_binding(record: Any, row: dict[str, Any], *, binding: str | None) -> None:
    if binding is None:
        record(
            CapabilityLayer.CONNECTION_BINDING,
            LayerState.NOT_EVALUATED,
            "No profile states how this capability binds, so nothing declares whether "
            "a connection is required.",
        )
    elif binding == "COMPUTE_ONLY":
        record(
            CapabilityLayer.CONNECTION_BINDING,
            LayerState.NOT_APPLICABLE,
            "This capability reaches no external system, so it binds no customer connection.",
        )
    elif row["connection_id"]:
        record(
            CapabilityLayer.CONNECTION_BINDING,
            LayerState.SATISFIED,
            f"An enrolled {row['required_provider']} connection is available at epoch "
            f"{row['connection_epoch']}.",
            str(row["connection_id"]),
        )
    else:
        record(
            CapabilityLayer.CONNECTION_BINDING,
            LayerState.REFUSED,
            f"No enabled {row['required_provider']} connection is enrolled in this scope.",
        )


def _record_probe(record: Any, row: dict[str, Any], *, binding: str | None, now: datetime) -> None:
    """Report the exact capability proof, and never invent one where none exists."""

    if binding is None:
        record(
            CapabilityLayer.CAPABILITY_PROBE,
            LayerState.NOT_EVALUATED,
            "No profile states how this capability binds, so no proof is defined for it.",
        )
        return
    if binding == "COMPUTE_ONLY":
        # The receipt table references a customer connection, so a compute-only
        # capability cannot hold one even in principle. Reporting that as a
        # refusal is what made the actuator row read `Denied` forever.
        record(
            CapabilityLayer.CAPABILITY_PROBE,
            LayerState.NOT_APPLICABLE,
            "A capability that binds no connection has no external capability to probe.",
        )
        return
    outcome = row["probe_outcome"]
    receipt = str(row["probe_receipt_ref"] or "")
    if outcome is None:
        record(
            CapabilityLayer.CAPABILITY_PROBE,
            LayerState.NOT_EVALUATED,
            "This exact Agent, Tool revision and connection have never been probed together.",
        )
        return
    seen = row["probe_observed_at"]
    if outcome == "PASSED" and row["probe_expires_at"] > now:
        record(
            CapabilityLayer.CAPABILITY_PROBE,
            LayerState.SATISFIED,
            "A current receipt proves this Agent reached this capability through the "
            "bound connection.",
            receipt,
            seen,
        )
        return
    if outcome == "PASSED":
        record(
            CapabilityLayer.CAPABILITY_PROBE,
            LayerState.REFUSED,
            "The last passing receipt has expired; capability proof is never inherited "
            "from an older observation.",
            receipt,
            seen,
        )
        return
    record(
        CapabilityLayer.CAPABILITY_PROBE,
        LayerState.REFUSED,
        f"The last probe failed: {row['probe_reason_code']}. "
        f"Missing grant: {row['probe_missing_grant']}.",
        receipt,
        seen,
    )
