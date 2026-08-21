"""Mechanical consistency checks for the target Solvant Relay contract."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import cast

import jsonschema  # type: ignore[import-untyped]
import yaml

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "specs" / "artifacts"


def load_json(name: str) -> dict[str, object]:
    with (ARTIFACTS / name).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise AssertionError(f"{name} must contain one object")
    return cast(dict[str, object], value)


def load_yaml(name: str) -> dict[str, object]:
    with (ARTIFACTS / name).open(encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise AssertionError(f"{name} must contain one object")
    return value


def sql_transition_rows() -> set[tuple[str, str, str, str, str]]:
    sql = (ARTIFACTS / "relay-schema.target.sql").read_text(encoding="utf-8")
    start = sql.index("INSERT INTO relay_transition_rules")
    values = sql[start : sql.index(";", start)]
    pattern = re.compile(
        r"\('(?P<machine>[^']+)','(?P<from>[^']+)','(?P<event>[^']+)',"
        r"'(?P<to>[^']+)','(?P<guard>[^']+)'\)"
    )
    return {
        (match["machine"], match["from"], match["event"], match["to"], match["guard"])
        for match in pattern.finditer(values)
    }


def yaml_transition_rows() -> set[tuple[str, str, str, str, str]]:
    artifact = load_yaml("relay-transitions.yaml")
    machines = artifact.get("machines")
    if not isinstance(machines, dict):
        raise AssertionError("relay-transitions.yaml machines must be an object")
    rows: set[tuple[str, str, str, str, str]] = set()
    for machine, body in machines.items():
        if not isinstance(body, dict) or not isinstance(body.get("transitions"), list):
            raise AssertionError(f"{machine} must declare transitions")
        for transition in body["transitions"]:
            if not isinstance(transition, dict):
                raise AssertionError(f"{machine} transition must be an object")
            rows.add(
                (
                    str(machine),
                    str(transition["from"]),
                    str(transition["event"]),
                    str(transition["to"]),
                    str(transition["guard"]),
                )
            )
    return rows


def main() -> None:
    for schema_name in (
        "relay-local-policy.schema.json",
        "relay-evidence-envelope.schema.json",
        "relay-qualification-receipt.schema.json",
    ):
        jsonschema.Draft202012Validator.check_schema(load_json(schema_name))

    actual = sql_transition_rows()
    declared = yaml_transition_rows()
    if actual != declared:
        raise AssertionError(
            "Relay SQL/YAML transition drift: "
            f"missing_from_sql={sorted(declared - actual)!r}; "
            f"missing_from_yaml={sorted(actual - declared)!r}"
        )

    catalog = load_yaml("relay-connectors.yaml")
    if catalog.get("catalog_key") != "gcp-observe.v1" or catalog.get("catalog_revision") != 1:
        raise AssertionError("Relay connector catalog identity drifted")
    if catalog.get("excluded_operations") is None:
        raise AssertionError("Relay connector catalog must fail closed explicitly")
    adapters = catalog.get("adapters")
    if not isinstance(adapters, dict):
        raise AssertionError("Relay connector catalog adapters must be an object")
    expected_adapter_pairs = {
        "cloud-monitoring.v1": ("CLOUD_MONITORING", "METRIC_READ"),
        "cloud-logging.v1": ("CLOUD_LOGGING", "LOG_SEARCH"),
        "cloud-trace.v1": ("CLOUD_TRACE", "TRACE_READ"),
        "error-reporting.v1": ("ERROR_REPORTING", "ERROR_GROUP_READ"),
    }
    for adapter_key, expected_pair in expected_adapter_pairs.items():
        adapter = adapters.get(adapter_key)
        if not isinstance(adapter, dict):
            raise AssertionError(f"missing Relay adapter {adapter_key}")
        observed = (adapter.get("connection_provider"), adapter.get("capability_key"))
        if observed != expected_pair:
            raise AssertionError(f"Relay adapter pair drifted for {adapter_key}: {observed!r}")
    monitoring_adapter = cast(dict[str, object], adapters["cloud-monitoring.v1"])
    monitoring_operations = monitoring_adapter.get("operations")
    if (
        not isinstance(monitoring_operations, dict)
        or "monitoring.time-series.read.v1" not in monitoring_operations
    ):
        raise AssertionError("Relay Cloud Monitoring operation key drifted")
    if "monitoring.time_series.read.v1" in monitoring_operations:
        raise AssertionError(
            "Relay Cloud Monitoring operation must use the canonical hyphenated key"
        )
    logging_adapter = cast(dict[str, object], adapters["cloud-logging.v1"])
    logging_operations = cast(dict[str, object], logging_adapter["operations"])
    audit = logging_operations["logging.audit-events.read.v1"]
    if not isinstance(audit, dict) or (
        audit.get("connection_provider"),
        audit.get("capability_key"),
    ) != ("CLOUD_AUDIT", "AUDIT_LOG_READ"):
        raise AssertionError("Relay Audit operation pair drifted")
    metadata_adapter = cast(dict[str, object], adapters["cloud-resource-metadata.v1"])
    metadata_operations = cast(dict[str, object], metadata_adapter["operations"])
    for operation, provider in (
        ("cloud_run.service_revision.read.v1", "CLOUD_RUN"),
        ("cloud_sql.instance_metadata.read.v1", "CLOUD_SQL"),
    ):
        value = metadata_operations.get(operation)
        if not isinstance(value, dict) or (
            value.get("connection_provider"),
            value.get("capability_key"),
        ) != (provider, "RESOURCE_METADATA_READ"):
            raise AssertionError(f"Relay metadata operation pair drifted for {operation}")

    vectors = load_yaml("relay-resource-binding-hash-vectors.yaml")
    fields = vectors.get("fields")
    cases = vectors.get("vectors")
    if not isinstance(fields, list) or not isinstance(cases, list):
        raise AssertionError("Relay resource-binding vectors are malformed")
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("values"), dict):
            raise AssertionError("Relay resource-binding vector case is malformed")
        values = cast(dict[str, object], case["values"])
        encoded: list[str] = []
        for field in fields:
            value = values.get(str(field))
            if value is None:
                encoded.append("-1:")
            else:
                rendered = str(value)
                encoded.append(f"{len(rendered.encode('utf-8'))}:{rendered}")
        preimage = "relay-resource-binding-v1|" + "|".join(encoded)
        observed_hash = "sha256:" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        if observed_hash != case.get("expected_hash"):
            raise AssertionError(f"Relay resource-binding hash vector failed: {case.get('name')}")

    acceptance = load_yaml("relay-acceptance.yaml")
    if acceptance.get("status") != "target" or acceptance.get("release_gate") is not False:
        raise AssertionError("Relay acceptance registry must remain target-only")
    tests = acceptance.get("tests")
    if not isinstance(tests, dict):
        raise AssertionError("Relay acceptance registry must contain tests")
    covered = {
        requirement
        for case in tests.values()
        if isinstance(case, dict)
        for requirement in case.get("requirements", [])
    }
    expected = {f"INV-RELAY-{number:02d}" for number in range(1, 31)}
    expected.add("REL-RELAY-01")
    if covered != expected:
        raise AssertionError(
            f"Relay acceptance coverage drift: missing={sorted(expected - covered)!r}; "
            f"unexpected={sorted(covered - expected)!r}"
        )
    if any(
        not isinstance(case, dict) or case.get("implementation", "missing") is not None
        for case in tests.values()
    ):
        raise AssertionError("Target Relay cases must remain explicit implementation gaps")

    spec = (ROOT / "specs" / "22-solvant-relay.md").read_text(encoding="utf-8")
    declared_invariants = set(re.findall(r"INV-RELAY-\d{2}", spec))
    if declared_invariants != expected - {"REL-RELAY-01"}:
        raise AssertionError("Relay invariant numbering drifted from the acceptance registry")

    print(
        f"Solvant Relay artifact contract passed "
        f"({len(actual)} transitions; {len(tests)} target cases)"
    )


if __name__ == "__main__":
    main()
