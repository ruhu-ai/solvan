"""Regenerate or verify the Alert profile/effective-set hash vectors."""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

import yaml

from solvan.application.workspace_hashing import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "specs" / "artifacts" / "alert-triage-profile-hash-vectors.yaml"


def _replacement(field: str, configured: dict[str, Any]) -> Any:
    if field in configured:
        return configured[field]
    requirement_match = re.fullmatch(
        r"tool_connection_requirements\[(\d+)]\.(binding_kind|provider|capability_key|external_project_selector)",
        field,
    )
    if requirement_match is not None:
        ordinal = int(requirement_match.group(1))
        leaf = requirement_match.group(2)
        if leaf == "binding_kind":
            return "COMPUTE_ONLY" if ordinal == 0 else "POLICY_SOURCE_CONNECTION"
        return "OTHER"
    if field == "connection_bindings.compute_only.tool.tool_key":
        return "compute_other"
    if field == "connection_bindings.compute_only.tool.version":
        return "2"
    match = re.fullmatch(r"(.+)\[(\d+)]\.(?:tool\.)?(tool_key|version)", field)
    if match is None:
        raise ValueError(f"no deterministic mutation value for {field}")
    prefix, ordinal_text, leaf = match.groups()
    ordinal = int(ordinal_text)
    if leaf == "version":
        return "2"
    if prefix == "tool_revisions":
        return f"other_tool_{ordinal}"
    if prefix == "tool_connection_requirements":
        return f"other_req_tool_{ordinal}"
    if prefix == "accepted_tools":
        return f"accepted_other_{ordinal}"
    raise ValueError(f"unsupported indexed mutation {field}")


def _set_path(material: dict[str, Any], field: str, value: Any) -> None:
    if field.endswith("_order"):
        key = field.removesuffix("_order")
        material[key] = list(reversed(material[key]))
        return
    path = field
    path = path.replace("connection_bindings.policy_source", "connection_bindings[0]")
    path = path.replace("connection_bindings.compute_only", "connection_bindings[1]")
    parts = re.findall(r"[^.\[\]]+|\d+", path)
    cursor: Any = material
    for part in parts[:-1]:
        cursor = cursor[int(part)] if part.isdigit() else cursor[part]
    leaf = parts[-1]
    if leaf.isdigit():
        cursor[int(leaf)] = value
    else:
        cursor[leaf] = value


def _computed() -> tuple[dict[str, str], dict[tuple[str, str], str], dict[str, str]]:
    document: dict[str, Any] = yaml.safe_load(VECTORS.read_text(encoding="utf-8"))
    bases: dict[str, dict[str, Any]] = {
        str(item["kind"]): json.loads(item["canonical_json"]) for item in document["vectors"]
    }
    canonical = {
        name: json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        for name, value in bases.items()
    }
    base_hashes = {name: canonical_sha256(value) for name, value in bases.items()}
    mutation_hashes: dict[tuple[str, str], str] = {}
    mutation_values: dict[str, dict[str, Any]] = document["mutation_values"]
    for item in document["mutation_vectors"]:
        base = str(item["base"])
        field = str(item["field"])
        mutated = copy.deepcopy(bases[base])
        configured = mutation_values.get(base, {})
        _set_path(mutated, field, _replacement(field, configured))
        mutation_hashes[(base, field)] = canonical_sha256(mutated)
    return base_hashes, mutation_hashes, canonical


def _render() -> str:
    base_hashes, mutation_hashes, canonical = _computed()
    lines = VECTORS.read_text(encoding="utf-8").splitlines()
    current_kind: str | None = None
    rendered: list[str] = []
    mutation_pattern = re.compile(
        r"^(\s*- \{base: ([^,]+), field: (.+), expected_hash: )sha256:[0-9a-f]{64}(\})$"
    )
    for line in lines:
        kind_match = re.match(r"^  - kind: (.+)$", line)
        if kind_match:
            current_kind = kind_match.group(1)
        elif current_kind is not None and line.startswith("    canonical_json: "):
            line = "    canonical_json: " + repr(canonical[current_kind])
        elif current_kind is not None and line.startswith("    expected_hash: "):
            line = f"    expected_hash: {base_hashes[current_kind]}"
            current_kind = None
        else:
            mutation_match = mutation_pattern.match(line)
            if mutation_match:
                prefix, base, raw_field, suffix = mutation_match.groups()
                field = raw_field.strip('"')
                line = f"{prefix}{mutation_hashes[(base, field)]}{suffix}"
        rendered.append(line)
    return "\n".join(rendered) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    rendered = _render()
    current = VECTORS.read_text(encoding="utf-8")
    if args.write:
        VECTORS.write_text(rendered, encoding="utf-8")
    elif rendered != current:
        raise SystemExit("Alert hash vectors are stale; run this tool with --write")


if __name__ == "__main__":
    main()
