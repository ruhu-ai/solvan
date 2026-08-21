#!/usr/bin/env python3
"""Validate checked-in first-party Agent Skills packs without executing them.

Beyond the interchange inspection, every pack is run through the exact
pack-to-revision conversion the release loader executes
(`tools.load_first_party_skill_packs.revision_for`), so any pack the loader
would refuse at deployment fails this merge gate instead.
"""

from __future__ import annotations

import ast
import io
import re
import sys
from pathlib import Path
from zipfile import ZipFile

import yaml

from solvan.application.operational_guidance import GuidanceError
from solvan.application.skills_interchange import SkillImportError, inspect_skill_archive

#: Deterministic placeholders for the loader conversion. The validator has no
#: database, so it cannot resolve real approved profiles; the conversion is
#: exercised with the loader's own family-to-agent mapping and one exact
#: placeholder profile reference so every pack-material check still runs.
_VALIDATION_COMMIT = "0" * 40
_VALIDATION_PROFILES = ("merge-gate.placeholder@1",)


def _validate_acceptance_registry(root: Path) -> int:
    registry_path = root / "specs/artifacts/skills-acceptance-registry.yaml"
    specification_path = root / "specs/18-agent-skills-interchange.md"
    try:
        registry = yaml.safe_load(registry_path.read_text())
    except (OSError, yaml.YAMLError) as error:
        print(f"{registry_path}: unreadable acceptance registry: {error}", file=sys.stderr)
        return 0
    if not isinstance(registry, dict) or registry.get("version") != 2:
        print(f"{registry_path}: acceptance registry version must be 2", file=sys.stderr)
        return 0
    records = registry.get("acceptance")
    if not isinstance(records, list):
        print(f"{registry_path}: acceptance must be a list", file=sys.stderr)
        return 0
    expected = set(
        re.findall(r"`((?:CT|IT|SEC)-SKILL-[A-Z0-9-]+)`", specification_path.read_text())
    )
    observed: set[str] = set()
    parsed_tests: dict[Path, set[str]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            print(f"{registry_path}: every acceptance entry needs an id", file=sys.stderr)
            return 0
        acceptance_id = record["id"]
        if acceptance_id in observed:
            print(f"{registry_path}: duplicate acceptance id {acceptance_id}", file=sys.stderr)
            return 0
        observed.add(acceptance_id)
        tests = record.get("tests")
        if not isinstance(tests, list) or not tests:
            print(f"{registry_path}: {acceptance_id} has no executable tests", file=sys.stderr)
            return 0
        for node_id in tests:
            if not isinstance(node_id, str) or "::" not in node_id:
                print(
                    f"{registry_path}: {acceptance_id} has invalid node id {node_id!r}",
                    file=sys.stderr,
                )
                return 0
            relative, function = node_id.split("::", 1)
            function = function.split("[", 1)[0]
            path = root / relative
            if path not in parsed_tests:
                try:
                    tree = ast.parse(path.read_text(), filename=str(path))
                except (OSError, SyntaxError) as error:
                    print(f"{registry_path}: cannot inspect {relative}: {error}", file=sys.stderr)
                    return 0
                parsed_tests[path] = {
                    node.name
                    for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                }
            if function not in parsed_tests[path]:
                print(
                    f"{registry_path}: {acceptance_id} references missing {node_id}",
                    file=sys.stderr,
                )
                return 0
        for command in record.get("commands", []):
            if not isinstance(command, str) or not (root / command).is_file():
                print(
                    f"{registry_path}: {acceptance_id} references missing command {command!r}",
                    file=sys.stderr,
                )
                return 0
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        print(
            f"{registry_path}: acceptance drift; missing={missing}, extra={extra}",
            file=sys.stderr,
        )
        return 0
    return len(observed)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from tools.load_first_party_skill_packs import (
        FAMILY_AGENT_KEYS,
        PackLoaderError,
        revision_for,
    )

    acceptance_count = _validate_acceptance_registry(root)
    if acceptance_count < 1:
        return 1
    packs = sorted(root.glob("guidance/*/*/SKILL.md"))
    if not packs:
        print("no first-party skill packs found", file=sys.stderr)
        return 1
    guidance_keys: set[str] = set()
    for skill_md in packs:
        if not skill_md.is_file():
            return 1
        pack = skill_md.parent
        provenance_path = pack / "PROVENANCE.yaml"
        if not provenance_path.is_file():
            print(f"{pack}: provenance attestation is missing", file=sys.stderr)
            return 1
        try:
            provenance = yaml.safe_load(provenance_path.read_text())
        except yaml.YAMLError:
            print(f"{pack}: provenance attestation is invalid YAML", file=sys.stderr)
            return 1
        if not isinstance(provenance, dict) or provenance.get("schema_version") != 1:
            print(f"{pack}: provenance schema version is invalid", file=sys.stderr)
            return 1
        if provenance.get("pack") != f"{pack.parent.name}.{pack.name}":
            print(f"{pack}: provenance pack key does not match path", file=sys.stderr)
            return 1
        if (
            provenance.get("source_kind") != "FIRST_PARTY"
            or provenance.get("license") != "Apache-2.0"
        ):
            print(f"{pack}: provenance source or license is invalid", file=sys.stderr)
            return 1
        files = [path for path in pack.rglob("*") if path.is_file()]
        archive_bytes = io.BytesIO()
        with ZipFile(archive_bytes, "w") as archive:
            for path in files:
                relative = path.relative_to(pack).as_posix()
                archive.writestr(f"{pack.name}/{relative}", path.read_bytes())
        try:
            inspection = inspect_skill_archive(archive_bytes.getvalue())
        except SkillImportError as error:
            print(f"{pack}: {error.code}", file=sys.stderr)
            return 1
        if "NAME_DIRECTORY_MISMATCH" in inspection.warnings:
            print(f"{pack}: frontmatter name must equal the pack directory name", file=sys.stderr)
            return 1
        if inspection.frontmatter.get("license") != "Apache-2.0":
            print(f"{pack}: license evidence is not Apache-2.0", file=sys.stderr)
            return 1
        if inspection.frontmatter.get("metadata", {}).get("solvan-provenance") != "first-party":
            print(f"{pack}: first-party provenance is missing", file=sys.stderr)
            return 1
        family = pack.parent.name
        agent_keys = FAMILY_AGENT_KEYS.get(family)
        if not agent_keys:
            print(
                f"{pack}: guidance family {family!r} is not in the loader's owner-agent registry",
                file=sys.stderr,
            )
            return 1
        try:
            revision = revision_for(
                pack,
                commit=_VALIDATION_COMMIT,
                agent_keys=agent_keys,
                profile_revisions=_VALIDATION_PROFILES,
            )
        except (PackLoaderError, GuidanceError, ValueError) as error:
            print(f"{pack}: release loader would refuse this pack: {error}", file=sys.stderr)
            return 1
        if revision.guidance_key in guidance_keys:
            print(f"{pack}: duplicate guidance key {revision.guidance_key}", file=sys.stderr)
            return 1
        guidance_keys.add(revision.guidance_key)
    print(
        f"validated {len(packs)} first-party skill pack(s) and "
        f"{acceptance_count} acceptance bindings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
