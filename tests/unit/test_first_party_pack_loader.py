"""The first-party pack loader publishes built-in product guidance (spec 18 §11)."""

from pathlib import Path

import pytest

import tools.load_first_party_skill_packs as loader
from solvan.application.operational_guidance import GuidanceKind, GuidanceLifecycle
from solvan.application.skills_interchange import inspect_skill_archive
from tools.load_first_party_skill_packs import (
    APPROVER_PRINCIPAL,
    AUTHOR_PRINCIPAL,
    EVALUATOR_PRINCIPAL,
    KNOWN_PREDICATES,
    PackLoaderError,
    _display_name,
    provenance_attestation_hash,
    release_commit,
    revision_for,
)

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _revision(pack: str, **overrides):
    return revision_for(
        ROOT / "guidance" / pack,
        commit=COMMIT,
        agent_keys=("evidence-agent",),
        profile_revisions=("evidence.gcp-core.v1@1",),
        **overrides,
    )


def _write_pack(
    root: Path,
    *,
    family: str = "reliability",
    directory: str = "triage-sample",
    name: str | None = None,
    description: str = "A bounded diagnostic checklist.",
    body: str = "# Read the checklist\n",
    provenance: bool = True,
) -> Path:
    pack = root / "guidance" / family / directory
    pack.mkdir(parents=True)
    (pack / "SKILL.md").write_text(
        f"---\nname: {name if name is not None else directory}\n"
        f"description: {description}\n---\n{body}",
        encoding="utf-8",
    )
    if provenance:
        (pack / "PROVENANCE.yaml").write_text(
            f"schema_version: 1\npack: {family}.{directory}\nsource_kind: FIRST_PARTY\n"
            "license: Apache-2.0\n",
            encoding="utf-8",
        )
    return pack


def test_release_principals_are_three_distinct_identities() -> None:
    assert len({AUTHOR_PRINCIPAL, EVALUATOR_PRINCIPAL, APPROVER_PRINCIPAL}) == 3
    assert AUTHOR_PRINCIPAL.startswith("product:")
    assert EVALUATOR_PRINCIPAL.startswith("release:")
    assert APPROVER_PRINCIPAL.startswith("release:")


def test_revision_pins_source_to_the_repository_path_not_the_commit() -> None:
    """Release provenance lives in decision IDs and receipts, not the digest.

    approval_digest covers source_ref, so embedding the commit SHA made every
    commit invalidate the digest-equality no-op and superseded every pack on
    the next load.
    """

    revision = _revision("reliability/triage-connection-exhaustion")
    assert revision.source_ref.startswith("guidance/reliability/triage-connection-exhaustion")
    assert COMMIT[:12] not in revision.source_ref
    assert revision.author_principal == AUTHOR_PRINCIPAL
    assert revision.lifecycle is GuidanceLifecycle.DRAFT
    assert revision.version == "1"
    assert revision.supersedes is None


def test_revision_carries_the_requested_version_and_supersedes_reference() -> None:
    revision = _revision(
        "reliability/triage-connection-exhaustion",
        version="3",
        supersedes="reliability.triage-connection-exhaustion@2",
    )
    assert revision.version == "3"
    assert revision.supersedes == "reliability.triage-connection-exhaustion@2"


def test_family_metadata_maps_kind_and_incident_classes() -> None:
    triage = _revision("reliability/triage-connection-exhaustion")
    assert triage.guidance_kind is GuidanceKind.DIAGNOSTIC_PROCEDURE
    assert "CONNECTION_EXHAUSTION" in triage.applicable_incident_classes
    lookup = _revision("platform/lookup-service-topology")
    assert lookup.guidance_kind is GuidanceKind.CHECKLIST
    template = _revision("reporting/postmortem-draft")
    assert template.guidance_kind is GuidanceKind.RUNBOOK
    knowledge = _revision("payments/payments-connection-pool")
    assert knowledge.guidance_kind is not GuidanceKind.SKILL


def test_step_predicates_stay_inside_the_registered_set() -> None:
    revision = _revision("payments/payments-connection-pool")
    for step in revision.steps:
        key = f"{step.completion_predicate_key}@{step.completion_predicate_version}"
        assert key in KNOWN_PREDICATES


def test_display_name_uppercases_only_exact_acronym_tokens() -> None:
    assert _display_name("payments-checkout-slo") == "Payments checkout SLO"
    assert _display_name("interpret-slo-burn") == "Interpret SLO burn"
    assert _display_name("slo-review") == "SLO review"
    assert _display_name("triage-slow-queries") == "Triage slow queries"
    assert _display_name("slot-machine-audit") == "Slot machine audit"
    assert _display_name("check-api-sli-health") == "Check API SLI health"


def test_release_commit_refuses_non_commit_values(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(PackLoaderError, match="full lowercase git commit"):
        release_commit("workspace")
    monkeypatch.setenv("SOLVAN_RELEASE_COMMIT", "UNSET")
    with pytest.raises(PackLoaderError, match="full lowercase git commit"):
        release_commit()


def test_release_commit_prefers_explicit_then_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_RELEASE_COMMIT", "f" * 40)
    assert release_commit("e" * 40) == "e" * 40
    assert release_commit() == "f" * 40


def test_release_commit_refuses_when_no_source_identifies_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOLVAN_RELEASE_COMMIT", raising=False)

    def no_git(*args: object, **kwargs: object) -> object:
        raise OSError("git is unavailable")

    monkeypatch.setattr(loader.subprocess, "run", no_git)
    with pytest.raises(PackLoaderError, match="unidentifiable"):
        release_commit()


def test_revision_for_refuses_empty_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    pack = _write_pack(tmp_path, body="\n\n")
    with pytest.raises(PackLoaderError, match="body is empty"):
        _revision_from(pack)


def test_revision_for_refuses_frontmatter_directory_name_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    pack = _write_pack(tmp_path, name="another-name")
    with pytest.raises(PackLoaderError, match="must equal the pack directory name"):
        _revision_from(pack)


def test_revision_for_refuses_missing_provenance_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    pack = _write_pack(tmp_path, provenance=False)
    with pytest.raises(PackLoaderError, match="provenance attestation is missing"):
        _revision_from(pack)
    with pytest.raises(PackLoaderError, match="provenance attestation is missing"):
        provenance_attestation_hash(pack)


def test_revision_for_refuses_forbidden_language_on_the_first_body_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    pack = _write_pack(tmp_path, body="Record the admin password before continuing.\n")
    with pytest.raises(ValueError, match="prohibited authority or secret"):
        _revision_from(pack)


def test_revision_for_refuses_over_length_description(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    pack = _write_pack(tmp_path, description="x" * 1010)
    with pytest.raises(ValueError, match="at most 1000"):
        _revision_from(pack)


def test_provenance_attestation_hash_is_content_bound(tmp_path: Path) -> None:
    pack = _write_pack(tmp_path)
    first = provenance_attestation_hash(pack)
    assert first.startswith("sha256:") and len(first) == 71
    (pack / "PROVENANCE.yaml").write_text("schema_version: 1\n", encoding="utf-8")
    assert provenance_attestation_hash(pack) != first


def test_the_package_is_byte_stable_and_carries_the_whole_pack_directory(
    tmp_path: Path,
) -> None:
    pack = _write_pack(tmp_path)
    (pack / "references").mkdir()
    (pack / "references" / "detail.md").write_text("# Detail\n", encoding="utf-8")
    first = loader._package_bytes(pack)
    assert first == loader._package_bytes(pack)
    inspection = inspect_skill_archive(first)
    assert inspection.frontmatter["name"] == "triage-sample"
    assert {item.path for item in inspection.files} == {
        "SKILL.md",
        "PROVENANCE.yaml",
        "references/detail.md",
    }


def test_the_package_digest_moves_only_with_the_pack_material(tmp_path: Path) -> None:
    pack = _write_pack(tmp_path)
    before = inspect_skill_archive(loader._package_bytes(pack)).source_bundle_hash
    (pack / "SKILL.md").write_text(
        "---\nname: triage-sample\ndescription: A bounded diagnostic checklist.\n---\n# Revised\n",
        encoding="utf-8",
    )
    assert inspect_skill_archive(loader._package_bytes(pack)).source_bundle_hash != before


def test_packaging_refuses_a_symbolic_link(tmp_path: Path) -> None:
    pack = _write_pack(tmp_path)
    (pack / "escape.md").symlink_to(tmp_path / "guidance")
    with pytest.raises(PackLoaderError, match="symbolic link"):
        loader._package_bytes(pack)


def test_the_import_records_no_scanner_verdict_it_did_not_produce() -> None:
    # Specification 18 §6.2 phase 3 does not run in the catalog-publication job:
    # there is no Model Armor gate or quarantine bucket there. The recorded state
    # must therefore name the absence and must never carry a verdict.
    assert loader.IMPORT_SCANNER_STATE == {"QUARANTINE_SCAN": "not-performed"}
    assert "ALLOWED" not in loader.IMPORT_SCANNER_STATE.values()


def test_repository_references_are_commit_pinned_and_resolvable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    pack = _write_pack(tmp_path)
    assert loader._repository_ref(pack, COMMIT) == (
        f"git:{COMMIT}:guidance/reliability/triage-sample"
    )
    assert loader._repository_ref(pack, COMMIT, suffix="/PROVENANCE.yaml").endswith(
        "/PROVENANCE.yaml"
    )


def test_first_party_authorship_is_attested_rather_than_assumed_from_location(
    tmp_path: Path,
) -> None:
    pack = _write_pack(tmp_path)
    loader._require_first_party_attestation(pack)
    (pack / "PROVENANCE.yaml").write_text(
        "schema_version: 1\npack: reliability.triage-sample\nsource_kind: IMPORTED\n"
        "license: Apache-2.0\n",
        encoding="utf-8",
    )
    with pytest.raises(PackLoaderError, match="FIRST_PARTY authorship"):
        loader._require_first_party_attestation(pack)


def test_the_compile_binding_writes_no_quarantine_object() -> None:
    with pytest.raises(PackLoaderError, match="writes no quarantine object"):
        loader._UnusedObjectWriter().put_bytes(
            object_name="skills/x/source.bin", content=b"", content_type="application/octet-stream"
        )


def _revision_from(pack: Path):
    return revision_for(
        pack,
        commit=COMMIT,
        agent_keys=("evidence-agent",),
        profile_revisions=("evidence.gcp-core.v1@1",),
    )
