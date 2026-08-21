from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from zipfile import ZipFile

import pytest
from pydantic import ValidationError

from solvan.application.operational_guidance import GuidanceLifecycle, GuidanceSourceKind
from solvan.application.skills_governance import (
    RefreshLedger,
    RepositoryObservation,
    SkillCompileCommand,
    compile_import,
    export_approved_revision,
    refresh_metadata_only,
)
from solvan.application.skills_interchange import inspect_skill_archive


def inspection():
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr(
            "demo/SKILL.md",
            "---\nname: demo\ndescription: inspect\nlicense: Apache-2.0\n---\nRead only.\n",
        )
    return inspect_skill_archive(output.getvalue())


def command() -> SkillCompileCommand:
    return SkillCompileCommand(
        guidance_key="reliability.demo",
        version="1",
        display_name="Demo skill",
        description="A safe demo skill",
        owner_department="Reliability",
        discoverable_departments=("Reliability",),
        applicable_service_kinds=("payments",),
        applicable_incident_classes=("availability",),
        symptom_tags=("errors",),
        purpose="incident-investigation",
        classification="INTERNAL",
        eligible_regions=("europe-west1",),
        allowed_agent_keys=("supervisor-agent",),
        required_profile_revisions=("evidence@1",),
        normalized_license_identifier="Apache-2.0",
        author_principal="user:author@example.com",
    )


def test_compile_is_draft_and_uses_typed_advisory_step() -> None:
    revision = compile_import(command=command(), attempt_id="sia_demo", inspection=inspection())
    assert str(revision.lifecycle) == "DRAFT"
    assert revision.steps[0].completion_predicate_key == "guidance-content-fetched"


def test_first_party_compilation_requires_exact_provenance() -> None:
    with pytest.raises(ValidationError, match="first-party attestation"):
        SkillCompileCommand.model_validate(
            {
                **command().model_dump(mode="json"),
                "source_classification": GuidanceSourceKind.SOLVAN_AUTHORED,
            }
        )
    first_party = SkillCompileCommand.model_validate(
        {
            **command().model_dump(mode="json"),
            "source_classification": GuidanceSourceKind.SOLVAN_AUTHORED,
            "provenance_attestation_ref": "gs://skills-attestations/pack#generation=7",
            "provenance_attestation_hash": "sha256:" + "7" * 64,
            "contains_third_party_material": False,
        }
    )
    revision = compile_import(
        command=first_party, attempt_id="sia_first_party", inspection=inspection()
    )
    assert revision.source_kind is GuidanceSourceKind.SOLVAN_AUTHORED

    imported = SkillCompileCommand.model_validate(
        {
            **command().model_dump(mode="json"),
            "source_classification": GuidanceSourceKind.IMPORTED,
            "provenance_attestation_ref": "gs://skills-attestations/pack#generation=8",
            "provenance_attestation_hash": "sha256:" + "8" * 64,
            "contains_third_party_material": True,
        }
    )
    assert (
        compile_import(
            command=imported, attempt_id="sia_imported", inspection=inspection()
        ).source_kind
        is GuidanceSourceKind.IMPORTED
    )


def test_export_requires_approval_and_refresh_is_fenced() -> None:
    revision = compile_import(command=command(), attempt_id="sia_demo", inspection=inspection())
    with pytest.raises(ValueError, match="LIFECYCLE_REFUSED"):
        export_approved_revision(
            revision=revision,
            files=inspection().files,
            destination_id="local",
        )
    ledger = RefreshLedger()
    lease = ledger.acquire("reliability.demo")
    with pytest.raises(ValueError, match="REFRESH_LEASE_HELD"):
        ledger.acquire("reliability.demo")
    with pytest.raises(ValueError, match="REFRESH_LEASE_FENCE"):
        ledger.release("reliability.demo", token="wrong")
    ledger.release("reliability.demo", token=lease.token)


def test_approved_export_rewrites_transport_metadata_and_preserves_content_digest() -> None:
    original = inspection()
    draft = compile_import(command=command(), attempt_id="sia_demo", inspection=original)
    approved = draft.model_copy(
        update={
            "lifecycle": GuidanceLifecycle.APPROVED,
            "evaluation_ref": "eval_demo",
            "approval_ref": "approval_demo",
            "approved_by_principal": "user:approver@example.com",
            "approved_at": datetime.now(UTC),
        }
    )
    bundle, receipt = export_approved_revision(
        revision=approved, files=original.files, destination_id="local"
    )
    exported = inspect_skill_archive(bundle)
    assert exported.guidance_content_hash == receipt.content_hash == approved.content_hash
    with pytest.raises(ValueError, match="STALE_CONTENT_ACKNOWLEDGMENT_NOT_APPLICABLE"):
        export_approved_revision(
            revision=approved,
            files=original.files,
            destination_id="local",
            stale_acknowledged=True,
        )


def test_deprecated_export_requires_and_records_explicit_stale_acknowledgment() -> None:
    original = inspection()
    deprecated = compile_import(
        command=command(), attempt_id="sia_demo", inspection=original
    ).model_copy(
        update={
            "lifecycle": GuidanceLifecycle.DEPRECATED,
            "evaluation_ref": "eval_demo",
            "approval_ref": "approval_demo",
            "approved_by_principal": "user:approver@example.com",
            "approved_at": datetime.now(UTC),
        }
    )
    with pytest.raises(ValueError, match="STALE_CONTENT_ACKNOWLEDGMENT_REQUIRED"):
        export_approved_revision(revision=deprecated, files=original.files, destination_id="local")
    _, receipt = export_approved_revision(
        revision=deprecated,
        files=original.files,
        destination_id="local",
        stale_acknowledged=True,
    )
    assert receipt.lifecycle == "DEPRECATED"


def test_refresh_is_metadata_only_and_token_fenced() -> None:
    class Connector:
        def __init__(self) -> None:
            self.called = False

        def observe_ref(
            self, *, repository_ref: str, upstream_ref: str, subdirectory: str
        ) -> RepositoryObservation:
            self.called = True
            assert repository_ref == "github://acme/demo"
            assert upstream_ref == "refs/heads/main"
            assert subdirectory == "guidance"
            return RepositoryObservation(commit_sha="a" * 40, subtree_hash="sha256:" + "1" * 64)

    connector = Connector()
    result = refresh_metadata_only(
        guidance_key="reliability.demo",
        repository_ref="github://acme/demo",
        upstream_ref="refs/heads/main",
        subdirectory="guidance",
        recorded_subtree_hash="sha256:" + "1" * 64,
        ledger=RefreshLedger(),
        connector=connector,
    )
    assert connector.called is True
    assert result.outcome == "UNCHANGED"
