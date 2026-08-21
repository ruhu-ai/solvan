from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
from pydantic import ValidationError

from apps.api.agent_skills import SkillExportHttpRequest, SkillImportHttpRequest
from solvan.application.skills_interchange_service import (
    InMemorySkillImportRepository,
    SkillImportCommand,
    SkillImportService,
)
from solvan.application.skills_security import DeterministicModelArmor
from solvan.domain import Scope


def package() -> bytes:
    """Build a byte-identical archive on every call.

    `ZipFile.writestr` stamps each entry with the *current* local time, and the
    ZIP format stores that at two-second resolution. Two calls that straddled a
    boundary produced different bytes, a different source bundle hash and so a
    different request hash — which made the idempotency assertion below fail
    roughly one run in five. Pinning the timestamp makes the fixture describe
    the same package every time, which is what the test is actually about.
    """

    output = BytesIO()
    with ZipFile(output, "w") as archive:
        entry = ZipInfo("demo/SKILL.md", date_time=(1980, 1, 1, 0, 0, 0))
        entry.compress_type = ZIP_DEFLATED
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, "---\nname: demo\ndescription: inspect\n---\nRead only.\n")
    return output.getvalue()


def request() -> SkillImportCommand:
    return SkillImportCommand(
        command_id="cmd_skill_1",
        scope=Scope(
            "org_01J4QZK8Q4J8Q6B95KQY4M9R2S",
            "prj_01J4QZK8Q4J8Q6B95KQY4M9R2S",
            "env_01J4QZK8Q4J8Q6B95KQY4M9R2S",
        ),
        purpose="GUIDANCE_IMPORT",
        classification="INTERNAL",
        region="europe-west1",
        source_kind="ARCHIVE",
        source_ref="upload://demo",
        principal="operator@example.com",
        authorization_ref="grant://author/1",
    )


def test_import_is_idempotent_and_quarantines() -> None:
    repository = InMemorySkillImportRepository()
    service = SkillImportService(repository, armor=DeterministicModelArmor())
    first = service.import_archive(request(), package())
    second = service.import_archive(request(), package())
    assert first.attempt_id == second.attempt_id
    assert first.decision == "QUARANTINED"
    assert first.inspection is not None


def test_service_construction_requires_an_armor_scanner() -> None:
    with pytest.raises(TypeError):
        SkillImportService(InMemorySkillImportRepository())  # type: ignore[call-arg]


def test_import_request_identity_excludes_retry_credentials_and_key() -> None:
    first = request()
    retried = first.model_copy(
        update={
            "authorization_ref": "grant://author/refreshed",
            "idempotency_key": "retry-key-0002",
        }
    )
    bundle_hash = "sha256:" + "a" * 64
    assert SkillImportService.request_hash(
        first, source_bundle_hash=bundle_hash
    ) == SkillImportService.request_hash(retried, source_bundle_hash=bundle_hash)


def test_import_request_identity_binds_scanner_policy_versions() -> None:
    bundle_hash = "sha256:" + "a" * 64
    first = SkillImportService.request_hash(
        request(),
        source_bundle_hash=bundle_hash,
        scanner_versions={"MODEL_ARMOR": "revision-1"},
    )
    changed = SkillImportService.request_hash(
        request(),
        source_bundle_hash=bundle_hash,
        scanner_versions={"MODEL_ARMOR": "revision-2"},
    )
    assert first != changed


def test_disallowed_license_is_preserved_in_quarantine_for_governance() -> None:
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr(
            "demo/SKILL.md",
            "---\nname: demo\ndescription: inspect\nlicense: GPL-3.0-only\n---\nRead only.\n",
        )
    result = SkillImportService(
        InMemorySkillImportRepository(), armor=DeterministicModelArmor()
    ).import_archive(request(), output.getvalue())
    assert result.decision == "QUARANTINED"
    assert result.inspection is not None
    assert result.reason_codes == ("LICENSE_POLICY_DENIED",)


def test_rejected_attempt_is_durable_and_idempotent() -> None:
    repository = InMemorySkillImportRepository()
    service = SkillImportService(repository, armor=DeterministicModelArmor())
    first = service.import_archive(request(), b"not-an-archive")
    second = service.import_archive(request(), b"not-an-archive")
    assert first.attempt_id == second.attempt_id
    assert first.decision == "REJECTED"
    assert first.reason_codes == ("ARCHIVE_TYPE_UNSUPPORTED",)


def test_bounds_rejection_is_durable_not_an_early_exception() -> None:
    repository = InMemorySkillImportRepository()
    service = SkillImportService(repository, armor=DeterministicModelArmor())
    first = service.import_archive(request(), b"x" * (1 * 1024 * 1024 + 1))
    second = service.import_archive(request(), b"x" * (1 * 1024 * 1024 + 1))
    assert first.attempt_id == second.attempt_id
    assert first.decision == "REJECTED"
    assert first.reason_codes == ("PACKAGE_BOUNDS_EXCEEDED",)


def test_multiple_structural_failures_are_all_persisted_once() -> None:
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("../unsafe.txt", "unsafe")
        archive.writestr("demo/payload.zip", b"PK\x03\x04nested")
        archive.writestr(
            "demo/SKILL.md", "---\nname: demo\ndescription: inspect\n---\nRead only.\n"
        )
    repository = InMemorySkillImportRepository()
    result = SkillImportService(repository, armor=DeterministicModelArmor()).import_archive(
        request(), output.getvalue()
    )
    assert result.decision == "REJECTED"
    assert result.reason_codes == ("PACKAGE_BOUNDS_EXCEEDED", "PATH_UNSAFE")


def test_http_commands_refuse_caller_supplied_authorization_references() -> None:
    with pytest.raises(ValidationError):
        SkillImportHttpRequest(
            schema_version=1,
            command_id="cmd-skill-import",
            purpose="GUIDANCE_IMPORT",
            classification="INTERNAL",
            region="europe-west1",
            source_kind="ARCHIVE",
            source_ref="upload://demo",
            archive_base64="AA==",
            authorization_ref="caller-selected",
        )
    with pytest.raises(ValidationError):
        SkillExportHttpRequest(
            version="1",
            destination_id="registered-destination",
            purpose="GUIDANCE_DISTRIBUTION",
            authorization_ref="caller-selected",
        )
