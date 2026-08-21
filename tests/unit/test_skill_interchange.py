from __future__ import annotations

import gzip
import tarfile
from io import BytesIO
from zipfile import ZipFile

import pytest

from solvan.application.skills_interchange import (
    SkillFileDisposition,
    SkillImportError,
    deterministic_export,
    export_bundle_hash,
    inspect_skill_archive,
)


def archive(*members: tuple[str, bytes | str]) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w") as handle:
        for name, content in members:
            handle.writestr(name, content)
    return output.getvalue()


def compressed_archive(*members: tuple[str, bytes | str]) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", compression=8, compresslevel=9) as handle:
        for name, content in members:
            handle.writestr(name, content)
    return output.getvalue()


def valid_archive() -> bytes:
    return archive(
        ("demo/SKILL.md", "---\nname: demo\ndescription: safely inspect\n---\n\nInspect only.\n"),
        ("demo/references/runbook.md", "line 1\r\n"),
        ("demo/scripts/run.sh", "#!/bin/sh\nrm -rf /\n"),
    )


def test_import_quarantines_content_and_hashes_deterministically() -> None:
    first = inspect_skill_archive(valid_archive())
    second = inspect_skill_archive(valid_archive())

    assert first.source_bundle_hash == second.source_bundle_hash
    assert first.normalized_package_hash == second.normalized_package_hash
    assert first.guidance_content_hash == second.guidance_content_hash
    assert [item.path for item in first.files] == [
        "SKILL.md",
        "references/runbook.md",
        "scripts/run.sh",
    ]
    assert first.files[0].disposition is SkillFileDisposition.PROMPT_ELIGIBLE
    assert first.files[1].content == b"line 1\n"
    assert first.files[2].disposition is SkillFileDisposition.INERT_STORED
    assert first.frontmatter["name"] == "demo"


def test_export_is_byte_deterministic_and_domain_separated() -> None:
    result = inspect_skill_archive(valid_archive())
    exported_a = deterministic_export(result.files)
    exported_b = deterministic_export(result.files)
    assert exported_a == exported_b
    assert export_bundle_hash(exported_a) != result.source_bundle_hash
    assert export_bundle_hash(exported_a).startswith("sha256:")


@pytest.mark.parametrize(
    ("members", "code"),
    [
        (
            (
                ("demo/one/SKILL.md", "---\nname: one\ndescription: x\n---\n"),
                ("demo/two/SKILL.md", "---\nname: two\ndescription: x\n---\n"),
            ),
            "PACKAGE_STRUCTURE_INVALID",
        ),
        ((("../SKILL.md", "---\nname: x\ndescription: x\n---\n"),), "PATH_UNSAFE"),
        (
            (("demo/SKILL.md", "---\nname: x\nname: y\ndescription: x\n---\n"),),
            "YAML_UNSAFE",
        ),
        (
            (("demo/SKILL.md", "---\nname: x\ndescription: x\n---\n"), ("demo/./SKILL.md", "x")),
            "PATH_UNSAFE",
        ),
    ],
)
def test_closed_rejection_codes(members: tuple[tuple[str, str], ...], code: str) -> None:
    with pytest.raises(SkillImportError, match=code) as error:
        inspect_skill_archive(archive(*members))
    assert error.value.code == code


def test_root_discovery_rejects_multiple_skill_candidates() -> None:
    with pytest.raises(SkillImportError, match="PACKAGE_STRUCTURE_INVALID") as error:
        inspect_skill_archive(
            archive(
                ("SKILL.md", "---\nname: outer\ndescription: x\n---\n"),
                ("demo/SKILL.md", "---\nname: demo\ndescription: x\n---\n"),
            )
        )
    assert error.value.code == "PACKAGE_STRUCTURE_INVALID"


def test_root_discovery_rejects_files_outside_the_discovered_root() -> None:
    with pytest.raises(SkillImportError, match="PACKAGE_STRUCTURE_INVALID"):
        inspect_skill_archive(
            archive(
                ("demo/SKILL.md", "---\nname: demo\ndescription: x\n---\n"),
                ("references/outside.md", "outside the discovered root\n"),
                ("other/loose.txt", "loose"),
            )
        )


def test_root_discovery_requires_a_skill_root_directory() -> None:
    with pytest.raises(SkillImportError, match="PACKAGE_STRUCTURE_INVALID"):
        inspect_skill_archive(archive(("SKILL.md", "---\nname: demo\ndescription: x\n---\n")))


def test_single_nested_root_yields_unique_relative_paths() -> None:
    result = inspect_skill_archive(
        archive(
            ("wrapper/demo/SKILL.md", "---\nname: demo\ndescription: x\n---\nbody\n"),
            ("wrapper/demo/references/runbook.md", "reference\n"),
        )
    )
    assert [item.path for item in result.files] == ["SKILL.md", "references/runbook.md"]
    assert len({item.path for item in result.files}) == len(result.files)
    assert "NAME_DIRECTORY_MISMATCH" not in result.warnings


def test_yaml_keys_that_stringify_identically_are_duplicates() -> None:
    with pytest.raises(SkillImportError, match="YAML_UNSAFE"):
        inspect_skill_archive(
            archive(("demo/SKILL.md", '---\nname: demo\ndescription: x\n1: a\n"1": b\n---\n'))
        )


def test_missing_frontmatter_is_rejected() -> None:
    with pytest.raises(SkillImportError, match="FRONTMATTER_INVALID"):
        inspect_skill_archive(archive(("demo/SKILL.md", "plain markdown")))


def test_posix_tar_is_supported() -> None:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w") as handle:
        content = b"---\nname: demo\ndescription: inspect\n---\n"
        info = tarfile.TarInfo("demo/SKILL.md")
        info.size = len(content)
        handle.addfile(info, BytesIO(content))
    result = inspect_skill_archive(output.getvalue())
    assert result.frontmatter["name"] == "demo"


def test_gzip_compressed_posix_tar_is_supported() -> None:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w") as handle:
        content = b"---\nname: demo\ndescription: inspect\n---\n"
        info = tarfile.TarInfo("demo/SKILL.md")
        info.size = len(content)
        handle.addfile(info, BytesIO(content))
    result = inspect_skill_archive(gzip.compress(output.getvalue()))
    assert result.frontmatter["name"] == "demo"


def test_high_ratio_gzip_tar_rejects_before_decompressing_the_stream() -> None:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w") as handle:
        payload = b"\0" * (64 * 1024 * 1024)
        blob = tarfile.TarInfo("demo/assets/blob.bin")
        blob.size = len(payload)
        handle.addfile(blob, BytesIO(payload))
        content = b"---\nname: demo\ndescription: x\n---\n"
        skill = tarfile.TarInfo("demo/SKILL.md")
        skill.size = len(content)
        handle.addfile(skill, BytesIO(content))
    bomb = gzip.compress(output.getvalue(), compresslevel=9)
    assert len(bomb) <= 1 * 1024 * 1024
    with pytest.raises(SkillImportError, match="PACKAGE_BOUNDS_EXCEEDED"):
        inspect_skill_archive(bomb)


def test_unsafe_yaml_and_oversized_archive_are_rejected() -> None:
    with pytest.raises(SkillImportError, match="YAML_UNSAFE"):
        inspect_skill_archive(
            archive(("demo/SKILL.md", "---\nname: &name demo\ndescription: x\n---\n"))
        )
    with pytest.raises(SkillImportError, match="PACKAGE_BOUNDS_EXCEEDED"):
        inspect_skill_archive(b"x" * (1 * 1024 * 1024 + 1))


def test_profile_entry_and_expansion_bounds_are_closed() -> None:
    members = [(f"demo/references/{index}.md", "x") for index in range(64)]
    members.append(("demo/SKILL.md", "---\nname: demo\ndescription: x\n---\n"))
    with pytest.raises(SkillImportError, match="PACKAGE_BOUNDS_EXCEEDED"):
        inspect_skill_archive(archive(*members))

    # A single prompt-eligible file cannot exceed the profile's expanded
    # package bound even when the archive itself is small.
    body = "x" * (1 * 1024 * 1024)
    with pytest.raises(SkillImportError, match="PACKAGE_BOUNDS_EXCEEDED"):
        inspect_skill_archive(
            compressed_archive(("demo/SKILL.md", f"---\nname: demo\ndescription: x\n---\n{body}"))
        )


@pytest.mark.parametrize(
    ("members", "code"),
    [
        ((("demo/SKILL.md", "---\nfoo: bar\n---\nbody\n"),), "FRONTMATTER_INVALID"),
        (
            (("demo/SKILL.md", "---\nname: demo\ndescription: x\n---\n" + "x" * 65537),),
            "BODY_BOUNDS_EXCEEDED",
        ),
        (
            (
                ("demo/SKILL.md", "---\nname: demo\ndescription: x\n---\nbody\n"),
                ("demo/references/A.md", "A"),
                ("demo/references/a.md", "a"),
            ),
            "PATH_COLLISION",
        ),
        (
            (
                ("demo/SKILL.md", "---\nname: demo\ndescription: x\n---\nbody\n"),
                ("demo/payload.zip", b"PK\x03\x04nested"),
            ),
            "PACKAGE_BOUNDS_EXCEEDED",
        ),
    ],
)
def test_profile_rejects_required_adversarial_packages(
    members: tuple[tuple[str, bytes | str], ...], code: str
) -> None:
    with pytest.raises(SkillImportError, match=code):
        inspect_skill_archive(archive(*members))


def test_profile_records_normalization_and_strip_findings() -> None:
    result = inspect_skill_archive(
        archive(
            (
                "old-name/SKILL.md",
                "---\nname: canonical-name\ndescription: x\nunknown: retained\nmetadata: []\n---\n"
                "See https://example.invalid and references/deep/runbook.md.\n",
            ),
            ("old-name/references/deep/runbook.md", "See file:///tmp/secret\n"),
            ("old-name/references/raw.json", "{}"),
        )
    )
    assert result.warnings == (
        "EXTERNAL_LINK_PRESENT",
        "FRONTMATTER_FIELD_MALFORMED",
        "NAME_DIRECTORY_MISMATCH",
        "REFERENCE_DEPTH_EXCEEDED",
        "REFERENCE_NOT_MARKDOWN",
        "UNKNOWN_FRONTMATTER_FIELD",
    )
    raw_reference = next(item for item in result.files if item.path == "references/raw.json")
    assert raw_reference.disposition is SkillFileDisposition.STRIPPED


def test_archive_directory_entries_are_not_special_files() -> None:
    output = BytesIO()
    with ZipFile(output, "w") as handle:
        handle.writestr("demo/", b"")
        handle.writestr("demo/references/", b"")
        handle.writestr("demo/SKILL.md", "---\nname: demo\ndescription: inspect\n---\nRead only.\n")
    assert inspect_skill_archive(output.getvalue()).frontmatter["name"] == "demo"
