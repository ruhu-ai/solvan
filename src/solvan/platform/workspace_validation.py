"""Deterministic patch validation and regional Cloud Run Sandbox orchestration."""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import cast

from solvan.platform.cloud_run_sandbox import (
    CloudRunSandboxExecutor,
    SandboxInputFile,
    SandboxOutputFile,
)
from solvan.platform.repository_snapshot import RepositorySnapshot

_DIFF_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class PatchValidationReceipt:
    sandbox_resource: str
    changed_paths: tuple[str, ...]
    reproduction_exit_code: int
    test_exit_code: int
    unified_diff: bytes
    reproduction_output: bytes
    test_output: bytes


@dataclass(frozen=True, slots=True)
class _ParsedReceipt:
    changed_paths: tuple[str, ...]
    reproduction_exit_code: int
    test_exit_code: int


def validate_unified_diff(
    unified_diff: str, *, allowed_file_globs: tuple[str, ...]
) -> tuple[str, ...]:
    encoded = unified_diff.encode()
    if not encoded or len(encoded) > 500_000 or "\x00" in unified_diff:
        raise ValueError("repair diff is empty, binary, or exceeds its byte ceiling")
    matches = _DIFF_HEADER.findall(unified_diff)
    if not matches:
        raise ValueError("repair output is not a git unified diff")
    paths: list[str] = []
    for left, right in matches:
        if left != right:
            raise ValueError("repair diff cannot rename files")
        parsed = PurePosixPath(left)
        if (
            left.startswith("/")
            or "\\" in left
            or ".." in parsed.parts
            or not any(fnmatch.fnmatchcase(left, pattern) for pattern in allowed_file_globs)
        ):
            raise ValueError("repair diff path is unsafe or outside the approved globs")
        if left not in paths:
            paths.append(left)
    if len(paths) > 32:
        raise ValueError("repair diff changes too many files")
    return tuple(paths)


class WorkspacePatchValidator:
    def __init__(self, sandbox: CloudRunSandboxExecutor) -> None:
        self._sandbox = sandbox

    def execute(
        self,
        *,
        case_id: str,
        snapshot: RepositorySnapshot,
        unified_diff: str,
        reproduction_command: str,
        test_command: str,
        allowed_file_globs: tuple[str, ...],
    ) -> PatchValidationReceipt:
        changed_paths = validate_unified_diff(unified_diff, allowed_file_globs=allowed_file_globs)
        reproduction = _command(reproduction_command, purpose="reproduction")
        command = _command(test_command, purpose="test")
        snapshot_bytes = json.dumps(
            {
                "schema_version": 1,
                "base_commit_sha": snapshot.base_commit_sha,
                "files": snapshot.prompt_payload(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        required = (
            "receipt.json",
            "repair.patch",
            "reproduction-output.txt",
            "test-output.txt",
        )
        result = self._sandbox.execute(
            execution_name=f"solvan-{case_id[-20:]}",
            reproduction_argv=tuple(reproduction),
            test_argv=tuple(command),
            files=(
                SandboxInputFile("snapshot.json", snapshot_bytes),
                SandboxInputFile("proposal.patch", unified_diff.encode()),
            ),
            output_names=required,
        )
        output_by_name = {item.name: item for item in result.output_files}
        if tuple(output_by_name) != required:
            raise RuntimeError("repair sandbox returned an incomplete or excess artifact set")
        receipt = _receipt(output_by_name["receipt.json"])
        if receipt.changed_paths != changed_paths:
            raise RuntimeError("sandbox changed-path receipt differs from validated patch")
        if output_by_name["repair.patch"].content != unified_diff.encode():
            raise RuntimeError("sandbox patch artifact differs from the proposed patch")
        if result.stderr.strip() and receipt.test_exit_code == 0:
            raise RuntimeError("sandbox reported stderr with a successful test receipt")
        return PatchValidationReceipt(
            sandbox_resource=result.sandbox_name,
            changed_paths=changed_paths,
            reproduction_exit_code=receipt.reproduction_exit_code,
            test_exit_code=receipt.test_exit_code,
            unified_diff=output_by_name["repair.patch"].content,
            reproduction_output=output_by_name["reproduction-output.txt"].content,
            test_output=output_by_name["test-output.txt"].content,
        )


def _receipt(item: SandboxOutputFile) -> _ParsedReceipt:
    try:
        value = json.loads(item.content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("repair sandbox receipt is not JSON") from error
    if not isinstance(value, dict) or set(value) != {
        "changed_paths",
        "reproduction_exit_code",
        "test_exit_code",
    }:
        raise RuntimeError("repair sandbox receipt has an unsupported schema")
    if (
        not isinstance(value["changed_paths"], list)
        or not all(isinstance(item, str) for item in value["changed_paths"])
        or not isinstance(value["reproduction_exit_code"], int)
        or not isinstance(value["test_exit_code"], int)
    ):
        raise RuntimeError("repair sandbox receipt fields are malformed")
    return _ParsedReceipt(
        tuple(cast(list[str], value["changed_paths"])),
        value["reproduction_exit_code"],
        value["test_exit_code"],
    )


def _command(value: str, *, purpose: str) -> list[str]:
    command = shlex.split(value, posix=True)
    if not command or len(command) > 32 or any(len(item) > 512 for item in command):
        raise ValueError(f"repair {purpose} command is empty or exceeds its argument ceiling")
    return command
