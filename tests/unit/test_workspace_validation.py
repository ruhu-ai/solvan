from __future__ import annotations

import json

import pytest

from solvan.platform.cloud_run_sandbox import SandboxExecutionResult, SandboxOutputFile
from solvan.platform.repository_snapshot import RepositoryFile, RepositorySnapshot
from solvan.platform.workspace_validation import WorkspacePatchValidator, validate_unified_diff

PATCH = """diff --git a/src/a.py b/src/a.py
--- a/src/a.py
+++ b/src/a.py
@@ -1 +1 @@
-x=1
+x=2
"""


class FakeSandbox:
    def __init__(self, *, exit_code: int = 0) -> None:
        self.exit_code = exit_code

    def execute(self, **_: object) -> SandboxExecutionResult:
        return SandboxExecutionResult(
            sandbox_name="cloud-run-sandbox://europe-west1/rev/execution/hash",
            exit_code=0,
            stdout="",
            stderr="",
            output_files=(
                SandboxOutputFile(
                    "receipt.json",
                    json.dumps(
                        {
                            "changed_paths": ["src/a.py"],
                            "reproduction_exit_code": 1,
                            "test_exit_code": self.exit_code,
                        }
                    ).encode(),
                ),
                SandboxOutputFile("repair.patch", PATCH.encode()),
                SandboxOutputFile("reproduction-output.txt", b"1 failed\n"),
                SandboxOutputFile("test-output.txt", b"1 passed\n"),
            ),
        )


def test_validates_paths_and_returns_authoritative_sandbox_receipt() -> None:
    sandbox = FakeSandbox()
    executor = WorkspacePatchValidator(sandbox)  # type: ignore[arg-type]
    receipt = executor.execute(
        case_id="rel_00000000000000000000000000",
        snapshot=RepositorySnapshot(
            "a" * 40,
            (RepositoryFile("src/a.py", "x=1\n", "sha256:fixture", "100644"),),
        ),
        unified_diff=PATCH,
        reproduction_command="python -m unittest tests.test_a",
        test_command="python -m unittest tests.test_a",
        allowed_file_globs=("src/*.py",),
    )
    assert receipt.test_exit_code == 0
    assert receipt.reproduction_exit_code == 1
    assert receipt.changed_paths == ("src/a.py",)


@pytest.mark.parametrize(
    "header",
    [
        "diff --git a/../secret b/../secret\n",
        "diff --git a/src/a.py b/src/b.py\n",
        "diff --git a/tests/a.py b/tests/a.py\n",
    ],
)
def test_rejects_traversal_rename_and_out_of_glob(header: str) -> None:
    with pytest.raises(ValueError):
        validate_unified_diff(header + "--- a/x\n+++ b/x\n", allowed_file_globs=("src/*.py",))


def test_rejects_malformed_sandbox_receipt() -> None:
    class Broken(FakeSandbox):
        def execute(self, **_: object) -> SandboxExecutionResult:
            return SandboxExecutionResult("s", 0, "", "", ())

    sandbox = Broken()
    with pytest.raises(RuntimeError, match="artifact set"):
        WorkspacePatchValidator(sandbox).execute(  # type: ignore[arg-type]
            case_id="rel_00000000000000000000000000",
            snapshot=RepositorySnapshot(
                "a" * 40,
                (RepositoryFile("src/a.py", "x=1\n", "sha256:fixture", "100644"),),
            ),
            unified_diff=PATCH,
            reproduction_command="python -m unittest",
            test_command="python -m unittest",
            allowed_file_globs=("src/*.py",),
        )
