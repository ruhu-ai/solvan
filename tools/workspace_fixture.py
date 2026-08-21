"""Canonical public-synthetic repository fixture for workspace qualification."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from solvan.domain import Scope
from solvan.platform.evidence_objects import GcsEvidenceWriter, ObjectReceipt

FIXTURE_ID = "payments-leak-v1"
ALLOWED_FILE_GLOBS = ("app/*.py", "tests/*.py")
REPRODUCTION_COMMAND = "python -m unittest -q tests.test_payments"
TEST_COMMAND = REPRODUCTION_COMMAND
REPOSITORY_BINDING_ID = "ghr_00000000000000000000000001"
REPRODUCTION_COMMAND_DEFINITION_ID = "rcd_00000000000000000000000001"
REGRESSION_COMMAND_DEFINITION_ID = "rcd_00000000000000000000000002"

_APP = """class PaymentHandler:
    def __init__(self, pool):
        self.pool = pool

    def charge(self, payment_id):
        connection = self.pool.getconn()
        return connection.execute(payment_id)
"""

_TEST = """import unittest

from app.payments import PaymentHandler


class FakeConnection:
    def execute(self, payment_id):
        return {"payment_id": payment_id, "status": "captured"}


class FakePool:
    def __init__(self):
        self.connection = FakeConnection()
        self.returned = []

    def getconn(self):
        return self.connection

    def putconn(self, connection):
        self.returned.append(connection)


class PaymentHandlerTest(unittest.TestCase):
    def test_connection_is_returned_after_charge(self):
        pool = FakePool()
        result = PaymentHandler(pool).charge("pay-101")
        self.assertEqual(result["status"], "captured")
        self.assertEqual(pool.returned, [pool.connection])


if __name__ == "__main__":
    unittest.main()
"""


def repository_snapshot(*, release_commit: str) -> dict[str, Any]:
    if len(release_commit) != 40 or any(
        character not in "0123456789abcdef" for character in release_commit
    ):
        raise ValueError("workspace fixture requires the exact lowercase release commit")

    def file(path: str, content: str) -> dict[str, str]:
        return {
            "path": path,
            "content": content,
            "content_hash": "sha256:" + hashlib.sha256(content.encode()).hexdigest(),
            "mode": "100644",
        }

    return {
        "schema_version": 2,
        "base_commit_sha": release_commit,
        "files": [file("app/payments.py", _APP), file("tests/test_payments.py", _TEST)],
    }


def upload_repository_snapshot(
    *,
    writer: GcsEvidenceWriter,
    scope: Scope,
    release_commit: str,
) -> ObjectReceipt:
    value = repository_snapshot(release_commit=release_commit)
    return writer.put_json(
        object_name=(
            f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
            f"fixtures/{FIXTURE_ID}/repository-snapshot.json"
        ),
        value=value,
    )


def canonical_snapshot_hash(*, release_commit: str) -> str:
    content = json.dumps(
        repository_snapshot(release_commit=release_commit),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(content).hexdigest()


def repository_policy(
    *,
    receipt: ObjectReceipt,
    release_commit: str,
    runtime_bucket: str,
    scope: Scope,
    provider: str = "GEMINI_ADK_AGENT_ENGINE",
) -> dict[str, Any]:
    if provider not in {"GEMINI_ADK_AGENT_ENGINE", "ANTIGRAVITY_SDK_CLOUD_RUN"}:
        raise ValueError("workspace fixture provider is unsupported")
    return {
        "repository_binding_id": REPOSITORY_BINDING_ID,
        "repository_snapshot_uri": receipt.uri,
        "repository_snapshot_hash": receipt.content_hash,
        "base_commit_sha": release_commit,
        "reproduction_command_definition_id": REPRODUCTION_COMMAND_DEFINITION_ID,
        "regression_command_definition_id": REGRESSION_COMMAND_DEFINITION_ID,
        "allowed_file_globs": list(ALLOWED_FILE_GLOBS),
        "artifact_output_uri": (
            f"gs://{runtime_bucket}/{scope.organization_id}/{scope.project_id}/"
            f"{scope.environment_id}/repairs/"
        ),
        "provider": provider,
    }
