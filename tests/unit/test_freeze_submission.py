from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tools.freeze_submission import build_freeze, freeze


def _manifest(root: Path) -> Path:
    fleet = {f"agent-{index}": f"resource-{index}" for index in range(6)}
    value = {
        "schema_version": 1,
        "status": "UNFROZEN",
        "category": "Fortified Enterprise Fleet",
        "representative": "Solvan Team",
        "devpost": {
            "submission_id": "submission-1",
            "submitted_at": "2026-08-30T12:00:00Z",
        },
        "source": {
            "repository_url": "https://github.com/example/solvan",
            "release_commit": "a" * 40,
            "branch": "main",
        },
        "deployment": {
            "environment": "staging",
            "project_id": "solvan-demo",
            "project_number": "123456789012",
            "region": "europe-west1",
            "deployment_id": "deploy-1",
            "test_url": "https://solvan.example.com",
            "retained_until": "2026-10-01T12:00:00Z",
            "image_digests": {"coordinator": f"sha256:{'1' * 64}"},
        },
        "platform": {
            "model_resource": "publishers/google/models/gemini",
            "agent_runtime_resources": fleet,
            "agent_runtime_revisions": fleet,
            "agent_registry_resources": fleet,
            "agent_identity_principals": fleet,
            "gateway_resources": {"gateway": "projects/demo/gateways/solvan"},
            "model_armor_template": "projects/demo/templates/solvan",
        },
        "evidence": {
            "deployment_receipt": "gs://evidence/deployment.json",
            "preflight_receipt": "gs://evidence/preflight.json",
            "scenario_receipts": {
                name: f"gs://evidence/{name.lower()}.json"
                for name in ("S1", "S2", "S3", "S4", "S5", "S6")
            },
            "cleanup_receipt": "gs://evidence/cleanup.json",
            "release_manifest_uri": "gs://evidence/release.json",
            "release_manifest_sha256": f"sha256:{'2' * 64}",
        },
        "submission": {
            "architecture_image": "docs/assets/architecture.svg",
            "architecture_image_sha256": "UNFILLED",
            "readme_sha256": "UNFILLED",
            "video_url": "https://www.youtube.com/watch?v=fixture",
            "video_duration_seconds": 220,
            "public_content_urls": [],
            "social_urls": [],
            "disclosure_inventory": "THIRD_PARTY_NOTICES.md",
            "disclosure_inventory_sha256": "UNFILLED",
        },
        "attestations": {
            "clean_published_commit": True,
            "platform_preflight_passed": True,
            "exact_s1_to_s6_set_passed": True,
            "zero_open_p0": True,
            "signed_out_access_verified": True,
            "video_rules_verified": True,
            "representative_approved_freeze": True,
        },
    }
    path = root / "freeze.yaml"
    path.write_text(yaml.safe_dump(value), encoding="utf-8")
    return path


def _repository(root: Path) -> None:
    (root / "docs/assets").mkdir(parents=True)
    (root / "docs/assets/architecture.svg").write_text("<svg/>", encoding="utf-8")
    (root / "README.md").write_text("# Solvan\n", encoding="utf-8")
    (root / "THIRD_PARTY_NOTICES.md").write_text("# Notices\n", encoding="utf-8")


def test_freeze_binds_repository_hashes_and_exact_fleet(tmp_path: Path) -> None:
    _repository(tmp_path)
    manifest = build_freeze(
        _manifest(tmp_path), repository_root=tmp_path, run=lambda _args: "a" * 40
    )
    assert manifest.status == "FROZEN"
    assert manifest.submission.readme_sha256.startswith("sha256:")
    assert set(manifest.evidence.scenario_receipts) == {"S1", "S2", "S3", "S4", "S5", "S6"}


def test_freeze_rejects_tampered_repository_hash(tmp_path: Path) -> None:
    _repository(tmp_path)
    path = _manifest(tmp_path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["submission"]["readme_sha256"] = f"sha256:{'f' * 64}"
    path.write_text(yaml.safe_dump(value), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        build_freeze(path, repository_root=tmp_path, run=lambda _args: "a" * 40)


def test_apply_requires_ack_and_clean_tree_then_writes_atomically(tmp_path: Path) -> None:
    _repository(tmp_path)
    path = _manifest(tmp_path)

    def run(arguments: list[str]) -> str:
        return "a" * 40 if arguments[1:3] == ["rev-parse", "HEAD"] else ""

    output = tmp_path / "out/frozen.json"
    with pytest.raises(ValueError, match="ack-deployment"):
        freeze(
            path,
            output=output,
            repository_root=tmp_path,
            acknowledgement=None,
            apply=True,
            run=run,
        )
    freeze(
        path,
        output=output,
        repository_root=tmp_path,
        acknowledgement="deploy-1",
        apply=True,
        run=run,
    )
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "FROZEN"
    output.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="immutable"):
        freeze(
            path,
            output=output,
            repository_root=tmp_path,
            acknowledgement="deploy-1",
            apply=True,
            run=run,
        )
