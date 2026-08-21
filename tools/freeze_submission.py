"""Validate and atomically freeze the exact Solvan competition submission."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

Run = Callable[[list[str]], str]
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
FULL_SHA_PATTERN = r"^[0-9a-f]{40}$"
REQUIRED_SCENARIOS = frozenset({"S1", "S2", "S3", "S4", "S5", "S6"})


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Devpost(StrictModel):
    submission_id: str = Field(min_length=1)
    submitted_at: datetime


class Source(StrictModel):
    repository_url: HttpUrl
    release_commit: str = Field(pattern=FULL_SHA_PATTERN)
    branch: str = Field(min_length=1)


class Deployment(StrictModel):
    environment: Literal["staging"]
    project_id: str = Field(min_length=1)
    project_number: str = Field(pattern=r"^[0-9]{6,20}$")
    region: Literal["europe-west1"]
    deployment_id: str = Field(min_length=1)
    test_url: HttpUrl
    retained_until: datetime
    image_digests: dict[str, str]

    @model_validator(mode="after")
    def validate_images(self) -> Self:
        if not self.image_digests or any(
            not name or re.fullmatch(SHA256_PATTERN, digest) is None
            for name, digest in self.image_digests.items()
        ):
            raise ValueError("every release image requires one immutable SHA-256 digest")
        return self


class Platform(StrictModel):
    model_resource: str = Field(min_length=1)
    agent_runtime_resources: dict[str, str]
    agent_runtime_revisions: dict[str, str]
    agent_registry_resources: dict[str, str]
    agent_identity_principals: dict[str, str]
    gateway_resources: dict[str, str]
    model_armor_template: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_fleet(self) -> Self:
        fleet = set(self.agent_runtime_resources)
        if len(fleet) < 6 or any(
            set(values) != fleet
            for values in (
                self.agent_runtime_revisions,
                self.agent_registry_resources,
                self.agent_identity_principals,
            )
        ):
            raise ValueError("Runtime, revision, Registry, and Identity maps must bind one fleet")
        if not self.gateway_resources:
            raise ValueError("submission requires at least one governed Gateway resource")
        return self


class Evidence(StrictModel):
    deployment_receipt: str = Field(pattern=r"^gs://")
    preflight_receipt: str = Field(pattern=r"^gs://")
    scenario_receipts: dict[str, str]
    cleanup_receipt: str = Field(pattern=r"^gs://")
    release_manifest_uri: str = Field(pattern=r"^gs://")
    release_manifest_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_scenarios(self) -> Self:
        if set(self.scenario_receipts) != REQUIRED_SCENARIOS or any(
            not ref.startswith("gs://") for ref in self.scenario_receipts.values()
        ):
            raise ValueError("submission evidence requires the exact S1-S6 GCS receipt set")
        return self


class Submission(StrictModel):
    architecture_image: str = Field(min_length=1)
    architecture_image_sha256: str = Field(pattern=SHA256_PATTERN)
    readme_sha256: str = Field(pattern=SHA256_PATTERN)
    video_url: HttpUrl
    video_duration_seconds: int = Field(gt=0, le=240)
    public_content_urls: tuple[HttpUrl, ...]
    social_urls: tuple[HttpUrl, ...]
    disclosure_inventory: str = Field(min_length=1)
    disclosure_inventory_sha256: str = Field(pattern=SHA256_PATTERN)


class Attestations(StrictModel):
    clean_published_commit: Literal[True]
    platform_preflight_passed: Literal[True]
    exact_s1_to_s6_set_passed: Literal[True]
    zero_open_p0: Literal[True]
    signed_out_access_verified: Literal[True]
    video_rules_verified: Literal[True]
    representative_approved_freeze: Literal[True]


class SubmissionFreezeManifest(StrictModel):
    schema_version: Literal[1]
    status: Literal["FROZEN"]
    category: Literal["Fortified Enterprise Fleet"]
    representative: str = Field(min_length=1)
    devpost: Devpost
    source: Source
    deployment: Deployment
    platform: Platform
    evidence: Evidence
    submission: Submission
    attestations: Attestations

    @model_validator(mode="after")
    def validate_timeline(self) -> Self:
        for value in (self.devpost.submitted_at, self.deployment.retained_until):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("submission timestamps must be timezone-aware")
        if self.deployment.retained_until <= self.devpost.submitted_at:
            raise ValueError("judged deployment retention must extend beyond submission")
        return self


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _run(arguments: list[str]) -> str:
    return subprocess.run(arguments, check=True, text=True, capture_output=True).stdout.strip()


def build_freeze(
    manifest_path: Path,
    *,
    repository_root: Path,
    run: Run = _run,
) -> SubmissionFreezeManifest:
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("submission freeze manifest must be an object")
    submission = raw.get("submission")
    if not isinstance(submission, dict):
        raise ValueError("submission freeze manifest has no submission object")
    bindings = {
        "architecture_image_sha256": _sha256(
            repository_root / str(submission.get("architecture_image", ""))
        ),
        "readme_sha256": _sha256(repository_root / "README.md"),
        "disclosure_inventory_sha256": _sha256(
            repository_root / str(submission.get("disclosure_inventory", ""))
        ),
    }
    for key, computed in bindings.items():
        supplied = submission.get(key)
        if supplied not in (None, "UNFILLED", computed):
            raise ValueError(f"{key} does not match repository content")
        submission[key] = computed
    raw["status"] = "FROZEN"
    manifest = SubmissionFreezeManifest.model_validate(raw)
    head = run(["git", "rev-parse", "HEAD"])
    if head != manifest.source.release_commit:
        raise ValueError("freeze commit does not match repository HEAD")
    return manifest


def freeze(
    manifest_path: Path,
    *,
    output: Path,
    repository_root: Path,
    acknowledgement: str | None,
    apply: bool,
    run: Run = _run,
) -> SubmissionFreezeManifest:
    manifest = build_freeze(manifest_path, repository_root=repository_root, run=run)
    if not apply:
        return manifest
    if acknowledgement != manifest.deployment.deployment_id:
        raise ValueError("--ack-deployment must exactly match the frozen deployment ID")
    if run(["git", "status", "--porcelain"]):
        raise ValueError("submission freeze requires a clean published commit")
    output.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if output.exists():
        if output.read_text(encoding="utf-8") != content:
            raise ValueError("existing frozen submission differs; freeze artifacts are immutable")
        return manifest
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(content)
        handle.flush()
    temporary.replace(output)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--ack-deployment")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        result = freeze(
            args.manifest,
            output=args.output,
            repository_root=args.repository_root.resolve(),
            acknowledgement=args.ack_deployment,
            apply=args.apply,
        )
        print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Submission freeze rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
