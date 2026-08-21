"""Static contract checks for the release image build graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tools.deploy_release import IMAGE_NAMES

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "api",
    "alert-ingress",
    "direct-gcp-reader",
    "pilot-qualification-verifier",
    "coordinator",
    "detector",
    "actuator",
    "evidence-broker",
    "verifier",
    "publisher",
    "payments-good",
    "payments-bad",
    "console",
    "memory-promoter",
    "antigravity-workspace",
    "workspace-sandbox",
    "workspace-adapter",
    "fixture-attester",
    "release-admin",
    "github-provider",
    "github-identity-broker",
    "deployment-controller",
    "release-verifier",
    "slack-liaison",
    "liaison-maintenance",
    "trigger-scheduler",
    "mcp-facade",
    "discord-liaison",
    "email-liaison",
    "relay-control",
}
CUSTOMER_IMAGE_OUTPUTS = {"solvant-relay"}


def validate(value: dict[str, Any]) -> None:
    if set(IMAGE_NAMES.values()) != EXPECTED:
        raise ValueError("release digest resolver and Cloud Build image set drifted")
    steps = value.get("steps")
    images = value.get("images")
    if not isinstance(steps, list) or not isinstance(images, list):
        raise ValueError("Cloud Build steps and images are required")
    step_ids = {step.get("id") for step in steps if isinstance(step, dict)}
    all_outputs = EXPECTED | CUSTOMER_IMAGE_OUTPUTS
    if step_ids != {f"build-{name}" for name in all_outputs}:
        raise ValueError("Cloud Build image step set drifted")
    antigravity_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("id") == "build-antigravity-workspace"
    ]
    if len(antigravity_steps) != 1:
        raise ValueError("Antigravity SDK image build is required")
    antigravity_args = antigravity_steps[0].get("args")
    if not isinstance(antigravity_args, list):
        raise ValueError("Antigravity image build arguments are malformed")
    if "--file=Dockerfile.antigravity" not in antigravity_args:
        raise ValueError("Antigravity image must use its isolated dependency closure")
    if any("UV_EXTRAS" in str(argument) for argument in antigravity_args):
        raise ValueError("Antigravity image must not inherit the shared application lock")
    image_names = {str(image).split("/")[-1].split(":")[0] for image in images}
    if image_names != all_outputs:
        raise ValueError("Cloud Build published image set drifted")
    if any(":${BUILD_ID}" not in str(image) for image in images):
        raise ValueError("release images must use the unique Cloud Build ID")
    service_account = value.get("serviceAccount")
    if service_account != (
        "projects/${PROJECT_ID}/serviceAccounts/solvan-build@${PROJECT_ID}.iam.gserviceaccount.com"
    ):
        raise ValueError("Cloud Build must use the dedicated service account")
    options = value.get("options")
    if not isinstance(options, dict) or options.get("logging") != "CLOUD_LOGGING_ONLY":
        raise ValueError("custom Cloud Build identity must use an approved log sink")


def main() -> int:
    value = yaml.safe_load((ROOT / "cloudbuild.yaml").read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("cloudbuild.yaml must be a mapping")
    validate(value)
    print(f"Cloud Build contract passed ({len(EXPECTED)} immutable image outputs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
