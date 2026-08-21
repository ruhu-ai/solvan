"""Refuse a shared public OAuth client as a configured approval audience.

Specification 05 §9 requires the approval token to be verified against the
explicit client audience configured for the release. The repository defaulted
to the Google Cloud SDK's client in a launcher and two Terraform examples, so
the check passed for any `gcloud auth print-identity-token` output anywhere.

The API refuses such a value at runtime. This refuses it in configuration,
because a default that has to be noticed by a reviewer is not a control, and
because the runtime refusal is only met by whoever starts the deployment.
"""

from __future__ import annotations

from pathlib import Path

from solvan.application.approval_audience import SHARED_PUBLIC_CLIENT_IDS

ROOT = Path(__file__).resolve().parents[1]
#: Where an audience is configured rather than discussed. Specifications and
#: reviews name the client deliberately when explaining why it is refused.
SEARCHED = ("scripts", "infra", "apps", "src", "cloudbuild.yaml")


def audience_findings() -> list[str]:
    findings: list[str] = []
    for entry in SEARCHED:
        target = ROOT / entry
        paths = sorted(target.rglob("*")) if target.is_dir() else [target]
        for path in paths:
            if not path.is_file() or path.suffix in {".pyc"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if path.resolve() == (ROOT / "src/solvan/application/approval_audience.py").resolve():
                continue
            for client in SHARED_PUBLIC_CLIENT_IDS:
                if client in text:
                    findings.append(
                        f"{path.relative_to(ROOT)}: [AUD001] configures the shared public client "
                        f"{client}; every installation mints tokens against it, so it binds a "
                        "token to no deployment. Use an OAuth client this environment owns"
                    )
    return findings


def main() -> int:
    findings = audience_findings()
    for finding in findings:
        print(finding)
    if findings:
        print(f"Approval audience check failed with {len(findings)} finding(s)")
        return 1
    print(f"No shared public client is configured as an approval audience ({len(SEARCHED)} roots)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
