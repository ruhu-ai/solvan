"""Validate the checked-in Ruhu adoption contract without claiming deployment."""

from __future__ import annotations

from pathlib import Path

from solvan.connectors import load_ruhu_profile

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    profile = load_ruhu_profile(
        ROOT / "specs" / "artifacts" / "ruhu-integration-profile.template.yaml"
    )
    blockers = profile.deployment_blockers()
    print(
        f"Ruhu profile valid ({profile.adoption.enabled_phase}; mutations denied; "
        f"{len(blockers)} deployment placeholders)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
