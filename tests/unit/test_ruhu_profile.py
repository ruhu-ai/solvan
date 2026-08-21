from pathlib import Path

import pytest
import yaml

from solvan.connectors import RuhuProfileError, load_ruhu_profile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "specs" / "artifacts" / "ruhu-integration-profile.template.yaml"


def test_template_is_strictly_observe_only_and_honestly_not_deployable() -> None:
    profile = load_ruhu_profile(PROFILE)
    assert profile.adoption.enabled_phase == "observe_only"
    assert profile.adoption.phases["observe_only"].mutations_allowed is False
    assert profile.data_boundary.memory_promotion_default == "denied"
    # The region is decided (europe-west1, see docs/OPEN-DECISIONS.md); the
    # remaining eight are genuinely unknown until Ruhu is deployed.
    assert len(profile.deployment_blockers()) == 8


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("adoption", "enabled_phase"), "approval_bound_rollback", "observe-only"),
        (("adoption", "phases", "observe_only", "mutations_allowed"), True, "mutations"),
        (
            ("environment", "synthetic_scope", "contains_real_customer_data"),
            True,
            "customer data",
        ),
        (("tools", "mutation", "ruhu_pool_generation_bump", "available"), True, "available"),
    ],
)
def test_authority_or_data_boundary_widening_is_rejected(
    tmp_path: Path, path: tuple[str, ...], value: object, message: str
) -> None:
    raw = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    target = raw
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    changed = tmp_path / "ruhu.yaml"
    changed.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(RuhuProfileError, match=message):
        load_ruhu_profile(changed)


def test_unknown_profile_field_is_rejected(tmp_path: Path) -> None:
    raw = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    raw["undeclared_authority"] = True
    changed = tmp_path / "ruhu.yaml"
    changed.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(RuhuProfileError, match="Extra inputs"):
        load_ruhu_profile(changed)
