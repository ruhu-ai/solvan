from pathlib import Path

import yaml

from tools.check_cloudbuild import validate


def test_release_cloudbuild_contract() -> None:
    value = yaml.safe_load(Path("cloudbuild.yaml").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    validate(value)
    steps = value["steps"]
    assert any(isinstance(step, dict) and step.get("id") == "build-solvant-relay" for step in steps)
