"""The documentation checker's own rules, tested against fixtures.

`check_docs` gates every specification and plan in the repository, so a rule
that silently matches nothing is the same failure mode `check_architecture`
already found in itself: a gate that reads as enforcement and checks nothing.
"""

from pathlib import Path

from tools import check_docs


def _plan(root: Path, name: str, status: str) -> None:
    active = root / "docs/exec-plans/active"
    active.mkdir(parents=True, exist_ok=True)
    (active / name).write_text(f"# {name}\n\nStatus: {status}\n", encoding="utf-8")


def test_an_active_plan_declaring_completion_is_a_finding(tmp_path: Path) -> None:
    for status in ("completed 2026-01-01", "Resolved by a later change", "done"):
        _plan(tmp_path, "plan.md", status)
        findings = check_docs.check_active_plan_status(tmp_path)
        assert findings, f"{status!r} must be refused in active/"
        assert "move it to completed/" in findings[0]


def test_a_plan_that_names_its_outstanding_work_passes(tmp_path: Path) -> None:
    _plan(tmp_path, "plan.md", "open -- staging qualification pending")
    assert check_docs.check_active_plan_status(tmp_path) == []


def test_completion_wording_later_in_the_status_is_not_a_finding(tmp_path: Path) -> None:
    """Only the leading word decides; a plan may say what it has finished."""

    _plan(tmp_path, "plan.md", "open -- the refinement is completed and verified")
    assert check_docs.check_active_plan_status(tmp_path) == []


def test_the_rule_reads_the_real_tree_without_findings(tmp_path: Path) -> None:
    """The repository itself must satisfy the rule the checker enforces."""

    assert check_docs.check_active_plan_status() == []
