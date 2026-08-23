"""The actuator's refusals must be visible to the thing that alerts on them.

These cases exist because the gap they close was invisible from either side. The
in-binary controls were correct and fail-closed, and the deployment had no alert
policy at all; once a policy exists, the remaining way to get it wrong is to bind
it to a log record the runtime never writes. So the assertions here compose the
two: they emit through the real code path, capture what the real logger receives,
and match it against the filter strings Terraform actually deploys.
"""

from __future__ import annotations

import ast
import logging
import pathlib
import re

from apps.actuator.local_policy import LOCAL_POLICY_REASON_CODES
from solvan.observability import (
    CONTROL_REFUSAL_EVENT,
    TELEMETRY_LOGGER_NAME,
    record_control_refusal,
)

_REPOSITORY = pathlib.Path(__file__).resolve().parents[2]
_ALERTING = _REPOSITORY / "infra/terraform/environments/gcp/alerting.tf"
_LOCAL_POLICY = _REPOSITORY / "apps/actuator/local_policy.py"


def _emitted_bodies(reason_code: str) -> list[str]:
    """Capture what the telemetry logger receives for one refusal."""

    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    logger = logging.getLogger(TELEMETRY_LOGGER_NAME)
    logger.addHandler(handler)
    try:
        record_control_refusal(service_name="actuator", reason_code=reason_code)
    finally:
        logger.removeHandler(handler)
    return [record.getMessage() for record in records]


def _raised_reason_codes() -> set[str]:
    """Every reason code literal the actuator's local policy can raise."""

    tree = ast.parse(_LOCAL_POLICY.read_text())
    codes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if not isinstance(target, ast.Name) or target.id != "LocalPolicyRefusal":
            continue
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            codes.add(first.value)
    return codes


def _metric_filters() -> list[str]:
    """The log-based metric filters declared in the deployed alerting stack."""

    text = _ALERTING.read_text()
    return re.findall(r"filter\s*=\s*<<-EOT\n(.*?)\n\s*EOT", text, flags=re.DOTALL)


def test_declared_reason_codes_match_the_ones_actually_raised() -> None:
    """The closed set is a contract, not a comment that drifts."""

    assert _raised_reason_codes() == set(LOCAL_POLICY_REASON_CODES)


def test_every_refusal_carries_its_reason_code_in_the_log_body() -> None:
    for reason_code in sorted(LOCAL_POLICY_REASON_CODES):
        bodies = _emitted_bodies(reason_code)
        assert bodies == [f"{CONTROL_REFUSAL_EVENT}:{reason_code}"]


def test_a_refusal_record_carries_no_content_beyond_its_reason_code() -> None:
    """Only enumerated fields. A refusal must never carry action or target."""

    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    logger = logging.getLogger(TELEMETRY_LOGGER_NAME)
    logger.addHandler(handler)
    try:
        record_control_refusal(service_name="actuator", reason_code="LOCAL_KILL_SWITCH_ENGAGED")
    finally:
        logger.removeHandler(handler)

    (record,) = records
    assert record.levelno == logging.WARNING
    assert record.__dict__["solvan.service"] == "actuator"
    assert record.__dict__["solvan.control.event"] == CONTROL_REFUSAL_EVENT
    assert record.__dict__["solvan.control.reason_code"] == "LOCAL_KILL_SWITCH_ENGAGED"
    solvan_fields = {key for key in record.__dict__ if key.startswith("solvan.")}
    assert solvan_fields == {
        "solvan.service",
        "solvan.control.event",
        "solvan.control.reason_code",
    }


def test_the_general_alert_filter_matches_every_reason_code() -> None:
    """One filter covers the closed set because every body shares its prefix."""

    filters = _metric_filters()
    general = [f for f in filters if CONTROL_REFUSAL_EVENT in f]
    assert general, "no log-based metric matches the control-refusal event"

    for reason_code in sorted(LOCAL_POLICY_REASON_CODES):
        (body,) = _emitted_bodies(reason_code)
        assert any(CONTROL_REFUSAL_EVENT in f and CONTROL_REFUSAL_EVENT in body for f in general)


def test_the_kill_switch_has_a_filter_bound_to_the_code_it_raises() -> None:
    """An engaged switch pages on its own, separately from routine refusals."""

    assert "LOCAL_KILL_SWITCH_ENGAGED" in LOCAL_POLICY_REASON_CODES
    dedicated = [f for f in _metric_filters() if "LOCAL_KILL_SWITCH_ENGAGED" in f]
    assert len(dedicated) == 1
    (body,) = _emitted_bodies("LOCAL_KILL_SWITCH_ENGAGED")
    assert "LOCAL_KILL_SWITCH_ENGAGED" in body
