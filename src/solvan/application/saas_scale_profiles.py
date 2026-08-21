"""Closed control posture for the SaaS deployment profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from solvan.application.saas_scale import DeploymentProfile


@dataclass(frozen=True, slots=True)
class ControlPosture:
    """The non-negotiable controls every deployment profile must retain."""

    scope_binding: bool
    rls: bool
    identity: bool
    audit: bool
    quota: bool
    defense_in_depth: bool

    def __post_init__(self) -> None:
        if not all(
            (
                self.scope_binding,
                self.rls,
                self.identity,
                self.audit,
                self.quota,
                self.defense_in_depth,
            )
        ):
            raise ValueError("every deployment profile must retain every control")


PROFILE_CONTROL_POSTURES: dict[str, ControlPosture] = {
    "OSS_SINGLE_TENANT": ControlPosture(True, True, True, True, True, True),
    "SHARED_CELL": ControlPosture(True, True, True, True, True, True),
    "DEDICATED_CELL": ControlPosture(True, True, True, True, True, True),
}


def validate_control_posture(profile: DeploymentProfile) -> ControlPosture:
    """Return the closed control posture or refuse an unknown profile."""

    from solvan.application.saas_scale import DeploymentProfile, ScaleRuntimeError

    if not isinstance(profile, DeploymentProfile):
        raise ScaleRuntimeError("deployment profile has no control posture")
    try:
        posture = PROFILE_CONTROL_POSTURES[profile.value]
    except KeyError as exc:
        raise ScaleRuntimeError("deployment profile has no control posture") from exc
    if not all(
        (
            posture.scope_binding,
            posture.rls,
            posture.identity,
            posture.audit,
            posture.quota,
            posture.defense_in_depth,
        )
    ):
        raise ScaleRuntimeError("deployment profile control posture is incomplete")
    return posture
