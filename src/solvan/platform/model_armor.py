"""Small fail-closed Model Armor boundary for model ingress and egress.

This module deliberately exposes only the two sanitization operations used by
Solvan. It grants no policy choice to a model or caller and never records the
screened text.
"""

from __future__ import annotations

from dataclasses import dataclass

from solvan.platform.google_rest import authorized_session


@dataclass(frozen=True, slots=True)
class GoogleModelArmorTextGate:
    """Screen text through one immutable regional Model Armor template."""

    template: str
    region: str
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        expected = f"/locations/{self.region}/templates/"
        if expected not in self.template:
            raise ValueError("Model Armor template is not in the configured release region")

    def screen_user_prompt(self, text: str) -> bool:
        return self._screen(text, operation="sanitizeUserPrompt", field="userPromptData")

    def screen_model_response(self, text: str) -> bool:
        return self._screen(text, operation="sanitizeModelResponse", field="modelResponseData")

    def _screen(self, text: str, *, operation: str, field: str) -> bool:
        response = authorized_session().post(
            (f"https://modelarmor.{self.region}.rep.googleapis.com/v1/{self.template}:{operation}"),
            json={field: {"text": text}},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        value = response.json()
        result = value.get("sanitizationResult") if isinstance(value, dict) else None
        state = result.get("filterMatchState") if isinstance(result, dict) else None
        invocation = result.get("invocationResult") if isinstance(result, dict) else None
        if invocation != "SUCCESS":
            raise RuntimeError(f"Model Armor could not complete {operation}")
        return state == "NO_MATCH_FOUND"
