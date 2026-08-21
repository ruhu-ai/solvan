"""Read-only, exact-release projection of immutable GCS release receipts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from solvan.application import EvidenceMode, EvidenceStatus, ScenarioReceipt, parse_scenario_receipt
from solvan.platform.google_rest import GoogleRestSession
from solvan.platform.preflight import PlatformPreflightReceipt
from solvan.platform.preflight_receipt import parse_platform_preflight_receipt

_SCENARIO_NAMES = (
    "Closed-loop recovery",
    "Concurrency and deduplication",
    "Agent recovery",
    "Stale approval",
    "Prompt injection and memory poisoning",
    "Cross-scope denial",
)
#: The platform components an operator reads on the readiness screen, and the
#: exact preflight proofs each one is entitled to claim. Public because the
#: Cloud SQL projection renders the same seven components when no cloud receipt
#: exists; two lists would let the console show a component here that the
#: receipt has no opinion about.
PLATFORM_PROOFS = {
    "Agent Registry": ("registry_six_agents_discovered",),
    "Agent Runtime": ("runtime_query_job_completed",),
    "Memory Bank": ("memory_exact_scope_recall", "memory_cross_scope_denied"),
    "Agent Identity": ("identity_matrix_denied_excess_authority",),
    "Agent Gateway": ("gateway_registered_route_allowed", "gateway_bypass_denied"),
    "Model Armor": (
        "model_armor_benign_allowed",
        "model_armor_injection_denied",
        "model_armor_pii_denied",
    ),
    "Agent Observability": ("otel_trace_correlated",),
}

#: A preflight receipt observes a topology at one moment. It stays bound to its
#: release commit forever, but the topology it describes can drift underneath
#: it, so past this horizon the receipt stops supporting a health claim and the
#: component reads unverified until preflight runs again. Verification is never
#: inherited from an older observation.
PLATFORM_RECEIPT_HORIZON = timedelta(hours=24)


def unverified_platform_components(*, detail: str, next_step: str) -> list[dict[str, str]]:
    """Return the platform block for a console with no bound cloud receipt.

    Absence of evidence is stated once, in the same shape the verified block
    uses, so the screen never reads healthy because nothing contradicted it.
    """

    return [
        {
            "name": name,
            "lifecycle": "Awaiting cloud evidence",
            "health": "UNKNOWN",
            "evidence": "UNVERIFIED",
            "detail": detail,
            "last_checked": "Not checked",
            "next_step": next_step,
        }
        for name in PLATFORM_PROOFS
    ]


@dataclass(frozen=True, slots=True)
class CloudReleaseBinding:
    project_id: str
    release_commit: str
    deployment_id: str
    evidence_bucket: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", self.project_id) is None:
            raise ValueError("release projection project is invalid")
        if re.fullmatch(r"[0-9a-f]{40}", self.release_commit) is None:
            raise ValueError("release projection commit is invalid")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", self.deployment_id) is None:
            raise ValueError("release projection deployment is invalid")
        if not self.evidence_bucket or "/" in self.evidence_bucket:
            raise ValueError("release projection bucket is invalid")


class GcsReleaseProjection:
    def __init__(self, *, binding: CloudReleaseBinding, session: GoogleRestSession) -> None:
        self._binding = binding
        self._session = session

    def load(self, *, now: datetime | None = None) -> tuple[list[dict[str, str]], dict[str, Any]]:
        observed_now = now or datetime.now(UTC)
        preflight, preflight_error = self._preflight()
        receipts, invalid_count = self._scenario_receipts()
        age = None if preflight is None else observed_now - preflight.observed_at
        expired = age is not None and age > PLATFORM_RECEIPT_HORIZON
        if preflight is None:
            platform = unverified_platform_components(
                detail=f"No valid bound preflight receipt ({preflight_error}).",
                next_step="Capture a valid bound platform preflight receipt.",
            )
        elif expired:
            platform = unverified_platform_components(
                detail=(
                    f"The bound {self._binding.deployment_id} preflight was observed "
                    f"{preflight.observed_at.isoformat()} and is past its "
                    f"{int(PLATFORM_RECEIPT_HORIZON.total_seconds() // 3600)}h horizon."
                ),
                next_step="Re-run the platform preflight against the deployed topology.",
            )
        else:
            proofs = dict(preflight.proof_results)
            platform = [
                self._verified_component(
                    name=name,
                    required=required,
                    passed=preflight.status in {"PASS", "DEGRADED"}
                    and all(proofs.get(proof) is True for proof in required),
                    observed_at=preflight.observed_at,
                    degraded=(
                        name == "Model Armor"
                        and dict(preflight.topology.gateway_policy_status)["inline_model_armor"]
                        == "DEGRADED_GOOGLE_AUTHZ_POLICY_CODE_13"
                    ),
                )
                for name, required in PLATFORM_PROOFS.items()
            ]
        scenarios: list[dict[str, str]] = []
        complete = preflight is not None and preflight.status == "PASS" and not expired
        for index, name in enumerate(_SCENARIO_NAMES, start=1):
            scenario_id = f"S{index}"
            receipt = receipts.get(scenario_id)
            expected_mode = (
                EvidenceMode.LIVE_GCP if scenario_id == "S1" else EvidenceMode.SCRIPTED_GCP
            )
            passed = bool(
                receipt and receipt.status is EvidenceStatus.PASS and receipt.mode is expected_mode
            )
            complete = complete and passed
            scenarios.append(
                {
                    "id": scenario_id,
                    "name": name,
                    "status": (
                        f"PASS · {expected_mode.value}"
                        if passed
                        else "NOT_RUN_ON_GCP"
                        if receipt is None
                        else f"{receipt.status.value} · {receipt.mode.value}"
                    ),
                }
            )
        if invalid_count:
            complete = False
        return platform, {
            "scenarios": scenarios,
            "commit": self._binding.release_commit,
            "cloud": "BOUND_GCP_EVIDENCE_COMPLETE" if complete else "PENDING_RECEIPTS",
            "gate": (
                "CLOUD_EVIDENCE_COMPLETE_LOCAL_AND_SUBMISSION_GATES_SEPARATE"
                if complete
                else "NOT_EVALUATED"
            ),
            "deployment_id": self._binding.deployment_id,
            "invalid_receipt_count": invalid_count,
        }

    def _verified_component(
        self,
        *,
        name: str,
        required: tuple[str, ...],
        passed: bool,
        observed_at: datetime,
        degraded: bool = False,
    ) -> dict[str, str]:
        if degraded and passed:
            return {
                "name": name,
                "lifecycle": "Cloud degraded",
                "health": "DEGRADED",
                "evidence": "CLOUD_VERIFIED_DEGRADATION",
                "detail": (
                    "Inline Agent Gateway Model Armor is disabled after Google AuthzPolicy "
                    "creation failed with server-side code 13; fail-closed in-process "
                    "sanitizeUserPrompt/sanitizeModelResponse probes passed."
                ),
                "last_checked": observed_at.isoformat(),
                "next_step": (
                    "Re-enable and re-probe the inline policy after Google resolves code 13."
                ),
            }
        return {
            "name": name,
            "lifecycle": "Cloud verified" if passed else "Awaiting cloud evidence",
            "health": "HEALTHY" if passed else "UNKNOWN",
            "evidence": "CLOUD_VERIFIED" if passed else "UNVERIFIED",
            "detail": f"Exact {self._binding.deployment_id} preflight proof: "
            + ", ".join(required),
            "last_checked": observed_at.isoformat(),
            "next_step": (
                "No action required; continue monitoring the bound receipt."
                if passed
                else "Capture a valid bound platform preflight receipt."
            ),
        }

    def _preflight(self) -> tuple[PlatformPreflightReceipt | None, str]:
        object_name = f"preflight/{self._binding.deployment_id}/receipt.json"
        try:
            value = self._get_json(object_name)
            receipt = parse_platform_preflight_receipt(value)
            if (
                receipt.project_id,
                receipt.release_commit,
                receipt.deployment_id,
                receipt.region,
                receipt.topology.evidence_bucket,
            ) != (
                self._binding.project_id,
                self._binding.release_commit,
                self._binding.deployment_id,
                "europe-west1",
                self._binding.evidence_bucket,
            ):
                raise ValueError("preflight receipt belongs to another release")
            if any(
                not ref.startswith(f"gs://{self._binding.evidence_bucket}/")
                for ref in receipt.evidence_refs
            ):
                raise ValueError("preflight evidence is outside the release bucket")
            return receipt, "none"
        except Exception as error:
            return None, type(error).__name__

    def _scenario_receipts(self) -> tuple[dict[str, ScenarioReceipt], int]:
        selected: dict[str, ScenarioReceipt] = {}
        invalid = 0
        for scenario_id in (f"S{index}" for index in range(1, 7)):
            prefix = f"scenarios/{self._binding.deployment_id}/{scenario_id}/receipts/"
            for object_name in self._list_names(prefix):
                try:
                    receipt = parse_scenario_receipt(self._get_json(object_name))
                    if (
                        receipt.scenario_id,
                        receipt.project_id,
                        receipt.release_commit,
                        receipt.deployment_id,
                        receipt.region,
                    ) != (
                        scenario_id,
                        self._binding.project_id,
                        self._binding.release_commit,
                        self._binding.deployment_id,
                        "europe-west1",
                    ):
                        raise ValueError("scenario receipt belongs to another release")
                    if any(
                        not ref.startswith((f"gs://{self._binding.evidence_bucket}/", "db://"))
                        for ref in receipt.evidence_refs
                    ):
                        raise ValueError("scenario evidence is outside the release boundary")
                except Exception:
                    invalid += 1
                    continue
                current = selected.get(scenario_id)
                if current is None or receipt.completed_at > current.completed_at:
                    selected[scenario_id] = receipt
        return selected, invalid

    def _list_names(self, prefix: str) -> tuple[str, ...]:
        response = self._session.get(
            f"https://storage.googleapis.com/storage/v1/b/"
            f"{quote(self._binding.evidence_bucket, safe='')}/o",
            params={"prefix": prefix, "fields": "items(name)", "maxResults": "100"},
            timeout=30,
        )
        response.raise_for_status()
        value = response.json()
        items = value.get("items", []) if isinstance(value, dict) else []
        if not isinstance(items, list):
            raise RuntimeError("Cloud Storage receipt listing is malformed")
        if len(items) >= 100:
            raise RuntimeError("Cloud Storage receipt listing exceeds the bounded release view")
        return tuple(
            str(item["name"])
            for item in items
            if isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and str(item["name"]).startswith(prefix)
        )

    def _get_json(self, object_name: str) -> dict[str, Any]:
        response = self._session.get(
            f"https://storage.googleapis.com/storage/v1/b/"
            f"{quote(self._binding.evidence_bucket, safe='')}/o/"
            f"{quote(object_name, safe='')}?alt=media",
            timeout=30,
        )
        response.raise_for_status()
        if len(response.content) > 1_048_576:
            raise ValueError("release receipt exceeds one MiB")
        value = json.loads(response.content)
        if not isinstance(value, dict):
            raise ValueError("release receipt is not a JSON object")
        return value
