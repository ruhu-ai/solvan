"""Customer-resident Solvant Relay command.

The executable performs one bounded outbound poll cycle and exits.  It is
intended for a customer-owned Cloud Run Job, CronJob, or supervisor; it never
opens a listener, keeps a control-plane connection authoritative, or accepts
an inbound command.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from apps.solvant_relay.cloud_logging import CloudLoggingRelayAdapter
from apps.solvant_relay.cloud_monitoring import CloudMonitoringRelayAdapter
from apps.solvant_relay.cloud_trace import CloudTraceRelayAdapter
from apps.solvant_relay.control_client import HttpObjectUploader, RelayControlClient
from apps.solvant_relay.kubernetes_metadata import KubernetesMetadataRelayAdapter
from apps.solvant_relay.ledger import EncryptedAttemptLedger
from apps.solvant_relay.managed_prometheus import ManagedPrometheusRelayAdapter
from apps.solvant_relay.policy import verify_local_policy
from apps.solvant_relay.readiness import build_runtime_policy_proof, verify_readiness_challenge
from apps.solvant_relay.runtime import RelayAttemptRunner, RelayRuntimeError
from apps.solvant_relay.signatures import EcdsaJobVerifier
from solvan.platform.google_rest import authorized_session


class RelayConfigurationError(RelayRuntimeError):
    """The customer deployment did not supply one required local binding."""


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RelayConfigurationError(f"{name} is required")
    return value


def _read_bytes(name: str, *, maximum: int) -> bytes:
    path = Path(_required(name))
    if not path.is_absolute() or path.is_symlink():
        raise RelayConfigurationError(f"{name} must be an absolute non-symlink path")
    try:
        value = path.read_bytes()
    except OSError as error:
        raise RelayConfigurationError(f"{name} cannot be read") from error
    if not value or len(value) > maximum:
        raise RelayConfigurationError(f"{name} is outside the safe local bound")
    return value


def _policy_document() -> dict[str, Any]:
    try:
        value = json.loads(_read_bytes("SOLVANT_RELAY_POLICY_PATH", maximum=64 * 1024))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RelayConfigurationError("SOLVANT_RELAY_POLICY_PATH is not valid JSON") from error
    if not isinstance(value, dict):
        raise RelayConfigurationError("SOLVANT_RELAY_POLICY_PATH is not an object")
    return value


def _local_kill_switch_engaged() -> bool:
    """Read a customer-owned kill switch without creating a permissive bypass.

    Suspending the CronJob remains an immediate customer control. A mounted
    state file gives a running worker a second way to report that it must not
    poll or claim new work. A configured file that is unsafe, unreadable, or
    malformed refuses the cycle before the poll request.
    """

    configured = os.environ.get("SOLVANT_RELAY_KILL_SWITCH_PATH")
    if configured is None:
        return False
    path = Path(configured)
    if not path.is_absolute() or path.is_symlink():
        raise RelayConfigurationError("SOLVANT_RELAY_KILL_SWITCH_PATH is unsafe")
    try:
        state = path.read_text(encoding="ascii")
    except OSError as error:
        raise RelayConfigurationError("SOLVANT_RELAY_KILL_SWITCH_PATH cannot be read") from error
    if state == "ENGAGED\n":
        return True
    if state == "DISENGAGED\n":
        return False
    raise RelayConfigurationError("SOLVANT_RELAY_KILL_SWITCH_PATH has an invalid state")


def run_once(*, now: datetime | None = None) -> str | None:
    """Complete one readiness/poll/collection cycle without accepting ingress."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    image_digest = _required("SOLVANT_RELAY_IMAGE_DIGEST")
    process_boot_id = _required("SOLVANT_RELAY_PROCESS_BOOT_ID")
    runtime_proof_key_id = _required("SOLVANT_RELAY_RUNTIME_PROOF_KEY_ID")
    image_attestation_digest = _required("SOLVANT_RELAY_IMAGE_ATTESTATION_DIGEST")
    relay_version = _required("SOLVANT_RELAY_VERSION")
    control = RelayControlClient.from_environment()
    policy_public_key = _read_bytes("SOLVANT_RELAY_POLICY_PUBLIC_KEY_PATH", maximum=16 * 1024)
    control_public_key = _read_bytes("SOLVANT_RELAY_CONTROL_PUBLIC_KEY_PATH", maximum=16 * 1024)
    runtime_private_key = _read_bytes(
        "SOLVANT_RELAY_RUNTIME_PROOF_PRIVATE_KEY_PATH", maximum=16 * 1024
    )
    ledger_key = _read_bytes("SOLVANT_RELAY_LEDGER_KEY_PATH", maximum=32)
    if len(ledger_key) != 32:
        raise RelayConfigurationError("SOLVANT_RELAY_LEDGER_KEY_PATH must contain 32 bytes")
    policy = verify_local_policy(
        _policy_document(),
        key_resolver=lambda _key_id: policy_public_key,
        now=current,
        expected_image_digest=image_digest,
        expected_audience=_required("SOLVAN_RELAY_CONTROL_AUDIENCE"),
    )
    challenge_envelope = control.readiness_challenge(
        body={
            "schema_version": 1,
            "process_boot_id": process_boot_id,
            "relay_version": relay_version,
            "image_digest": image_digest,
            "runtime_proof_key_id": runtime_proof_key_id,
        }
    )
    challenge, _nonce = verify_readiness_challenge(
        challenge_envelope,
        key_resolver=lambda _key_id: control_public_key,
        now=current,
    )
    proof = build_runtime_policy_proof(
        challenge=challenge,
        policy=policy,
        runtime_proof_key_id=runtime_proof_key_id,
        private_key_resolver=lambda _key_id: runtime_private_key,
        now=current,
    )
    proof_response = control.readiness_proof(
        body={
            "schema_version": 1,
            **proof.unsigned_projection(),
            "signature_base64": proof.signature_base64,
        }
    )
    if (
        proof_response.get("proof_id") != proof.proof_id
        or proof_response.get("proof_digest") != proof.proof_digest
    ):
        raise RelayRuntimeError("control plane did not acknowledge the exact runtime proof")
    runner = RelayAttemptRunner(
        control=control,
        job_verifier=EcdsaJobVerifier(key_resolver=lambda _key_id: control_public_key),
        monitoring=CloudMonitoringRelayAdapter(session=authorized_session()),
        adapters={
            "managed-prometheus.v1": ManagedPrometheusRelayAdapter(session=authorized_session()),
            "cloud-logging.v1": CloudLoggingRelayAdapter(session=authorized_session()),
            "cloud-trace.v1": CloudTraceRelayAdapter(session=authorized_session()),
            "kubernetes-metadata.v1": KubernetesMetadataRelayAdapter(session=authorized_session()),
        },
        uploader=HttpObjectUploader(),
        ledger=EncryptedAttemptLedger(
            directory=Path(_required("SOLVANT_RELAY_LEDGER_DIR")), key=ledger_key
        ),
        process_boot_id=process_boot_id,
    )
    runner.acknowledge_terminal_outcomes(now=current)
    poll = control.poll(
        body={
            "schema_version": 1,
            "relay_version": relay_version,
            "process_boot_id": process_boot_id,
            "image_digest": image_digest,
            "image_attestation_digest": image_attestation_digest,
            "local_policy_id": policy.policy_id,
            "local_policy_digest": policy.digest,
            "runtime_policy_proof_id": proof.proof_id,
            "runtime_policy_proof_digest": proof.proof_digest,
            "connector_catalog_digest": policy.connector_catalog_digest,
            "relay_connection_epoch": policy.relay_connection_epoch,
            "enrollment_epoch": policy.enrollment_epoch,
            "kill_switch_engaged": _local_kill_switch_engaged(),
            "declared_adapter_revisions": sorted(
                {str(adapter["adapter_revision"]) for adapter in policy.adapters.values()}
            ),
        }
    )
    if poll is None:
        return None
    return runner.execute(policy=policy, envelope=poll, now=current)


def main() -> int:
    try:
        run_once()
    except RelayRuntimeError:
        # Do not leak policy, credentials, provider data, object URLs, or raw
        # control-plane responses through a process log.
        sys.stderr.write("solvant-relay: bounded cycle refused\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by customer runtime image
    raise SystemExit(main())
