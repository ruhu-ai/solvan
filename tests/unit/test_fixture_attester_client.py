import hashlib

import httpx
import pytest
import rfc8785

from solvan.application import SyntheticAttestationRequest
from solvan.platform import (
    FixtureAttesterClient,
    FixtureAttesterConfiguration,
    FixtureAttesterError,
)


class FakeTokenProvider:
    def token(self, *, audience: str) -> str:
        assert audience == "https://attester.example.run.app"
        return "identity-token"


def _request() -> SyntheticAttestationRequest:
    return SyntheticAttestationRequest(
        workspace_id="wsp_00000000000000000000000000",
        workspace_generation=1,
        fixture_id="payments-leak-v1",
        artifact_manifest_ref="gs://runtime/workspaces/input.json",
        artifact_manifest_hash=f"sha256:{'1' * 64}",
    )


def test_client_authenticates_and_parses_strict_attestation_receipt() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer identity-token"
        assert request.url.path == "/internal/v1/synthetic-attestations"
        signed = {
            "schema_version": 1,
            "attestation_id": "att_00000000000000000000000000",
            "organization_id": "org_00000000000000000000000000",
            "project_id": "prj_00000000000000000000000000",
            "environment_id": "env_00000000000000000000000000",
            "release_commit": "a" * 40,
            "deployment_id": "deploy-1",
            "fixture_id": "payments-leak-v1",
            "classification": "PUBLIC",
            "synthetic": True,
            "artifact_manifest_ref": "gs://runtime/workspaces/input.json",
            "artifact_manifest_hash": f"sha256:{'1' * 64}",
            "issuer_principal": "serviceAccount:attester@example.com",
            "issued_at": "2026-08-08T12:00:00Z",
            "expires_at": "2026-08-08T13:00:00Z",
            "canonicalization": "RFC8785",
            "signature_algorithm": "EC_SIGN_P256_SHA256",
            "kms_key_version": (
                "projects/demo/locations/europe-west1/keyRings/workspace/"
                "cryptoKeys/attester/cryptoKeyVersions/1"
            ),
        }
        payload = rfc8785.dumps(signed)
        return httpx.Response(
            200,
            json={
                "attestation_ref": "gs://evidence/attestation.json",
                "attestation_hash": f"sha256:{'2' * 64}",
                "attestation": {
                    **signed,
                    "signed_payload_hash": (f"sha256:{hashlib.sha256(payload).hexdigest()}"),
                    "signature_ref": "gs://evidence/signature.der",
                    "signature_hash": f"sha256:{'3' * 64}",
                },
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        attester = FixtureAttesterClient(
            config=FixtureAttesterConfiguration(
                base_url="https://attester.example.run.app",
                audience="https://attester.example.run.app",
            ),
            client=client,
            token_provider=FakeTokenProvider(),
        )
        receipt = attester.attest(_request())
    assert receipt.attestation.fixture_id == "payments-leak-v1"


def test_client_translates_private_service_failure() -> None:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"detail": "denied"})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        attester = FixtureAttesterClient(
            config=FixtureAttesterConfiguration(
                base_url="https://attester.example.run.app",
                audience="https://attester.example.run.app",
            ),
            client=client,
            token_provider=FakeTokenProvider(),
        )
        with pytest.raises(FixtureAttesterError, match="attestation failed"):
            attester.attest(_request())


@pytest.mark.parametrize(
    ("base_url", "audience"),
    [
        ("http://attester.example", "https://attester.example"),
        ("https://attester.example/", "https://attester.example"),
        ("https://attester.example", "not-https"),
    ],
)
def test_configuration_rejects_noncanonical_origins(base_url: str, audience: str) -> None:
    with pytest.raises(ValueError):
        FixtureAttesterConfiguration(base_url=base_url, audience=audience)
