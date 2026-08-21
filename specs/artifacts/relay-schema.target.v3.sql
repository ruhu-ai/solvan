-- Forward-only Relay image-attestation binding correction.
--
-- The poll contract binds an attestation digest. v1 recorded its component
-- evidence but no immutable digest for the attestation statement, so the
-- control plane could not compare the Relay's declaration to registration.
-- Existing rows remain ineligible until re-attested with this value.
BEGIN;
SET search_path TO solvan_relay, solvan, public;

ALTER TABLE relay_image_attestations
  ADD COLUMN attestation_digest text
    CHECK (attestation_digest IS NULL OR attestation_digest ~ '^sha256:[0-9a-f]{64}$');

CREATE INDEX relay_image_attestation_poll_idx
  ON relay_image_attestations(id,image_digest,decision,expires_at)
  WHERE attestation_digest IS NOT NULL;

COMMIT;
