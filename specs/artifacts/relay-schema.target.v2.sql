-- Forward-only Relay runtime-proof key correction.
--
-- v1 retained only a digest for customer runtime proof keys. A digest lets the
-- control plane detect a substituted key but cannot verify the proof signature.
-- Existing registrations remain fail-closed until an administrator records a
-- new immutable key revision with this public-key reference; this migration
-- never invents a reference or rewrites historical key material.
BEGIN;
SET search_path TO solvan_relay, solvan, public;

ALTER TABLE relay_runtime_proof_key_revisions
  ADD COLUMN public_key_ref text;

CREATE INDEX relay_runtime_proof_key_verification_idx
  ON relay_runtime_proof_key_revisions
    (organization_id,project_id,environment_id,enrollment_id,enrollment_epoch,
     key_id,lifecycle,valid_from,verify_until)
  WHERE public_key_ref IS NOT NULL;

COMMIT;
