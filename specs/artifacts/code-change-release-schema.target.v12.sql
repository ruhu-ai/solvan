-- Target migration: release candidates retain the exact signed envelope authority.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

ALTER TABLE release_candidates
  ADD COLUMN candidate_envelope_ref text NOT NULL CHECK (candidate_envelope_ref ~ '^gs://'),
  ADD COLUMN candidate_envelope_hash text NOT NULL
    CHECK (candidate_envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN issued_at timestamptz NOT NULL;

COMMIT;
