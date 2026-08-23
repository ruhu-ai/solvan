-- Forward-only: make steer-grant consumption durable.
--
-- A steer submission grant is one-time by contract (specification 14 §10.2),
-- but consumption lived in GrantIssuer._consumed, an in-process set: it did
-- not survive a restart, was invisible to a second serving instance, and grew
-- unboundedly in a long-lived process. Actual once-only came from the parked
-- decision's idempotency, which made the grant's own guarantee decorative.
-- This table is the durable form: one row per consumed nonce, and the
-- primary key makes a second consumption a constraint violation rather than
-- a race. Rows are scoped so an identical nonce in another environment is a
-- different fact, and immutable -- consumption is history, never updated.

BEGIN;

CREATE TABLE IF NOT EXISTS solvan_liaison.liaison_consumed_steer_grants (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  nonce text NOT NULL CHECK (length(nonce) BETWEEN 8 AND 128),
  grant_digest text NOT NULL CHECK (grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  parked_request_id text NOT NULL,
  confirming_principal text NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, nonce)
);

COMMIT;
