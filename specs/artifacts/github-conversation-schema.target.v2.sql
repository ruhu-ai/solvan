-- Target migration: one continuous install flow (specification 24 §9).
--
-- Connecting used to make an operator leave the product, find the App on
-- GitHub unprompted, install it, and come back knowing to press a button.
-- GitHub can redirect back to us instead, carrying the installation it just
-- created — but that redirect arrives as an ordinary browser GET that cannot
-- carry a step-up challenge, so the authority has to be established before the
-- operator leaves and carried across.
--
-- That is what this table is. An intent is minted only after an operator
-- re-authenticates, is single-use, expires in minutes, and stores only the
-- digest of the opaque state, so a database read cannot replay one.

BEGIN;
SET search_path TO solvan_conversation, solvan, public;

CREATE TABLE github_installation_intents (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ghi_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  -- The digest, never the state. What GitHub redirects back with is a bearer
  -- value for these few minutes; storing it would make every reader of this
  -- table able to complete somebody else's installation.
  state_hash text NOT NULL CHECK (state_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL')),
  actor_principal text NOT NULL,
  -- The challenge the operator spent to begin. Recorded so the durable answer
  -- to "who authorized this installation" is not merely "somebody had a link".
  challenge_id text NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','CONSUMED','REFUSED')),
  installation_id bigint CHECK (installation_id IS NULL OR installation_id > 0),
  bound_count integer CHECK (bound_count IS NULL OR bound_count >= 0),
  error_class text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  -- One state completes one installation. A replayed redirect finds the row
  -- already consumed rather than creating a second set of bindings.
  UNIQUE (organization_id, project_id, environment_id, state_hash),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  CHECK (expires_at > created_at),
  -- A consumed intent names what it produced; a refused one names why.
  CHECK ((status <> 'CONSUMED')
    OR (installation_id IS NOT NULL AND consumed_at IS NOT NULL AND bound_count IS NOT NULL)),
  CHECK ((status = 'REFUSED') = (error_class IS NOT NULL))
);

CREATE INDEX github_installation_intents_pending
  ON github_installation_intents
    (organization_id, project_id, environment_id, status, expires_at);

COMMIT;
