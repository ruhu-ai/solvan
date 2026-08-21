-- Transaction-bound operator presence proof (specification 05 §4.2).
--
-- Google remains the sole human identity issuer.  It cannot be asked to
-- reauthenticate an account, so a consequential action proves recent presence
-- with a one-use code delivered to the verified email already bound to the
-- live Google actor.  Email cannot create an actor or a session by itself.

BEGIN;

-- v3 proposed general email sign-in.  That widens identity issuance and stores
-- a brute-forceable digest of a six-digit secret.  Remove the path completely;
-- no compatibility route is retained.
DROP TABLE solvan_identity.email_login_codes;

ALTER TABLE solvan_identity.external_identities
  DROP CONSTRAINT external_identities_provider_check;
ALTER TABLE solvan_identity.external_identities
  ADD CONSTRAINT external_identities_provider_check CHECK (provider = 'GOOGLE');

-- Step-up no longer returns through the identity provider, so a login
-- transaction cannot be its completion fence.
ALTER TABLE solvan_identity.step_up_transactions
  DROP COLUMN login_transaction_id;
ALTER TABLE solvan_identity.step_up_transactions
  ADD CONSTRAINT step_up_transactions_identity_tuple_key
  UNIQUE (id,actor_id,requesting_session_id);

CREATE TABLE solvan_identity.operator_step_up_codes (
  id text PRIMARY KEY CHECK (id ~ '^sup_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  step_up_transaction_id text NOT NULL UNIQUE
    REFERENCES solvan_identity.step_up_transactions(id),
  requesting_session_id text NOT NULL REFERENCES solvan_identity.operator_sessions(id),
  actor_id text NOT NULL REFERENCES solvan_identity.actors(actor_id),
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  email text NOT NULL CHECK (email = lower(email) AND position('@' IN email) > 1),
  -- A numeric code has too little entropy for a plain digest.  This verifier is
  -- HMAC'd with a dedicated Secret Manager value and bound to this transaction.
  verifier_hmac text NOT NULL CHECK (verifier_hmac ~ '^hmac-sha256:[0-9a-f]{64}$'),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  delivery_status text NOT NULL DEFAULT 'PENDING'
    CHECK (delivery_status IN ('PENDING','DELIVERED','FAILED')),
  delivery_receipt text,
  delivered_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING','CONSUMED','TERMINAL')),
  consumed_at timestamptz,
  terminal_reason text CHECK (terminal_reason IS NULL OR terminal_reason IN
    ('SUPERSEDED','DELIVERY_FAILED','ATTEMPTS_EXHAUSTED','EXPIRED')),
  terminal_at timestamptz,
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  FOREIGN KEY (step_up_transaction_id,actor_id,requesting_session_id)
    REFERENCES solvan_identity.step_up_transactions
      (id,actor_id,requesting_session_id),
  CHECK (expires_at > created_at),
  CHECK ((delivery_status = 'DELIVERED') =
         (delivery_receipt IS NOT NULL AND delivered_at IS NOT NULL)),
  CHECK ((delivery_status = 'FAILED') = (terminal_reason = 'DELIVERY_FAILED')),
  CHECK ((status = 'CONSUMED') = (consumed_at IS NOT NULL)),
  CHECK ((status = 'TERMINAL') =
         (terminal_reason IS NOT NULL AND terminal_at IS NOT NULL)),
  CHECK (status <> 'CONSUMED' OR delivery_status = 'DELIVERED')
);

CREATE UNIQUE INDEX operator_step_up_one_pending_per_session_idx
  ON solvan_identity.operator_step_up_codes(requesting_session_id)
  WHERE status = 'PENDING';
CREATE INDEX operator_step_up_issuance_ceiling_idx
  ON solvan_identity.operator_step_up_codes
     (organization_id,project_id,environment_id,actor_id,created_at DESC);
ALTER TABLE solvan_identity.operator_step_up_codes
  ADD CONSTRAINT operator_step_up_codes_presence_tuple_key
  UNIQUE (id,step_up_transaction_id,actor_id,requesting_session_id);

-- This is the evidence a challenge references.  It says which already-known
-- actor demonstrated possession, how, for which frozen action, and across
-- which exact session rotation.  It contains no code and no provider token.
CREATE TABLE solvan_identity.step_up_presence_events (
  id text PRIMARY KEY CHECK (id ~ '^pev_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  step_up_transaction_id text NOT NULL UNIQUE
    REFERENCES solvan_identity.step_up_transactions(id),
  code_id text NOT NULL UNIQUE REFERENCES solvan_identity.operator_step_up_codes(id),
  actor_id text NOT NULL REFERENCES solvan_identity.actors(actor_id),
  requesting_session_id text NOT NULL REFERENCES solvan_identity.operator_sessions(id),
  resulting_session_id text NOT NULL UNIQUE REFERENCES solvan_identity.operator_sessions(id),
  method text NOT NULL CHECK (method IN ('EMAIL_OTP')),
  proven_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (code_id,step_up_transaction_id,actor_id,requesting_session_id)
    REFERENCES solvan_identity.operator_step_up_codes
      (id,step_up_transaction_id,actor_id,requesting_session_id),
  CHECK (requesting_session_id <> resulting_session_id),
  UNIQUE (id,step_up_transaction_id,actor_id,resulting_session_id)
);

ALTER TABLE solvan_identity.action_challenges
  DROP COLUMN authentication_event_id;
ALTER TABLE solvan_identity.action_challenges
  ADD COLUMN presence_event_id text NOT NULL
    REFERENCES solvan_identity.step_up_presence_events(id);
ALTER TABLE solvan_identity.action_challenges
  ADD CONSTRAINT action_challenges_presence_binding_fkey
  FOREIGN KEY (presence_event_id,step_up_transaction_id,actor_id,session_id)
    REFERENCES solvan_identity.step_up_presence_events
      (id,step_up_transaction_id,actor_id,resulting_session_id);

COMMIT;
