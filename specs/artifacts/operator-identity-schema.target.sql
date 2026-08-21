-- Operator identity, session, and step-up challenge (specification 05 §4.2).
--
-- Google issues the identity assertion; nothing here stores one. What is stored
-- is who an assertion resolved to, what that actor may do, and the exact
-- one-use permission to take a single action.
--
-- The durable identity is the external identity, never an email. An email is a
-- current attribute: it changes, and a reassigned address must not inherit the
-- authority of whoever held it before.

BEGIN;

CREATE SCHEMA IF NOT EXISTS solvan_identity;
SET LOCAL search_path TO solvan_identity, solvan, public;

CREATE TABLE actors (
  actor_id text PRIMARY KEY CHECK (actor_id ~ '^act_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One row per identity a provider asserts. The issuer is stored canonically
-- because a provider may present equivalent forms of the same issuer, and two
-- spellings would otherwise make one person two actors holding separate roles.
CREATE TABLE external_identities (
  provider text NOT NULL CHECK (provider IN ('GOOGLE')),
  canonical_issuer text NOT NULL CHECK (canonical_issuer = lower(canonical_issuer)
    AND canonical_issuer !~ '^https?://' AND canonical_issuer !~ '/$'),
  subject text NOT NULL CHECK (length(subject) > 0),
  actor_id text NOT NULL REFERENCES actors(actor_id),
  -- Current attributes for display, notification, and domain policy. Never an
  -- identity, and never a join key.
  email text NOT NULL CHECK (email = lower(email) AND position('@' IN email) > 1),
  hosted_domain text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, canonical_issuer, subject),
  -- One provider identity resolves to one actor. Re-pointing it at another
  -- actor is an account takeover expressed as an update.
  UNIQUE (provider, canonical_issuer, subject, actor_id)
);
CREATE INDEX external_identities_by_actor_idx ON external_identities(actor_id);
CREATE INDEX external_identities_by_email_idx ON external_identities(email);

-- What an actor may do, in one exact scope. The principal is an actor, so an
-- email can no longer be granted a role and a rename cannot transfer one.
CREATE TABLE actor_memberships (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  actor_id text NOT NULL REFERENCES actors(actor_id),
  role text NOT NULL CHECK (role IN ('OPERATOR','APPROVER','ADMIN')),
  granted_by_actor_id text NOT NULL REFERENCES actors(actor_id),
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, actor_id, role),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  CHECK (expires_at IS NULL OR expires_at > granted_at)
);

-- A grant authored before its holder has ever signed in. It confers nothing
-- until redeemed, expires, and is consumed once: an invitation that never
-- expired would let a later holder of a reassigned address claim the role.
CREATE TABLE actor_invitations (
  id text PRIMARY KEY CHECK (id ~ '^inv_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  email text NOT NULL CHECK (email = lower(email) AND position('@' IN email) > 1),
  admitted_domain text NOT NULL CHECK (admitted_domain = lower(admitted_domain)),
  role text NOT NULL CHECK (role IN ('OPERATOR','APPROVER','ADMIN')),
  invited_by_actor_id text NOT NULL REFERENCES actors(actor_id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by_actor_id text REFERENCES actors(actor_id),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  CHECK (expires_at > created_at),
  -- Consumed means both facts or neither. A consumption timestamp without the
  -- actor it admitted records that something happened and not to whom.
  CHECK ((consumed_at IS NULL) = (consumed_by_actor_id IS NULL))
);
CREATE UNIQUE INDEX actor_invitations_one_open_per_grant_idx
  ON actor_invitations(organization_id, project_id, environment_id, email, role)
  WHERE consumed_at IS NULL;

-- A pending sign-in. The browser holds an opaque reference; the state, nonce,
-- and PKCE verifier live here, so a forged callback cannot supply its own.
CREATE TABLE login_transactions (
  id text PRIMARY KEY CHECK (id ~ '^lgn_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  state_hash text NOT NULL UNIQUE CHECK (state_hash ~ '^sha256:[0-9a-f]{64}$'),
  nonce_hash text NOT NULL CHECK (nonce_hash ~ '^sha256:[0-9a-f]{64}$'),
  pkce_verifier_hash text NOT NULL CHECK (pkce_verifier_hash ~ '^sha256:[0-9a-f]{64}$'),
  audience text NOT NULL,
  return_path text NOT NULL CHECK (return_path ~ '^/'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > created_at)
);

-- What the OAuth callback verified. Approval never sees an assertion; it sees a
-- challenge referencing one of these.
CREATE TABLE authentication_events (
  id text PRIMARY KEY CHECK (id ~ '^aev_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  actor_id text NOT NULL REFERENCES actors(actor_id),
  canonical_issuer text NOT NULL,
  subject text NOT NULL,
  audience text NOT NULL,
  authenticated_at timestamptz NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  hosted_domain text,
  CHECK (observed_at >= authenticated_at)
);

-- Authenticated identity, never authority. Only a hash of the credential is
-- stored, so reading this table cannot impersonate its holder.
CREATE TABLE operator_sessions (
  id text PRIMARY KEY CHECK (id ~ '^ses_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  actor_id text NOT NULL REFERENCES actors(actor_id),
  credential_hash text NOT NULL UNIQUE CHECK (credential_hash ~ '^sha256:[0-9a-f]{64}$'),
  authentication_event_id text NOT NULL REFERENCES authentication_events(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  rotated_from_session_id text REFERENCES operator_sessions(id),
  CHECK (idle_expires_at > created_at),
  CHECK (absolute_expires_at > created_at),
  -- An idle window longer than the absolute ceiling is an absolute ceiling that
  -- does not cap anything.
  CHECK (idle_expires_at <= absolute_expires_at)
);
CREATE INDEX operator_sessions_by_actor_idx ON operator_sessions(actor_id);

-- The frozen operation, created before re-authentication and bound to the
-- session that requested it. Rotation happens between this and the challenge,
-- which is why the two are separate records.
CREATE TABLE step_up_transactions (
  id text PRIMARY KEY CHECK (id ~ '^stu_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  requesting_session_id text NOT NULL REFERENCES operator_sessions(id),
  actor_id text NOT NULL REFERENCES actors(actor_id),
  operation text NOT NULL CHECK (length(operation) > 0),
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  material_digest text NOT NULL CHECK (material_digest ~ '^sha256:[0-9a-f]{64}$'),
  login_transaction_id text REFERENCES login_transactions(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  CHECK (expires_at > created_at)
);

-- Authority for exactly one decision. One use, one operation, one material.
CREATE TABLE action_challenges (
  id text PRIMARY KEY CHECK (id ~ '^chl_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  step_up_transaction_id text NOT NULL UNIQUE REFERENCES step_up_transactions(id),
  session_id text NOT NULL REFERENCES operator_sessions(id),
  actor_id text NOT NULL REFERENCES actors(actor_id),
  authentication_event_id text NOT NULL REFERENCES authentication_events(id),
  operation text NOT NULL CHECK (length(operation) > 0),
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  material_digest text NOT NULL CHECK (material_digest ~ '^sha256:[0-9a-f]{64}$'),
  csrf_token_hash text NOT NULL CHECK (csrf_token_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'ISSUED' CHECK (status IN ('ISSUED','CONSUMED','TERMINAL')),
  consumed_at timestamptz,
  terminal_reason text CHECK (terminal_reason IS NULL OR terminal_reason IN
    ('EXPIRED','ROLE_REMOVED','MATERIAL_CHANGED','SESSION_ROTATED','CALLBACK_FAILED')),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  CHECK (expires_at > created_at),
  -- Consumed exactly when it says so, and terminal states carry their reason.
  CHECK ((status = 'CONSUMED') = (consumed_at IS NOT NULL)),
  CHECK ((status = 'TERMINAL') = (terminal_reason IS NOT NULL))
);
CREATE INDEX action_challenges_by_session_idx ON action_challenges(session_id);

COMMIT;
