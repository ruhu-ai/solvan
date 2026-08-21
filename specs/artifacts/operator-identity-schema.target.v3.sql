-- Email sign-in, alongside Google (specification 05 §4.2).
--
-- Google remains the strongest issuer and the default. Email exists because
-- admission is not always to a Google Workspace: a person Solvan must admit may
-- have no Google account, and until now they could not be admitted at all.
--
-- What email does not change: admission. A code proves control of a mailbox and
-- nothing else. The address must still be at an admitted domain, and an explicit
-- membership is still what lets it in — exactly as for a verified Google
-- assertion. Eligibility is not admission, whichever door it arrives through.
--
-- What it must not become is a weaker route to an account that already has a
-- stronger one. That is a policy decision the application makes per environment,
-- not something this schema can express, so it is enforced in code and recorded
-- there.

BEGIN;

-- One person, one actor, whichever way they prove who they are. The identity is
-- keyed on (provider, canonical_issuer, subject) as before; for email the issuer
-- is this deployment and the subject is the address, so a person who signs in
-- with Google and with email holds two identities against one actor once an
-- administrator links them. They are never linked silently — the same rule that
-- governs migrating an email-keyed binding.
ALTER TABLE solvan_identity.external_identities
  DROP CONSTRAINT external_identities_provider_check;

ALTER TABLE solvan_identity.external_identities
  ADD CONSTRAINT external_identities_provider_check
  CHECK (provider IN ('GOOGLE', 'EMAIL'));

-- A one-use code, held as a digest for the same reason a session credential is:
-- the server never needs the original, only enough to recognize it. Nothing here
-- is a bearer credential at rest.
CREATE TABLE solvan_identity.email_login_codes (
  id text PRIMARY KEY CHECK (id ~ '^elc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  email text NOT NULL CHECK (email = lower(email) AND position('@' IN email) > 1),
  code_hash text NOT NULL CHECK (code_hash ~ '^sha256:[0-9a-f]{64}$'),
  -- Bounded attempts, because a six-digit code is guessable at scale otherwise.
  -- The ceiling is enforced here as well as in code so that a second caller
  -- cannot reopen a code the first exhausted.
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  -- What the code was minted for. A sign-in code must not be spendable as a
  -- step-up for a consequential action, or re-authentication would be satisfied
  -- by a code the person already used to get in.
  purpose text NOT NULL CHECK (purpose IN ('SIGN_IN', 'STEP_UP')),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  CHECK (expires_at > created_at)
);

-- One live code per address and purpose. Without this, requesting a second code
-- leaves the first usable, and a person who forwarded the first by mistake has
-- no way to invalidate it.
CREATE UNIQUE INDEX email_login_codes_one_live_per_purpose_idx
  ON solvan_identity.email_login_codes
     (organization_id, project_id, environment_id, email, purpose)
  WHERE consumed_at IS NULL;

COMMIT;
