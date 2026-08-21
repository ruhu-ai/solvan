-- Target migration: an install intent is spent when it is claimed, not when
-- the installation it started finishes (specification 24 §9).
--
-- v2 recorded the intent but only moved it off PENDING at completion, and
-- completion happens in a later transaction — after two GitHub round trips.
-- Between those two points the row still read PENDING, so a second delivery of
-- the same redirect (a double click, a link prefetch, a GitHub retry) found a
-- usable intent and raced the first to create the same bindings. The unique
-- index on state_hash did not prevent that: it stops the same state being
-- *minted* twice, which for a 32-byte random value never happens, and says
-- nothing about the same state being *presented* twice.
--
-- CLAIMED is the missing state. One conditional UPDATE moves PENDING to
-- CLAIMED, so exactly one presentation of a link proceeds and every later one
-- finds it spent — while the row still records what it went on to produce.

BEGIN;
SET search_path TO solvan_conversation, solvan, public;

ALTER TABLE github_installation_intents
  DROP CONSTRAINT github_installation_intents_status_check;
ALTER TABLE github_installation_intents
  ADD CONSTRAINT github_installation_intents_status_check
  CHECK (status IN ('PENDING','CLAIMED','CONSUMED','REFUSED'));

ALTER TABLE github_installation_intents
  ADD COLUMN claimed_at timestamptz;

-- A pending intent has not been presented, so it cannot name when it was.
ALTER TABLE github_installation_intents
  ADD CONSTRAINT github_installation_intents_pending_unclaimed
  CHECK (status <> 'PENDING' OR claimed_at IS NULL);

-- A claimed or completed intent was presented exactly once, and says when.
-- REFUSED is deliberately outside this rule: an intent can be refused for
-- having expired before anybody presented it at all.
ALTER TABLE github_installation_intents
  ADD CONSTRAINT github_installation_intents_spent_claim_time
  CHECK (status NOT IN ('CLAIMED','CONSUMED') OR claimed_at IS NOT NULL);

COMMIT;
