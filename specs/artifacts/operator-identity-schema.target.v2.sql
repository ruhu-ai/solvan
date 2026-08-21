-- The PKCE verifier is replayed, so it cannot be stored as a digest.
--
-- v1 stored `pkce_verifier_hash`, mirroring how the session credential and the
-- state are held: the server never needs the original, so it keeps only enough
-- to recognize it. The verifier is different in kind. It is sent to the token
-- endpoint when the authorization code is redeemed, so a digest of it cannot
-- complete the exchange, and the first implementation kept the value in process
-- memory instead — which loses every in-flight sign-in on a restart and fails
-- outright when a second instance serves the callback.
--
-- It is a short-lived secret at rest, bounded by the transaction's own expiry
-- and single claim. That is the cost of a flow where the browser holds nothing.

BEGIN;

ALTER TABLE solvan_identity.login_transactions
  DROP CONSTRAINT login_transactions_pkce_verifier_hash_check;

ALTER TABLE solvan_identity.login_transactions
  RENAME COLUMN pkce_verifier_hash TO pkce_verifier;

ALTER TABLE solvan_identity.login_transactions
  ADD CONSTRAINT login_transactions_pkce_verifier_length_check
  CHECK (length(pkce_verifier) BETWEEN 43 AND 128);

COMMIT;
