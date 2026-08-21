-- Target migration: close the GitHub reviewer-link lifecycle contract.
-- This remains outside the implemented release schema until cloud qualification.

BEGIN;

SET search_path TO solvan_delivery, solvan, public;

ALTER TABLE solvan.actor_role_bindings
  DROP CONSTRAINT actor_role_bindings_role_check;
ALTER TABLE solvan.actor_role_bindings
  ADD CONSTRAINT actor_role_bindings_role_check
  CHECK (role IN ('OPERATOR','APPROVER','ADMIN','CODE_CHANGE_APPROVER','RELEASE_APPROVER'));

ALTER TABLE github_oauth_client_profiles
  ADD CONSTRAINT github_oauth_official_endpoint_boundary
  CHECK (
    authorization_endpoint='https://github.com/login/oauth/authorize'
    AND token_endpoint='https://github.com/login/oauth/access_token'
    AND api_base_url='https://api.github.com'
  );

ALTER TABLE github_identity_link_transactions
  ALTER COLUMN pkce_verifier_ciphertext DROP NOT NULL;

ALTER TABLE github_identity_link_transactions
  DROP CONSTRAINT github_identity_link_transactions_check;

ALTER TABLE github_identity_link_transactions
  ADD CONSTRAINT github_identity_link_transaction_material
  CHECK (
    (status = 'PENDING'
      AND consumed_at IS NULL
      AND pkce_verifier_ciphertext IS NOT NULL)
    OR
    (status IN ('CONSUMED','EXPIRED','REFUSED')
      AND consumed_at IS NOT NULL
      AND pkce_verifier_ciphertext IS NULL)
  );

CREATE OR REPLACE FUNCTION delivery_guard_oauth_client_profile()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'OAuth client profiles are append-only';
  END IF;
  IF OLD.status <> 'ACTIVE' OR NEW.status <> 'REVOKED'
     OR NEW.revoked_at IS NULL
     OR (OLD.organization_id,OLD.project_id,OLD.environment_id,OLD.id,
         OLD.provider_kind,OLD.github_app_client_id,OLD.client_secret_ref,
         OLD.authorization_endpoint,OLD.token_endpoint,OLD.api_base_url,
         OLD.callback_uri,OLD.protocol_version,OLD.token_expiration_required,
         OLD.configuration_hash,OLD.activated_at)
        IS DISTINCT FROM
        (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id,
         NEW.provider_kind,NEW.github_app_client_id,NEW.client_secret_ref,
         NEW.authorization_endpoint,NEW.token_endpoint,NEW.api_base_url,
         NEW.callback_uri,NEW.protocol_version,NEW.token_expiration_required,
         NEW.configuration_hash,NEW.activated_at) THEN
    RAISE EXCEPTION 'OAuth client profile material is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_oauth_client_profile_guard
BEFORE UPDATE OR DELETE ON github_oauth_client_profiles
FOR EACH ROW EXECUTE FUNCTION delivery_guard_oauth_client_profile();

CREATE OR REPLACE FUNCTION delivery_guard_reviewer_binding_projection()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'reviewer binding projection changes require an append-only event';
  END IF;
  IF (OLD.organization_id,OLD.project_id,OLD.environment_id,OLD.id,
      OLD.repository_binding_id,OLD.solvan_principal,OLD.github_account_node_id,
      OLD.github_login,OLD.binding_proof_ref,OLD.binding_proof_hash,
      OLD.reviewer_policy_hash,OLD.expires_at,OLD.created_at)
     IS DISTINCT FROM
     (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id,
      NEW.repository_binding_id,NEW.solvan_principal,NEW.github_account_node_id,
      NEW.github_login,NEW.binding_proof_ref,NEW.binding_proof_hash,
      NEW.reviewer_policy_hash,NEW.expires_at,NEW.created_at) THEN
    RAISE EXCEPTION 'reviewer binding identity and proof material are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_reviewer_binding_projection_guard
BEFORE UPDATE OR DELETE ON github_reviewer_bindings
FOR EACH ROW EXECUTE FUNCTION delivery_guard_reviewer_binding_projection();

CREATE OR REPLACE FUNCTION delivery_apply_reviewer_binding_event()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  prior_sequence integer;
  projected_status text;
BEGIN
  SELECT COALESCE(max(sequence_no),0)
    INTO prior_sequence
    FROM github_reviewer_binding_events
   WHERE organization_id=NEW.organization_id
     AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id
     AND github_reviewer_binding_id=NEW.github_reviewer_binding_id
     AND id <> NEW.id;
  IF NEW.sequence_no <> prior_sequence + 1 THEN
    RAISE EXCEPTION 'reviewer binding event sequence is not contiguous';
  END IF;

  projected_status := CASE NEW.event_kind
    WHEN 'LINKED' THEN 'ACTIVE'
    WHEN 'REVALIDATED' THEN 'ACTIVE'
    WHEN 'REVALIDATION_REQUIRED' THEN 'REVALIDATION_REQUIRED'
    WHEN 'EXPIRED' THEN 'EXPIRED'
    WHEN 'REVOKED' THEN 'REVOKED'
    WHEN 'REPLACED' THEN 'REPLACED'
  END;

  UPDATE github_reviewer_bindings
     SET status=projected_status,
         revoked_at=CASE WHEN projected_status IN ('REVOKED','REPLACED')
                         THEN NEW.occurred_at ELSE NULL END
   WHERE organization_id=NEW.organization_id
     AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id
     AND id=NEW.github_reviewer_binding_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'reviewer binding event has no binding projection';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_reviewer_binding_event_projection
AFTER INSERT ON github_reviewer_binding_events
FOR EACH ROW EXECUTE FUNCTION delivery_apply_reviewer_binding_event();

COMMIT;
