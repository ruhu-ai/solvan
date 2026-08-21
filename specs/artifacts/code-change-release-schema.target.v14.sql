-- Target migration: independent release-verifier key and stage-bound receipt authority.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

CREATE TABLE release_verifier_keys (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rvk_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  verifier_identity text NOT NULL, key_version text NOT NULL,
  public_verification_ref text NOT NULL CHECK (
    public_verification_ref ~ '^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[1-9][0-9]*$'),
  verifier_policy_hash text NOT NULL CHECK (verifier_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  activated_at timestamptz NOT NULL, revoked_at timestamptz, revoked_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,verifier_identity,key_version),
  CHECK ((status='ACTIVE' AND revoked_at IS NULL AND revoked_reason IS NULL)
      OR (status='REVOKED' AND revoked_at IS NOT NULL AND length(revoked_reason)>=8))
);
CREATE UNIQUE INDEX delivery_one_active_release_verifier_key
  ON release_verifier_keys(organization_id,project_id,environment_id)
  WHERE status='ACTIVE';

CREATE FUNCTION delivery_guard_release_verifier_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'release verifier key cannot be deleted';
  END IF;
  IF TG_OP='UPDATE' AND (
      OLD.status<>'ACTIVE' OR NEW.status<>'REVOKED'
      OR to_jsonb(OLD)-'status'-'revoked_at'-'revoked_reason'
         IS DISTINCT FROM to_jsonb(NEW)-'status'-'revoked_at'-'revoked_reason') THEN
    RAISE EXCEPTION 'release verifier key material is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_release_verifier_key_guard
BEFORE UPDATE OR DELETE ON release_verifier_keys
FOR EACH ROW EXECUTE FUNCTION delivery_guard_release_verifier_key();
CREATE TRIGGER delivery_release_verifier_key_no_truncate
BEFORE TRUNCATE ON release_verifier_keys
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM release_target_profiles)
     OR EXISTS (SELECT 1 FROM release_verification_receipts) THEN
    RAISE EXCEPTION 'unqualified target or verifier rows cannot be guessed into verifier authority';
  END IF;
END $$;

ALTER TABLE release_target_profiles
  ADD COLUMN verifier_identity text NOT NULL,
  ADD COLUMN verifier_key_version text NOT NULL,
  ADD CONSTRAINT release_target_profile_verifier_key_fk
    FOREIGN KEY (organization_id,project_id,environment_id,verifier_identity,
                 verifier_key_version)
    REFERENCES release_verifier_keys(
      organization_id,project_id,environment_id,verifier_identity,key_version);

ALTER TABLE release_verification_receipts
  ADD COLUMN stage_ordinal integer NOT NULL CHECK (stage_ordinal>0),
  ADD COLUMN observation_window_generation bigint NOT NULL
    CHECK (observation_window_generation>0),
  ADD COLUMN window_start timestamptz NOT NULL,
  ADD COLUMN window_end timestamptz NOT NULL,
  ADD COLUMN observed_target_version text NOT NULL,
  ADD COLUMN observed_assignment_hash text NOT NULL
    CHECK (observed_assignment_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN verifier_key_version text NOT NULL,
  ADD COLUMN receipt_envelope_ref text NOT NULL CHECK (receipt_envelope_ref ~ '^gs://'),
  ADD COLUMN receipt_envelope_hash text NOT NULL
    CHECK (receipt_envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT release_verification_window_ck CHECK (window_start<window_end),
  ADD CONSTRAINT release_verification_stage_generation_uk UNIQUE
    (organization_id,project_id,environment_id,deployment_rollout_id,
     stage_ordinal,observation_window_generation);

CREATE FUNCTION delivery_guard_release_verification_authority() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM deployment_rollouts rollout
      JOIN release_target_profiles profile
        ON profile.organization_id=rollout.organization_id
       AND profile.project_id=rollout.project_id
       AND profile.environment_id=rollout.environment_id
       AND profile.id=rollout.release_target_profile_id
       AND profile.profile_hash=rollout.release_target_profile_hash
       AND profile.status='ACTIVE'
       AND profile.verification_profile_hash=NEW.verification_profile_hash
       AND NEW.stage_ordinal<=cardinality(profile.canary_percentages)
       AND profile.verifier_identity=NEW.verifier_identity
       AND profile.verifier_key_version=NEW.verifier_key_version
      JOIN release_verifier_keys verifier_key
        ON verifier_key.organization_id=profile.organization_id
       AND verifier_key.project_id=profile.project_id
       AND verifier_key.environment_id=profile.environment_id
       AND verifier_key.verifier_identity=profile.verifier_identity
       AND verifier_key.key_version=profile.verifier_key_version
       AND verifier_key.status='ACTIVE'
      JOIN release_target_reservations reservation
        ON reservation.organization_id=rollout.organization_id
       AND reservation.project_id=rollout.project_id
       AND reservation.environment_id=rollout.environment_id
       AND reservation.id=rollout.target_reservation_id
       AND reservation.target_key=rollout.target_key
       AND reservation.status IN ('HELD','RECONCILING')
       AND reservation.lease_expires_at>NEW.observed_at
       AND reservation.held_by_identity<>NEW.verifier_identity
     WHERE rollout.organization_id=NEW.organization_id
       AND rollout.project_id=NEW.project_id
       AND rollout.environment_id=NEW.environment_id
       AND rollout.id=NEW.deployment_rollout_id
       AND rollout.predeploy_snapshot_ref=NEW.predeploy_snapshot_ref
       AND rollout.predeploy_snapshot_hash=NEW.predeploy_snapshot_hash
       AND rollout.intended_effect_hash=NEW.intended_effect_hash
       AND rollout.status IN ('CANARY_READY','PROMOTING','VERIFYING')
  ) THEN
    RAISE EXCEPTION 'RELEASE_VERIFICATION_AUTHORITY_INVALID' USING ERRCODE='23973';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_release_verification_authority_fence
BEFORE INSERT ON release_verification_receipts
FOR EACH ROW EXECUTE FUNCTION delivery_guard_release_verification_authority();

ALTER TABLE release_verifier_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_verifier_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON release_verifier_keys
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON release_verifier_keys FROM PUBLIC;

COMMIT;
