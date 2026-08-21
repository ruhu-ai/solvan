-- Target migration: independent rollback-effect verification and finalization.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

CREATE TABLE release_rollback_verification_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rrv_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  deployment_rollout_id text NOT NULL, expected_revision text NOT NULL,
  observed_target_version text NOT NULL,
  observed_assignment_hash text NOT NULL CHECK (observed_assignment_hash ~ '^sha256:[0-9a-f]{64}$'),
  result text NOT NULL CHECK (result IN ('VERIFIED','FAILED')),
  verifier_identity text NOT NULL,verifier_key_version text NOT NULL,
  receipt_envelope_ref text NOT NULL CHECK (receipt_envelope_ref ~ '^gs://'),
  receipt_envelope_hash text NOT NULL CHECK (receipt_envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  signature_ref text NOT NULL CHECK (signature_ref ~ '^gs://'),
  signature_hash text NOT NULL CHECK (signature_hash ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,deployment_rollout_id),
  FOREIGN KEY (organization_id,project_id,environment_id,deployment_rollout_id)
    REFERENCES deployment_rollouts(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,verifier_identity,verifier_key_version)
    REFERENCES release_verifier_keys(organization_id,project_id,environment_id,
                                     verifier_identity,key_version)
);
CREATE TRIGGER delivery_rollback_verification_append_only
BEFORE UPDATE OR DELETE ON release_rollback_verification_receipts
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_rollback_verification_no_truncate
BEFORE TRUNCATE ON release_rollback_verification_receipts
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

CREATE FUNCTION delivery_guard_rollback_verification() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM deployment_rollouts rollout
      JOIN release_target_observations observation
        ON observation.organization_id=rollout.organization_id
       AND observation.project_id=rollout.project_id
       AND observation.environment_id=rollout.environment_id
       AND observation.observation_hash=rollout.predeploy_snapshot_hash
       AND observation.current_revision=NEW.expected_revision
      JOIN release_verifier_keys verifier_key
        ON verifier_key.organization_id=rollout.organization_id
       AND verifier_key.project_id=rollout.project_id
       AND verifier_key.environment_id=rollout.environment_id
       AND verifier_key.verifier_identity=NEW.verifier_identity
       AND verifier_key.key_version=NEW.verifier_key_version
       AND verifier_key.status='ACTIVE'
     WHERE rollout.organization_id=NEW.organization_id
       AND rollout.project_id=NEW.project_id
       AND rollout.environment_id=NEW.environment_id
       AND rollout.id=NEW.deployment_rollout_id
       AND rollout.status='ROLLBACK_PENDING'
  ) THEN
    RAISE EXCEPTION 'ROLLBACK_VERIFICATION_AUTHORITY_INVALID' USING ERRCODE='23970';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_rollback_verification_authority_fence
BEFORE INSERT ON release_rollback_verification_receipts
FOR EACH ROW EXECUTE FUNCTION delivery_guard_rollback_verification();

ALTER TABLE private_command_dispatches
  DROP CONSTRAINT private_command_dispatches_command_kind_check,
  ADD CONSTRAINT private_command_dispatches_command_kind_check CHECK (
    command_kind IN ('WORKSPACE_TOOL_INVOKE','EXPLORATORY_SANDBOX_RUN','ADJUDICATE_PATCH',
      'QUALIFY_CODE_CHANGE','CREATE_PR','SYNC_PR','MERGE_PR','START_GITHUB_LINK',
      'CONSUME_GITHUB_CALLBACK','REVOKE_GITHUB_LINK','OBSERVE_RELEASE_TARGET',
      'OBSERVE_RELEASE_BASELINE','START_ROLLOUT','PREPARE_CANARY','PROMOTE_CANARY',
      'FINALIZE_ROLLOUT','REGISTER_VERIFICATION_FAILURE','ROLLBACK_RELEASE',
      'VERIFY_RELEASE_EFFECT','VERIFY_ROLLBACK_EFFECT','FINALIZE_ROLLBACK'));

ALTER TABLE release_rollback_verification_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_rollback_verification_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON release_rollback_verification_receipts
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON release_rollback_verification_receipts FROM PUBLIC;

COMMIT;
