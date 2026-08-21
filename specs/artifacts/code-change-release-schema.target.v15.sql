-- Target migration: verifier-owned health baseline bound into deployment approval.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

CREATE TABLE release_health_baselines (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rhb_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL, release_candidate_id text NOT NULL,
  release_target_profile_id text NOT NULL, target_observation_hash text NOT NULL
    CHECK (target_observation_hash ~ '^sha256:[0-9a-f]{64}$'),
  verification_profile_hash text NOT NULL
    CHECK (verification_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  target_version text NOT NULL, target_assignment_hash text NOT NULL
    CHECK (target_assignment_hash ~ '^sha256:[0-9a-f]{64}$'),
  window_start timestamptz NOT NULL, window_end timestamptz NOT NULL,
  signal_results_hash text NOT NULL CHECK (signal_results_hash ~ '^sha256:[0-9a-f]{64}$'),
  baseline_ref text NOT NULL CHECK (baseline_ref ~ '^gs://'),
  baseline_hash text NOT NULL CHECK (baseline_hash ~ '^sha256:[0-9a-f]{64}$'),
  verifier_identity text NOT NULL, verifier_key_version text NOT NULL,
  signature_ref text NOT NULL CHECK (signature_ref ~ '^gs://'),
  signature_hash text NOT NULL CHECK (signature_hash ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,
          target_observation_hash,verification_profile_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,release_candidate_id)
    REFERENCES release_candidates(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,release_target_profile_id)
    REFERENCES release_target_profiles(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,verifier_identity,
               verifier_key_version)
    REFERENCES release_verifier_keys(
      organization_id,project_id,environment_id,verifier_identity,key_version),
  CHECK (window_start<window_end AND observed_at>=window_end)
);
CREATE TRIGGER delivery_release_health_baseline_append_only
BEFORE UPDATE OR DELETE ON release_health_baselines
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_release_health_baseline_no_truncate
BEFORE TRUNCATE ON release_health_baselines
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

CREATE FUNCTION delivery_guard_release_health_baseline() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM code_change_requests request
      JOIN release_candidates candidate
        ON candidate.organization_id=request.organization_id
       AND candidate.project_id=request.project_id
       AND candidate.environment_id=request.environment_id
       AND candidate.code_change_request_id=request.id
       AND candidate.id=NEW.release_candidate_id
      JOIN release_target_observations observation
        ON observation.organization_id=request.organization_id
       AND observation.project_id=request.project_id
       AND observation.environment_id=request.environment_id
       AND observation.code_change_request_id=request.id
       AND observation.release_candidate_id=candidate.id
       AND observation.release_target_profile_id=NEW.release_target_profile_id
       AND observation.observation_hash=NEW.target_observation_hash
       AND observation.target_version=NEW.target_version
       AND observation.assignment_hash=NEW.target_assignment_hash
      JOIN release_target_profiles profile
        ON profile.organization_id=observation.organization_id
       AND profile.project_id=observation.project_id
       AND profile.environment_id=observation.environment_id
       AND profile.id=observation.release_target_profile_id
       AND profile.status='ACTIVE'
       AND profile.verification_profile_hash=NEW.verification_profile_hash
       AND profile.verifier_identity=NEW.verifier_identity
       AND profile.verifier_key_version=NEW.verifier_key_version
      JOIN release_verifier_keys verifier_key
        ON verifier_key.organization_id=profile.organization_id
       AND verifier_key.project_id=profile.project_id
       AND verifier_key.environment_id=profile.environment_id
       AND verifier_key.verifier_identity=profile.verifier_identity
       AND verifier_key.key_version=profile.verifier_key_version
       AND verifier_key.status='ACTIVE'
     WHERE request.organization_id=NEW.organization_id
       AND request.project_id=NEW.project_id
       AND request.environment_id=NEW.environment_id
       AND request.id=NEW.code_change_request_id
       AND request.state='DEPLOYMENT_APPROVAL_PENDING'
  ) THEN
    RAISE EXCEPTION 'RELEASE_HEALTH_BASELINE_AUTHORITY_INVALID' USING ERRCODE='23972';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_release_health_baseline_authority_fence
BEFORE INSERT ON release_health_baselines
FOR EACH ROW EXECUTE FUNCTION delivery_guard_release_health_baseline();

ALTER TABLE code_change_decisions
  ADD COLUMN release_health_baseline_id text,
  ADD COLUMN release_health_baseline_hash text CHECK (
    release_health_baseline_hash IS NULL
    OR release_health_baseline_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT code_change_decision_health_baseline_fk
    FOREIGN KEY (organization_id,project_id,environment_id,release_health_baseline_id)
    REFERENCES release_health_baselines(organization_id,project_id,environment_id,id),
  DROP CONSTRAINT code_change_decision_deployment_shape_ck,
  ADD CONSTRAINT code_change_decision_deployment_shape_ck CHECK (
    (stage='DEPLOYMENT' AND decision='APPROVED'
     AND release_candidate_id IS NOT NULL AND release_target_profile_id IS NOT NULL
     AND release_target_observation_hash IS NOT NULL
     AND release_health_baseline_id IS NOT NULL
     AND release_health_baseline_hash IS NOT NULL)
    OR NOT (stage='DEPLOYMENT' AND decision='APPROVED'));

DROP TRIGGER delivery_deployment_decision_material_fence ON code_change_decisions;
DROP FUNCTION delivery_guard_deployment_decision_material();
CREATE FUNCTION delivery_guard_deployment_decision_material() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.stage='DEPLOYMENT' AND NEW.decision='APPROVED' AND NOT EXISTS (
    SELECT 1
      FROM code_change_requests request
      JOIN release_candidates candidate
        ON candidate.organization_id=request.organization_id
       AND candidate.project_id=request.project_id
       AND candidate.environment_id=request.environment_id
       AND candidate.code_change_request_id=request.id
       AND candidate.id=NEW.release_candidate_id
      JOIN release_target_observations observation
        ON observation.organization_id=request.organization_id
       AND observation.project_id=request.project_id
       AND observation.environment_id=request.environment_id
       AND observation.code_change_request_id=request.id
       AND observation.release_candidate_id=candidate.id
       AND observation.release_target_profile_id=NEW.release_target_profile_id
       AND observation.observation_hash=NEW.release_target_observation_hash
       AND observation.observed_at>NEW.decided_at-interval '5 minutes'
       AND NOT EXISTS (
         SELECT 1 FROM release_target_observations newer
          WHERE newer.organization_id=observation.organization_id
            AND newer.project_id=observation.project_id
            AND newer.environment_id=observation.environment_id
            AND newer.code_change_request_id=observation.code_change_request_id
            AND newer.observed_at>observation.observed_at)
      JOIN release_target_profiles profile
        ON profile.organization_id=observation.organization_id
       AND profile.project_id=observation.project_id
       AND profile.environment_id=observation.environment_id
       AND profile.id=observation.release_target_profile_id
       AND profile.status='ACTIVE'
       AND profile.target_key=observation.target_key
       AND profile.expected_target_epoch=observation.target_epoch
       AND profile.runtime_service_account=observation.runtime_service_account
      JOIN release_health_baselines baseline
        ON baseline.organization_id=request.organization_id
       AND baseline.project_id=request.project_id
       AND baseline.environment_id=request.environment_id
       AND baseline.id=NEW.release_health_baseline_id
       AND baseline.baseline_hash=NEW.release_health_baseline_hash
       AND baseline.code_change_request_id=request.id
       AND baseline.release_candidate_id=candidate.id
       AND baseline.release_target_profile_id=profile.id
       AND baseline.target_observation_hash=observation.observation_hash
       AND baseline.verification_profile_hash=profile.verification_profile_hash
       AND baseline.observed_at>NEW.decided_at-interval '15 minutes'
     WHERE request.organization_id=NEW.organization_id
       AND request.project_id=NEW.project_id
       AND request.environment_id=NEW.environment_id
       AND request.id=NEW.code_change_request_id
       AND request.state='DEPLOYMENT_APPROVAL_PENDING'
  ) THEN
    RAISE EXCEPTION 'DEPLOYMENT_DECISION_TARGET_MATERIAL_INVALID' USING ERRCODE='23974';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_deployment_decision_material_fence
BEFORE INSERT ON code_change_decisions
FOR EACH ROW EXECUTE FUNCTION delivery_guard_deployment_decision_material();

ALTER TABLE deployment_rollouts
  ADD COLUMN release_health_baseline_id text NOT NULL,
  ADD COLUMN release_health_baseline_ref text NOT NULL CHECK (
    release_health_baseline_ref ~ '^gs://'),
  ADD COLUMN release_health_baseline_hash text NOT NULL CHECK (
    release_health_baseline_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT deployment_rollout_health_baseline_fk
    FOREIGN KEY (organization_id,project_id,environment_id,release_health_baseline_id)
    REFERENCES release_health_baselines(organization_id,project_id,environment_id,id);

ALTER TABLE release_verification_receipts
  ADD COLUMN release_health_baseline_ref text NOT NULL CHECK (
    release_health_baseline_ref ~ '^gs://'),
  ADD COLUMN release_health_baseline_hash text NOT NULL CHECK (
    release_health_baseline_hash ~ '^sha256:[0-9a-f]{64}$');

ALTER TABLE private_command_dispatches
  DROP CONSTRAINT private_command_dispatches_command_kind_check,
  ADD CONSTRAINT private_command_dispatches_command_kind_check CHECK (
    command_kind IN ('WORKSPACE_TOOL_INVOKE','EXPLORATORY_SANDBOX_RUN','ADJUDICATE_PATCH',
      'QUALIFY_CODE_CHANGE','CREATE_PR','SYNC_PR','MERGE_PR','START_GITHUB_LINK',
      'CONSUME_GITHUB_CALLBACK','REVOKE_GITHUB_LINK','OBSERVE_RELEASE_TARGET',
      'OBSERVE_RELEASE_BASELINE','START_ROLLOUT','PREPARE_CANARY','PROMOTE_CANARY',
      'ROLLBACK_RELEASE','VERIFY_RELEASE_EFFECT'));

ALTER TABLE release_health_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_health_baselines FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON release_health_baselines
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON release_health_baselines FROM PUBLIC;

COMMIT;
