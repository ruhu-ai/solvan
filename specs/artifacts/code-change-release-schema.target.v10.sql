-- Target migration: durable Cloud Run target observations and deployment-decision binding.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

CREATE TABLE release_target_observations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rto_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL, release_candidate_id text NOT NULL,
  release_target_profile_id text NOT NULL,
  target_key text NOT NULL, target_version text NOT NULL,
  target_epoch bigint NOT NULL CHECK (target_epoch>0),
  service_generation bigint NOT NULL CHECK (service_generation>0),
  service_etag_hash text NOT NULL CHECK (service_etag_hash ~ '^sha256:[0-9a-f]{64}$'),
  runtime_service_account text NOT NULL,
  current_release_candidate_id text NOT NULL,
  current_revision text NOT NULL,
  assignment_ref text NOT NULL CHECK (assignment_ref ~ '^gs://'),
  assignment_hash text NOT NULL CHECK (assignment_hash ~ '^sha256:[0-9a-f]{64}$'),
  observation_ref text NOT NULL CHECK (observation_ref ~ '^gs://'),
  observation_hash text NOT NULL CHECK (observation_hash ~ '^sha256:[0-9a-f]{64}$'),
  observer_identity text NOT NULL, observer_service_revision text NOT NULL,
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,observation_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,release_candidate_id)
    REFERENCES release_candidates(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,current_release_candidate_id)
    REFERENCES release_candidates(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,release_target_profile_id)
    REFERENCES release_target_profiles(organization_id,project_id,environment_id,id)
);

CREATE TRIGGER delivery_release_target_observation_append_only
BEFORE UPDATE OR DELETE ON release_target_observations
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_release_target_observation_no_truncate
BEFORE TRUNCATE ON release_target_observations
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

ALTER TABLE code_change_decisions
  ADD COLUMN release_candidate_id text,
  ADD COLUMN release_target_profile_id text,
  ADD COLUMN release_target_observation_hash text
    CHECK (release_target_observation_hash IS NULL
      OR release_target_observation_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT code_change_decision_release_candidate_fk
    FOREIGN KEY (organization_id,project_id,environment_id,release_candidate_id)
    REFERENCES release_candidates(organization_id,project_id,environment_id,id),
  ADD CONSTRAINT code_change_decision_release_target_profile_fk
    FOREIGN KEY (organization_id,project_id,environment_id,release_target_profile_id)
    REFERENCES release_target_profiles(organization_id,project_id,environment_id,id),
  ADD CONSTRAINT code_change_decision_deployment_shape_ck CHECK (
    (stage='DEPLOYMENT' AND decision='APPROVED'
     AND release_candidate_id IS NOT NULL AND release_target_profile_id IS NOT NULL
     AND release_target_observation_hash IS NOT NULL)
    OR NOT (stage='DEPLOYMENT' AND decision='APPROVED'));

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
       AND profile.id=NEW.release_target_profile_id
       AND profile.status='ACTIVE'
       AND profile.target_key=observation.target_key
       AND profile.expected_target_epoch=observation.target_epoch
       AND profile.runtime_service_account=observation.runtime_service_account
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

ALTER TABLE release_target_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_target_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON release_target_observations
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON release_target_observations FROM PUBLIC;

COMMIT;
