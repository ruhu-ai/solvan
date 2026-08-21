-- Target migration: signed release-candidate and exact Cloud Run target authority.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

ALTER TABLE release_candidates
  ADD COLUMN build_invocation_hash text NOT NULL
    CHECK (build_invocation_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN provenance_ref text NOT NULL CHECK (provenance_ref ~ '^gs://');

CREATE TABLE release_signer_keys (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rsk_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  signer_identity text NOT NULL, key_version text NOT NULL,
  public_verification_ref text NOT NULL CHECK (
    public_verification_ref ~ '^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[1-9][0-9]*$'),
  signer_policy_hash text NOT NULL CHECK (signer_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  activated_at timestamptz NOT NULL, revoked_at timestamptz, revoked_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,signer_identity,key_version),
  CHECK ((status='ACTIVE' AND revoked_at IS NULL AND revoked_reason IS NULL)
      OR (status='REVOKED' AND revoked_at IS NOT NULL AND length(revoked_reason)>=8))
);
CREATE UNIQUE INDEX delivery_one_active_release_signer
  ON release_signer_keys(organization_id,project_id,environment_id)
  WHERE status='ACTIVE';

CREATE FUNCTION delivery_guard_release_signer_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'release signer key cannot be deleted';
  END IF;
  IF TG_OP='UPDATE' AND (
      OLD.status<>'ACTIVE' OR NEW.status<>'REVOKED'
      OR to_jsonb(OLD)-'status'-'revoked_at'-'revoked_reason'
         IS DISTINCT FROM to_jsonb(NEW)-'status'-'revoked_at'-'revoked_reason') THEN
    RAISE EXCEPTION 'release signer key material is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_release_signer_key_guard
BEFORE UPDATE OR DELETE ON release_signer_keys
FOR EACH ROW EXECUTE FUNCTION delivery_guard_release_signer_key();
CREATE TRIGGER delivery_release_signer_key_no_truncate
BEFORE TRUNCATE ON release_signer_keys
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

ALTER TABLE release_candidates
  ADD CONSTRAINT release_candidate_signer_key_fk
  FOREIGN KEY (organization_id,project_id,environment_id,signer_identity,signer_key_version)
  REFERENCES release_signer_keys(
    organization_id,project_id,environment_id,signer_identity,key_version);

CREATE FUNCTION delivery_guard_release_candidate_authority() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM code_change_requests request
      JOIN code_change_github_observations observation
        ON observation.organization_id=request.organization_id
       AND observation.project_id=request.project_id
       AND observation.environment_id=request.environment_id
       AND observation.code_change_request_id=request.id
       AND observation.observation_kind='MERGED'
       AND observation.merge_commit_sha=NEW.merged_commit_sha
       AND observation.head_tree_hash=NEW.source_tree_hash
      JOIN release_signer_keys signer
        ON signer.organization_id=request.organization_id
       AND signer.project_id=request.project_id
       AND signer.environment_id=request.environment_id
       AND signer.signer_identity=NEW.signer_identity
       AND signer.key_version=NEW.signer_key_version
       AND signer.status='ACTIVE'
     WHERE request.organization_id=NEW.organization_id
       AND request.project_id=NEW.project_id
       AND request.environment_id=NEW.environment_id
       AND request.id=NEW.code_change_request_id
       AND request.repository_binding_id=NEW.repository_binding_id
       AND request.state='MERGED'
       AND request.proposed_tree_hash=NEW.source_tree_hash
  ) THEN
    RAISE EXCEPTION 'RELEASE_CANDIDATE_LINEAGE_OR_SIGNER_INVALID' USING ERRCODE='23976';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_release_candidate_authority_fence
BEFORE INSERT ON release_candidates
FOR EACH ROW EXECUTE FUNCTION delivery_guard_release_candidate_authority();

CREATE TABLE release_target_profiles (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rtp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  target_key text NOT NULL, provider_kind text NOT NULL
    CHECK (provider_kind='GCP_CLOUD_RUN_V2'),
  service_resource_name text NOT NULL CHECK (
    service_resource_name ~ '^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/services/[a-z][a-z0-9-]{0,61}[a-z0-9]$'),
  external_project_id text NOT NULL CHECK (
    external_project_id ~ '^[a-z][a-z0-9-]{4,61}[a-z0-9]$'),
  location text NOT NULL CHECK (location ~ '^[a-z]+-[a-z]+[0-9]$'),
  service_name text NOT NULL CHECK (service_name ~ '^[a-z][a-z0-9-]{0,61}[a-z0-9]$'),
  expected_target_epoch bigint NOT NULL CHECK (expected_target_epoch>0),
  runtime_service_account text NOT NULL CHECK (
    runtime_service_account ~ '^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,61}[a-z0-9][.]iam[.]gserviceaccount[.]com$'),
  deployment_manifest_profile_ref text NOT NULL CHECK (deployment_manifest_profile_ref ~ '^gs://'),
  deployment_manifest_profile_hash text NOT NULL
    CHECK (deployment_manifest_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  rollout_policy_ref text NOT NULL CHECK (rollout_policy_ref ~ '^gs://'),
  rollout_policy_hash text NOT NULL CHECK (rollout_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  canary_percentages smallint[] NOT NULL,
  observation_windows_seconds integer[] NOT NULL,
  rollout_deadline_seconds integer NOT NULL CHECK (rollout_deadline_seconds BETWEEN 60 AND 86400),
  maximum_concurrent_rollouts integer NOT NULL CHECK (maximum_concurrent_rollouts=1),
  verification_profile_id text NOT NULL, verification_profile_version text NOT NULL,
  verification_profile_ref text NOT NULL CHECK (verification_profile_ref ~ '^gs://'),
  verification_profile_hash text NOT NULL CHECK (verification_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  profile_hash text NOT NULL CHECK (profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  approved_by_principal text NOT NULL, approved_at timestamptz NOT NULL,
  revoked_at timestamptz, revoked_reason text, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,target_key,expected_target_epoch),
  UNIQUE (organization_id,project_id,environment_id,service_resource_name,expected_target_epoch),
  CHECK (service_resource_name=('projects/'||external_project_id||'/locations/'||location||'/services/'||service_name)),
  CHECK (cardinality(canary_percentages)=cardinality(observation_windows_seconds)),
  CHECK (cardinality(canary_percentages) BETWEEN 2 AND 10),
  CHECK (canary_percentages[1] BETWEEN 1 AND 99
    AND canary_percentages[cardinality(canary_percentages)]=100),
  CHECK (0 < ALL(canary_percentages) AND 100 >= ALL(canary_percentages)),
  CHECK (0 < ALL(observation_windows_seconds)),
  CHECK ((status='ACTIVE' AND revoked_at IS NULL AND revoked_reason IS NULL)
      OR (status='REVOKED' AND revoked_at IS NOT NULL AND length(revoked_reason)>=8))
);

CREATE FUNCTION delivery_guard_release_target_profile() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'release target profile cannot be deleted';
  END IF;
  IF TG_OP='UPDATE' AND (
      OLD.status<>'ACTIVE' OR NEW.status<>'REVOKED'
      OR to_jsonb(OLD)-'status'-'revoked_at'-'revoked_reason'
         IS DISTINCT FROM to_jsonb(NEW)-'status'-'revoked_at'-'revoked_reason') THEN
    RAISE EXCEPTION 'release target profile material is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_release_target_profile_guard
BEFORE UPDATE OR DELETE ON release_target_profiles
FOR EACH ROW EXECUTE FUNCTION delivery_guard_release_target_profile();
CREATE TRIGGER delivery_release_target_profile_no_truncate
BEFORE TRUNCATE ON release_target_profiles
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

ALTER TABLE deployment_rollouts
  ADD COLUMN release_target_profile_id text NOT NULL,
  ADD COLUMN release_target_profile_hash text NOT NULL
    CHECK (release_target_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN predeploy_assignment_hash text NOT NULL
    CHECK (predeploy_assignment_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN rollback_assignment_hash text NOT NULL
    CHECK (rollback_assignment_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT deployment_rollout_target_profile_fk
  FOREIGN KEY (organization_id,project_id,environment_id,release_target_profile_id)
  REFERENCES release_target_profiles(organization_id,project_id,environment_id,id),
  ADD CONSTRAINT deployment_rollout_assignment_hash_ck
    CHECK (predeploy_assignment_hash=rollback_assignment_hash);

CREATE FUNCTION delivery_guard_rollout_target_profile() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM release_target_profiles profile
     WHERE profile.organization_id=NEW.organization_id
       AND profile.project_id=NEW.project_id
       AND profile.environment_id=NEW.environment_id
       AND profile.id=NEW.release_target_profile_id
       AND profile.status='ACTIVE'
       AND profile.profile_hash=NEW.release_target_profile_hash
       AND profile.target_key=NEW.target_key
       AND profile.provider_kind=NEW.target_provider
       AND profile.expected_target_epoch=NEW.expected_target_epoch
       AND profile.rollout_policy_hash=NEW.rollout_policy_hash
       AND profile.verification_profile_id=NEW.verification_profile_id
       AND profile.verification_profile_version=NEW.verification_profile_version
       AND profile.verification_profile_hash=NEW.verification_profile_hash
  ) THEN
    RAISE EXCEPTION 'RELEASE_TARGET_PROFILE_INVALID' USING ERRCODE='23975';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_rollout_target_profile_fence
BEFORE INSERT OR UPDATE ON deployment_rollouts
FOR EACH ROW EXECUTE FUNCTION delivery_guard_rollout_target_profile();

ALTER TABLE release_signer_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_signer_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON release_signer_keys
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
ALTER TABLE release_target_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_target_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON release_target_profiles
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON release_signer_keys,release_target_profiles FROM PUBLIC;

COMMIT;
