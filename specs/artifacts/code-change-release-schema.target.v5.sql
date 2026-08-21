-- Target migration: governed source for Code Change Request policy material.

BEGIN;

SET search_path TO solvan_delivery, solvan, public;

CREATE TABLE code_delivery_profiles (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^cdp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  profile_version integer NOT NULL CHECK (profile_version > 0),
  maximum_request_lifetime_minutes integer NOT NULL
    CHECK (maximum_request_lifetime_minutes BETWEEN 10 AND 1440),
  allowed_paths_json jsonb NOT NULL,
  allowed_paths_hash text NOT NULL CHECK (allowed_paths_hash ~ '^sha256:[0-9a-f]{64}$'),
  required_checks_policy_ref text NOT NULL CHECK (required_checks_policy_ref ~ '^gs://'),
  required_checks_policy_hash text NOT NULL CHECK (required_checks_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  required_check_definition_paths_json jsonb NOT NULL,
  required_check_definition_paths_hash text NOT NULL CHECK (required_check_definition_paths_hash ~ '^sha256:[0-9a-f]{64}$'),
  reviewer_policy_ref text NOT NULL CHECK (reviewer_policy_ref ~ '^gs://'),
  reviewer_policy_hash text NOT NULL CHECK (reviewer_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  pr_creation_policy_ref text NOT NULL CHECK (pr_creation_policy_ref ~ '^gs://'),
  pr_creation_policy_hash text NOT NULL CHECK (pr_creation_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  merge_policy_ref text NOT NULL CHECK (merge_policy_ref ~ '^gs://'),
  merge_policy_hash text NOT NULL CHECK (merge_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  deployment_policy_ref text NOT NULL CHECK (deployment_policy_ref ~ '^gs://'),
  deployment_policy_hash text NOT NULL CHECK (deployment_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  profile_hash text NOT NULL CHECK (profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  approval_ref text NOT NULL CHECK (approval_ref ~ '^gs://'),
  approval_hash text NOT NULL CHECK (approval_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  activated_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,repository_binding_id,profile_version),
  UNIQUE (organization_id,project_id,environment_id,repository_binding_id,profile_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id),
  CHECK (jsonb_typeof(allowed_paths_json)='array' AND jsonb_array_length(allowed_paths_json)>0),
  CHECK (jsonb_typeof(required_check_definition_paths_json)='array'
         AND jsonb_array_length(required_check_definition_paths_json)>0),
  CHECK ((status='ACTIVE' AND revoked_at IS NULL) OR (status='REVOKED' AND revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX code_delivery_one_active_profile
  ON code_delivery_profiles (organization_id,project_id,environment_id,repository_binding_id)
  WHERE status='ACTIVE';

CREATE OR REPLACE FUNCTION delivery_guard_code_delivery_profile()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'code delivery profiles are append-only';
  END IF;
  IF OLD.status <> 'ACTIVE' OR NEW.status <> 'REVOKED' OR NEW.revoked_at IS NULL
     OR to_jsonb(OLD)-'status'-'revoked_at' IS DISTINCT FROM
        to_jsonb(NEW)-'status'-'revoked_at' THEN
    RAISE EXCEPTION 'code delivery profile material is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_code_delivery_profile_guard
BEFORE UPDATE OR DELETE ON code_delivery_profiles
FOR EACH ROW EXECUTE FUNCTION delivery_guard_code_delivery_profile();

ALTER TABLE code_delivery_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_delivery_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON code_delivery_profiles
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON code_delivery_profiles FROM PUBLIC;

COMMIT;
