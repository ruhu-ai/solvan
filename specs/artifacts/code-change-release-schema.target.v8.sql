-- Target migration: immutable GitHub observation authority for governed merge.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

ALTER TABLE code_change_operations
  DROP CONSTRAINT code_change_operations_operation_kind_check,
  ADD CONSTRAINT code_change_operations_operation_kind_check CHECK (
    operation_kind IN ('CREATE_BRANCH','CREATE_PR','MARK_PR_READY','SYNC_PR','MERGE_PR'));

CREATE TABLE code_change_github_observations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^cgo_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL,
  sequence_no integer NOT NULL CHECK (sequence_no>0),
  observation_kind text NOT NULL CHECK (
    observation_kind IN ('PR_CREATED','PR_SYNC','MERGE_REVALIDATION','MERGED')),
  pull_request_number integer NOT NULL CHECK (pull_request_number>0),
  pull_request_url text NOT NULL CHECK (pull_request_url ~ '^https://'),
  branch_name text NOT NULL CHECK (branch_name ~ '^solvan/ccr/ccr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  base_commit_sha text NOT NULL CHECK (base_commit_sha ~ '^[0-9a-f]{40}$'),
  head_commit_sha text NOT NULL CHECK (head_commit_sha ~ '^[0-9a-f]{40}$'),
  merge_commit_sha text CHECK (merge_commit_sha IS NULL OR merge_commit_sha ~ '^[0-9a-f]{40}$'),
  head_tree_hash text NOT NULL CHECK (head_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  diff_hash text NOT NULL CHECK (diff_hash ~ '^sha256:[0-9a-f]{64}$'),
  required_check_state text NOT NULL CHECK (
    required_check_state IN ('PENDING','PASSING','FAILING')),
  required_checks_ref text NOT NULL CHECK (required_checks_ref ~ '^gs://'),
  required_checks_hash text NOT NULL CHECK (required_checks_hash ~ '^sha256:[0-9a-f]{64}$'),
  branch_rule_ref text NOT NULL CHECK (branch_rule_ref ~ '^gs://'),
  branch_rule_hash text NOT NULL CHECK (branch_rule_hash ~ '^sha256:[0-9a-f]{64}$'),
  review_state text NOT NULL CHECK (
    review_state IN ('PENDING','APPROVED','CHANGES_REQUESTED')),
  review_state_ref text NOT NULL CHECK (review_state_ref ~ '^gs://'),
  review_state_hash text NOT NULL CHECK (review_state_hash ~ '^sha256:[0-9a-f]{64}$'),
  approved_account_node_ids text[] NOT NULL,
  required_check_definitions_ref text NOT NULL CHECK (required_check_definitions_ref ~ '^gs://'),
  required_check_definitions_hash text NOT NULL CHECK (required_check_definitions_hash ~ '^sha256:[0-9a-f]{64}$'),
  repository_policy_hash text NOT NULL CHECK (repository_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_service_revision text NOT NULL,
  observation_ref text NOT NULL CHECK (observation_ref ~ '^gs://'),
  observation_hash text NOT NULL CHECK (observation_hash ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,sequence_no),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,observation_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  CHECK (cardinality(approved_account_node_ids)<=10),
  CHECK ((observation_kind='MERGED')=(merge_commit_sha IS NOT NULL))
);

CREATE TRIGGER delivery_code_change_github_observation_append_only
BEFORE UPDATE OR DELETE ON code_change_github_observations
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_code_change_github_observation_no_truncate
BEFORE TRUNCATE ON code_change_github_observations
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

ALTER TABLE code_change_decisions
  ADD CONSTRAINT code_change_decision_reviewer_binding_fk
  FOREIGN KEY (organization_id,project_id,environment_id,github_reviewer_binding_id)
  REFERENCES github_reviewer_bindings(organization_id,project_id,environment_id,id);

CREATE FUNCTION delivery_guard_merge_decision_material() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.stage='MERGE' AND NEW.decision='APPROVED' AND NOT EXISTS (
    SELECT 1
      FROM code_change_requests request
      JOIN github_reviewer_bindings binding
        ON binding.organization_id=request.organization_id
       AND binding.project_id=request.project_id
       AND binding.environment_id=request.environment_id
       AND binding.id=NEW.github_reviewer_binding_id
       AND binding.repository_binding_id=request.repository_binding_id
       AND binding.solvan_principal=NEW.principal
       AND binding.reviewer_policy_hash=request.reviewer_policy_hash
       AND binding.status='ACTIVE' AND binding.expires_at>NEW.decided_at
      JOIN code_change_github_observations observation
        ON observation.organization_id=request.organization_id
       AND observation.project_id=request.project_id
       AND observation.environment_id=request.environment_id
       AND observation.code_change_request_id=request.id
       AND observation.required_check_state='PASSING'
       AND observation.review_state='APPROVED'
       AND observation.review_state_hash=NEW.github_review_state_hash
       AND binding.github_account_node_id=ANY(observation.approved_account_node_ids)
       AND NOT EXISTS (
         SELECT 1 FROM code_change_github_observations newer
          WHERE newer.organization_id=observation.organization_id
            AND newer.project_id=observation.project_id
            AND newer.environment_id=observation.environment_id
            AND newer.code_change_request_id=observation.code_change_request_id
            AND newer.sequence_no>observation.sequence_no)
     WHERE request.organization_id=NEW.organization_id
       AND request.project_id=NEW.project_id
       AND request.environment_id=NEW.environment_id
       AND request.id=NEW.code_change_request_id
  ) THEN
    RAISE EXCEPTION 'MERGE_DECISION_REVIEWER_MATERIAL_INVALID' USING ERRCODE='23977';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_merge_decision_material_fence
BEFORE INSERT ON code_change_decisions
FOR EACH ROW EXECUTE FUNCTION delivery_guard_merge_decision_material();

ALTER TABLE code_change_github_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_change_github_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON code_change_github_observations
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON code_change_github_observations FROM PUBLIC;

COMMIT;
