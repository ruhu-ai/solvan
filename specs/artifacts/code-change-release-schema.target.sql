-- Solvan governed Code Change, Release, and Code Repair Workspace: TARGET DDL.
--
-- Apply only after the release schema (schema.sql). This is deliberately a
-- separate schema and does not make an unqualified GitHub or deployment path
-- live. Every effect still requires the services and acceptance evidence in
-- specifications 04, 07, and 23.

BEGIN;
CREATE SCHEMA IF NOT EXISTS solvan_delivery;
SET search_path TO solvan_delivery, solvan, public;

CREATE FUNCTION delivery_reject_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'delivery history is append-only' USING ERRCODE = '23981';
END $$;

CREATE TABLE repair_plan_command_definitions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rcd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  command_hash text NOT NULL CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
  command_kind text NOT NULL CHECK (command_kind IN ('REPRODUCTION','REGRESSION')),
  argv_json jsonb NOT NULL, working_directory text NOT NULL,
  declared_inputs_hash text NOT NULL CHECK (declared_inputs_hash ~ '^sha256:[0-9a-f]{64}$'),
  declared_outputs_hash text NOT NULL CHECK (declared_outputs_hash ~ '^sha256:[0-9a-f]{64}$'),
  timeout_ms integer NOT NULL CHECK (timeout_ms BETWEEN 1 AND 120000),
  cpu_millis integer NOT NULL CHECK (cpu_millis BETWEEN 1 AND 1000),
  memory_mib integer NOT NULL CHECK (memory_mib BETWEEN 16 AND 1024),
  output_byte_limit integer NOT NULL CHECK (output_byte_limit BETWEEN 1 AND 131072),
  network_mode text NOT NULL CHECK (network_mode='NONE'),
  catalog_hash text NOT NULL CHECK (catalog_hash ~ '^sha256:[0-9a-f]{64}$'),
  lifecycle text NOT NULL CHECK (lifecycle IN ('APPROVED','RETIRED','REVOKED')),
  approved_ref text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,repository_binding_id,command_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id),
  CHECK (jsonb_typeof(argv_json)='array' AND jsonb_array_length(argv_json)>0)
);

CREATE TABLE repair_plan_command_catalogs (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rcc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repair_plan_id text NOT NULL, repair_plan_version integer NOT NULL CHECK (repair_plan_version>0),
  command_ordinal integer NOT NULL CHECK (command_ordinal>0),
  command_definition_id text NOT NULL, command_hash text NOT NULL CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
  base_tree_hash text NOT NULL CHECK (base_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  argv_json jsonb NOT NULL, working_directory text NOT NULL,
  declared_inputs_hash text NOT NULL CHECK (declared_inputs_hash ~ '^sha256:[0-9a-f]{64}$'),
  timeout_ms integer NOT NULL CHECK (timeout_ms BETWEEN 1 AND 120000),
  cpu_millis integer NOT NULL CHECK (cpu_millis BETWEEN 1 AND 1000),
  memory_mib integer NOT NULL CHECK (memory_mib BETWEEN 16 AND 1024),
  output_byte_limit integer NOT NULL CHECK (output_byte_limit BETWEEN 1 AND 131072),
  network_mode text NOT NULL CHECK (network_mode='NONE'),
  status text NOT NULL CHECK (status IN ('RESOLVED','UNRESOLVED','RETIRED')),
  catalog_hash text NOT NULL CHECK (catalog_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,repair_plan_id,repair_plan_version,command_ordinal),
  UNIQUE (organization_id,project_id,environment_id,repair_plan_id,repair_plan_version,command_definition_id),
  FOREIGN KEY (organization_id,project_id,environment_id,command_definition_id)
    REFERENCES repair_plan_command_definitions(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,repair_plan_id)
    REFERENCES solvan.repair_plans(organization_id,project_id,environment_id,id),
  CHECK (jsonb_typeof(argv_json)='array' AND jsonb_array_length(argv_json)>0)
);

CREATE TABLE repair_plan_guidance_selection_sets (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rgs_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repair_plan_id text NOT NULL, repair_plan_version integer NOT NULL CHECK (repair_plan_version>0),
  selection_set_hash text NOT NULL CHECK (selection_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('PENDING_BIND','BOUND','SUPERSEDED')),
  bound_agent_run_id text, superseded_at timestamptz, superseded_reason text,
  created_at timestamptz NOT NULL DEFAULT now(), bound_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,id,selection_set_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,repair_plan_id)
    REFERENCES solvan.repair_plans(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,bound_agent_run_id)
    REFERENCES solvan.agent_runs(organization_id,project_id,environment_id,id),
  CHECK ((status='PENDING_BIND' AND bound_agent_run_id IS NULL AND bound_at IS NULL
          AND superseded_at IS NULL AND superseded_reason IS NULL) OR
         (status='BOUND' AND bound_agent_run_id IS NOT NULL AND bound_at IS NOT NULL
          AND superseded_at IS NULL AND superseded_reason IS NULL) OR
         (status='SUPERSEDED' AND superseded_at IS NOT NULL AND superseded_reason IS NOT NULL
          AND ((bound_agent_run_id IS NULL AND bound_at IS NULL) OR
               (bound_agent_run_id IS NOT NULL AND bound_at IS NOT NULL))))
);
CREATE UNIQUE INDEX repair_guidance_one_active_set ON repair_plan_guidance_selection_sets
  (organization_id,project_id,environment_id,repair_plan_id,repair_plan_version)
  WHERE status IN ('PENDING_BIND','BOUND');

CREATE TABLE repair_plan_guidance_selections (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rgi_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  selection_set_id text NOT NULL, selection_ordinal integer NOT NULL CHECK (selection_ordinal>0),
  guidance_key text NOT NULL, guidance_version text NOT NULL,
  guidance_content_hash text NOT NULL CHECK (guidance_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  guidance_revision_hash text NOT NULL CHECK (guidance_revision_hash ~ '^sha256:[0-9a-f]{64}$'),
  profile_material_hash text NOT NULL CHECK (profile_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  selection_reason text NOT NULL, selected_by_kind text NOT NULL CHECK (selected_by_kind IN ('DETERMINISTIC','MODEL_RANKED')),
  selected_by_identity text NOT NULL, selected_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,selection_set_id,selection_ordinal),
  UNIQUE (organization_id,project_id,environment_id,selection_set_id,guidance_key,guidance_version),
  FOREIGN KEY (organization_id,project_id,environment_id,selection_set_id)
    REFERENCES repair_plan_guidance_selection_sets(organization_id,project_id,environment_id,id)
);

CREATE FUNCTION delivery_guard_guidance_set() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'PENDING_BIND' THEN
      RAISE EXCEPTION 'GUIDANCE_SET_MUST_START_PENDING' USING ERRCODE='23987';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'guidance selection set is append-only' USING ERRCODE='23988';
  END IF;
  IF OLD.status NOT IN ('PENDING_BIND','BOUND') OR NEW.repair_plan_id IS DISTINCT FROM OLD.repair_plan_id
     OR NEW.repair_plan_version IS DISTINCT FROM OLD.repair_plan_version
     OR NEW.selection_set_hash IS DISTINCT FROM OLD.selection_set_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'GUIDANCE_SET_HISTORY_MUTATION' USING ERRCODE='23989';
  END IF;
  IF (OLD.status='PENDING_BIND' AND NEW.status='BOUND' AND NEW.bound_agent_run_id IS NOT NULL AND NEW.bound_at IS NOT NULL
      AND NEW.superseded_at IS NULL AND NEW.superseded_reason IS NULL) OR
     (NEW.status='SUPERSEDED' AND NEW.superseded_at IS NOT NULL AND NEW.superseded_reason IS NOT NULL
      AND ((OLD.status='PENDING_BIND' AND NEW.bound_agent_run_id IS NULL AND NEW.bound_at IS NULL) OR
           (OLD.status='BOUND' AND NEW.bound_agent_run_id=OLD.bound_agent_run_id AND NEW.bound_at=OLD.bound_at))) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'GUIDANCE_SET_TRANSITION_ILLEGAL' USING ERRCODE='23990';
END $$;
CREATE TRIGGER delivery_guidance_set_fence BEFORE INSERT OR UPDATE OR DELETE
ON repair_plan_guidance_selection_sets FOR EACH ROW EXECUTE FUNCTION delivery_guard_guidance_set();
CREATE TRIGGER delivery_guidance_selection_append_only BEFORE UPDATE OR DELETE
ON repair_plan_guidance_selections FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();

CREATE TABLE workspace_candidate_generations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^wcg_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repair_plan_id text NOT NULL, repair_plan_version integer NOT NULL CHECK (repair_plan_version>0),
  agent_run_id text NOT NULL, parent_generation_id text, generation_ordinal integer NOT NULL CHECK (generation_ordinal>0),
  base_tree_hash text NOT NULL CHECK (base_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  changed_paths_hash text NOT NULL CHECK (changed_paths_hash ~ '^sha256:[0-9a-f]{64}$'),
  candidate_tree_hash text NOT NULL CHECK (candidate_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  candidate_manifest_ref text NOT NULL, candidate_manifest_hash text NOT NULL CHECK (candidate_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  aggregate_bytes integer NOT NULL CHECK (aggregate_bytes BETWEEN 0 AND 1048576),
  file_count integer NOT NULL CHECK (file_count BETWEEN 0 AND 128),
  input_hash text NOT NULL CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'), created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,agent_run_id,generation_ordinal),
  UNIQUE (organization_id,project_id,environment_id,agent_run_id,candidate_tree_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,repair_plan_id)
    REFERENCES solvan.repair_plans(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,agent_run_id)
    REFERENCES solvan.agent_runs(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,parent_generation_id)
    REFERENCES workspace_candidate_generations(organization_id,project_id,environment_id,id),
  CHECK ((generation_ordinal=1 AND parent_generation_id IS NULL) OR
         (generation_ordinal>1 AND parent_generation_id IS NOT NULL))
);

CREATE TABLE exploratory_sandbox_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^esr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  agent_run_id text NOT NULL, candidate_generation_id text NOT NULL,
  command_catalog_id text NOT NULL, command_hash text NOT NULL CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
  sandbox_image_hash text NOT NULL CHECK (sandbox_image_hash ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'), exit_code integer NOT NULL,
  stdout_ref text NOT NULL, stdout_hash text NOT NULL CHECK (stdout_hash ~ '^sha256:[0-9a-f]{64}$'),
  stderr_ref text NOT NULL, stderr_hash text NOT NULL CHECK (stderr_hash ~ '^sha256:[0-9a-f]{64}$'),
  output_bytes integer NOT NULL CHECK (output_bytes BETWEEN 0 AND 131072),
  trust_class text NOT NULL CHECK (trust_class='EXPERIMENTAL'),
  started_at timestamptz NOT NULL, completed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,agent_run_id,candidate_generation_id,command_hash,request_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,agent_run_id)
    REFERENCES solvan.agent_runs(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,candidate_generation_id)
    REFERENCES workspace_candidate_generations(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,command_catalog_id)
    REFERENCES repair_plan_command_catalogs(organization_id,project_id,environment_id,id),
  CHECK (completed_at>=started_at)
);

CREATE TABLE code_change_requests (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ccr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  reliability_case_id text NOT NULL, patch_artifact_id text NOT NULL,
  patch_digest text NOT NULL CHECK (patch_digest ~ '^sha256:[0-9a-f]{64}$'),
  patch_transform_version text NOT NULL, patch_transform_ref text NOT NULL,
  patch_transform_hash text NOT NULL CHECK (patch_transform_hash ~ '^sha256:[0-9a-f]{64}$'),
  proposed_tree_hash text NOT NULL CHECK (proposed_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'), repository_policy_hash text NOT NULL CHECK (repository_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  default_branch text NOT NULL, base_commit_sha text NOT NULL CHECK (base_commit_sha ~ '^[0-9a-f]{40}$'),
  base_tree_hash text NOT NULL CHECK (base_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  allowed_paths_hash text NOT NULL CHECK (allowed_paths_hash ~ '^sha256:[0-9a-f]{64}$'),
  adjudication_receipt_ref text NOT NULL, adjudication_receipt_hash text NOT NULL CHECK (adjudication_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  required_checks_policy_ref text NOT NULL, required_checks_policy_hash text NOT NULL CHECK (required_checks_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  required_check_definition_paths_hash text NOT NULL CHECK (required_check_definition_paths_hash ~ '^sha256:[0-9a-f]{64}$'),
  base_required_check_definitions_ref text NOT NULL, base_required_check_definitions_hash text NOT NULL CHECK (base_required_check_definitions_hash ~ '^sha256:[0-9a-f]{64}$'),
  reviewer_policy_ref text NOT NULL, reviewer_policy_hash text NOT NULL CHECK (reviewer_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  pr_creation_policy_ref text NOT NULL, pr_creation_policy_hash text NOT NULL CHECK (pr_creation_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  merge_policy_ref text NOT NULL, merge_policy_hash text NOT NULL CHECK (merge_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  deployment_policy_ref text NOT NULL, deployment_policy_hash text NOT NULL CHECK (deployment_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  immutable_request_hash text NOT NULL CHECK (immutable_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('PATCH_VALIDATED','PR_CREATION_APPROVAL_PENDING','PR_REQUESTED','PR_CREATED','CI_PENDING','CI_PASSED','CI_FAILED','GITHUB_REVIEW_PENDING','MERGE_APPROVAL_PENDING','MERGED','RELEASE_CANDIDATE','DEPLOYMENT_APPROVAL_PENDING','CANARY_DEPLOYING','VERIFYING','PROMOTED','VERIFICATION_FAILED','ROLLBACK_APPROVAL_PENDING','ROLLING_BACK','ROLLED_BACK','ROLLBACK_REJECTED','ROLLBACK_EXPIRED','ROLLBACK_AMBIGUOUS','EXPIRED','BLOCKED','ABANDONED')),
  sequence_no integer NOT NULL DEFAULT 0 CHECK (sequence_no>=0), expires_at timestamptz NOT NULL,
  created_by_principal text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,immutable_request_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,reliability_case_id)
    REFERENCES solvan.reliability_cases(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,patch_artifact_id)
    REFERENCES solvan.patch_artifacts(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id)
);

CREATE TABLE code_change_transitions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^cct_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL, sequence_no integer NOT NULL CHECK (sequence_no>0),
  from_state text NOT NULL, to_state text NOT NULL, expected_sequence_no integer NOT NULL CHECK (expected_sequence_no>=0),
  input_hash text NOT NULL CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'), idempotency_key text NOT NULL,
  actor_kind text NOT NULL CHECK (actor_kind IN ('HUMAN','COORDINATOR','GITHUB_PROVIDER','DEPLOYMENT_CONTROLLER','RELEASE_VERIFIER','SYSTEM')),
  actor_identity text NOT NULL, receipt_ref text, receipt_hash text CHECK (receipt_hash IS NULL OR receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  decision_id text, decision_digest text CHECK (decision_digest IS NULL OR decision_digest ~ '^sha256:[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,sequence_no),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,idempotency_key),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  CHECK ((to_state IN ('PR_REQUESTED','MERGED','CANARY_DEPLOYING','ROLLING_BACK')) =
    (decision_id IS NOT NULL AND decision_digest IS NOT NULL))
);

CREATE FUNCTION delivery_transition_allowed(from_value text, to_value text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT (from_value,to_value) IN (
    ('PATCH_VALIDATED','PR_CREATION_APPROVAL_PENDING'),
    ('PR_CREATION_APPROVAL_PENDING','PR_REQUESTED'),
    ('PR_CREATION_APPROVAL_PENDING','EXPIRED'),
    ('PR_REQUESTED','PR_CREATED'), ('PR_REQUESTED','BLOCKED'),
    ('PR_CREATED','CI_PENDING'), ('CI_PENDING','CI_PASSED'),
    ('CI_PENDING','CI_FAILED'), ('CI_FAILED','BLOCKED'),
    ('CI_PASSED','GITHUB_REVIEW_PENDING'),
    ('GITHUB_REVIEW_PENDING','MERGE_APPROVAL_PENDING'),
    ('MERGE_APPROVAL_PENDING','MERGED'), ('MERGE_APPROVAL_PENDING','EXPIRED'),
    ('MERGED','RELEASE_CANDIDATE'),
    ('RELEASE_CANDIDATE','DEPLOYMENT_APPROVAL_PENDING'),
    ('DEPLOYMENT_APPROVAL_PENDING','CANARY_DEPLOYING'),
    ('DEPLOYMENT_APPROVAL_PENDING','EXPIRED'),
    ('CANARY_DEPLOYING','VERIFYING'), ('CANARY_DEPLOYING','BLOCKED'),
    ('VERIFYING','PROMOTED'), ('VERIFYING','VERIFICATION_FAILED'),
    ('VERIFICATION_FAILED','ROLLBACK_APPROVAL_PENDING'),
    ('ROLLBACK_APPROVAL_PENDING','ROLLING_BACK'),
    ('ROLLBACK_APPROVAL_PENDING','ROLLBACK_REJECTED'),
    ('ROLLBACK_APPROVAL_PENDING','ROLLBACK_EXPIRED'),
    ('ROLLBACK_APPROVAL_PENDING','BLOCKED'),
    ('ROLLING_BACK','ROLLED_BACK'), ('ROLLING_BACK','ROLLBACK_AMBIGUOUS'),
    ('BLOCKED','ABANDONED'), ('EXPIRED','BLOCKED'),
    ('ROLLBACK_REJECTED','BLOCKED'), ('ROLLBACK_EXPIRED','BLOCKED'),
    ('ROLLBACK_AMBIGUOUS','BLOCKED')
  )
$$;

CREATE FUNCTION delivery_guard_transition_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE request_state text; request_sequence integer;
BEGIN
  SELECT state,sequence_no INTO request_state,request_sequence
  FROM code_change_requests
  WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
    AND environment_id=NEW.environment_id AND id=NEW.code_change_request_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CODE_CHANGE_REQUEST_NOT_FOUND' USING ERRCODE='23982';
  END IF;
  IF NEW.expected_sequence_no<>request_sequence OR NEW.sequence_no<>request_sequence+1
     OR NEW.from_state<>request_state THEN
    RAISE EXCEPTION 'CODE_CHANGE_TRANSITION_STALE' USING ERRCODE='23983';
  END IF;
  IF NOT delivery_transition_allowed(NEW.from_state,NEW.to_state) THEN
    RAISE EXCEPTION 'CODE_CHANGE_TRANSITION_ILLEGAL' USING ERRCODE='23984';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION delivery_project_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE code_change_requests
  SET state=NEW.to_state, sequence_no=NEW.sequence_no
  WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
    AND environment_id=NEW.environment_id AND id=NEW.code_change_request_id;
  RETURN NEW;
END $$;

CREATE FUNCTION delivery_guard_request_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'code change request cannot be deleted' USING ERRCODE='23991';
  END IF;
  IF pg_trigger_depth() = 1 THEN
    RAISE EXCEPTION 'code change request state is transition projected only'
      USING ERRCODE='23985';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id OR
     NEW.project_id IS DISTINCT FROM OLD.project_id OR
     NEW.environment_id IS DISTINCT FROM OLD.environment_id OR
     NEW.id IS DISTINCT FROM OLD.id OR
     NEW.immutable_request_hash IS DISTINCT FROM OLD.immutable_request_hash OR
     NEW.patch_digest IS DISTINCT FROM OLD.patch_digest OR
     NEW.proposed_tree_hash IS DISTINCT FROM OLD.proposed_tree_hash OR
     NEW.repository_binding_id IS DISTINCT FROM OLD.repository_binding_id OR
     NEW.base_commit_sha IS DISTINCT FROM OLD.base_commit_sha OR
     NEW.base_tree_hash IS DISTINCT FROM OLD.base_tree_hash OR
     NEW.created_by_principal IS DISTINCT FROM OLD.created_by_principal OR
     NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'code change request immutable material changed'
      USING ERRCODE='23986';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER delivery_transition_fence BEFORE INSERT ON code_change_transitions
FOR EACH ROW EXECUTE FUNCTION delivery_guard_transition_insert();
CREATE TRIGGER delivery_transition_projection AFTER INSERT ON code_change_transitions
FOR EACH ROW EXECUTE FUNCTION delivery_project_transition();
CREATE TRIGGER delivery_request_projection_guard BEFORE UPDATE ON code_change_requests
FOR EACH ROW EXECUTE FUNCTION delivery_guard_request_projection();
CREATE TRIGGER delivery_request_delete_guard BEFORE DELETE ON code_change_requests
FOR EACH ROW EXECUTE FUNCTION delivery_guard_request_projection();

CREATE TABLE code_change_decisions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ccd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL, stage text NOT NULL CHECK (stage IN ('PR_CREATION','MERGE','DEPLOYMENT','ROLLBACK')),
  sequence_no integer NOT NULL CHECK (sequence_no>0), decision_digest text NOT NULL CHECK (decision_digest ~ '^sha256:[0-9a-f]{64}$'),
  principal text NOT NULL, github_reviewer_binding_id text, github_review_state_hash text CHECK (github_review_state_hash IS NULL OR github_review_state_hash ~ '^sha256:[0-9a-f]{64}$'),
  decision text NOT NULL CHECK (decision IN ('APPROVED','REJECTED','EXPIRED','SUPERSEDED')),
  reason text NOT NULL, decided_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  supersedes_id text, authorization_snapshot_hash text NOT NULL CHECK (authorization_snapshot_hash ~ '^sha256:[0-9a-f]{64}$'),
  step_up_receipt_hash text NOT NULL CHECK (step_up_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,stage,sequence_no),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,stage,decision_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,supersedes_id)
    REFERENCES code_change_decisions(organization_id,project_id,environment_id,id),
  CHECK (expires_at>=decided_at),
  CHECK ((sequence_no=1 AND supersedes_id IS NULL) OR
         (sequence_no>1 AND supersedes_id IS NOT NULL))
);
CREATE UNIQUE INDEX code_change_one_decision_root ON code_change_decisions
  (organization_id,project_id,environment_id,code_change_request_id,stage)
  WHERE supersedes_id IS NULL;
CREATE UNIQUE INDEX code_change_one_decision_successor ON code_change_decisions
  (organization_id,project_id,environment_id,supersedes_id)
  WHERE supersedes_id IS NOT NULL;

CREATE FUNCTION delivery_guard_decision_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE predecessor code_change_decisions%ROWTYPE;
BEGIN
  IF NEW.sequence_no=1 THEN
    IF EXISTS (SELECT 1 FROM code_change_decisions WHERE organization_id=NEW.organization_id
      AND project_id=NEW.project_id AND environment_id=NEW.environment_id
      AND code_change_request_id=NEW.code_change_request_id AND stage=NEW.stage) THEN
      RAISE EXCEPTION 'DECISION_ROOT_ALREADY_EXISTS' USING ERRCODE='23992';
    END IF;
    RETURN NEW;
  END IF;
  SELECT * INTO predecessor FROM code_change_decisions WHERE organization_id=NEW.organization_id
    AND project_id=NEW.project_id AND environment_id=NEW.environment_id AND id=NEW.supersedes_id
  FOR UPDATE;
  IF NOT FOUND OR predecessor.code_change_request_id<>NEW.code_change_request_id
     OR predecessor.stage<>NEW.stage OR predecessor.sequence_no<>NEW.sequence_no-1 THEN
    RAISE EXCEPTION 'DECISION_PREDECESSOR_INVALID' USING ERRCODE='23993';
  END IF;
  IF EXISTS (SELECT 1 FROM code_change_decisions WHERE organization_id=NEW.organization_id
      AND project_id=NEW.project_id AND environment_id=NEW.environment_id
      AND supersedes_id=NEW.supersedes_id) THEN
    RAISE EXCEPTION 'DECISION_CHAIN_FORK' USING ERRCODE='23994';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_decision_chain_fence BEFORE INSERT ON code_change_decisions
FOR EACH ROW EXECUTE FUNCTION delivery_guard_decision_insert();

ALTER TABLE code_change_transitions ADD CONSTRAINT code_change_transition_decision_fk
  FOREIGN KEY (organization_id,project_id,environment_id,decision_id)
  REFERENCES code_change_decisions(organization_id,project_id,environment_id,id);

CREATE OR REPLACE FUNCTION delivery_guard_transition_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE request_state text; request_sequence integer; required_stage text;
DECLARE required_actor text; live_decision_id text; live_decision_digest text;
BEGIN
  SELECT state,sequence_no INTO request_state,request_sequence
  FROM code_change_requests
  WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
    AND environment_id=NEW.environment_id AND id=NEW.code_change_request_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CODE_CHANGE_REQUEST_NOT_FOUND' USING ERRCODE='23982';
  END IF;
  IF NEW.expected_sequence_no<>request_sequence OR NEW.sequence_no<>request_sequence+1
     OR NEW.from_state<>request_state THEN
    RAISE EXCEPTION 'CODE_CHANGE_TRANSITION_STALE' USING ERRCODE='23983';
  END IF;
  IF NOT delivery_transition_allowed(NEW.from_state,NEW.to_state) THEN
    RAISE EXCEPTION 'CODE_CHANGE_TRANSITION_ILLEGAL' USING ERRCODE='23984';
  END IF;
  IF now() > (SELECT expires_at FROM code_change_requests WHERE organization_id=NEW.organization_id
      AND project_id=NEW.project_id AND environment_id=NEW.environment_id AND id=NEW.code_change_request_id)
     AND NEW.to_state NOT IN ('EXPIRED','BLOCKED','ABANDONED') THEN
    RAISE EXCEPTION 'CODE_CHANGE_REQUEST_EXPIRED' USING ERRCODE='23995';
  END IF;
  required_stage := CASE NEW.to_state WHEN 'PR_REQUESTED' THEN 'PR_CREATION'
    WHEN 'MERGED' THEN 'MERGE' WHEN 'CANARY_DEPLOYING' THEN 'DEPLOYMENT'
    WHEN 'ROLLING_BACK' THEN 'ROLLBACK' ELSE NULL END;
  required_actor := CASE NEW.to_state WHEN 'PR_REQUESTED' THEN 'COORDINATOR'
    WHEN 'MERGED' THEN 'GITHUB_PROVIDER' WHEN 'CANARY_DEPLOYING' THEN 'DEPLOYMENT_CONTROLLER'
    WHEN 'ROLLING_BACK' THEN 'DEPLOYMENT_CONTROLLER' ELSE NULL END;
  IF required_stage IS NOT NULL THEN
    SELECT d.id,d.decision_digest INTO live_decision_id,live_decision_digest
    FROM code_change_decisions d
    WHERE d.organization_id=NEW.organization_id AND d.project_id=NEW.project_id
      AND d.environment_id=NEW.environment_id AND d.code_change_request_id=NEW.code_change_request_id
      AND d.stage=required_stage AND d.decision='APPROVED' AND d.expires_at>now()
      AND NOT EXISTS (SELECT 1 FROM code_change_decisions child
        WHERE child.organization_id=d.organization_id AND child.project_id=d.project_id
          AND child.environment_id=d.environment_id AND child.supersedes_id=d.id)
    FOR UPDATE;
    IF live_decision_id IS NULL OR NEW.decision_id IS DISTINCT FROM live_decision_id
       OR NEW.decision_digest IS DISTINCT FROM live_decision_digest
       OR NEW.actor_kind IS DISTINCT FROM required_actor THEN
      RAISE EXCEPTION 'CODE_CHANGE_DECISION_REQUIRED' USING ERRCODE='23996';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TABLE github_oauth_client_profiles (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gop_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  provider_kind text NOT NULL CHECK (provider_kind='GITHUB_APP_USER_TO_SERVER'),
  github_app_client_id text NOT NULL, client_secret_ref text NOT NULL,
  authorization_endpoint text NOT NULL CHECK (authorization_endpoint ~ '^https://'),
  token_endpoint text NOT NULL CHECK (token_endpoint ~ '^https://'), api_base_url text NOT NULL CHECK (api_base_url ~ '^https://'),
  callback_uri text NOT NULL CHECK (callback_uri ~ '^https://'), protocol_version text NOT NULL,
  token_expiration_required boolean NOT NULL CHECK (token_expiration_required),
  configuration_hash text NOT NULL CHECK (configuration_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')), activated_at timestamptz, revoked_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,configuration_hash),
  CHECK ((status='ACTIVE')=(activated_at IS NOT NULL AND revoked_at IS NULL))
);
CREATE UNIQUE INDEX github_one_active_oauth_profile ON github_oauth_client_profiles
  (organization_id,project_id,environment_id) WHERE status='ACTIVE';

CREATE TABLE github_reviewer_bindings (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^grb_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'), solvan_principal text NOT NULL, github_account_node_id text NOT NULL,
  github_login text NOT NULL, binding_proof_ref text NOT NULL, binding_proof_hash text NOT NULL CHECK (binding_proof_hash ~ '^sha256:[0-9a-f]{64}$'),
  reviewer_policy_hash text NOT NULL CHECK (reviewer_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVALIDATION_REQUIRED','EXPIRED','REVOKED','REPLACED')),
  expires_at timestamptz NOT NULL, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id)
);
CREATE UNIQUE INDEX github_reviewer_one_active_principal ON github_reviewer_bindings
  (organization_id,project_id,environment_id,repository_binding_id,solvan_principal) WHERE status='ACTIVE';
CREATE UNIQUE INDEX github_reviewer_one_active_account ON github_reviewer_bindings
  (organization_id,project_id,environment_id,repository_binding_id,github_account_node_id) WHERE status='ACTIVE';

CREATE TABLE github_reviewer_binding_events (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gre_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  github_reviewer_binding_id text NOT NULL, sequence_no integer NOT NULL CHECK (sequence_no>0),
  event_kind text NOT NULL CHECK (event_kind IN ('LINKED','REVALIDATED','REVALIDATION_REQUIRED','EXPIRED','REVOKED','REPLACED')),
  actor_kind text NOT NULL CHECK (actor_kind IN ('HUMAN','GITHUB_IDENTITY_BROKER','GITHUB_PROVIDER','SYSTEM')),
  actor_identity text NOT NULL, input_hash text NOT NULL CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
  receipt_ref text NOT NULL, receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,github_reviewer_binding_id,sequence_no),
  FOREIGN KEY (organization_id,project_id,environment_id,github_reviewer_binding_id)
    REFERENCES github_reviewer_bindings(organization_id,project_id,environment_id,id)
);
CREATE TRIGGER delivery_reviewer_binding_event_append_only BEFORE UPDATE OR DELETE
ON github_reviewer_binding_events FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();

CREATE TABLE github_identity_link_transactions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^glt_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  oauth_client_profile_id text NOT NULL, repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'), solvan_principal text NOT NULL,
  solvan_session_binding_hash text NOT NULL CHECK (solvan_session_binding_hash ~ '^sha256:[0-9a-f]{64}$'),
  state_hash text NOT NULL CHECK (state_hash ~ '^sha256:[0-9a-f]{64}$'), pkce_verifier_ciphertext text NOT NULL,
  pkce_key_version text NOT NULL, requested_permission_hash text NOT NULL CHECK (requested_permission_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('PENDING','CONSUMED','EXPIRED','REFUSED')), expires_at timestamptz NOT NULL,
  consumed_at timestamptz, failure_code text, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,state_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,oauth_client_profile_id)
    REFERENCES github_oauth_client_profiles(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id),
  CHECK ((status='PENDING')=(consumed_at IS NULL))
);

CREATE TABLE code_change_operations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^cco_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL, transition_sequence_no integer NOT NULL CHECK (transition_sequence_no>0),
  operation_kind text NOT NULL CHECK (operation_kind IN ('CREATE_BRANCH','CREATE_PR','SYNC_PR','MERGE_PR')),
  material_hash text NOT NULL CHECK (material_hash ~ '^sha256:[0-9a-f]{64}$'), idempotency_key text NOT NULL,
  provider_request_id text, worker_lease_token uuid, status text NOT NULL CHECK (status IN ('PREPARED','ISSUED','RECONCILING','SUCCEEDED','REFUSED','AMBIGUOUS','EXPIRED','CANCELLED')),
  request_ref text NOT NULL, request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'), response_ref text, response_hash text CHECK (response_hash IS NULL OR response_hash ~ '^sha256:[0-9a-f]{64}$'), error_class text,
  prepared_at timestamptz NOT NULL DEFAULT now(), issued_at timestamptz, reconciled_at timestamptz, completed_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,operation_kind,material_hash),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,idempotency_key),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  CHECK ((status IN ('ISSUED','RECONCILING','SUCCEEDED','AMBIGUOUS'))=(issued_at IS NOT NULL))
);

CREATE TABLE private_command_dispatches (
  id text PRIMARY KEY CHECK (id ~ '^cmd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  command_kind text NOT NULL CHECK (command_kind IN ('WORKSPACE_TOOL_INVOKE','EXPLORATORY_SANDBOX_RUN','ADJUDICATE_PATCH','CREATE_PR','SYNC_PR','MERGE_PR','START_GITHUB_LINK','CONSUME_GITHUB_CALLBACK','REVOKE_GITHUB_LINK','PREPARE_CANARY','PROMOTE_CANARY','ROLLBACK_RELEASE','VERIFY_RELEASE_EFFECT')),
  subject_id text NOT NULL, material_hash text NOT NULL CHECK (material_hash ~ '^sha256:[0-9a-f]{64}$'),
  idempotency_key text NOT NULL, payload_ref text NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  payload_schema_hash text NOT NULL CHECK (payload_schema_hash ~ '^sha256:[0-9a-f]{64}$'),
  admitted_caller_identity text NOT NULL, admitted_audience_hash text NOT NULL CHECK (admitted_audience_hash ~ '^sha256:[0-9a-f]{64}$'),
  deadline timestamptz NOT NULL, status text NOT NULL CHECK (status IN ('PREPARED','ISSUED','RECONCILING','SUCCEEDED','REFUSED','AMBIGUOUS','EXPIRED','CANCELLED')),
  response_ref text, response_hash text CHECK (response_hash IS NULL OR response_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
  UNIQUE (organization_id,project_id,environment_id,command_kind,subject_id,material_hash,idempotency_key),
  CHECK ((status IN ('SUCCEEDED','REFUSED','AMBIGUOUS','EXPIRED','CANCELLED'))=(completed_at IS NOT NULL))
);

CREATE FUNCTION delivery_guard_private_command() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'PREPARED' OR NEW.response_ref IS NOT NULL OR NEW.response_hash IS NOT NULL
       OR NEW.completed_at IS NOT NULL THEN
      RAISE EXCEPTION 'PRIVATE_COMMAND_MUST_START_PREPARED' USING ERRCODE='23999';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'private command cannot be deleted' USING ERRCODE='23999';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.project_id IS DISTINCT FROM OLD.project_id
     OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
     OR NEW.command_kind IS DISTINCT FROM OLD.command_kind
     OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
     OR NEW.material_hash IS DISTINCT FROM OLD.material_hash
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.payload_ref IS DISTINCT FROM OLD.payload_ref
     OR NEW.payload_hash IS DISTINCT FROM OLD.payload_hash
     OR NEW.payload_schema_hash IS DISTINCT FROM OLD.payload_schema_hash
     OR NEW.admitted_caller_identity IS DISTINCT FROM OLD.admitted_caller_identity
     OR NEW.admitted_audience_hash IS DISTINCT FROM OLD.admitted_audience_hash
     OR NEW.deadline IS DISTINCT FROM OLD.deadline
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'PRIVATE_COMMAND_MATERIAL_IMMUTABLE' USING ERRCODE='23999';
  END IF;
  IF NOT (OLD.status='PREPARED' AND NEW.status IN ('ISSUED','RECONCILING','SUCCEEDED','REFUSED','AMBIGUOUS','EXPIRED','CANCELLED')
       OR OLD.status='ISSUED' AND NEW.status IN ('RECONCILING','SUCCEEDED','REFUSED','AMBIGUOUS')
       OR OLD.status='RECONCILING' AND NEW.status IN ('SUCCEEDED','REFUSED','AMBIGUOUS')) THEN
    RAISE EXCEPTION 'PRIVATE_COMMAND_STATUS_ILLEGAL' USING ERRCODE='23999';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_private_command_fence BEFORE INSERT OR UPDATE OR DELETE
ON private_command_dispatches FOR EACH ROW EXECUTE FUNCTION delivery_guard_private_command();

CREATE TABLE release_candidates (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rlc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL, repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'), merged_commit_sha text NOT NULL CHECK (merged_commit_sha ~ '^[0-9a-f]{40}$'),
  source_tree_hash text NOT NULL CHECK (source_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  build_definition_ref text NOT NULL, build_definition_hash text NOT NULL CHECK (build_definition_hash ~ '^sha256:[0-9a-f]{64}$'), builder_identity text NOT NULL,
  build_invocation_ref text NOT NULL, build_artifact_ref text NOT NULL, build_artifact_hash text NOT NULL CHECK (build_artifact_hash ~ '^sha256:[0-9a-f]{64}$'),
  sbom_ref text NOT NULL, sbom_hash text NOT NULL CHECK (sbom_hash ~ '^sha256:[0-9a-f]{64}$'), provenance_predicate_type text NOT NULL, provenance_predicate_version text NOT NULL, provenance_hash text NOT NULL CHECK (provenance_hash ~ '^sha256:[0-9a-f]{64}$'),
  release_signature_ref text NOT NULL, release_signature_hash text NOT NULL CHECK (release_signature_hash ~ '^sha256:[0-9a-f]{64}$'), signer_identity text NOT NULL, signer_key_version text NOT NULL,
  deployment_manifest_ref text NOT NULL, deployment_manifest_hash text NOT NULL CHECK (deployment_manifest_hash ~ '^sha256:[0-9a-f]{64}$'), release_policy_hash text NOT NULL CHECK (release_policy_hash ~ '^sha256:[0-9a-f]{64}$'), created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,code_change_request_id,build_artifact_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id)
);

CREATE TABLE release_target_reservations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^dtr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  target_key text NOT NULL, expected_target_version text NOT NULL,
  expected_target_epoch bigint NOT NULL CHECK (expected_target_epoch>0),
  reservation_material_hash text NOT NULL CHECK (reservation_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('HELD','RECONCILING','RELEASED','EXPIRED')),
  lease_token uuid NOT NULL, lease_expires_at timestamptz NOT NULL,
  held_by_identity text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,target_key,id)
);
CREATE UNIQUE INDEX delivery_one_active_target_reservation ON release_target_reservations
  (organization_id,project_id,environment_id,target_key)
  WHERE status IN ('HELD','RECONCILING');

CREATE TABLE deployment_rollouts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^dro_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  release_candidate_id text NOT NULL, target_key text NOT NULL, target_provider text NOT NULL CHECK (target_provider='GCP_CLOUD_RUN_V2'),
  expected_target_version text NOT NULL, expected_target_epoch bigint NOT NULL CHECK (expected_target_epoch>0), target_reservation_id text NOT NULL,
  rollout_policy_hash text NOT NULL CHECK (rollout_policy_hash ~ '^sha256:[0-9a-f]{64}$'), approval_digest text NOT NULL CHECK (approval_digest ~ '^sha256:[0-9a-f]{64}$'),
  predeploy_snapshot_ref text NOT NULL, predeploy_snapshot_hash text NOT NULL CHECK (predeploy_snapshot_hash ~ '^sha256:[0-9a-f]{64}$'),
  predeploy_release_candidate_id text NOT NULL, predeploy_assignment_ref text NOT NULL, rollback_release_candidate_id text NOT NULL, rollback_assignment_ref text NOT NULL,
  release_effect_template_id text NOT NULL, release_effect_template_version text NOT NULL, release_effect_input_refs_hash text NOT NULL CHECK (release_effect_input_refs_hash ~ '^sha256:[0-9a-f]{64}$'), intended_effect_hash text NOT NULL CHECK (intended_effect_hash ~ '^sha256:[0-9a-f]{64}$'),
  verification_profile_id text NOT NULL, verification_profile_version text NOT NULL, verification_profile_hash text NOT NULL CHECK (verification_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('PENDING_APPROVAL','CANARY_DEPLOYING','CANARY_READY','PROMOTING','VERIFYING','PROMOTED','VERIFICATION_FAILED','ROLLBACK_PENDING','ROLLING_BACK','ROLLED_BACK','BLOCKED','AMBIGUOUS')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,release_candidate_id)
    REFERENCES release_candidates(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,predeploy_release_candidate_id)
    REFERENCES release_candidates(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,rollback_release_candidate_id)
    REFERENCES release_candidates(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,target_key,target_reservation_id)
    REFERENCES release_target_reservations(organization_id,project_id,environment_id,target_key,id),
  UNIQUE (organization_id,project_id,environment_id,target_reservation_id),
  CHECK (rollback_release_candidate_id=predeploy_release_candidate_id),
  CHECK (rollback_assignment_ref=predeploy_assignment_ref)
);
CREATE UNIQUE INDEX deployment_one_active_rollout_per_target ON deployment_rollouts
  (organization_id,project_id,environment_id,target_key)
  WHERE status IN ('PENDING_APPROVAL','CANARY_DEPLOYING','CANARY_READY','PROMOTING',
                 'VERIFYING','VERIFICATION_FAILED','ROLLBACK_PENDING','ROLLING_BACK');

CREATE FUNCTION delivery_guard_rollout_reservation() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE reservation_status text; reservation_expires timestamptz;
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'deployment rollout cannot be deleted' USING ERRCODE='23997';
  END IF;
  SELECT status,lease_expires_at INTO reservation_status,reservation_expires
  FROM release_target_reservations WHERE organization_id=NEW.organization_id
    AND project_id=NEW.project_id AND environment_id=NEW.environment_id
    AND id=NEW.target_reservation_id AND target_key=NEW.target_key FOR UPDATE;
  IF reservation_status NOT IN ('HELD','RECONCILING') OR reservation_expires<=now() THEN
    RAISE EXCEPTION 'RELEASE_TARGET_RESERVATION_STALE' USING ERRCODE='23998';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_rollout_reservation_fence BEFORE INSERT OR UPDATE OR DELETE
ON deployment_rollouts FOR EACH ROW EXECUTE FUNCTION delivery_guard_rollout_reservation();

CREATE TABLE deployment_rollout_operations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^dgo_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  deployment_rollout_id text NOT NULL, operation_kind text NOT NULL CHECK (operation_kind IN ('PREPARE_CANARY','PROMOTE_CANARY','ROLLBACK_RELEASE')),
  stage_ordinal integer NOT NULL CHECK (stage_ordinal>0), material_hash text NOT NULL CHECK (material_hash ~ '^sha256:[0-9a-f]{64}$'), idempotency_key text NOT NULL,
  provider_request_id text, worker_lease_token uuid, status text NOT NULL CHECK (status IN ('PREPARED','ISSUED','RECONCILING','SUCCEEDED','REFUSED','AMBIGUOUS','EXPIRED','CANCELLED')),
  request_ref text NOT NULL, request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'), response_ref text, response_hash text CHECK (response_hash IS NULL OR response_hash ~ '^sha256:[0-9a-f]{64}$'), error_class text,
  prepared_at timestamptz NOT NULL DEFAULT now(), issued_at timestamptz, reconciled_at timestamptz, completed_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,deployment_rollout_id,operation_kind,stage_ordinal,material_hash),
  UNIQUE (organization_id,project_id,environment_id,deployment_rollout_id,idempotency_key),
  FOREIGN KEY (organization_id,project_id,environment_id,deployment_rollout_id)
    REFERENCES deployment_rollouts(organization_id,project_id,environment_id,id),
  CHECK ((status IN ('ISSUED','RECONCILING','SUCCEEDED','AMBIGUOUS'))=(issued_at IS NOT NULL))
);

CREATE TABLE release_verification_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rvr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  deployment_rollout_id text NOT NULL, verifier_identity text NOT NULL,
  verification_profile_hash text NOT NULL CHECK (verification_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  predeploy_snapshot_ref text NOT NULL, predeploy_snapshot_hash text NOT NULL CHECK (predeploy_snapshot_hash ~ '^sha256:[0-9a-f]{64}$'),
  postdeploy_observation_ref text NOT NULL, postdeploy_observation_hash text NOT NULL CHECK (postdeploy_observation_hash ~ '^sha256:[0-9a-f]{64}$'),
  intended_effect_hash text NOT NULL CHECK (intended_effect_hash ~ '^sha256:[0-9a-f]{64}$'),
  result text NOT NULL CHECK (result IN ('VERIFIED','FAILED','INCONCLUSIVE')), signature_ref text NOT NULL, signature_hash text NOT NULL CHECK (signature_hash ~ '^sha256:[0-9a-f]{64}$'), observed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,deployment_rollout_id,verification_profile_hash,postdeploy_observation_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,deployment_rollout_id)
    REFERENCES deployment_rollouts(organization_id,project_id,environment_id,id)
);

-- History rows are write-once. The application has no UPDATE/DELETE path; a
-- deployment role must receive INSERT/SELECT only for these relations.
CREATE TRIGGER delivery_transition_append_only BEFORE UPDATE OR DELETE ON code_change_transitions
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_decision_append_only BEFORE UPDATE OR DELETE ON code_change_decisions
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_candidate_append_only BEFORE UPDATE OR DELETE ON workspace_candidate_generations
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_exploratory_append_only BEFORE UPDATE OR DELETE ON exploratory_sandbox_receipts
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_verification_append_only BEFORE UPDATE OR DELETE ON release_verification_receipts
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();

-- Every delivery relation that carries tenant scope is protected at the
-- database boundary as well as in every typed service.  Command identifiers
-- are globally unique for safe private routing, but that does not make their
-- tenant rows globally readable.  FORCE is intentional: a runtime role must
-- never become a scope-bypass simply because it owns a relation in a local
-- qualification database.
DO $delivery_scope_policies$
DECLARE scoped_table record;
BEGIN
  FOR scoped_table IN
    SELECT table_name
      FROM information_schema.columns
     WHERE table_schema = 'solvan_delivery'
       AND column_name IN ('organization_id','project_id','environment_id')
     GROUP BY table_name
    HAVING count(DISTINCT column_name) = 3
  LOOP
    EXECUTE format('ALTER TABLE solvan_delivery.%I ENABLE ROW LEVEL SECURITY',
                   scoped_table.table_name);
    EXECUTE format('ALTER TABLE solvan_delivery.%I FORCE ROW LEVEL SECURITY',
                   scoped_table.table_name);
    EXECUTE format(
      'CREATE POLICY delivery_scope_isolation ON solvan_delivery.%I '
      'USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))',
      scoped_table.table_name);
  END LOOP;
END
$delivery_scope_policies$;

-- Runtime identities use non-owner database roles. The target bootstrap grants
-- only the relation/function permissions in code-change-release-database-authority.md and
-- never GRANTs UPDATE, DELETE, TRUNCATE, ownership, or schema-creation on this
-- schema to a workload identity. Public receives no access by default.
REVOKE ALL ON ALL TABLES IN SCHEMA solvan_delivery FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA solvan_delivery FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA solvan_delivery FROM PUBLIC;
CREATE TRIGGER delivery_request_no_truncate BEFORE TRUNCATE ON code_change_requests
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_transition_no_truncate BEFORE TRUNCATE ON code_change_transitions
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_decision_no_truncate BEFORE TRUNCATE ON code_change_decisions
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_candidate_no_truncate BEFORE TRUNCATE ON workspace_candidate_generations
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_exploratory_no_truncate BEFORE TRUNCATE ON exploratory_sandbox_receipts
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_verification_no_truncate BEFORE TRUNCATE ON release_verification_receipts
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

COMMIT;
