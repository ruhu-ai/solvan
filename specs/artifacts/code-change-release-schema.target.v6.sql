-- Target migration: provider-qualified Code Change Request creation.
-- A browser, channel, or model can request qualification, but only the
-- GitHub Provider receipt supplies repository policy and tree material.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

ALTER TABLE private_command_dispatches
  DROP CONSTRAINT private_command_dispatches_command_kind_check,
  ADD CONSTRAINT private_command_dispatches_command_kind_check CHECK (
    command_kind IN (
      'WORKSPACE_TOOL_INVOKE','EXPLORATORY_SANDBOX_RUN','ADJUDICATE_PATCH',
      'QUALIFY_CODE_CHANGE','CREATE_PR','SYNC_PR','MERGE_PR',
      'START_GITHUB_LINK','CONSUME_GITHUB_CALLBACK','REVOKE_GITHUB_LINK',
      'PREPARE_CANARY','PROMOTE_CANARY','ROLLBACK_RELEASE','VERIFY_RELEASE_EFFECT'
    )
  );

CREATE TABLE patch_adjudication_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^adr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  patch_artifact_id text NOT NULL, candidate_generation_id text NOT NULL,
  base_tree_hash text NOT NULL CHECK (base_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  candidate_tree_hash text NOT NULL CHECK (candidate_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  command_definitions_hash text NOT NULL CHECK (command_definitions_hash ~ '^sha256:[0-9a-f]{64}$'),
  sandbox_resource text NOT NULL, sandbox_image_hash text NOT NULL CHECK (sandbox_image_hash ~ '^sha256:[0-9a-f]{64}$'),
  reproduction_exit_code integer NOT NULL, test_exit_code integer NOT NULL,
  receipt_ref text NOT NULL CHECK (receipt_ref ~ '^gs://'),
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  coordinator_service_revision text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,patch_artifact_id),
  UNIQUE (organization_id,project_id,environment_id,candidate_generation_id,receipt_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,patch_artifact_id)
    REFERENCES solvan.patch_artifacts(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,candidate_generation_id)
    REFERENCES workspace_candidate_generations(organization_id,project_id,environment_id,id),
  CHECK (reproduction_exit_code<>0 AND test_exit_code=0)
);

CREATE TABLE code_change_qualification_intents (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^cqi_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  reliability_case_id text NOT NULL, patch_artifact_id text NOT NULL,
  candidate_generation_id text NOT NULL, code_delivery_profile_id text NOT NULL,
  adjudication_receipt_id text NOT NULL,
  repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_policy_hash text NOT NULL CHECK (repository_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  adjudication_receipt_ref text NOT NULL CHECK (adjudication_receipt_ref ~ '^gs://'),
  adjudication_receipt_hash text NOT NULL CHECK (adjudication_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  requested_by_principal text NOT NULL, expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,candidate_generation_id,code_delivery_profile_id),
  FOREIGN KEY (organization_id,project_id,environment_id,reliability_case_id)
    REFERENCES solvan.reliability_cases(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,patch_artifact_id)
    REFERENCES solvan.patch_artifacts(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,candidate_generation_id)
    REFERENCES workspace_candidate_generations(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,adjudication_receipt_id)
    REFERENCES patch_adjudication_receipts(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,code_delivery_profile_id)
    REFERENCES code_delivery_profiles(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id),
  CHECK (expires_at > created_at)
);

CREATE TABLE code_change_qualification_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^cqr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  qualification_intent_id text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('QUALIFIED','REFUSED')),
  reason_code text NOT NULL,
  repository_binding_id text NOT NULL CHECK (repository_binding_id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_policy_hash text NOT NULL CHECK (repository_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  code_delivery_profile_id text NOT NULL,
  code_delivery_profile_hash text NOT NULL CHECK (code_delivery_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  default_branch text,
  base_commit_sha text CHECK (base_commit_sha IS NULL OR base_commit_sha ~ '^[0-9a-f]{40}$'),
  base_tree_ref text CHECK (base_tree_ref IS NULL OR base_tree_ref ~ '^gs://'),
  base_tree_hash text CHECK (base_tree_hash IS NULL OR base_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  patch_transform_version text,
  patch_transform_ref text CHECK (patch_transform_ref IS NULL OR patch_transform_ref ~ '^gs://'),
  patch_transform_hash text CHECK (patch_transform_hash IS NULL OR patch_transform_hash ~ '^sha256:[0-9a-f]{64}$'),
  proposed_tree_hash text CHECK (proposed_tree_hash IS NULL OR proposed_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  base_required_check_definitions_ref text CHECK (base_required_check_definitions_ref IS NULL OR base_required_check_definitions_ref ~ '^gs://'),
  base_required_check_definitions_hash text CHECK (base_required_check_definitions_hash IS NULL OR base_required_check_definitions_hash ~ '^sha256:[0-9a-f]{64}$'),
  attributes_evaluation_ref text CHECK (attributes_evaluation_ref IS NULL OR attributes_evaluation_ref ~ '^gs://'),
  attributes_evaluation_hash text CHECK (attributes_evaluation_hash IS NULL OR attributes_evaluation_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_observation_ref text NOT NULL CHECK (provider_observation_ref ~ '^gs://'),
  provider_observation_hash text NOT NULL CHECK (provider_observation_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_service_revision text NOT NULL, observed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,qualification_intent_id),
  FOREIGN KEY (organization_id,project_id,environment_id,qualification_intent_id)
    REFERENCES code_change_qualification_intents(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,repository_binding_id)
    REFERENCES solvan.github_repositories(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,code_delivery_profile_id)
    REFERENCES code_delivery_profiles(organization_id,project_id,environment_id,id),
  CHECK (
    (outcome='QUALIFIED' AND reason_code='QUALIFIED'
      AND default_branch IS NOT NULL AND base_commit_sha IS NOT NULL
      AND base_tree_ref IS NOT NULL AND base_tree_hash IS NOT NULL
      AND patch_transform_version='solvan-regular-tree-transform/v1'
      AND patch_transform_ref IS NOT NULL AND patch_transform_hash IS NOT NULL
      AND proposed_tree_hash IS NOT NULL
      AND base_required_check_definitions_ref IS NOT NULL
      AND base_required_check_definitions_hash IS NOT NULL
      AND attributes_evaluation_ref IS NOT NULL AND attributes_evaluation_hash IS NOT NULL)
    OR
    (outcome='REFUSED' AND reason_code<>'QUALIFIED'
      AND default_branch IS NULL AND base_commit_sha IS NULL
      AND base_tree_ref IS NULL AND base_tree_hash IS NULL
      AND patch_transform_version IS NULL
      AND patch_transform_ref IS NULL AND patch_transform_hash IS NULL
      AND proposed_tree_hash IS NULL
      AND base_required_check_definitions_ref IS NULL
      AND base_required_check_definitions_hash IS NULL
      AND attributes_evaluation_ref IS NULL AND attributes_evaluation_hash IS NULL)
  )
);

CREATE TRIGGER delivery_code_change_qualification_intent_append_only
BEFORE UPDATE OR DELETE ON code_change_qualification_intents
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_patch_adjudication_receipt_append_only
BEFORE UPDATE OR DELETE ON patch_adjudication_receipts
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_code_change_qualification_receipt_append_only
BEFORE UPDATE OR DELETE ON code_change_qualification_receipts
FOR EACH ROW EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_code_change_qualification_intent_no_truncate
BEFORE TRUNCATE ON code_change_qualification_intents
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();
CREATE TRIGGER delivery_patch_adjudication_receipt_no_truncate
BEFORE TRUNCATE ON patch_adjudication_receipts
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

CREATE FUNCTION delivery_guard_qualification_intent_source()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM patch_adjudication_receipts a
      JOIN solvan.patch_artifacts p
        ON (p.organization_id,p.project_id,p.environment_id,p.id)=
           (a.organization_id,a.project_id,a.environment_id,a.patch_artifact_id)
      JOIN code_delivery_profiles d
        ON d.organization_id=a.organization_id AND d.project_id=a.project_id
       AND d.environment_id=a.environment_id AND d.id=NEW.code_delivery_profile_id
      JOIN solvan.github_repositories r
        ON r.organization_id=a.organization_id AND r.project_id=a.project_id
       AND r.environment_id=a.environment_id AND r.id=NEW.repository_binding_id
     WHERE a.organization_id=NEW.organization_id AND a.project_id=NEW.project_id
       AND a.environment_id=NEW.environment_id AND a.id=NEW.adjudication_receipt_id
       AND a.patch_artifact_id=NEW.patch_artifact_id
       AND a.candidate_generation_id=NEW.candidate_generation_id
       AND a.receipt_ref=NEW.adjudication_receipt_ref
       AND a.receipt_hash=NEW.adjudication_receipt_hash
       AND p.reliability_case_id=NEW.reliability_case_id AND p.status='TESTS_PASSED'
       AND d.repository_binding_id=NEW.repository_binding_id AND d.status='ACTIVE'
       AND r.policy_hash=NEW.repository_policy_hash AND r.status='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'QUALIFICATION_INTENT_SOURCE_NOT_AUTHORITATIVE' USING ERRCODE='23979';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_qualification_intent_source_fence
BEFORE INSERT ON code_change_qualification_intents
FOR EACH ROW EXECUTE FUNCTION delivery_guard_qualification_intent_source();
CREATE TRIGGER delivery_code_change_qualification_receipt_no_truncate
BEFORE TRUNCATE ON code_change_qualification_receipts
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM code_change_requests) THEN
    RAISE EXCEPTION 'legacy code change requests cannot be migrated without qualification receipts';
  END IF;
END $$;

ALTER TABLE code_change_requests
  ADD COLUMN qualification_receipt_id text NOT NULL,
  ADD COLUMN code_delivery_profile_id text NOT NULL,
  ADD CONSTRAINT code_change_request_qualification_receipt_fk
    FOREIGN KEY (organization_id,project_id,environment_id,qualification_receipt_id)
    REFERENCES code_change_qualification_receipts(organization_id,project_id,environment_id,id),
  ADD CONSTRAINT code_change_request_delivery_profile_fk
    FOREIGN KEY (organization_id,project_id,environment_id,code_delivery_profile_id)
    REFERENCES code_delivery_profiles(organization_id,project_id,environment_id,id);

CREATE FUNCTION delivery_guard_qualified_code_change_request()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE receipt code_change_qualification_receipts%ROWTYPE;
DECLARE intent code_change_qualification_intents%ROWTYPE;
DECLARE profile code_delivery_profiles%ROWTYPE;
BEGIN
  SELECT * INTO receipt FROM code_change_qualification_receipts
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND id=NEW.qualification_receipt_id;
  SELECT * INTO intent FROM code_change_qualification_intents
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND id=receipt.qualification_intent_id;
  SELECT * INTO profile FROM code_delivery_profiles
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND id=NEW.code_delivery_profile_id;
  IF receipt.outcome<>'QUALIFIED' OR profile.status<>'ACTIVE' OR intent.expires_at<=now()
     OR NEW.state<>'PATCH_VALIDATED' OR NEW.sequence_no<>0
     OR NEW.reliability_case_id<>intent.reliability_case_id
     OR NEW.patch_artifact_id<>intent.patch_artifact_id
     OR NEW.repository_binding_id<>intent.repository_binding_id
     OR NEW.repository_binding_id<>receipt.repository_binding_id
     OR NEW.repository_policy_hash<>receipt.repository_policy_hash
     OR NEW.code_delivery_profile_id<>intent.code_delivery_profile_id
     OR NEW.code_delivery_profile_id<>receipt.code_delivery_profile_id
     OR receipt.code_delivery_profile_hash<>profile.profile_hash
     OR NEW.patch_transform_version<>receipt.patch_transform_version
     OR NEW.patch_transform_ref<>receipt.patch_transform_ref
     OR NEW.patch_transform_hash<>receipt.patch_transform_hash
     OR NEW.proposed_tree_hash<>receipt.proposed_tree_hash
     OR NEW.default_branch<>receipt.default_branch
     OR NEW.base_commit_sha<>receipt.base_commit_sha OR NEW.base_tree_hash<>receipt.base_tree_hash
     OR NEW.allowed_paths_hash<>profile.allowed_paths_hash
     OR NEW.adjudication_receipt_ref<>intent.adjudication_receipt_ref
     OR NEW.adjudication_receipt_hash<>intent.adjudication_receipt_hash
     OR NEW.required_checks_policy_ref<>profile.required_checks_policy_ref
     OR NEW.required_checks_policy_hash<>profile.required_checks_policy_hash
     OR NEW.required_check_definition_paths_hash<>profile.required_check_definition_paths_hash
     OR NEW.base_required_check_definitions_ref<>receipt.base_required_check_definitions_ref
     OR NEW.base_required_check_definitions_hash<>receipt.base_required_check_definitions_hash
     OR NEW.reviewer_policy_ref<>profile.reviewer_policy_ref
     OR NEW.reviewer_policy_hash<>profile.reviewer_policy_hash
     OR NEW.pr_creation_policy_ref<>profile.pr_creation_policy_ref
     OR NEW.pr_creation_policy_hash<>profile.pr_creation_policy_hash
     OR NEW.merge_policy_ref<>profile.merge_policy_ref
     OR NEW.merge_policy_hash<>profile.merge_policy_hash
     OR NEW.deployment_policy_ref<>profile.deployment_policy_ref
     OR NEW.deployment_policy_hash<>profile.deployment_policy_hash THEN
    RAISE EXCEPTION 'CODE_CHANGE_REQUEST_LACKS_EXACT_PROVIDER_QUALIFICATION'
      USING ERRCODE='23980';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER delivery_qualified_code_change_request_fence
BEFORE INSERT ON code_change_requests
FOR EACH ROW EXECUTE FUNCTION delivery_guard_qualified_code_change_request();

ALTER TABLE code_change_qualification_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_change_qualification_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE code_change_qualification_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_change_qualification_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE patch_adjudication_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE patch_adjudication_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON code_change_qualification_intents
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
CREATE POLICY delivery_scope_isolation ON code_change_qualification_receipts
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
CREATE POLICY delivery_scope_isolation ON patch_adjudication_receipts
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON code_change_qualification_intents FROM PUBLIC;
REVOKE ALL ON code_change_qualification_receipts FROM PUBLIC;
REVOKE ALL ON patch_adjudication_receipts FROM PUBLIC;

COMMIT;
