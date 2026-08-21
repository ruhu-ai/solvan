-- Solvan governed operability: TARGET schema for specifications 16 and 17.
-- Profile persistence is schema-version 2; this file supersedes the former
-- unordered tool_profile_connections/profile_hash target shape in full.
--
-- This implementation is deliberately isolated from the competition release
-- DDL. It is loaded after `solvan.schema.sql` into PostgreSQL 16 and exercised
-- by constraint oracles and repositories. Promotion into release DDL requires
-- an explicit documentation-policy decision; implementation alone does not
-- enlarge the MSR.

BEGIN;

CREATE SCHEMA IF NOT EXISTS solvan_operability;
SET search_path TO solvan_operability, solvan, public;

CREATE TABLE catalog_principals (
  principal_key text PRIMARY KEY CHECK
    (principal_key ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
  registry_kind text NOT NULL CHECK
    (registry_kind IN ('AGENT','DETERMINISTIC_SERVICE')),
  execution_role text NOT NULL CHECK
    (execution_role IN ('SUPERVISOR','SPECIALIST','WORKSPACE','WORKSPACE_PROVIDER','SERVICE')),
  model_backed boolean NOT NULL,
  manifest_hash text NOT NULL CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (model_backed = (registry_kind = 'AGENT')),
  CHECK ((model_backed AND execution_role <> 'SERVICE') OR
         (NOT model_backed AND execution_role = 'SERVICE'))
);

CREATE TABLE tool_definitions (
  tool_key text PRIMARY KEY CHECK (tool_key ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'),
  display_name text NOT NULL,
  owner_department text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tool_revisions (
  tool_key text NOT NULL,
  version text NOT NULL CHECK (length(version) > 0),
  description text NOT NULL CHECK (length(description) > 0),
  permission_class text NOT NULL CHECK
    (permission_class IN ('READ','COMPUTE','PROPOSE','MUTATE')),
  implementation_kind text NOT NULL CHECK
    (implementation_kind IN ('APPLICATION_SERVICE','CONNECTOR','DETERMINISTIC_SERVICE','MCP')),
  required_capabilities_json jsonb NOT NULL CHECK
    (jsonb_typeof(required_capabilities_json) = 'array' AND
     jsonb_array_length(required_capabilities_json) > 0),
  required_connection_providers_json jsonb NOT NULL CHECK
    (jsonb_typeof(required_connection_providers_json) = 'array' AND
     jsonb_array_length(required_connection_providers_json) > 0),
  input_schema_ref text NOT NULL,
  input_schema_hash text NOT NULL CHECK (input_schema_hash ~ '^sha256:[0-9a-f]{64}$'),
  output_schema_ref text NOT NULL,
  output_schema_hash text NOT NULL CHECK (output_schema_hash ~ '^sha256:[0-9a-f]{64}$'),
  use_cases_json jsonb NOT NULL CHECK
    (jsonb_typeof(use_cases_json) = 'array' AND jsonb_array_length(use_cases_json) > 0),
  anti_use_cases_json jsonb NOT NULL CHECK
    (jsonb_typeof(anti_use_cases_json) = 'array' AND
     jsonb_array_length(anti_use_cases_json) > 0),
  evidence_kind text NOT NULL CHECK (evidence_kind IN
    ('LOGS','METRICS','TRACES','EVENTS','TOPOLOGY','DEPLOYMENT_METADATA',
     'QUERY_STATS','ARTIFACT','NONE')),
  output_semantics_json jsonb NOT NULL CHECK
    (jsonb_typeof(output_semantics_json) = 'array' AND
     jsonb_array_length(output_semantics_json) > 0),
  supported_retrieval_controls_json jsonb NOT NULL CHECK
    (jsonb_typeof(supported_retrieval_controls_json) = 'array' AND
     jsonb_array_length(supported_retrieval_controls_json) > 0),
  no_data_semantics text NOT NULL CHECK
    (no_data_semantics IN ('HEALTHY','UNKNOWN','NOT_APPLICABLE')),
  failure_taxonomy_json jsonb NOT NULL CHECK
    (jsonb_typeof(failure_taxonomy_json) = 'array' AND
     jsonb_array_length(failure_taxonomy_json) > 0),
  supported_data_classes_json jsonb NOT NULL CHECK
    (jsonb_typeof(supported_data_classes_json) = 'array' AND
     jsonb_array_length(supported_data_classes_json) > 0),
  runtime_regions_json jsonb NOT NULL CHECK
    (jsonb_typeof(runtime_regions_json) = 'array' AND
     jsonb_array_length(runtime_regions_json) > 0),
  registry_resource text NOT NULL,
  gateway_destination text NOT NULL,
  model_armor_coverage text NOT NULL CHECK (model_armor_coverage IN
    ('SUPPORTED_OPERATION','NOT_SUPPORTED','NOT_APPLICABLE')),
  network_policy_hash text NOT NULL CHECK
    (network_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  timeout_ms integer NOT NULL CHECK (timeout_ms BETWEEN 1 AND 300000),
  max_input_bytes integer NOT NULL CHECK (max_input_bytes BETWEEN 1 AND 10000000),
  max_output_bytes integer NOT NULL CHECK (max_output_bytes BETWEEN 1 AND 10000000),
  default_call_budget integer NOT NULL CHECK (default_call_budget BETWEEN 1 AND 100),
  idempotency text NOT NULL CHECK
    (idempotency IN ('NOT_APPLICABLE','NATIVE','SOLVAN_RECONCILED')),
  lifecycle text NOT NULL CHECK
    (lifecycle IN ('DRAFT','APPROVED','DEPRECATED','RETIRED')),
  approval_ref text,
  evaluation_ref text,
  supersedes_version text,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tool_key, version),
  UNIQUE (tool_key, content_hash),
  FOREIGN KEY (tool_key) REFERENCES tool_definitions(tool_key),
  FOREIGN KEY (tool_key, supersedes_version) REFERENCES tool_revisions(tool_key, version),
  CHECK (permission_class <> 'MUTATE' OR implementation_kind = 'DETERMINISTIC_SERVICE'),
  CHECK (lifecycle <> 'APPROVED' OR
    (approval_ref IS NOT NULL AND evaluation_ref IS NOT NULL)),
  CHECK (supersedes_version IS NULL OR supersedes_version <> version)
);

CREATE INDEX tool_revisions_lifecycle_idx
  ON tool_revisions(tool_key, lifecycle, created_at DESC);
CREATE INDEX tool_revisions_route_idx
  ON tool_revisions(registry_resource, gateway_destination);

CREATE TABLE tool_revision_requesters (
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  requester_key text NOT NULL,
  PRIMARY KEY (tool_key, tool_version, requester_key),
  FOREIGN KEY (tool_key, tool_version) REFERENCES tool_revisions(tool_key, version),
  FOREIGN KEY (requester_key) REFERENCES catalog_principals(principal_key)
);
CREATE INDEX tool_requesters_by_principal_idx
  ON tool_revision_requesters(requester_key, tool_key, tool_version);

CREATE FUNCTION reject_model_mutation_binding() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $binding$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM tool_revisions revision
      JOIN catalog_principals principal ON principal.principal_key = NEW.requester_key
     WHERE revision.tool_key = NEW.tool_key
       AND revision.version = NEW.tool_version
       AND revision.permission_class = 'MUTATE'
       AND principal.model_backed
  ) THEN
    RAISE EXCEPTION 'a model-backed Agent cannot request a MUTATE Tool';
  END IF;
  RETURN NEW;
END
$binding$;
CREATE CONSTRAINT TRIGGER tool_requester_no_model_mutation
AFTER INSERT OR UPDATE ON tool_revision_requesters
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION reject_model_mutation_binding();

CREATE TABLE tool_profile_revisions (
  schema_version integer NOT NULL CHECK (schema_version = 2),
  canonicalization_version integer NOT NULL CHECK (canonicalization_version = 1),
  profile_key text NOT NULL CHECK (profile_key ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'),
  version text NOT NULL,
  purpose text NOT NULL,
  allowed_agent_key text NOT NULL,
  maximum_total_calls integer NOT NULL CHECK (maximum_total_calls BETWEEN 0 AND 1000),
  maximum_parallel_calls integer NOT NULL CHECK
    (maximum_parallel_calls BETWEEN 0 AND maximum_total_calls),
  maximum_read_window_ms bigint NOT NULL CHECK (maximum_read_window_ms > 0),
  maximum_aggregate_evidence_bytes bigint NOT NULL CHECK
    (maximum_aggregate_evidence_bytes > 0),
  data_classification_ceiling text NOT NULL CHECK (data_classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  runtime_region text NOT NULL,
  lifecycle text NOT NULL CHECK
    (lifecycle IN ('DRAFT','APPROVED','DEPRECATED','RETIRED')),
  profile_material_hash text NOT NULL CHECK
    (profile_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  approval_ref text,
  evaluation_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_key, version),
  UNIQUE (profile_key, profile_material_hash),
  UNIQUE (profile_key, version, profile_material_hash),
  FOREIGN KEY (allowed_agent_key) REFERENCES catalog_principals(principal_key),
  CHECK (lifecycle <> 'APPROVED' OR
    (approval_ref IS NOT NULL AND evaluation_ref IS NOT NULL)),
  CHECK ((maximum_total_calls = 0) = (maximum_parallel_calls = 0))
);
CREATE INDEX tool_profiles_by_agent_idx
  ON tool_profile_revisions(allowed_agent_key, lifecycle, created_at DESC);

CREATE FUNCTION require_model_agent_profile() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $profile_agent$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM catalog_principals
     WHERE principal_key = NEW.allowed_agent_key
       AND registry_kind = 'AGENT' AND model_backed
  ) THEN
    RAISE EXCEPTION 'a Tool profile requires a model-backed Agent';
  END IF;
  RETURN NEW;
END
$profile_agent$;
CREATE CONSTRAINT TRIGGER tool_profile_model_agent
AFTER INSERT OR UPDATE ON tool_profile_revisions
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION require_model_agent_profile();

CREATE TABLE tool_profile_members (
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal > 0),
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  PRIMARY KEY (profile_key, profile_version, ordinal),
  UNIQUE (profile_key, profile_version, tool_key, tool_version),
  UNIQUE (profile_key, profile_version, ordinal, tool_key, tool_version),
  FOREIGN KEY (profile_key, profile_version)
    REFERENCES tool_profile_revisions(profile_key, version),
  FOREIGN KEY (tool_key, tool_version) REFERENCES tool_revisions(tool_key, version)
);
CREATE INDEX tool_profile_members_by_tool_idx
  ON tool_profile_members(tool_key, tool_version);

CREATE TABLE tool_profile_connection_requirements (
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal > 0),
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  binding_kind text NOT NULL CHECK
    (binding_kind IN ('COMPUTE_ONLY','POLICY_SOURCE_CONNECTION')),
  provider text,
  capability_key text,
  external_project_selector text,
  PRIMARY KEY (profile_key, profile_version, ordinal),
  FOREIGN KEY (profile_key, profile_version, ordinal, tool_key, tool_version)
    REFERENCES tool_profile_members(profile_key, profile_version, ordinal,
                                    tool_key, tool_version),
  CHECK (
    (binding_kind = 'COMPUTE_ONLY' AND provider IS NULL AND
      capability_key IS NULL AND external_project_selector IS NULL) OR
    (binding_kind = 'POLICY_SOURCE_CONNECTION' AND
      (provider,capability_key) IN
        (('CLOUD_MONITORING','METRIC_READ'),
         ('CLOUD_LOGGING','LOG_SEARCH'),('CLOUD_AUDIT','AUDIT_LOG_READ'),
         ('CLOUD_TRACE','TRACE_READ'),('ERROR_REPORTING','ERROR_GROUP_READ'),
         ('MANAGED_PROMETHEUS','PROMQL_READ'),
         ('KUBERNETES','KUBERNETES_METADATA_READ'),
         ('CLOUD_RUN','RESOURCE_METADATA_READ'),
         ('CLOUD_SQL','RESOURCE_METADATA_READ')) AND
      external_project_selector = 'TARGET_RESOURCE_PROJECT')
  )
);

CREATE FUNCTION validate_profile_requirement_shape() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $profile_requirement_shape$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tool_profile_members m
    LEFT JOIN tool_profile_connection_requirements r
      ON (r.profile_key,r.profile_version,r.ordinal,r.tool_key,r.tool_version) =
         (m.profile_key,m.profile_version,m.ordinal,m.tool_key,m.tool_version)
    WHERE r.ordinal IS NULL
  ) OR EXISTS (
    SELECT 1 FROM tool_profile_connection_requirements r
    LEFT JOIN tool_profile_members m
      ON (m.profile_key,m.profile_version,m.ordinal,m.tool_key,m.tool_version) =
         (r.profile_key,r.profile_version,r.ordinal,r.tool_key,r.tool_version)
    WHERE m.ordinal IS NULL
  ) THEN
    RAISE EXCEPTION 'a profile requires exactly one same-ordinal connection requirement per member';
  END IF;
  RETURN NULL;
END
$profile_requirement_shape$;
CREATE CONSTRAINT TRIGGER tool_profile_member_requirement_shape
AFTER INSERT OR UPDATE OR DELETE ON tool_profile_members
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION validate_profile_requirement_shape();
CREATE CONSTRAINT TRIGGER tool_profile_requirement_member_shape
AFTER INSERT OR UPDATE OR DELETE ON tool_profile_connection_requirements
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION validate_profile_requirement_shape();

CREATE FUNCTION reject_profile_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $profile_mutation$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tool_revisions
     WHERE tool_key = NEW.tool_key AND version = NEW.tool_version
       AND permission_class = 'MUTATE'
  ) THEN
    RAISE EXCEPTION 'a model-facing profile cannot contain a MUTATE Tool';
  END IF;
  RETURN NEW;
END
$profile_mutation$;
CREATE CONSTRAINT TRIGGER tool_profile_member_no_mutation
AFTER INSERT OR UPDATE ON tool_profile_members
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION reject_profile_mutation();

CREATE TABLE tool_probe_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tpr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  agent_key text NOT NULL,
  identity_ref text NOT NULL,
  registry_resource text NOT NULL,
  gateway_policy_ref text NOT NULL,
  network_policy_hash text NOT NULL CHECK
    (network_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  outcome text NOT NULL CHECK (outcome IN ('PASSED','FAILED')),
  reason_code text,
  missing_grant text,
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > observed_at),
  receipt_ref text NOT NULL,
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  trace_id text CHECK (trace_id IS NULL OR trace_id ~ '^[0-9a-f]{32}$'),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, connection_id)
    REFERENCES solvan.tenant_connections(organization_id, project_id, environment_id, id),
  FOREIGN KEY (tool_key, tool_version) REFERENCES tool_revisions(tool_key, version),
  FOREIGN KEY (agent_key) REFERENCES catalog_principals(principal_key),
  CHECK ((outcome = 'PASSED' AND reason_code IS NULL AND missing_grant IS NULL) OR
         (outcome = 'FAILED' AND reason_code IS NOT NULL AND missing_grant IS NOT NULL))
);
CREATE INDEX tool_probes_resolution_idx ON tool_probe_receipts
  (organization_id, project_id, environment_id, connection_id, tool_key,
   tool_version, agent_key, observed_at DESC);
CREATE INDEX tool_probes_expiry_idx ON tool_probe_receipts(expires_at)
  WHERE outcome = 'PASSED';

CREATE TABLE agent_run_tool_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  agent_run_id text NOT NULL,
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  profile_material_hash text NOT NULL CHECK
    (profile_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  accepted_tool_count integer NOT NULL CHECK (accepted_tool_count >= 0),
  effective_tool_set_hash text NOT NULL CHECK
    (effective_tool_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  identity_ref text NOT NULL,
  runtime_region text NOT NULL,
  accepted_data_classification text NOT NULL CHECK
    (accepted_data_classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  classification_ceiling text NOT NULL CHECK
    (classification_ceiling IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  policy_head_activation_id text,
  policy_head_epoch bigint NOT NULL CHECK (policy_head_epoch >= 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  accepted_step_budget_hash text NOT NULL CHECK
    (accepted_step_budget_hash ~ '^sha256:[0-9a-f]{64}$'),
  bound_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, agent_run_id),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES solvan.agent_runs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (profile_key, profile_version, profile_material_hash)
    REFERENCES tool_profile_revisions(profile_key, version, profile_material_hash),
  CHECK ((policy_head_activation_id IS NULL AND policy_head_epoch=0) OR
         (policy_head_activation_id IS NOT NULL AND policy_head_epoch > 0))
);

CREATE TABLE agent_run_accepted_tool_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  agent_run_id text NOT NULL,
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal > 0),
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  binding_kind text NOT NULL CHECK
    (binding_kind IN ('COMPUTE_ONLY','POLICY_SOURCE_CONNECTION')),
  provider text,
  capability_key text,
  external_project_selector text,
  connection_id text,
  connection_epoch bigint,
  capability_receipt_id text,
  capability_receipt_hash text,
  external_project_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, agent_run_id, ordinal),
  UNIQUE (organization_id, project_id, environment_id, agent_run_id, tool_key, tool_version),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES agent_run_tool_bindings(organization_id, project_id, environment_id, agent_run_id),
  FOREIGN KEY (profile_key, profile_version, ordinal, tool_key, tool_version)
    REFERENCES tool_profile_members(profile_key, profile_version, ordinal,
                                    tool_key, tool_version),
  FOREIGN KEY (profile_key, profile_version, ordinal)
    REFERENCES tool_profile_connection_requirements(profile_key, profile_version, ordinal),
  FOREIGN KEY (organization_id, project_id, environment_id, connection_id)
    REFERENCES solvan.tenant_connections(organization_id, project_id, environment_id, id),
  CHECK (
    (binding_kind = 'COMPUTE_ONLY' AND provider IS NULL AND capability_key IS NULL AND
      external_project_selector IS NULL AND connection_id IS NULL AND
      connection_epoch IS NULL AND capability_receipt_id IS NULL AND
      capability_receipt_hash IS NULL AND external_project_id IS NULL) OR
    (binding_kind = 'POLICY_SOURCE_CONNECTION' AND
      (provider,capability_key) IN
        (('CLOUD_MONITORING','METRIC_READ'),
         ('CLOUD_LOGGING','LOG_SEARCH'),('CLOUD_AUDIT','AUDIT_LOG_READ'),
         ('CLOUD_TRACE','TRACE_READ'),('ERROR_REPORTING','ERROR_GROUP_READ'),
         ('MANAGED_PROMETHEUS','PROMQL_READ'),
         ('KUBERNETES','KUBERNETES_METADATA_READ'),
         ('CLOUD_RUN','RESOURCE_METADATA_READ'),
         ('CLOUD_SQL','RESOURCE_METADATA_READ')) AND
      external_project_selector = 'TARGET_RESOURCE_PROJECT' AND
      connection_id IS NOT NULL AND connection_epoch > 0 AND capability_receipt_id IS NOT NULL AND
      capability_receipt_hash ~ '^sha256:[0-9a-f]{64}$' AND external_project_id ~ '^[a-z][a-z0-9-]{4,61}[a-z0-9]$')
  )
);

CREATE FUNCTION validate_accepted_tool_binding() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $accepted_tool_binding$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM agent_run_tool_bindings run
      JOIN tool_profile_connection_requirements requirement
        ON (requirement.profile_key,requirement.profile_version,requirement.ordinal) =
           (NEW.profile_key,NEW.profile_version,NEW.ordinal)
     WHERE (run.organization_id,run.project_id,run.environment_id,run.agent_run_id) =
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.agent_run_id)
       AND (run.profile_key,run.profile_version) = (NEW.profile_key,NEW.profile_version)
       AND requirement.binding_kind=NEW.binding_kind
       AND requirement.provider IS NOT DISTINCT FROM NEW.provider
       AND requirement.capability_key IS NOT DISTINCT FROM NEW.capability_key
       AND requirement.external_project_selector IS NOT DISTINCT FROM NEW.external_project_selector
  ) THEN
    RAISE EXCEPTION 'accepted Tool binding is not the exact profile requirement';
  END IF;
  RETURN NEW;
END
$accepted_tool_binding$;
CREATE CONSTRAINT TRIGGER accepted_tool_binding_exact_profile_requirement
AFTER INSERT OR UPDATE ON agent_run_accepted_tool_bindings
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION validate_accepted_tool_binding();

CREATE FUNCTION refuse_frozen_operability_history_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $frozen_operability_history$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '55000',
    MESSAGE = format('%s is immutable after insert', TG_TABLE_NAME);
END
$frozen_operability_history$;
CREATE TRIGGER agent_run_tool_binding_immutable
BEFORE UPDATE OR DELETE ON agent_run_tool_bindings
FOR EACH ROW EXECUTE FUNCTION refuse_frozen_operability_history_mutation();
CREATE TRIGGER agent_run_accepted_tool_binding_immutable
BEFORE UPDATE OR DELETE ON agent_run_accepted_tool_bindings
FOR EACH ROW EXECUTE FUNCTION refuse_frozen_operability_history_mutation();

CREATE FUNCTION require_agent_run_tool_binding() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, solvan, pg_temp
AS $run_binding$
BEGIN
  IF NEW.status IN ('DISPATCHED','RUNNING') AND
     (OLD.status IS DISTINCT FROM NEW.status) THEN
    IF NOT EXISTS (
      SELECT 1 FROM catalog_principals
       WHERE principal_key = NEW.agent_key AND registry_kind='AGENT' AND model_backed
    ) THEN
      RAISE EXCEPTION 'an Agent Runtime attempt requires a catalog principal';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM agent_run_tool_bindings b
       WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
         AND environment_id=NEW.environment_id AND agent_run_id=NEW.id
         AND NEW.effective_tool_set_hash IS NOT NULL
         AND b.effective_tool_set_hash=NEW.effective_tool_set_hash
         -- The accepted rows reconstruct the exact policy-narrowed subset.
         -- Every accepted row is separately constrained to one exact profile
         -- member/requirement; cardinality binds the frozen subset rather than
         -- widening it back to all profile members.
         AND (SELECT count(*)
                FROM agent_run_accepted_tool_bindings accepted
               WHERE accepted.organization_id=b.organization_id
                 AND accepted.project_id=b.project_id
                 AND accepted.environment_id=b.environment_id
                 AND accepted.agent_run_id=b.agent_run_id
                 AND accepted.profile_key=b.profile_key
                 AND accepted.profile_version=b.profile_version) =
             b.accepted_tool_count
    ) THEN
      RAISE EXCEPTION
        'an Agent Runtime attempt requires its exact frozen Tool binding';
    END IF;
  END IF;
  RETURN NEW;
END
$run_binding$;
CREATE CONSTRAINT TRIGGER agent_run_requires_tool_binding
AFTER UPDATE OF status ON solvan.agent_runs
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION require_agent_run_tool_binding();

CREATE TABLE tool_call_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  tool_call_id text NOT NULL,
  agent_run_id text NOT NULL,
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  accepted_binding_ordinal integer NOT NULL CHECK (accepted_binding_ordinal > 0),
  binding_kind text NOT NULL CHECK
    (binding_kind IN ('COMPUTE_ONLY','POLICY_SOURCE_CONNECTION')),
  connection_id text,
  connection_epoch bigint,
  capability_receipt_id text,
  capability_receipt_hash text,
  external_project_id text,
  identity_ref text NOT NULL,
  gateway_policy_ref text NOT NULL,
  gateway_decision_ref text,
  gateway_attestation_status text NOT NULL CHECK
    (gateway_attestation_status IN ('PENDING','VERIFIED','UNAVAILABLE')),
  input_bytes integer NOT NULL CHECK (input_bytes >= 0),
  output_bytes integer CHECK (output_bytes IS NULL OR output_bytes >= 0),
  cache_status text NOT NULL CHECK
    (cache_status IN ('MISS','HIT','NOT_APPLICABLE')),
  otel_span_id text NOT NULL CHECK (otel_span_id ~ '^[0-9a-f]{16}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, tool_call_id),
  FOREIGN KEY (organization_id, project_id, environment_id, tool_call_id)
    REFERENCES solvan.tool_calls(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES agent_run_tool_bindings(organization_id, project_id, environment_id,
                                       agent_run_id),
  FOREIGN KEY (tool_key, tool_version) REFERENCES tool_revisions(tool_key, version),
  FOREIGN KEY (profile_key, profile_version)
    REFERENCES tool_profile_revisions(profile_key, version),
  CHECK ((gateway_attestation_status = 'VERIFIED') =
         (gateway_decision_ref IS NOT NULL)),
  CHECK ((completed_at IS NULL) = (output_bytes IS NULL)),
  CHECK (
    (binding_kind = 'COMPUTE_ONLY' AND connection_id IS NULL AND connection_epoch IS NULL AND
      capability_receipt_id IS NULL AND capability_receipt_hash IS NULL AND external_project_id IS NULL) OR
    (binding_kind = 'POLICY_SOURCE_CONNECTION' AND connection_id IS NOT NULL AND
      connection_epoch > 0 AND capability_receipt_id IS NOT NULL AND
      capability_receipt_hash ~ '^sha256:[0-9a-f]{64}$' AND external_project_id IS NOT NULL)
  )
);
CREATE INDEX tool_call_receipts_run_idx ON tool_call_receipts
  (organization_id, project_id, environment_id, agent_run_id, created_at);
CREATE INDEX tool_call_receipts_profile_idx ON tool_call_receipts
  (profile_key, profile_version, tool_key, tool_version, created_at);

CREATE FUNCTION validate_tool_call_receipt_binding() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, solvan, pg_temp
AS $tool_call_binding$
DECLARE
  call_row record;
  binding_row record;
BEGIN
  SELECT agent_run_id, tool_name INTO call_row
    FROM solvan.tool_calls
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND id=NEW.tool_call_id;
  SELECT profile_key, profile_version, identity_ref
    INTO binding_row
    FROM agent_run_tool_bindings
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND agent_run_id=NEW.agent_run_id;
  IF call_row.agent_run_id IS DISTINCT FROM NEW.agent_run_id OR
     call_row.tool_name IS DISTINCT FROM NEW.tool_key OR
     binding_row.profile_key IS DISTINCT FROM NEW.profile_key OR
     binding_row.profile_version IS DISTINCT FROM NEW.profile_version OR
     binding_row.identity_ref IS DISTINCT FROM NEW.identity_ref OR NOT EXISTS (
       SELECT 1 FROM agent_run_accepted_tool_bindings accepted
        WHERE accepted.organization_id=NEW.organization_id
          AND accepted.project_id=NEW.project_id
          AND accepted.environment_id=NEW.environment_id
          AND accepted.agent_run_id=NEW.agent_run_id
          AND accepted.profile_key=NEW.profile_key
          AND accepted.profile_version=NEW.profile_version
          AND accepted.ordinal=NEW.accepted_binding_ordinal
          AND accepted.tool_key=NEW.tool_key AND accepted.tool_version=NEW.tool_version
          AND accepted.binding_kind=NEW.binding_kind
          AND accepted.connection_id IS NOT DISTINCT FROM NEW.connection_id
          AND accepted.connection_epoch IS NOT DISTINCT FROM NEW.connection_epoch
          AND accepted.capability_receipt_id IS NOT DISTINCT FROM NEW.capability_receipt_id
          AND accepted.capability_receipt_hash IS NOT DISTINCT FROM NEW.capability_receipt_hash
          AND accepted.external_project_id IS NOT DISTINCT FROM NEW.external_project_id
     )
  THEN
    RAISE EXCEPTION 'Tool call receipt does not match the frozen run binding';
  END IF;
  RETURN NEW;
END
$tool_call_binding$;
CREATE CONSTRAINT TRIGGER tool_call_receipt_exact_binding
AFTER INSERT OR UPDATE ON tool_call_receipts
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION validate_tool_call_receipt_binding();

-- Operational Guidance -----------------------------------------------------

CREATE TABLE operability_role_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  principal text NOT NULL,
  role text NOT NULL CHECK (role IN
    ('GUIDANCE_AUTHOR','GUIDANCE_EVALUATOR','GUIDANCE_APPROVER','GUIDANCE_EXPORTER',
     'TRIGGER_POLICY_AUTHOR','TRIGGER_POLICY_EVALUATOR',
     'TRIGGER_POLICY_APPROVER','TRIGGER_POLICY_ACTIVATOR',
     'TRIGGER_POLICY_LIFECYCLE_MANAGER','OPERABILITY_ADMIN')),
  department text NOT NULL,
  granted_by text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, principal, role, department),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id),
  CHECK (expires_at IS NULL OR expires_at > granted_at)
);
CREATE INDEX operability_roles_principal_idx ON operability_role_bindings
  (organization_id, project_id, environment_id, principal, expires_at);

CREATE TABLE operability_audit_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^goa_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  principal text NOT NULL,
  event_type text NOT NULL,
  entity_ref text NOT NULL,
  material_digest text NOT NULL CHECK (material_digest ~ '^sha256:[0-9a-f]{64}$'),
  decision_request_id text NOT NULL CHECK (length(decision_request_id) BETWEEN 8 AND 128),
  reason_code text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, decision_request_id),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments(organization_id, project_id, id)
);
CREATE INDEX operability_audit_entity_idx ON operability_audit_events
  (organization_id, project_id, environment_id, entity_ref, occurred_at DESC);

CREATE TABLE guidance_definitions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL CHECK
    (guidance_key ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'),
  display_name text NOT NULL,
  owner_department text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, guidance_key)
);

CREATE TABLE guidance_revisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  version text NOT NULL,
  description text NOT NULL,
  discoverable_departments_json jsonb NOT NULL CHECK
    (jsonb_typeof(discoverable_departments_json) = 'array' AND
     jsonb_array_length(discoverable_departments_json) > 0),
  guidance_kind text NOT NULL CHECK (guidance_kind IN
    ('RUNBOOK','SKILL','CHECKLIST','DIAGNOSTIC_PROCEDURE')),
  applicable_service_kinds_json jsonb NOT NULL,
  applicable_incident_classes_json jsonb NOT NULL,
  symptom_tags_json jsonb NOT NULL,
  purpose text NOT NULL,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  eligible_regions_json jsonb NOT NULL CHECK
    (jsonb_typeof(eligible_regions_json) = 'array' AND
     jsonb_array_length(eligible_regions_json) > 0),
  content_ref text NOT NULL,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  revision_hash text NOT NULL CHECK (revision_hash ~ '^sha256:[0-9a-f]{64}$'),
  source_kind text NOT NULL CHECK
    (source_kind IN ('SOLVAN_AUTHORED','CUSTOMER_AUTHORED','IMPORTED')),
  source_ref text NOT NULL,
  source_license text,
  evaluation_ref text,
  approval_ref text,
  approved_digest text CHECK
    (approved_digest IS NULL OR approved_digest ~ '^sha256:[0-9a-f]{64}$'),
  author_principal text NOT NULL,
  approved_by_principal text,
  supersedes_version text,
  lifecycle text NOT NULL CHECK (lifecycle IN
    ('DRAFT','IN_REVIEW','APPROVED','DEPRECATED','RETIRED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  -- Revision identity is (guidance_key, version). Content is deliberately not
  -- unique per key: a metadata-only successor legitimately reuses the same
  -- content_hash (spec 17 §5; spec 18 §7.5).
  PRIMARY KEY (organization_id, project_id, environment_id, guidance_key, version),
  -- The lineage is a non-branching chain: at most one successor per
  -- predecessor (spec 18 §7.5). Concurrent successor proposals conflict here.
  UNIQUE (organization_id, project_id, environment_id, guidance_key, supersedes_version),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key)
    REFERENCES guidance_definitions(organization_id, project_id, environment_id, guidance_key),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key, supersedes_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version),
  CHECK (source_kind <> 'IMPORTED' OR source_license IS NOT NULL),
  CHECK (lifecycle <> 'APPROVED' OR
    (evaluation_ref IS NOT NULL AND approval_ref IS NOT NULL AND
     approved_digest = revision_hash AND approved_by_principal IS NOT NULL AND
     approved_at IS NOT NULL AND approved_by_principal <> author_principal)),
  CHECK (supersedes_version IS NULL OR supersedes_version <> version)
);
CREATE INDEX guidance_discovery_idx ON guidance_revisions
  (organization_id, project_id, environment_id, lifecycle, classification, created_at DESC);

-- Exactly one lineage root per key: NULL predecessors are not distinct here.
CREATE UNIQUE INDEX guidance_revisions_one_root
  ON guidance_revisions (organization_id, project_id, environment_id, guidance_key)
  WHERE supersedes_version IS NULL;

CREATE TABLE guidance_revision_agents (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  agent_key text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version, agent_key),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version),
  FOREIGN KEY (agent_key) REFERENCES catalog_principals(principal_key)
);

CREATE TABLE guidance_revision_profiles (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version, profile_key, profile_version),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version),
  FOREIGN KEY (profile_key, profile_version)
    REFERENCES tool_profile_revisions(profile_key, version)
);

CREATE TABLE guidance_steps (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  step_key text NOT NULL CHECK (step_key ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'),
  ordinal integer NOT NULL CHECK (ordinal > 0),
  title text NOT NULL,
  objective text NOT NULL,
  step_kind text NOT NULL CHECK
    (step_kind IN ('OBSERVE','COMPUTE','PROPOSE','CHECKPOINT')),
  prerequisite_step_keys_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK
    (jsonb_typeof(prerequisite_step_keys_json) = 'array'),
  completion_predicate_key text NOT NULL,
  completion_predicate_version text NOT NULL,
  required_evidence_kinds_json jsonb NOT NULL CHECK
    (jsonb_typeof(required_evidence_kinds_json) = 'array' AND
     jsonb_array_length(required_evidence_kinds_json) > 0),
  maximum_tool_requests integer NOT NULL CHECK (maximum_tool_requests BETWEEN 0 AND 100),
  on_blocked text NOT NULL CHECK
    (on_blocked IN ('CONTINUE','STOP_INCONCLUSIVE','ESCALATE')),
  PRIMARY KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version, step_key),
  UNIQUE (organization_id, project_id, environment_id,
          guidance_key, guidance_version, ordinal),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version)
);

CREATE TABLE guidance_step_tools (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  step_key text NOT NULL,
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version, step_key, tool_key, tool_version),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version, step_key)
    REFERENCES guidance_steps(organization_id, project_id, environment_id,
                              guidance_key, guidance_version, step_key),
  FOREIGN KEY (tool_key, tool_version) REFERENCES tool_revisions(tool_key, version)
);

CREATE TABLE guidance_ingestion_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gir_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  decision text NOT NULL CHECK (decision IN ('ACCEPTED','REJECTED')),
  reason_codes_json jsonb NOT NULL CHECK
    (jsonb_typeof(reason_codes_json) = 'array' AND
     jsonb_array_length(reason_codes_json) > 0),
  armor_verdict_ref text,
  evaluated_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version)
);

CREATE TABLE guidance_evaluations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gev_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  revision_digest text NOT NULL CHECK (revision_digest ~ '^sha256:[0-9a-f]{64}$'),
  suite_version text NOT NULL CHECK (length(suite_version) BETWEEN 1 AND 120),
  decision text NOT NULL CHECK (decision IN ('PASS','FAIL')),
  passed_cases integer NOT NULL CHECK (passed_cases >= 0),
  failed_cases integer NOT NULL CHECK (failed_cases >= 0),
  receipt_ref text NOT NULL,
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  evaluator_principal text NOT NULL,
  reason_codes_json jsonb NOT NULL CHECK
    (jsonb_typeof(reason_codes_json) = 'array' AND
     jsonb_array_length(reason_codes_json) > 0),
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id,
          guidance_key, guidance_version, revision_digest, suite_version),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version),
  CHECK ((decision = 'PASS') = (failed_cases = 0)),
  CHECK (passed_cases + failed_cases > 0)
);
CREATE INDEX guidance_evaluations_revision_idx ON guidance_evaluations
  (organization_id, project_id, environment_id,
   guidance_key, guidance_version, evaluated_at DESC);

CREATE TABLE guidance_approvals (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gap_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  revision_digest text NOT NULL CHECK (revision_digest ~ '^sha256:[0-9a-f]{64}$'),
  evaluation_ref text NOT NULL,
  approver_principal text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
  decision_request_id text NOT NULL CHECK (length(decision_request_id) BETWEEN 8 AND 128),
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, decision_request_id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version)
);

ALTER TABLE guidance_revisions
  ADD FOREIGN KEY (organization_id, project_id, environment_id, approval_ref)
  REFERENCES guidance_approvals(organization_id, project_id, environment_id, id);
ALTER TABLE guidance_revisions
  ADD FOREIGN KEY (organization_id, project_id, environment_id, evaluation_ref)
  REFERENCES guidance_evaluations(organization_id, project_id, environment_id, id);

CREATE TABLE guidance_selections (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gsl_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  agent_run_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  guidance_hash text NOT NULL CHECK (guidance_hash ~ '^sha256:[0-9a-f]{64}$'),
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  profile_material_hash text NOT NULL CHECK
    (profile_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  connection_epochs_json jsonb NOT NULL CHECK
    (jsonb_typeof(connection_epochs_json) = 'object' AND
     connection_epochs_json <> '{}'::jsonb),
  selection_role text NOT NULL CHECK (selection_role IN ('PRIMARY','SUPPORTING')),
  selection_reason text NOT NULL,
  selected_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, agent_run_id,
          guidance_key, guidance_version),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES solvan.agent_runs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version),
  FOREIGN KEY (profile_key, profile_version)
    REFERENCES tool_profile_revisions(profile_key, version)
);
CREATE UNIQUE INDEX guidance_one_primary_per_run_idx ON guidance_selections
  (organization_id, project_id, environment_id, agent_run_id)
  WHERE selection_role = 'PRIMARY';

CREATE TABLE guidance_step_runs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gsr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  selection_id text NOT NULL,
  step_key text NOT NULL,
  status text NOT NULL CHECK (status IN
    ('PENDING','RUNNING','SATISFIED','NOT_SATISFIED','BLOCKED',
     'SKIPPED_POLICY','NOT_APPLICABLE','ERROR')),
  predicate_key text NOT NULL,
  predicate_version text NOT NULL,
  predicate_result_ref text,
  cited_records_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK
    (jsonb_typeof(cited_records_json) = 'array'),
  reason_code text,
  tool_requests integer NOT NULL DEFAULT 0 CHECK (tool_requests >= 0),
  started_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, selection_id, step_key),
  FOREIGN KEY (organization_id, project_id, environment_id, selection_id)
    REFERENCES guidance_selections(organization_id, project_id, environment_id, id),
  CHECK (status NOT IN ('SATISFIED','NOT_SATISFIED','NOT_APPLICABLE') OR
    (predicate_result_ref IS NOT NULL AND jsonb_array_length(cited_records_json) > 0)),
  CHECK (status NOT IN ('BLOCKED','SKIPPED_POLICY','ERROR') OR reason_code IS NOT NULL),
  CHECK (status IN ('PENDING','RUNNING') OR completed_at IS NOT NULL)
);

CREATE TABLE guidance_step_tool_calls (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  step_run_id text NOT NULL,
  tool_call_id text NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, step_run_id, tool_call_id),
  FOREIGN KEY (organization_id, project_id, environment_id, step_run_id)
    REFERENCES guidance_step_runs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, tool_call_id)
    REFERENCES tool_call_receipts(organization_id, project_id, environment_id, tool_call_id)
);
CREATE INDEX guidance_step_tool_calls_receipt_idx ON guidance_step_tool_calls
  (organization_id, project_id, environment_id, tool_call_id);

CREATE FUNCTION require_guidance_step_tool_call() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, solvan, pg_temp
AS $guidance_step_tool_call$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM guidance_step_runs sr
      JOIN guidance_selections s ON
        (s.organization_id,s.project_id,s.environment_id,s.id)=
        (sr.organization_id,sr.project_id,sr.environment_id,sr.selection_id)
      JOIN guidance_steps gs ON
        (gs.organization_id,gs.project_id,gs.environment_id,gs.guidance_key,
         gs.guidance_version,gs.step_key)=
        (s.organization_id,s.project_id,s.environment_id,s.guidance_key,
         s.guidance_version,sr.step_key)
      JOIN guidance_step_tools gst ON
        (gst.organization_id,gst.project_id,gst.environment_id,gst.guidance_key,
         gst.guidance_version,gst.step_key)=
        (s.organization_id,s.project_id,s.environment_id,s.guidance_key,
         s.guidance_version,sr.step_key)
      JOIN tool_call_receipts tcr ON
        (tcr.organization_id,tcr.project_id,tcr.environment_id,tcr.tool_call_id,
         tcr.agent_run_id,tcr.tool_key,tcr.tool_version)=
        (s.organization_id,s.project_id,s.environment_id,NEW.tool_call_id,
         s.agent_run_id,gst.tool_key,gst.tool_version)
     WHERE (sr.organization_id,sr.project_id,sr.environment_id,sr.id)=
       (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.step_run_id)
       AND (
         SELECT count(*)
           FROM guidance_step_tool_calls linked
          WHERE (linked.organization_id,linked.project_id,linked.environment_id,
                 linked.step_run_id)=
                (NEW.organization_id,NEW.project_id,NEW.environment_id,
                 NEW.step_run_id)
       ) <= gs.maximum_tool_requests
  ) THEN
    RAISE EXCEPTION
      'a guidance step may cite only bounded, allowed, same-run Tool receipts';
  END IF;
  UPDATE guidance_step_runs
     SET tool_requests=(
       SELECT count(*) FROM guidance_step_tool_calls linked
        WHERE (linked.organization_id,linked.project_id,linked.environment_id,
               linked.step_run_id)=
              (NEW.organization_id,NEW.project_id,NEW.environment_id,
               NEW.step_run_id)
     )
   WHERE (organization_id,project_id,environment_id,id)=
         (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.step_run_id);
  RETURN NEW;
END
$guidance_step_tool_call$;
CREATE CONSTRAINT TRIGGER guidance_step_tool_call_exact
AFTER INSERT OR UPDATE ON guidance_step_tool_calls
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION require_guidance_step_tool_call();

-- Trigger policies ---------------------------------------------------------

CREATE TABLE trigger_policy_revisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  policy_key text NOT NULL CHECK (policy_key ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'),
  version text NOT NULL,
  owner_department text NOT NULL,
  trigger_kind text NOT NULL CHECK (trigger_kind IN
    ('DEPLOYMENT_ROLLOUT','ALERT_OPENED','ERROR_SIGNATURE','SCHEDULE',
     'RECURRENCE_DUE','VERIFICATION_DUE')),
  source_connection_id text NOT NULL,
  source_connection_epoch bigint NOT NULL CHECK (source_connection_epoch > 0),
  source_tool_key text NOT NULL,
  source_tool_version text NOT NULL,
  source_agent_key text NOT NULL,
  source_identity_ref text NOT NULL CHECK (length(source_identity_ref) BETWEEN 1 AND 512),
  source_capability_class text NOT NULL CHECK (source_capability_class IN
    ('LOG_SEARCH','METRIC_READ','AUDIT_LOG_READ','TRACE_READ',
     'ERROR_GROUP_READ','ASSET_SEARCH','RESOURCE_ADMIN_READ',
     'RESOURCE_METADATA_READ')),
  target_selector_ref text NOT NULL,
  incident_class text NOT NULL CHECK (incident_class ~ '^[a-z][a-z0-9_]{2,79}$'),
  severity text NOT NULL CHECK (severity IN ('SEV1','SEV2','SEV3','SEV4')),
  deduplication_dimension text NOT NULL CHECK
    (deduplication_dimension ~ '^[a-z][a-z0-9_-]{1,79}$'),
  action_budget integer NOT NULL CHECK (action_budget BETWEEN 1 AND 10),
  repeated_action_limit integer NOT NULL CHECK (repeated_action_limit BETWEEN 1 AND 3),
  guidance_key text,
  guidance_version text,
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  delay_ms bigint NOT NULL CHECK (delay_ms BETWEEN 0 AND 604800000),
  cooldown_ms bigint NOT NULL CHECK (cooldown_ms BETWEEN 0 AND 2592000000),
  maximum_pending_per_target integer NOT NULL CHECK
    (maximum_pending_per_target BETWEEN 1 AND 100),
  supersession text NOT NULL CHECK
    (supersession IN ('KEEP_ALL','LATEST_WAITING_PER_TARGET')),
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  lifecycle text NOT NULL CHECK
    (lifecycle IN ('DRAFT','APPROVED')),
  author_principal text NOT NULL,
  approved_by_principal text,
  approval_ref text,
  evaluation_ref text,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, policy_key, version),
  UNIQUE (organization_id, project_id, environment_id, policy_key, version,
          policy_hash),
  UNIQUE (organization_id, project_id, environment_id, policy_key, version,
          policy_hash, evaluation_ref, approval_ref, source_connection_epoch,
          supersession),
  FOREIGN KEY (organization_id, project_id, environment_id, source_connection_id)
    REFERENCES solvan.tenant_connections(organization_id, project_id, environment_id, id),
  FOREIGN KEY (source_tool_key, source_tool_version)
    REFERENCES tool_revisions(tool_key, version),
  FOREIGN KEY (source_tool_key, source_tool_version, source_agent_key)
    REFERENCES tool_revision_requesters(tool_key, tool_version, requester_key),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES guidance_revisions(organization_id, project_id, environment_id,
                                  guidance_key, version),
  FOREIGN KEY (profile_key, profile_version)
    REFERENCES tool_profile_revisions(profile_key, version),
  CHECK ((guidance_key IS NULL) = (guidance_version IS NULL)),
  CHECK (repeated_action_limit <= action_budget),
  CHECK (lifecycle <> 'APPROVED' OR
    (approval_ref IS NOT NULL AND evaluation_ref IS NOT NULL AND
     approved_by_principal IS NOT NULL AND approved_at IS NOT NULL AND
     approved_by_principal <> author_principal))
);

ALTER TABLE solvan.incidents
  ADD CONSTRAINT incidents_trigger_policy_fk
  FOREIGN KEY (organization_id, project_id, environment_id,
               trigger_policy_key, trigger_policy_version)
  REFERENCES trigger_policy_revisions
    (organization_id, project_id, environment_id, policy_key, version);

CREATE TABLE trigger_policy_evaluations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tev_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  policy_key text NOT NULL,
  policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  suite_version text NOT NULL CHECK (length(suite_version) BETWEEN 1 AND 120),
  decision text NOT NULL CHECK (decision IN ('PASS','FAIL')),
  passed_cases integer NOT NULL CHECK (passed_cases >= 0),
  failed_cases integer NOT NULL CHECK (failed_cases >= 0),
  receipt_ref text NOT NULL,
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  evaluator_principal text NOT NULL,
  reason_codes_json jsonb NOT NULL CHECK
    (jsonb_typeof(reason_codes_json) = 'array' AND
     jsonb_array_length(reason_codes_json) > 0),
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id,
          policy_key, policy_version, policy_hash, suite_version),
  UNIQUE (organization_id, project_id, environment_id, id, policy_key,
          policy_version, policy_hash, decision),
  FOREIGN KEY (organization_id, project_id, environment_id, policy_key, policy_version)
    REFERENCES trigger_policy_revisions(organization_id, project_id, environment_id,
                                        policy_key, version),
  CHECK ((decision = 'PASS') = (failed_cases = 0)),
  CHECK (passed_cases + failed_cases > 0)
);

CREATE TABLE trigger_policy_approvals (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tap_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  policy_key text NOT NULL,
  policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  evaluation_ref text NOT NULL,
  evaluation_decision text NOT NULL DEFAULT 'PASS' CHECK (evaluation_decision = 'PASS'),
  approver_principal text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
  decision_request_id text NOT NULL CHECK (length(decision_request_id) BETWEEN 8 AND 128),
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, decision_request_id),
  UNIQUE (organization_id, project_id, environment_id, id, policy_key,
          policy_version, policy_hash, evaluation_ref, decision),
  FOREIGN KEY (organization_id, project_id, environment_id, policy_key, policy_version)
    REFERENCES trigger_policy_revisions(organization_id, project_id, environment_id,
                                        policy_key, version),
  FOREIGN KEY (organization_id, project_id, environment_id, evaluation_ref)
    REFERENCES trigger_policy_evaluations(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, evaluation_ref,
               policy_key, policy_version, policy_hash, evaluation_decision)
    REFERENCES trigger_policy_evaluations
      (organization_id, project_id, environment_id, id, policy_key,
       policy_version, policy_hash, decision)
);

CREATE FUNCTION validate_trigger_policy_approval() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $trigger_policy_approval$
DECLARE
  revision_author text;
  evaluation_actor text;
BEGIN
  SELECT author_principal INTO revision_author
    FROM trigger_policy_revisions
   WHERE (organization_id,project_id,environment_id,policy_key,version,policy_hash)=
         (NEW.organization_id,NEW.project_id,NEW.environment_id,
          NEW.policy_key,NEW.policy_version,NEW.policy_hash);
  SELECT evaluator_principal INTO evaluation_actor
    FROM trigger_policy_evaluations
   WHERE (organization_id,project_id,environment_id,id,policy_key,
          policy_version,policy_hash,decision)=
         (NEW.organization_id,NEW.project_id,NEW.environment_id,
          NEW.evaluation_ref,NEW.policy_key,NEW.policy_version,
          NEW.policy_hash,'PASS');
  IF revision_author IS NULL OR evaluation_actor IS NULL OR
     revision_author = evaluation_actor OR
     NEW.approver_principal IN (revision_author,evaluation_actor) THEN
    RAISE EXCEPTION 'trigger policy author, evaluator, and approver must be distinct';
  END IF;
  RETURN NEW;
END
$trigger_policy_approval$;
CREATE CONSTRAINT TRIGGER trigger_policy_approval_separation
AFTER INSERT OR UPDATE ON trigger_policy_approvals
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION validate_trigger_policy_approval();

ALTER TABLE trigger_policy_revisions
  ADD FOREIGN KEY (organization_id, project_id, environment_id, approval_ref)
  REFERENCES trigger_policy_approvals(organization_id, project_id, environment_id, id);
ALTER TABLE trigger_policy_revisions
  ADD FOREIGN KEY (organization_id, project_id, environment_id, evaluation_ref)
  REFERENCES trigger_policy_evaluations(organization_id, project_id, environment_id, id);

CREATE TABLE trigger_policy_activations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tpa_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  policy_key text NOT NULL, policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  activation_kind text NOT NULL CHECK (activation_kind IN ('ACTIVATE','DEACTIVATE','REPLACE')),
  head_epoch bigint NOT NULL CHECK (head_epoch > 0),
  expected_prior_head_epoch bigint NOT NULL CHECK (expected_prior_head_epoch >= 0),
  expected_activation_id text, evaluation_ref text NOT NULL,
  evaluation_decision text NOT NULL DEFAULT 'PASS' CHECK (evaluation_decision = 'PASS'),
  approval_ref text NOT NULL,
  approval_decision text NOT NULL DEFAULT 'APPROVE' CHECK (approval_decision = 'APPROVE'),
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  supersession text NOT NULL CHECK
    (supersession IN ('KEEP_ALL','LATEST_WAITING_PER_TARGET')),
  actor_principal text NOT NULL, idempotency_key text NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  reason_code text NOT NULL, activated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,policy_key,head_epoch),
  UNIQUE (organization_id,project_id,environment_id,id,policy_key,policy_version,
          policy_hash,head_epoch),
  UNIQUE (organization_id,project_id,environment_id,id,policy_key,policy_version,
          policy_hash,head_epoch,activation_kind),
  UNIQUE (organization_id,project_id,environment_id,id,policy_key,policy_version,
          policy_hash,head_epoch,connection_epoch,placement_epoch,supersession),
  UNIQUE (organization_id,project_id,environment_id,id,policy_key,policy_version,
          policy_hash,head_epoch,activation_kind,connection_epoch,
          placement_epoch,supersession),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key,request_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key,policy_version,
               policy_hash,evaluation_ref,approval_ref,connection_epoch,supersession)
    REFERENCES trigger_policy_revisions
      (organization_id,project_id,environment_id,policy_key,version,policy_hash,
       evaluation_ref,approval_ref,source_connection_epoch,supersession),
  FOREIGN KEY (organization_id,project_id,environment_id,evaluation_ref,
               policy_key,policy_version,policy_hash,evaluation_decision)
    REFERENCES trigger_policy_evaluations
      (organization_id,project_id,environment_id,id,policy_key,policy_version,
       policy_hash,decision),
  FOREIGN KEY (organization_id,project_id,environment_id,approval_ref,
               policy_key,policy_version,policy_hash,evaluation_ref,approval_decision)
    REFERENCES trigger_policy_approvals
      (organization_id,project_id,environment_id,id,policy_key,policy_version,
       policy_hash,evaluation_ref,decision),
  CHECK ((activation_kind='ACTIVATE' AND
          ((expected_prior_head_epoch=0 AND expected_activation_id IS NULL) OR
           (expected_prior_head_epoch > 0 AND expected_activation_id IS NOT NULL))) OR
         (activation_kind IN ('DEACTIVATE','REPLACE') AND
          expected_prior_head_epoch > 0 AND expected_activation_id IS NOT NULL))
);
CREATE TABLE trigger_policy_current_heads (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  policy_key text NOT NULL, head_epoch bigint NOT NULL CHECK (head_epoch > 0),
  activation_id text NOT NULL, policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  activation_kind text NOT NULL CHECK
    (activation_kind IN ('ACTIVATE','DEACTIVATE','REPLACE')),
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  supersession text NOT NULL CHECK
    (supersession IN ('KEEP_ALL','LATEST_WAITING_PER_TARGET')),
  is_current boolean NOT NULL DEFAULT true,
  PRIMARY KEY (organization_id,project_id,environment_id,policy_key),
  FOREIGN KEY (organization_id,project_id,environment_id,activation_id,policy_key,
               policy_version,policy_hash,head_epoch,activation_kind,connection_epoch,
               placement_epoch,supersession)
    REFERENCES trigger_policy_activations
      (organization_id,project_id,environment_id,id,policy_key,policy_version,
       policy_hash,head_epoch,activation_kind,connection_epoch,placement_epoch,supersession),
  CHECK (is_current = (activation_kind IN ('ACTIVATE','REPLACE')))
);
CREATE TABLE trigger_policy_lifecycle_decisions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tpl_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  policy_key text NOT NULL, policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  lifecycle_epoch bigint NOT NULL CHECK (lifecycle_epoch > 0),
  expected_prior_lifecycle_epoch bigint NOT NULL CHECK (expected_prior_lifecycle_epoch >= 0),
  operation text NOT NULL CHECK (operation IN ('MARK_ELIGIBLE','RETIRE')),
  actor_principal text NOT NULL,
  idempotency_key text NOT NULL, request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  reason_code text NOT NULL, decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,policy_key,policy_version,lifecycle_epoch),
  UNIQUE (organization_id,project_id,environment_id,id,policy_key,policy_version,
          policy_hash,lifecycle_epoch,operation),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key,request_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key,
               policy_version,policy_hash)
    REFERENCES trigger_policy_revisions
      (organization_id,project_id,environment_id,policy_key,version,policy_hash),
  CHECK ((operation='MARK_ELIGIBLE' AND lifecycle_epoch=1 AND
          expected_prior_lifecycle_epoch=0) OR
         (operation='RETIRE' AND lifecycle_epoch > 1 AND
          expected_prior_lifecycle_epoch=lifecycle_epoch-1))
);
CREATE TABLE trigger_policy_current_lifecycles (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  policy_key text NOT NULL, policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  lifecycle_epoch bigint NOT NULL,
  availability text NOT NULL CHECK (availability IN ('ELIGIBLE','RETIRED')),
  decision_id text NOT NULL,
  decision_operation text NOT NULL CHECK
    (decision_operation IN ('MARK_ELIGIBLE','RETIRE')),
  PRIMARY KEY (organization_id,project_id,environment_id,policy_key,policy_version),
  FOREIGN KEY (organization_id,project_id,environment_id,decision_id,policy_key,
               policy_version,policy_hash,lifecycle_epoch,decision_operation)
    REFERENCES trigger_policy_lifecycle_decisions
      (organization_id,project_id,environment_id,id,policy_key,policy_version,
       policy_hash,lifecycle_epoch,operation),
  UNIQUE (organization_id,project_id,environment_id,policy_key,policy_version,
          policy_hash,lifecycle_epoch,decision_id,availability),
  CHECK ((availability='ELIGIBLE' AND decision_operation='MARK_ELIGIBLE') OR
         (availability='RETIRED' AND decision_operation='RETIRE'))
);
CREATE TABLE trigger_policy_replacement_intents (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tpr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  retiring_policy_key text NOT NULL, retiring_policy_version text NOT NULL,
  retiring_policy_hash text NOT NULL CHECK (retiring_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  expected_head_epoch bigint NOT NULL,
  expected_activation_id text NOT NULL, successor_policy_key text NOT NULL,
  successor_version text NOT NULL, successor_hash text NOT NULL CHECK (successor_hash ~ '^sha256:[0-9a-f]{64}$'),
  successor_evaluation_ref text NOT NULL, successor_approval_ref text NOT NULL,
  successor_supersession text NOT NULL CHECK
    (successor_supersession IN ('KEEP_ALL','LATEST_WAITING_PER_TARGET')),
  connection_epoch bigint NOT NULL, placement_epoch bigint NOT NULL,
  expected_lifecycle_epoch bigint NOT NULL CHECK (expected_lifecycle_epoch > 0),
  actor_principal text NOT NULL, idempotency_key text NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  compound_request_hash text NOT NULL CHECK (compound_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key),
  UNIQUE (organization_id,project_id,environment_id,compound_request_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,expected_activation_id,
               retiring_policy_key,retiring_policy_version,retiring_policy_hash,
               expected_head_epoch)
    REFERENCES trigger_policy_activations
      (organization_id,project_id,environment_id,id,policy_key,policy_version,
       policy_hash,head_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,successor_policy_key,
               successor_version,successor_hash,successor_evaluation_ref,
               successor_approval_ref,connection_epoch,successor_supersession)
    REFERENCES trigger_policy_revisions
      (organization_id,project_id,environment_id,policy_key,version,policy_hash,
       evaluation_ref,approval_ref,source_connection_epoch,supersession),
  CHECK (expected_lifecycle_epoch > 0),
  CHECK (successor_policy_key = retiring_policy_key)
);

CREATE TABLE trigger_policy_replacement_consumptions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  replacement_intent_id text NOT NULL,
  lifecycle_decision_id text NOT NULL,
  consumed_by_principal text NOT NULL,
  consumed_request_hash text NOT NULL CHECK
    (consumed_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,replacement_intent_id),
  UNIQUE (organization_id,project_id,environment_id,lifecycle_decision_id),
  FOREIGN KEY (organization_id,project_id,environment_id,replacement_intent_id)
    REFERENCES trigger_policy_replacement_intents
      (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,lifecycle_decision_id)
    REFERENCES trigger_policy_lifecycle_decisions
      (organization_id,project_id,environment_id,id)
);

CREATE FUNCTION validate_trigger_policy_authority_actor() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $trigger_policy_authority_actor$
DECLARE
  required_role text;
  primary_department text;
  secondary_department text;
  primary_author text;
  primary_approver text;
  secondary_author text;
  secondary_approver text;
BEGIN
  IF TG_TABLE_NAME = 'trigger_policy_activations' THEN
    required_role := CASE
      WHEN NEW.activation_kind='DEACTIVATE' AND NEW.reason_code='POLICY_RETIRED'
        THEN 'TRIGGER_POLICY_LIFECYCLE_MANAGER'
      ELSE 'TRIGGER_POLICY_ACTIVATOR'
    END;
    SELECT owner_department,author_principal,approved_by_principal
      INTO primary_department,primary_author,primary_approver
      FROM trigger_policy_revisions
     WHERE (organization_id,project_id,environment_id,policy_key,version)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.policy_key,NEW.policy_version);
  ELSIF TG_TABLE_NAME = 'trigger_policy_lifecycle_decisions' THEN
    required_role := 'TRIGGER_POLICY_LIFECYCLE_MANAGER';
    SELECT owner_department,author_principal,approved_by_principal
      INTO primary_department,primary_author,primary_approver
      FROM trigger_policy_revisions
     WHERE (organization_id,project_id,environment_id,policy_key,version)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.policy_key,NEW.policy_version);
  ELSE
    required_role := 'TRIGGER_POLICY_ACTIVATOR';
    SELECT owner_department,author_principal,approved_by_principal
      INTO primary_department,primary_author,primary_approver
      FROM trigger_policy_revisions
     WHERE (organization_id,project_id,environment_id,policy_key,version)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.retiring_policy_key,NEW.retiring_policy_version);
    SELECT owner_department,author_principal,approved_by_principal
      INTO secondary_department,secondary_author,secondary_approver
      FROM trigger_policy_revisions
     WHERE (organization_id,project_id,environment_id,policy_key,version)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.successor_policy_key,NEW.successor_version);
  END IF;

  IF NEW.actor_principal IS NOT DISTINCT FROM primary_author OR
     NEW.actor_principal IS NOT DISTINCT FROM primary_approver OR
     (secondary_author IS NOT NULL AND
      NEW.actor_principal IS NOT DISTINCT FROM secondary_author) OR
     (secondary_approver IS NOT NULL AND
      NEW.actor_principal IS NOT DISTINCT FROM secondary_approver) OR
     primary_department IS NULL OR NOT EXISTS (
    SELECT 1 FROM operability_role_bindings role_binding
     WHERE (role_binding.organization_id,role_binding.project_id,
            role_binding.environment_id,role_binding.principal,
            role_binding.role,role_binding.department)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.actor_principal,required_role,primary_department)
       AND (role_binding.expires_at IS NULL OR
            role_binding.expires_at > clock_timestamp())
  ) OR (secondary_department IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM operability_role_bindings role_binding
     WHERE (role_binding.organization_id,role_binding.project_id,
            role_binding.environment_id,role_binding.principal,
            role_binding.role,role_binding.department)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.actor_principal,required_role,secondary_department)
       AND (role_binding.expires_at IS NULL OR
            role_binding.expires_at > clock_timestamp())
  )) THEN
    RAISE EXCEPTION 'trigger policy authority actor lacks the exact active role';
  END IF;
  RETURN NEW;
END
$trigger_policy_authority_actor$;
CREATE CONSTRAINT TRIGGER trigger_policy_activation_actor
AFTER INSERT ON trigger_policy_activations
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION validate_trigger_policy_authority_actor();
CREATE CONSTRAINT TRIGGER trigger_policy_lifecycle_actor
AFTER INSERT ON trigger_policy_lifecycle_decisions
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION validate_trigger_policy_authority_actor();
CREATE CONSTRAINT TRIGGER trigger_policy_replacement_actor
AFTER INSERT ON trigger_policy_replacement_intents
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION validate_trigger_policy_authority_actor();

CREATE TRIGGER trigger_policy_activation_immutable
BEFORE UPDATE OR DELETE ON trigger_policy_activations
FOR EACH ROW EXECUTE FUNCTION refuse_frozen_operability_history_mutation();
CREATE TRIGGER trigger_policy_lifecycle_decision_immutable
BEFORE UPDATE OR DELETE ON trigger_policy_lifecycle_decisions
FOR EACH ROW EXECUTE FUNCTION refuse_frozen_operability_history_mutation();
CREATE TRIGGER trigger_policy_replacement_intent_immutable
BEFORE UPDATE OR DELETE ON trigger_policy_replacement_intents
FOR EACH ROW EXECUTE FUNCTION refuse_frozen_operability_history_mutation();
CREATE TRIGGER trigger_policy_replacement_consumption_immutable
BEFORE UPDATE OR DELETE ON trigger_policy_replacement_consumptions
FOR EACH ROW EXECUTE FUNCTION refuse_frozen_operability_history_mutation();

CREATE TABLE trigger_firings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^trf_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  policy_key text NOT NULL,
  policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  activation_id text NOT NULL,
  activation_kind text NOT NULL CHECK (activation_kind IN ('ACTIVATE','REPLACE')),
  head_epoch bigint NOT NULL CHECK (head_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  supersession text NOT NULL CHECK
    (supersession IN ('KEEP_ALL','LATEST_WAITING_PER_TARGET')),
  lifecycle_decision_id text NOT NULL,
  lifecycle_operation text NOT NULL DEFAULT 'MARK_ELIGIBLE'
    CHECK (lifecycle_operation = 'MARK_ELIGIBLE'),
  lifecycle_epoch bigint NOT NULL CHECK (lifecycle_epoch > 0),
  source_event_id text NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence > 0),
  source_event_hash text NOT NULL CHECK (source_event_hash ~ '^sha256:[0-9a-f]{64}$'),
  source_observed_at timestamptz NOT NULL,
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  target_key text NOT NULL,
  target_snapshot_hash text NOT NULL CHECK
    (target_snapshot_hash ~ '^sha256:[0-9a-f]{64}$'),
  region text NOT NULL,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  due_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN
    ('WAITING','CLAIMED','RUNNING','ENQUEUED','SUPPRESSED','SUPERSEDED','BLOCKED','COMPLETED')),
  decision_reason text,
  claim_owner text,
  claim_token uuid,
  claim_expires_at timestamptz,
  coordinator_inbox_event_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, policy_key,
          policy_version, source_event_id),
  FOREIGN KEY (organization_id, project_id, environment_id, policy_key,
               policy_version, policy_hash)
    REFERENCES trigger_policy_revisions(organization_id, project_id, environment_id,
                                        policy_key, version, policy_hash),
  FOREIGN KEY (organization_id, project_id, environment_id, activation_id,
               policy_key,policy_version,policy_hash,head_epoch,activation_kind,connection_epoch,
               placement_epoch,supersession)
    REFERENCES trigger_policy_activations
      (organization_id,project_id,environment_id,id,policy_key,policy_version,
       policy_hash,head_epoch,activation_kind,connection_epoch,placement_epoch,supersession),
  FOREIGN KEY (organization_id,project_id,environment_id,lifecycle_decision_id,
               policy_key,policy_version,policy_hash,lifecycle_epoch,
               lifecycle_operation)
    REFERENCES trigger_policy_lifecycle_decisions
      (organization_id,project_id,environment_id,id,policy_key,policy_version,
       policy_hash,lifecycle_epoch,operation),
  FOREIGN KEY (organization_id, project_id, environment_id, connection_id)
    REFERENCES solvan.tenant_connections(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, coordinator_inbox_event_id)
    REFERENCES solvan.inbox_events(organization_id, project_id, environment_id, id),
  CHECK (status <> 'CLAIMED' OR
    (claim_owner IS NOT NULL AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CHECK (status NOT IN ('SUPPRESSED','SUPERSEDED','BLOCKED') OR
    decision_reason IS NOT NULL),
  CHECK (status <> 'ENQUEUED' OR coordinator_inbox_event_id IS NOT NULL)
);
CREATE INDEX trigger_firings_due_idx ON trigger_firings
  (organization_id, project_id, environment_id, due_at)
  WHERE status = 'WAITING';
CREATE INDEX trigger_firings_target_idx ON trigger_firings
  (organization_id, project_id, environment_id, policy_key, policy_version,
   target_key, created_at DESC);
CREATE UNIQUE INDEX trigger_one_latest_waiting_idx ON trigger_firings
  (organization_id,project_id,environment_id,policy_key,policy_version,target_key)
  WHERE status='WAITING' AND supersession='LATEST_WAITING_PER_TARGET';

CREATE FUNCTION enforce_trigger_firing_state() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $trigger_firing_state$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status NOT IN ('WAITING','SUPPRESSED') THEN
      RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'trigger firing must enter through a legal root state';
    END IF;
  ELSE
    IF OLD.status = NEW.status THEN
      IF OLD.status = 'CLAIMED' AND
         OLD.claim_expires_at > clock_timestamp() AND
         ROW(NEW.claim_owner,NEW.claim_token,NEW.claim_expires_at)
         IS DISTINCT FROM
         ROW(OLD.claim_owner,OLD.claim_token,OLD.claim_expires_at) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
          MESSAGE = 'healthy trigger firing lease cannot be replaced';
      ELSIF OLD.status <> 'CLAIMED' AND
         ROW(NEW.decision_reason,NEW.claim_owner,NEW.claim_token,
             NEW.claim_expires_at,NEW.coordinator_inbox_event_id,NEW.completed_at)
         IS DISTINCT FROM
         ROW(OLD.decision_reason,OLD.claim_owner,OLD.claim_token,
             OLD.claim_expires_at,OLD.coordinator_inbox_event_id,OLD.completed_at) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
          MESSAGE = 'trigger firing state fields are immutable without a transition';
      END IF;
    ELSIF NOT (
      (OLD.status = 'WAITING' AND NEW.status IN ('CLAIMED','SUPERSEDED')) OR
      (OLD.status = 'CLAIMED' AND NEW.status IN ('ENQUEUED','BLOCKED')) OR
      (OLD.status = 'ENQUEUED' AND NEW.status = 'RUNNING') OR
      (OLD.status = 'RUNNING' AND NEW.status = 'COMPLETED')
    ) THEN
      RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'illegal trigger firing status transition';
    END IF;
  END IF;

  IF NEW.status = 'CLAIMED' THEN
    IF NEW.claim_owner IS NULL OR NEW.claim_token IS NULL OR
       NEW.claim_expires_at IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'claimed trigger firing requires the complete lease tuple';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM trigger_firing_wakeups wakeup
       WHERE (wakeup.organization_id,wakeup.project_id,wakeup.environment_id,
              wakeup.firing_id)=
             (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id)
         AND wakeup.status='CLAIMED'
         AND ROW(wakeup.claim_owner,wakeup.claim_token,wakeup.claim_expires_at)=
             ROW(NEW.claim_owner,NEW.claim_token,NEW.claim_expires_at)
    ) THEN
      RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'claimed trigger firing must match its exact claimed wakeup';
    END IF;
  ELSIF NEW.claim_owner IS NOT NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claim_expires_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'non-claimed trigger firing cannot retain a lease tuple';
  END IF;

  IF (NEW.status IN ('ENQUEUED','RUNNING','COMPLETED')) <>
     (NEW.coordinator_inbox_event_id IS NOT NULL) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'trigger firing inbox result does not match its state';
  END IF;

  IF (NEW.status IN ('SUPPRESSED','SUPERSEDED','BLOCKED','COMPLETED')) <>
     (NEW.completed_at IS NOT NULL) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'trigger firing completion time does not match its state';
  END IF;

  IF NEW.status IN ('SUPPRESSED','SUPERSEDED','BLOCKED') THEN
    IF NEW.decision_reason IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'closed trigger refusal requires a reason code';
    END IF;
  ELSIF NEW.decision_reason IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'trigger firing reason code is invalid for its state';
  END IF;

  RETURN NEW;
END
$trigger_firing_state$;
CREATE TRIGGER trigger_firing_state_guard
BEFORE INSERT OR UPDATE ON trigger_firings
FOR EACH ROW EXECUTE FUNCTION enforce_trigger_firing_state();

CREATE FUNCTION protect_trigger_firing_frozen_material() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $trigger_firing_frozen_material$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'trigger_firings history cannot be deleted';
  END IF;
  IF ROW(NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id,
         NEW.policy_key,NEW.policy_version,NEW.policy_hash,NEW.activation_id,
         NEW.activation_kind,NEW.head_epoch,NEW.placement_epoch,NEW.supersession,
         NEW.lifecycle_decision_id,NEW.lifecycle_operation,NEW.lifecycle_epoch,
         NEW.source_event_id,NEW.source_sequence,NEW.source_event_hash,
         NEW.source_observed_at,NEW.connection_id,NEW.connection_epoch,
         NEW.target_key,NEW.target_snapshot_hash,NEW.region,NEW.classification,
         NEW.due_at,NEW.created_at)
     IS DISTINCT FROM
     ROW(OLD.organization_id,OLD.project_id,OLD.environment_id,OLD.id,
         OLD.policy_key,OLD.policy_version,OLD.policy_hash,OLD.activation_id,
         OLD.activation_kind,OLD.head_epoch,OLD.placement_epoch,OLD.supersession,
         OLD.lifecycle_decision_id,OLD.lifecycle_operation,OLD.lifecycle_epoch,
         OLD.source_event_id,OLD.source_sequence,OLD.source_event_hash,
         OLD.source_observed_at,OLD.connection_id,OLD.connection_epoch,
         OLD.target_key,OLD.target_snapshot_hash,OLD.region,OLD.classification,
         OLD.due_at,OLD.created_at) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'trigger_firings frozen material is immutable';
  END IF;
  RETURN NEW;
END
$trigger_firing_frozen_material$;
CREATE TRIGGER trigger_firing_frozen_material_immutable
BEFORE UPDATE OR DELETE ON trigger_firings
FOR EACH ROW EXECUTE FUNCTION protect_trigger_firing_frozen_material();

CREATE TABLE trigger_firing_wakeups (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^twk_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  firing_id text NOT NULL,
  wake_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK
    (status IN ('PENDING','CLAIMED','COMPLETED','CANCELLED')),
  claimed_at timestamptz,
  claim_owner text,
  claim_token uuid,
  claim_expires_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, firing_id)
    REFERENCES trigger_firings(organization_id, project_id, environment_id, id),
  CHECK (status <> 'CLAIMED' OR
    (claimed_at IS NOT NULL AND claim_owner IS NOT NULL AND
     claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CHECK (status <> 'COMPLETED' OR completed_at IS NOT NULL)
);
CREATE UNIQUE INDEX trigger_one_active_wakeup_idx ON trigger_firing_wakeups
  (organization_id, project_id, environment_id, firing_id)
  WHERE status IN ('PENDING','CLAIMED');
CREATE INDEX trigger_wakeup_due_idx ON trigger_firing_wakeups
  (organization_id, project_id, environment_id, wake_at)
  WHERE status = 'PENDING';

CREATE TABLE trigger_firing_suppressions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tfs_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  firing_id text NOT NULL,
  replacement_firing_id text,
  kind text NOT NULL CHECK
    (kind IN ('COOLDOWN','MAX_PENDING','SUPERSESSION','STALE_SEQUENCE','POLICY')),
  reason_code text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, firing_id)
    REFERENCES trigger_firings(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, replacement_firing_id)
    REFERENCES trigger_firings(organization_id, project_id, environment_id, id)
);

-- Scope every target tenant table with the same immutable database-role
-- binding as the release schema. Catalog principals and global definitions
-- contain no tenant data; all probes, guidance, profiles-by-connection, runs,
-- policies, and firings are isolated.
DO $scope_policies$
DECLARE
  scoped_table record;
BEGIN
  FOR scoped_table IN
    SELECT table_name
      FROM information_schema.columns
     WHERE table_schema = 'solvan_operability'
       AND column_name IN ('organization_id','project_id','environment_id')
     GROUP BY table_name
    HAVING count(DISTINCT column_name) = 3
  LOOP
    EXECUTE format('ALTER TABLE solvan_operability.%I ENABLE ROW LEVEL SECURITY',
                   scoped_table.table_name);
    EXECUTE format(
      'CREATE POLICY scope_isolation ON solvan_operability.%I '
      'USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))',
      scoped_table.table_name
    );
  END LOOP;
END
$scope_policies$;

COMMIT;
