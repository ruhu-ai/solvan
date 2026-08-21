-- Solvan governed Production Graph: TARGET schema for specification 20.
-- This remains outside the release DDL. It is nevertheless executable: source
-- authority, completeness, materiality, promotion, placement and citations are
-- relational facts rather than application comments.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE SCHEMA IF NOT EXISTS solvan_graph;
SET search_path TO solvan_graph, public;

CREATE TABLE graph_scope_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  lifecycle text NOT NULL CHECK (lifecycle IN ('ACTIVE','MOVED','DELETED')),
  is_current boolean NOT NULL,
  bound_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch),
  FOREIGN KEY (organization_id,placement_epoch,cell_id)
    REFERENCES solvan_scale.tenant_placements(organization_id,placement_epoch,cell_id),
  CHECK (NOT is_current OR lifecycle='ACTIVE')
);
CREATE UNIQUE INDEX graph_one_current_scope
  ON graph_scope_bindings(organization_id,project_id,environment_id)
  WHERE is_current;

-- The four source tiers are policy revisions, not free-form provenance.
CREATE TABLE graph_source_policies (
  source_key text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  tier smallint NOT NULL CHECK (tier BETWEEN 1 AND 4),
  provider text NOT NULL,
  authority_class text NOT NULL CHECK (authority_class IN
    ('CATALOG','IDENTITY_AUTHORITY','DECLARED_RELATIONSHIP','OBSERVED_HINT')),
  launch_stage text NOT NULL CHECK (launch_stage IN ('GA','PREVIEW')),
  entitlement_required boolean NOT NULL,
  required_for_complete boolean NOT NULL,
  allowed_node_kinds text[] NOT NULL,
  allowed_edge_kinds text[] NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  effective_at timestamptz NOT NULL,
  retired_at timestamptz,
  PRIMARY KEY (source_key,revision),
  UNIQUE (policy_hash),
  UNIQUE (source_key,revision,tier,required_for_complete,policy_hash),
  CONSTRAINT graph_observed_hint_edge_kinds CHECK (authority_class <> 'OBSERVED_HINT' OR
    allowed_edge_kinds <@ ARRAY['DEPENDS_ON_OBSERVED']::text[]),
  CONSTRAINT graph_optional_tier_four CHECK (tier <> 4 OR NOT required_for_complete),
  CONSTRAINT graph_preview_only_tier_four CHECK (launch_stage <> 'PREVIEW' OR tier=4)
);

-- First-party source policy registry. These are the exact adapters implemented
-- by the coordinator; installing the target schema therefore cannot yield an
-- empty, fixture-only catalog. policy_hash is SHA-256 over the canonical
-- schema-version-1 policy document recorded by specification 20.
INSERT INTO graph_source_policies VALUES
 ('app_hub',1,1,'app-hub-v1','CATALOG','GA',false,true,
  ARRAY['DEPLOYMENT','SERVICE'],ARRAY[]::text[],
  'sha256:f4b2799990adb69891e12424433f18fa88b02b26de9db22f55bbe2631926932c',now(),NULL),
 ('cloud_asset_inventory_search',1,1,'cloud-asset-inventory','CATALOG','GA',false,true,
  ARRAY['DATABASE','QUEUE','SERVICE'],ARRAY[]::text[],
  'sha256:94b7bd0ae3a2e8752be49a491723ea11b1e2e0adf79844839ec1a4c7b66dafb8',now(),NULL),
 ('iam',1,2,'cloud-iam','IDENTITY_AUTHORITY','GA',false,true,
  ARRAY[]::text[],ARRAY['ALLOWED_TO_CALL'],
  'sha256:c230469cc82d7a24845dfb0a2b352efd9ca34b82f9b0afa7066c3fad437dc102',now(),NULL),
 ('asset_relationships',1,3,'cloud-asset-inventory','DECLARED_RELATIONSHIP','GA',true,true,
  ARRAY[]::text[],ARRAY['DEPENDS_ON_DECLARED','STORES_IN'],
  'sha256:93f2ac54070122c2fb2726e63f84f48912ade6bd4aa5730ffa2e408d620580ec',now(),NULL);

CREATE TABLE graph_reconciliation_runs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  run_id text NOT NULL,
  source_policy_set_hash text NOT NULL CHECK
    (source_policy_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  requested_by text NOT NULL,
  state text NOT NULL CHECK (state IN
    ('PENDING','RUNNING','COMPLETED','DEGRADED','FAILED','CANCELLED')),
  lease_owner text,
  lease_token uuid,
  lease_expires_at timestamptz,
  requested_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  ended_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch)
    REFERENCES graph_scope_bindings
      (organization_id,project_id,environment_id,cell_id,placement_epoch),
  CONSTRAINT graph_run_lease_shape CHECK ((state='RUNNING')=
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CONSTRAINT graph_run_start_shape CHECK
    ((state='PENDING')=(started_at IS NULL)),
  CONSTRAINT graph_run_terminal_shape CHECK
    ((state IN ('COMPLETED','DEGRADED','FAILED','CANCELLED'))=(ended_at IS NOT NULL))
);
CREATE UNIQUE INDEX graph_one_active_reconciliation
  ON graph_reconciliation_runs(organization_id,project_id,environment_id)
  WHERE state IN ('PENDING','RUNNING');
CREATE UNIQUE INDEX graph_run_request_identity
  ON graph_reconciliation_runs(organization_id,project_id,environment_id,run_id);

-- The exact policy set is frozen when the run is created. Completeness is
-- evaluated against these source revisions, never against mutable current
-- policy rows and never merely against a tier that another source happened to
-- satisfy.
CREATE TABLE graph_reconciliation_run_sources (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  run_id text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal > 0),
  source_key text NOT NULL,
  source_revision bigint NOT NULL,
  tier smallint NOT NULL CHECK (tier BETWEEN 1 AND 4),
  required_for_complete boolean NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY
    (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id,source_key,source_revision),
  UNIQUE
    (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id,ordinal),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id)
    REFERENCES graph_reconciliation_runs
      (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id),
  FOREIGN KEY (source_key,source_revision,tier,required_for_complete,policy_hash)
    REFERENCES graph_source_policies
      (source_key,revision,tier,required_for_complete,policy_hash)
);

CREATE TABLE graph_source_observations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  run_id text NOT NULL,
  observation_id text NOT NULL,
  source_key text NOT NULL,
  source_revision bigint NOT NULL,
  tool_invocation_ref text NOT NULL,
  response_digest text NOT NULL CHECK (response_digest ~ '^sha256:[0-9a-f]{64}$'),
  page_count integer NOT NULL CHECK (page_count >= 0),
  element_count integer NOT NULL CHECK (element_count >= 0),
  pagination_complete boolean NOT NULL,
  outcome text NOT NULL CHECK (outcome IN
    ('COMPLETE','PARTIAL','UNAVAILABLE','NOT_ENTITLED','REFUSED_REGION','REFUSED_CLASSIFICATION')),
  region text NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,observation_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id)
    REFERENCES graph_reconciliation_runs
      (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id),
  CONSTRAINT graph_observation_run_source_fk FOREIGN KEY
    (organization_id,project_id,environment_id,cell_id,placement_epoch,
     run_id,source_key,source_revision)
    REFERENCES graph_reconciliation_run_sources
      (organization_id,project_id,environment_id,cell_id,placement_epoch,
       run_id,source_key,source_revision),
  FOREIGN KEY (source_key,source_revision)
    REFERENCES graph_source_policies(source_key,revision),
  CONSTRAINT graph_observation_completion CHECK
    ((outcome='COMPLETE' AND pagination_complete AND page_count > 0) OR
     (outcome='PARTIAL' AND NOT pagination_complete AND page_count > 0) OR
     (outcome NOT IN ('COMPLETE','PARTIAL') AND NOT pagination_complete)),
  CONSTRAINT graph_observation_empty_failure CHECK
    (outcome IN ('COMPLETE','PARTIAL') OR element_count=0),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch,
          run_id,source_key,source_revision)
);

CREATE TABLE graph_snapshots (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  snapshot_id text NOT NULL CHECK (snapshot_id ~ '^pgs_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  snapshot_version bigint NOT NULL CHECK (snapshot_version > 0),
  run_id text NOT NULL,
  status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','RETIRED')),
  completeness text CHECK (completeness IN ('COMPLETE','INCOMPLETE')),
  material_hash text CHECK (material_hash ~ '^sha256:[0-9a-f]{64}$'),
  content_hash text CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  autonomy_eligible boolean NOT NULL DEFAULT false,
  reconciled_at timestamptz NOT NULL,
  approved_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_version),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id)
    REFERENCES graph_reconciliation_runs
      (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id),
  CONSTRAINT graph_snapshot_finalized CHECK
    ((material_hash IS NULL)=(content_hash IS NULL)),
  CONSTRAINT graph_approved_is_final CHECK
    (status='DRAFT' OR (material_hash IS NOT NULL AND approved_at IS NOT NULL)),
  CONSTRAINT graph_autonomy_needs_complete CHECK
    (NOT autonomy_eligible OR (status='APPROVED' AND completeness='COMPLETE'))
);
CREATE UNIQUE INDEX graph_one_approved_snapshot
  ON graph_snapshots(organization_id,project_id,environment_id)
  WHERE status='APPROVED';

CREATE TABLE graph_snapshot_tier_status (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  snapshot_id text NOT NULL,
  tier smallint NOT NULL CHECK (tier BETWEEN 1 AND 4),
  required_for_complete boolean NOT NULL,
  outcome text NOT NULL CHECK (outcome IN
    ('COMPLETE','UNAVAILABLE','NOT_ENTITLED','DEGRADED','NOT_CONFIGURED')),
  observation_count integer NOT NULL CHECK (observation_count >= 0),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,tier),
  CONSTRAINT graph_tier_snapshot_fk FOREIGN KEY
    (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
    REFERENCES graph_snapshots
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
      ON DELETE CASCADE,
  CONSTRAINT graph_tier_complete_has_observation CHECK
    (outcome <> 'COMPLETE' OR observation_count > 0)
);

CREATE TABLE graph_nodes (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  snapshot_id text NOT NULL,
  node_id text NOT NULL CHECK (node_id ~ '^pgn_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  node_key text NOT NULL,
  node_kind text NOT NULL,
  resource_ref text NOT NULL,
  -- Specification 13 §4.2. The declared location of this node, typed rather
  -- than parsed out of resource_ref. A read resolves the project it addresses
  -- from here, in the snapshot the incident pinned, so the address cannot move
  -- under a completed investigation.
  external_project_id text
    CHECK (external_project_id IS NULL OR
           external_project_id ~ '^[a-z][a-z0-9-]{4,61}$'),
  owner_team text,
  declared_environment text,
  business_criticality text,
  data_classification text,
  authorization_boundary text,
  verification_profile text,
  region text NOT NULL,
  instrumentation_state text NOT NULL CHECK (instrumentation_state IN
    ('INSTRUMENTED','UNINSTRUMENTED','UNKNOWN')),
  observation_id text NOT NULL,
  source_key text NOT NULL,
  source_revision bigint NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,node_key),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,node_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
    REFERENCES graph_snapshots
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
      ON DELETE CASCADE,
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,observation_id)
    REFERENCES graph_source_observations
      (organization_id,project_id,environment_id,cell_id,placement_epoch,observation_id),
  FOREIGN KEY (source_key,source_revision)
    REFERENCES graph_source_policies(source_key,revision),
  CHECK ((node_kind IN ('SERVICE','DEPLOYMENT','DATABASE','QUEUE'))
         = (external_project_id IS NOT NULL))
);

CREATE TABLE graph_edges (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  snapshot_id text NOT NULL,
  edge_id text NOT NULL CHECK (edge_id ~ '^pge_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  edge_key text NOT NULL,
  from_node_key text NOT NULL,
  to_node_key text NOT NULL,
  edge_kind text NOT NULL,
  observation_id text NOT NULL,
  source_key text NOT NULL,
  source_revision bigint NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,edge_key),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,edge_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,from_node_key)
    REFERENCES graph_nodes
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,node_key),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,to_node_key)
    REFERENCES graph_nodes
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,node_key),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,observation_id)
    REFERENCES graph_source_observations
      (organization_id,project_id,environment_id,cell_id,placement_epoch,observation_id),
  FOREIGN KEY (source_key,source_revision)
    REFERENCES graph_source_policies(source_key,revision),
  CHECK (from_node_key <> to_node_key)
);

CREATE FUNCTION graph_element_source_allowed() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_graph,pg_temp AS $$
DECLARE policy graph_source_policies%ROWTYPE;
DECLARE observation record;
BEGIN
  SELECT * INTO policy FROM graph_source_policies
   WHERE source_key=NEW.source_key AND revision=NEW.source_revision;
  SELECT source_key,source_revision INTO observation FROM graph_source_observations
   WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch,observation_id)=
         (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.cell_id,
          NEW.placement_epoch,NEW.observation_id);
  IF observation.source_key IS DISTINCT FROM NEW.source_key
     OR observation.source_revision IS DISTINCT FROM NEW.source_revision THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='GRAPH_SOURCE_OBSERVATION_MISMATCH',
      CONSTRAINT='graph_source_observation_match';
  END IF;
  IF TG_TABLE_NAME='graph_nodes'
     AND NOT ((to_jsonb(NEW)->>'node_kind')=ANY(policy.allowed_node_kinds)) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='GRAPH_NODE_KIND_NOT_ALLOWED',
      CONSTRAINT='graph_node_source_policy';
  END IF;
  IF TG_TABLE_NAME='graph_edges'
     AND NOT ((to_jsonb(NEW)->>'edge_kind')=ANY(policy.allowed_edge_kinds)) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='GRAPH_EDGE_KIND_NOT_ALLOWED',
      CONSTRAINT='graph_edge_source_policy';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER graph_node_source_gate BEFORE INSERT ON graph_nodes
  FOR EACH ROW EXECUTE FUNCTION graph_element_source_allowed();
CREATE TRIGGER graph_edge_source_gate BEFORE INSERT ON graph_edges
  FOR EACH ROW EXECUTE FUNCTION graph_element_source_allowed();

CREATE TABLE graph_snapshot_diffs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  diff_id text NOT NULL,
  base_snapshot_id text,
  candidate_snapshot_id text NOT NULL,
  node_changes integer NOT NULL CHECK (node_changes >= 0),
  edge_changes integer NOT NULL CHECK (edge_changes >= 0),
  owner_changes integer NOT NULL CHECK (owner_changes >= 0),
  environment_changes integer NOT NULL CHECK (environment_changes >= 0),
  criticality_changes integer NOT NULL CHECK (criticality_changes >= 0),
  classification_changes integer NOT NULL CHECK (classification_changes >= 0),
  authorization_changes integer NOT NULL CHECK (authorization_changes >= 0),
  verification_profile_changes integer NOT NULL CHECK (verification_profile_changes >= 0),
  region_changes integer NOT NULL CHECK (region_changes >= 0),
  source_authority_changes integer NOT NULL CHECK (source_authority_changes >= 0),
  instrumentation_changes integer NOT NULL CHECK (instrumentation_changes >= 0),
  completeness_changes integer NOT NULL CHECK (completeness_changes >= 0),
  governed_change_count integer GENERATED ALWAYS AS
    (node_changes+edge_changes+owner_changes+environment_changes+criticality_changes+
     classification_changes+authorization_changes+verification_profile_changes+
     region_changes+source_authority_changes+instrumentation_changes+completeness_changes) STORED,
  diff_hash text NOT NULL CHECK (diff_hash ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,diff_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,candidate_snapshot_id)
    REFERENCES graph_snapshots
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch,candidate_snapshot_id),
  CHECK (base_snapshot_id IS NULL OR base_snapshot_id <> candidate_snapshot_id)
);

CREATE TABLE graph_promotion_decisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  decision_id text NOT NULL,
  snapshot_id text NOT NULL,
  predecessor_snapshot_id text,
  decision text NOT NULL CHECK (decision IN ('HUMAN_APPROVED','AUTO_PROMOTED','REJECTED')),
  decided_by text,
  content_hash text NOT NULL,
  reason_ref text,
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,decision_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
    REFERENCES graph_snapshots
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id),
  CHECK ((decision IN ('HUMAN_APPROVED','REJECTED'))=(decided_by IS NOT NULL)),
  CHECK (decision <> 'REJECTED' OR reason_ref IS NOT NULL)
);

CREATE TABLE graph_staleness_policy_revisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  autonomy_max_age_seconds integer NOT NULL CHECK (autonomy_max_age_seconds BETWEEN 60 AND 2592000),
  assisted_max_age_seconds integer NOT NULL CHECK (assisted_max_age_seconds BETWEEN 60 AND 31536000),
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  approved_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,revision),
  CHECK (assisted_max_age_seconds >= autonomy_max_age_seconds)
);
CREATE TABLE graph_staleness_policy_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  binding_epoch bigint NOT NULL CHECK (binding_epoch > 0),
  policy_revision bigint NOT NULL,
  is_current boolean NOT NULL,
  bound_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,binding_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_revision)
    REFERENCES graph_staleness_policy_revisions
      (organization_id,project_id,environment_id,revision)
);
CREATE UNIQUE INDEX graph_one_current_staleness_policy
  ON graph_staleness_policy_bindings(organization_id,project_id,environment_id)
  WHERE is_current;

CREATE FUNCTION graph_read_current(
  p_organization_id text,p_project_id text,p_environment_id text)
RETURNS TABLE (
  snapshot_id text,snapshot_version bigint,reconciled_at timestamptz,
  age_seconds bigint,completeness text,autonomy_eligible boolean,
  assisted_usable boolean,cell_id text,placement_epoch bigint,
  graph_policy_binding_epoch bigint)
LANGUAGE sql STABLE SET search_path=solvan_graph,solvan,pg_temp AS $$
  SELECT snapshot.snapshot_id,snapshot.snapshot_version,snapshot.reconciled_at,
    greatest(0,floor(extract(epoch FROM (now()-snapshot.reconciled_at)))::bigint),
    snapshot.completeness,
    snapshot.autonomy_eligible AND
      extract(epoch FROM (now()-snapshot.reconciled_at))<=policy.autonomy_max_age_seconds,
    extract(epoch FROM (now()-snapshot.reconciled_at))<=policy.assisted_max_age_seconds,
    snapshot.cell_id,snapshot.placement_epoch,binding.binding_epoch
  FROM graph_scope_bindings scope
  JOIN graph_snapshots snapshot ON
    (snapshot.organization_id,snapshot.project_id,snapshot.environment_id,
     snapshot.cell_id,snapshot.placement_epoch)=
    (scope.organization_id,scope.project_id,scope.environment_id,
     scope.cell_id,scope.placement_epoch)
   AND snapshot.status='APPROVED'
  JOIN solvan.production_graph_snapshots authority ON
    (authority.organization_id,authority.project_id,authority.environment_id,
     authority.id)=
    (snapshot.organization_id,snapshot.project_id,snapshot.environment_id,
     snapshot.snapshot_id)
   AND authority.status='APPROVED' AND authority.superseded_at IS NULL
  JOIN graph_staleness_policy_bindings binding ON
    (binding.organization_id,binding.project_id,binding.environment_id)=
    (scope.organization_id,scope.project_id,scope.environment_id)
   AND binding.is_current
  JOIN graph_staleness_policy_revisions policy ON
    (policy.organization_id,policy.project_id,policy.environment_id,policy.revision)=
    (binding.organization_id,binding.project_id,binding.environment_id,
     binding.policy_revision)
  WHERE scope.organization_id=p_organization_id
    AND scope.project_id=p_project_id
    AND scope.environment_id=p_environment_id
    AND scope.is_current AND scope.lifecycle='ACTIVE'
$$;

CREATE TABLE graph_findings (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, finding_id text NOT NULL,
  snapshot_id text NOT NULL, finding_kind text NOT NULL CHECK (finding_kind IN
    ('UNDECLARED_DEPENDENCY','UNOBSERVED_DECLARATION','UNINSTRUMENTED_COMPONENT',
     'ORPHANED_RESOURCE','SOURCE_INCOMPLETE','CLASSIFICATION_CONFLICT')),
  subject_node_key text, subject_edge_key text, detail_ref text NOT NULL,
  subject_source_key text,
  subject_source_revision bigint,
  status text NOT NULL CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,finding_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
    REFERENCES graph_snapshots
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id),
  FOREIGN KEY (subject_source_key,subject_source_revision)
    REFERENCES graph_source_policies(source_key,revision),
  CHECK ((subject_source_key IS NULL)=(subject_source_revision IS NULL)),
  CHECK (((subject_node_key IS NOT NULL)::integer
         +(subject_edge_key IS NOT NULL)::integer
         +(subject_source_key IS NOT NULL)::integer)=1),
  CHECK ((finding_kind='SOURCE_INCOMPLETE')=(subject_source_key IS NOT NULL))
);
CREATE UNIQUE INDEX graph_unique_node_finding ON graph_findings
  (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,
   finding_kind,subject_node_key) WHERE subject_node_key IS NOT NULL;
CREATE UNIQUE INDEX graph_unique_edge_finding ON graph_findings
  (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,
   finding_kind,subject_edge_key) WHERE subject_edge_key IS NOT NULL;
CREATE UNIQUE INDEX graph_unique_source_finding ON graph_findings
  (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,
   finding_kind,subject_source_key,subject_source_revision)
  WHERE subject_source_key IS NOT NULL;

CREATE TABLE graph_citations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, citation_id text NOT NULL,
  snapshot_id text NOT NULL, consumer_kind text NOT NULL CHECK (consumer_kind IN
    ('AGENT_RUN','HYPOTHESIS','ACTION_AUTHORIZATION','VERIFICATION','CONVERSATION_TURN')),
  consumer_ref text NOT NULL, consumer_attempt bigint NOT NULL CHECK (consumer_attempt > 0),
  cited_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,citation_id),
  CONSTRAINT graph_citation_snapshot_fk FOREIGN KEY
    (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
    REFERENCES graph_snapshots
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id),
  UNIQUE (organization_id,project_id,environment_id,consumer_kind,consumer_ref,consumer_attempt)
);

CREATE TABLE graph_deletion_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  lifecycle_job_id text NOT NULL,
  deletion_epoch bigint NOT NULL,
  snapshot_count integer NOT NULL CHECK (snapshot_count >= 0),
  content_row_count bigint NOT NULL CHECK (content_row_count >= snapshot_count),
  terminal_digest text NOT NULL CHECK (terminal_digest ~ '^sha256:[0-9a-f]{64}$'),
  deleted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,deletion_epoch),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch),
  FOREIGN KEY (organization_id,lifecycle_job_id)
    REFERENCES solvan_scale.tenant_lifecycle_jobs(organization_id,job_id)
);

CREATE FUNCTION graph_promotion_write_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_graph,pg_temp AS $$
BEGIN
  IF current_setting('solvan_graph.promotion_transaction',true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='GRAPH_PROMOTION_FUNCTION_REQUIRED',
      CONSTRAINT='graph_promotion_function_only';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER graph_snapshot_status_guard BEFORE UPDATE OF status ON graph_snapshots
  FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION graph_promotion_write_guard();
CREATE TRIGGER graph_decision_insert_guard BEFORE INSERT ON graph_promotion_decisions
  FOR EACH ROW EXECUTE FUNCTION graph_promotion_write_guard();

CREATE FUNCTION graph_finalize_snapshot(
  p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,p_snapshot text)
RETURNS void LANGUAGE plpgsql SET search_path=solvan_graph,solvan,pg_temp AS $$
DECLARE missing_required integer; required_sources integer; mat text; content text;
DECLARE source_status text; tier_status text; snapshot_run_id text;
DECLARE scope_ceiling text;
BEGIN
  SELECT run_id INTO snapshot_run_id FROM graph_snapshots WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)=
    (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot) AND status='DRAFT';
  IF snapshot_run_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='GRAPH_FINALIZE_REFUSED',
      CONSTRAINT='graph_finalize_draft_once';
  END IF;
  SELECT classification_ceiling INTO scope_ceiling FROM graph_scope_bindings WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  IF scope_ceiling IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='GRAPH_SCOPE_CEILING_MISSING',
      CONSTRAINT='graph_finalize_scope_ceiling';
  END IF;
  SELECT count(*) FILTER (WHERE required_for_complete),
         count(*) FILTER (WHERE required_for_complete AND NOT EXISTS (
           SELECT 1 FROM graph_source_observations observed WHERE
             (observed.organization_id,observed.project_id,observed.environment_id,
              observed.cell_id,observed.placement_epoch,observed.run_id,
              observed.source_key,observed.source_revision)=
             (planned.organization_id,planned.project_id,planned.environment_id,
              planned.cell_id,planned.placement_epoch,planned.run_id,
              planned.source_key,planned.source_revision)
             AND observed.outcome='COMPLETE' AND observed.pagination_complete))
    INTO required_sources,missing_required
    FROM graph_reconciliation_run_sources planned WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id)=
      (p_org,p_project,p_environment,p_cell,p_epoch,snapshot_run_id);
  SELECT 'sha256:'||encode(public.digest(coalesce(string_agg(v,'|' ORDER BY v),'')::bytea,'sha256'),'hex')
    INTO mat FROM (
      SELECT concat_ws(':','N',node_key,node_kind,resource_ref,external_project_id,
        owner_team,declared_environment,
        business_criticality,coalesce(data_classification,scope_ceiling),
        CASE WHEN data_classification IS NULL THEN 'SCOPE_CEILING' ELSE 'SOURCE' END,
        authorization_boundary,verification_profile,
        region,instrumentation_state,source_key,source_revision) v FROM graph_nodes
       WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)=
             (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot)
      UNION ALL
      SELECT concat_ws(':','E',edge_key,from_node_key,to_node_key,edge_kind,source_key,source_revision)
        FROM graph_edges WHERE
        (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)=
        (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot)
    ) material;
  SELECT coalesce(string_agg(
           concat_ws(':',planned.ordinal,planned.source_key,planned.source_revision,
             planned.policy_hash,planned.required_for_complete,
             coalesce(observed.outcome,'MISSING'),
             coalesce(observed.pagination_complete,false)),'|' ORDER BY planned.ordinal),'')
    INTO source_status
    FROM graph_reconciliation_run_sources planned
    LEFT JOIN graph_source_observations observed ON
      (observed.organization_id,observed.project_id,observed.environment_id,
       observed.cell_id,observed.placement_epoch,observed.run_id,
       observed.source_key,observed.source_revision)=
      (planned.organization_id,planned.project_id,planned.environment_id,
       planned.cell_id,planned.placement_epoch,planned.run_id,
       planned.source_key,planned.source_revision)
   WHERE (planned.organization_id,planned.project_id,planned.environment_id,
          planned.cell_id,planned.placement_epoch,planned.run_id)=
         (p_org,p_project,p_environment,p_cell,p_epoch,snapshot_run_id);
  SELECT coalesce(string_agg(tier||':'||outcome,'|' ORDER BY tier),'')
    INTO tier_status FROM graph_snapshot_tier_status
   WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)=
         (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot);
  content:='sha256:'||encode(public.digest(
    (mat||':sources:'||source_status||':tiers:'||tier_status)::bytea,'sha256'),'hex');
  UPDATE graph_snapshots SET material_hash=mat,content_hash=content,
    completeness=CASE WHEN required_sources>0 AND missing_required=0
      THEN 'COMPLETE' ELSE 'INCOMPLETE' END
   WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)=
         (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot)
     AND status='DRAFT' AND material_hash IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='GRAPH_FINALIZE_REFUSED',
    CONSTRAINT='graph_finalize_draft_once'; END IF;
END $$;

CREATE FUNCTION graph_promote_snapshot(
  p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,p_snapshot text,
  p_decision_id text,p_mode text,p_principal text DEFAULT NULL,p_reason text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SET search_path=solvan_graph,pg_temp AS $$
DECLARE candidate graph_snapshots%ROWTYPE; predecessor graph_snapshots%ROWTYPE; changes integer;
BEGIN
  PERFORM set_config('solvan_graph.promotion_transaction','on',true);
  SELECT * INTO candidate FROM graph_snapshots WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)=
    (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot) FOR UPDATE;
  IF candidate.status <> 'DRAFT' OR candidate.material_hash IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='GRAPH_CANDIDATE_NOT_FINAL',
      CONSTRAINT='graph_promote_final_candidate'; END IF;
  SELECT * INTO predecessor FROM graph_snapshots WHERE
    organization_id=p_org AND project_id=p_project AND environment_id=p_environment
    AND status='APPROVED' FOR UPDATE;
  IF p_mode='AUTO_PROMOTED' THEN
    IF predecessor.snapshot_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='GRAPH_FIRST_SNAPSHOT_NEEDS_HUMAN',CONSTRAINT='graph_first_snapshot_human'; END IF;
    SELECT governed_change_count INTO changes FROM graph_snapshot_diffs WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch,candidate_snapshot_id)=
      (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot)
      AND base_snapshot_id=predecessor.snapshot_id;
    IF changes IS DISTINCT FROM 0 OR candidate.material_hash <> predecessor.material_hash
       OR candidate.completeness <> 'COMPLETE'
       OR EXISTS (SELECT 1 FROM graph_promotion_decisions WHERE content_hash=candidate.content_hash
                    AND decision='REJECTED') THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='GRAPH_AUTO_PROMOTION_REFUSED',
        CONSTRAINT='graph_auto_exact_predecessor'; END IF;
  ELSIF p_mode='HUMAN_APPROVED' THEN
    IF p_principal IS NULL THEN RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='GRAPH_HUMAN_PRINCIPAL_REQUIRED',CONSTRAINT='graph_human_principal'; END IF;
  ELSE RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='GRAPH_PROMOTION_MODE_REFUSED',
    CONSTRAINT='graph_promotion_mode'; END IF;
  -- The release projection is the sole graph authority consumed by incidents,
  -- evidence, verification and action policy. Candidate rows remain immutable
  -- reconciliation history. Both sides change in this one transaction, so an
  -- approved candidate can never exist without the exact citable projection.
  UPDATE solvan.production_graph_snapshots SET status='RETIRED',superseded_at=now()
   WHERE organization_id=p_org AND project_id=p_project AND environment_id=p_environment
     AND status='APPROVED' AND superseded_at IS NULL;
  INSERT INTO solvan.production_graph_snapshots
    (organization_id,project_id,environment_id,id,version,status,
     source_manifest_ref,content_hash,effective_at,approved_by,approved_at)
  VALUES
    (p_org,p_project,p_environment,candidate.snapshot_id,candidate.snapshot_version,
     'APPROVED','graph-decision:'||p_decision_id,candidate.content_hash,
     candidate.reconciled_at,coalesce(p_principal,'workload:coordinator'),now());
  INSERT INTO solvan.production_graph_nodes
    (organization_id,project_id,environment_id,id,snapshot_id,node_key,node_kind,
     resource_ref,external_project_id,classification,provenance_ref,attributes_json)
  SELECT p_org,p_project,p_environment,node.node_id,candidate.snapshot_id,
         node.node_key,node.node_kind,node.resource_ref,node.external_project_id,
         coalesce(node.data_classification,scope.classification_ceiling),
         'graph-observation:'||node.observation_id,
         jsonb_strip_nulls(jsonb_build_object(
           'owner_team',node.owner_team,
           'declared_environment',node.declared_environment,
           'business_criticality',node.business_criticality,
           'authorization_boundary',node.authorization_boundary,
           'verification_profile',node.verification_profile,
           'region',node.region,
           'instrumentation_state',node.instrumentation_state,
           'classification_source',CASE WHEN node.data_classification IS NULL
             THEN 'ENVIRONMENT_CEILING' ELSE 'SOURCE' END,
           'source_key',node.source_key,
           'source_revision',node.source_revision))
    FROM graph_nodes node
    JOIN graph_scope_bindings scope ON
      (scope.organization_id,scope.project_id,scope.environment_id,
       scope.cell_id,scope.placement_epoch)=
      (node.organization_id,node.project_id,node.environment_id,
       node.cell_id,node.placement_epoch)
    WHERE
      (node.organization_id,node.project_id,node.environment_id,node.cell_id,
       node.placement_epoch,node.snapshot_id)=
      (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot);
  INSERT INTO solvan.production_graph_edges
    (organization_id,project_id,environment_id,id,snapshot_id,source_node_id,
     target_node_id,edge_kind,provenance_ref,attributes_json)
  SELECT p_org,p_project,p_environment,edge.edge_id,candidate.snapshot_id,
         source_node.node_id,target_node.node_id,edge.edge_kind,
         'graph-observation:'||edge.observation_id,
         jsonb_build_object('source_key',edge.source_key,
                            'source_revision',edge.source_revision)
    FROM graph_edges edge
    JOIN graph_nodes source_node ON
      (source_node.organization_id,source_node.project_id,source_node.environment_id,
       source_node.cell_id,source_node.placement_epoch,source_node.snapshot_id,
       source_node.node_key)=
      (edge.organization_id,edge.project_id,edge.environment_id,edge.cell_id,
       edge.placement_epoch,edge.snapshot_id,edge.from_node_key)
    JOIN graph_nodes target_node ON
      (target_node.organization_id,target_node.project_id,target_node.environment_id,
       target_node.cell_id,target_node.placement_epoch,target_node.snapshot_id,
       target_node.node_key)=
      (edge.organization_id,edge.project_id,edge.environment_id,edge.cell_id,
       edge.placement_epoch,edge.snapshot_id,edge.to_node_key)
   WHERE (edge.organization_id,edge.project_id,edge.environment_id,edge.cell_id,
          edge.placement_epoch,edge.snapshot_id)=
         (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot);
  UPDATE graph_snapshots SET status='RETIRED',autonomy_eligible=false
   WHERE organization_id=p_org AND project_id=p_project AND environment_id=p_environment
     AND status='APPROVED';
  UPDATE graph_snapshots SET status='APPROVED',approved_at=now(),
    autonomy_eligible=(completeness='COMPLETE') WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)=
    (p_org,p_project,p_environment,p_cell,p_epoch,p_snapshot);
  INSERT INTO graph_promotion_decisions VALUES
    (p_org,p_project,p_environment,p_cell,p_epoch,p_decision_id,p_snapshot,
     predecessor.snapshot_id,p_mode,p_principal,candidate.content_hash,p_reason,now());
  PERFORM set_config('solvan_graph.promotion_transaction','off',true);
END $$;

CREATE FUNCTION graph_history_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_graph,pg_temp AS $$
BEGIN
  IF current_setting('solvan_graph.purge_transaction',true)='on' THEN RETURN OLD; END IF;
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='GRAPH_HISTORY_IMMUTABLE',
    CONSTRAINT='graph_history_immutable';
END $$;
CREATE TRIGGER graph_observations_immutable BEFORE UPDATE OR DELETE ON graph_source_observations
  FOR EACH ROW EXECUTE FUNCTION graph_history_immutable();
CREATE TRIGGER graph_run_sources_immutable BEFORE UPDATE OR DELETE ON graph_reconciliation_run_sources
  FOR EACH ROW EXECUTE FUNCTION graph_history_immutable();
CREATE TRIGGER graph_decisions_immutable BEFORE UPDATE OR DELETE ON graph_promotion_decisions
  FOR EACH ROW EXECUTE FUNCTION graph_history_immutable();
CREATE TRIGGER graph_citations_immutable BEFORE UPDATE OR DELETE ON graph_citations
  FOR EACH ROW EXECUTE FUNCTION graph_history_immutable();

-- The lifecycle service calls this only after the SaaS deletion job is in its
-- verified purge phase. The digest and counts prove terminal deletion without
-- retaining source identifiers, topology, findings, or citations.
CREATE FUNCTION graph_purge_scope(
  p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,
  p_lifecycle_job text,p_deletion_epoch bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=solvan_graph,solvan_scale,pg_temp AS $$
DECLARE job solvan_scale.tenant_lifecycle_jobs%ROWTYPE;
DECLARE snapshot_total integer; content_total bigint; terminal text;
BEGIN
  IF p_deletion_epoch < 1 THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='GRAPH_DELETION_EPOCH_INVALID',
      CONSTRAINT='graph_deletion_epoch_positive';
  END IF;
  SELECT * INTO job FROM solvan_scale.tenant_lifecycle_jobs
   WHERE organization_id=p_org AND job_id=p_lifecycle_job FOR UPDATE;
  IF job.job_kind IS DISTINCT FROM 'DELETE' OR job.state IS DISTINCT FROM 'VERIFYING'
     OR job.legal_hold_ref IS NOT NULL OR job.unsettled_mutation_count<>0
     OR job.source_cell_id IS DISTINCT FROM p_cell
     OR job.expected_placement_epoch IS DISTINCT FROM p_epoch THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='GRAPH_PURGE_LIFECYCLE_REFUSED',
      CONSTRAINT='graph_purge_verified_delete_only';
  END IF;
  SELECT count(*) INTO snapshot_total FROM graph_snapshots WHERE
   (organization_id,project_id,environment_id,cell_id,placement_epoch)=
   (p_org,p_project,p_environment,p_cell,p_epoch);
  SELECT
    (SELECT count(*) FROM graph_reconciliation_runs WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_source_observations WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_reconciliation_run_sources WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_snapshots WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_snapshot_tier_status WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_nodes WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_edges WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_snapshot_diffs WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_promotion_decisions WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_findings WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_citations WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))+
    (SELECT count(*) FROM graph_staleness_policy_revisions WHERE
      (organization_id,project_id,environment_id)=(p_org,p_project,p_environment))+
    (SELECT count(*) FROM graph_staleness_policy_bindings WHERE
      (organization_id,project_id,environment_id)=(p_org,p_project,p_environment))+
    (SELECT count(*) FROM graph_scope_bindings WHERE
      (organization_id,project_id,environment_id,cell_id,placement_epoch)=
      (p_org,p_project,p_environment,p_cell,p_epoch))
   INTO content_total;
  terminal:='sha256:'||encode(public.digest(concat_ws(':','GRAPH_PURGED',p_org,
    p_project,p_environment,p_cell,p_epoch,p_deletion_epoch,snapshot_total,content_total)::bytea,
    'sha256'),'hex');
  PERFORM set_config('solvan_graph.purge_transaction','on',true);
  DELETE FROM graph_citations WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_findings WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_promotion_decisions WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_snapshot_diffs WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_edges WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_nodes WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_snapshot_tier_status WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_snapshots WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_source_observations WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_reconciliation_run_sources WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_reconciliation_runs WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  DELETE FROM graph_staleness_policy_bindings WHERE
    (organization_id,project_id,environment_id)=(p_org,p_project,p_environment);
  DELETE FROM graph_staleness_policy_revisions WHERE
    (organization_id,project_id,environment_id)=(p_org,p_project,p_environment);
  DELETE FROM graph_scope_bindings WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch);
  INSERT INTO graph_deletion_receipts VALUES
    (p_org,p_project,p_environment,p_cell,p_epoch,p_lifecycle_job,p_deletion_epoch,
     snapshot_total,content_total,terminal,now());
  PERFORM set_config('solvan_graph.purge_transaction','off',true);
END $$;

REVOKE INSERT,UPDATE,DELETE ON graph_promotion_decisions FROM PUBLIC;
REVOKE ALL ON FUNCTION graph_purge_scope(text,text,text,text,bigint,text,bigint) FROM PUBLIC;
COMMIT;
