-- Solvan competition-release schema: authoritative DDL.
-- PostgreSQL 16+. Application models must mirror this file; CI compares them.

BEGIN;

CREATE SCHEMA IF NOT EXISTS solvan;
SET search_path TO solvan, public;

CREATE TABLE organizations (
  id text PRIMARY KEY CHECK (id ~ '^org_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE projects (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text NOT NULL CHECK (id ~ '^prj_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  display_name text NOT NULL,
  gcp_project_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, gcp_project_id)
);

CREATE TABLE environments (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^env_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  display_name text NOT NULL,
  region text NOT NULL,
  classification text CHECK (classification IS NULL OR classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, id),
  FOREIGN KEY (organization_id, project_id)
    REFERENCES projects(organization_id, id)
);

CREATE TABLE actor_role_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  principal text NOT NULL,
  role text NOT NULL CHECK (role IN ('OPERATOR','APPROVER','ADMIN')),
  granted_by text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, principal, role),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id)
);

CREATE TABLE display_sequences (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  entity_type text NOT NULL CHECK (entity_type IN ('INC','REL','ACT')),
  next_value bigint NOT NULL CHECK (next_value > 0),
  PRIMARY KEY (organization_id, project_id, environment_id, entity_type),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id)
);

CREATE TABLE services (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^svc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  service_key text NOT NULL,
  display_name text NOT NULL,
  platform_kind text NOT NULL CHECK (platform_kind IN
    ('CLOUD_RUN_SERVICE','CLOUD_SQL_INSTANCE','EXTERNAL')),
  platform_resource text NOT NULL,
  owner_department text NOT NULL,
  lifecycle text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle IN ('ACTIVE','RETIRED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, service_key),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id)
);

CREATE TABLE service_dependencies (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  upstream_service_id text NOT NULL,
  downstream_service_id text NOT NULL,
  dependency_kind text NOT NULL CHECK (dependency_kind IN
    ('DEPENDS_ON','STORES_IN','CALLS')),
  source_ref text NOT NULL,
  graph_version bigint NOT NULL CHECK (graph_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id,
    upstream_service_id, downstream_service_id, dependency_kind, graph_version),
  FOREIGN KEY (organization_id, project_id, environment_id, upstream_service_id)
    REFERENCES services(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, downstream_service_id)
    REFERENCES services(organization_id, project_id, environment_id, id),
  CHECK (upstream_service_id <> downstream_service_id)
);

CREATE TABLE production_graph_snapshots (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^pgs_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  version bigint NOT NULL CHECK (version > 0),
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RETIRED')),
  source_manifest_ref text NOT NULL,
  content_hash text NOT NULL,
  effective_at timestamptz NOT NULL,
  superseded_at timestamptz,
  approved_by text,
  approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, version),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id),
  CHECK (superseded_at IS NULL OR superseded_at >= effective_at),
  CHECK ((status <> 'APPROVED') OR
    (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);

CREATE UNIQUE INDEX production_graph_one_current
  ON production_graph_snapshots (organization_id, project_id, environment_id)
  WHERE status = 'APPROVED' AND superseded_at IS NULL;

CREATE TABLE production_graph_nodes (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^pgn_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  snapshot_id text NOT NULL,
  node_key text NOT NULL,
  node_kind text NOT NULL CHECK (node_kind IN
    ('SERVICE','DEPLOYMENT','DATABASE','QUEUE','REPOSITORY','OWNER','SLO',
     'SYNTHETIC_CHECK','AGENT','TOOL','VERIFICATION_PROFILE')),
  resource_ref text,
  -- Specification 13 §4.2. Where this node's resource actually lives, typed
  -- rather than parsed out of resource_ref. Every read resolves the project it
  -- addresses from the node it is reading about, in the snapshot the incident
  -- pinned, so a database in a different project than its service is the
  -- ordinary case rather than a query sent to the wrong estate.
  external_project_id text CHECK (external_project_id IS NULL OR
    external_project_id ~ '^[a-z][a-z0-9-]{4,61}$'),
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  provenance_ref text NOT NULL,
  attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, snapshot_id, id),
  UNIQUE (organization_id, project_id, environment_id, snapshot_id, node_key),
  FOREIGN KEY (organization_id, project_id, environment_id, snapshot_id)
    REFERENCES production_graph_snapshots
      (organization_id, project_id, environment_id, id),
  -- Exactly the Google Cloud node kinds carry a Google Cloud project. A
  -- REPOSITORY names a git snapshot and a VERIFICATION_PROFILE names a Solvan
  -- record; neither has a project, and requiring one would force a fiction.
  -- Nullable alone would let a Cloud Run or Cloud SQL node carry no address and
  -- be read at whatever project the caller happened to hold.
  CHECK ((node_kind IN ('SERVICE','DEPLOYMENT','DATABASE','QUEUE'))
         = (external_project_id IS NOT NULL))
);

CREATE TABLE production_graph_edges (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^pge_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  snapshot_id text NOT NULL,
  source_node_id text NOT NULL,
  target_node_id text NOT NULL,
  edge_kind text NOT NULL CHECK (edge_kind IN
    ('DEPENDS_ON','DEPENDS_ON_DECLARED','DEPENDS_ON_OBSERVED','DEPLOYED_AS',
     'STORES_IN','OWNED_BY','VERIFIED_BY','IMPLEMENTED_BY','ALLOWED_TO_CALL')),
  provenance_ref text NOT NULL,
  attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, snapshot_id,
    source_node_id, target_node_id, edge_kind),
  FOREIGN KEY (organization_id, project_id, environment_id, snapshot_id)
    REFERENCES production_graph_snapshots
      (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, snapshot_id, source_node_id)
    REFERENCES production_graph_nodes
      (organization_id, project_id, environment_id, snapshot_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, snapshot_id, target_node_id)
    REFERENCES production_graph_nodes
      (organization_id, project_id, environment_id, snapshot_id, id),
  CHECK (source_node_id <> target_node_id)
);

CREATE TABLE detection_rules (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  service_id text NOT NULL,
  incident_class text NOT NULL,
  signal_kind text NOT NULL,
  query_json jsonb NOT NULL,
  evaluation_interval_ms integer NOT NULL CHECK
    (evaluation_interval_ms BETWEEN 20000 AND 30000),
  comparator text NOT NULL CHECK (comparator IN ('GT','GTE','LT','LTE')),
  threshold numeric NOT NULL,
  sustained_windows integer NOT NULL CHECK (sustained_windows > 0),
  severity text NOT NULL CHECK (severity IN ('SEV1','SEV2','SEV3','SEV4')),
  deduplication_dimension text NOT NULL,
  action_budget integer NOT NULL CHECK (action_budget > 0),
  repeated_action_limit integer NOT NULL CHECK (repeated_action_limit > 0),
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RETIRED')),
  calibration_receipt_ref text,
  approved_by text,
  approved_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id, version),
  FOREIGN KEY (organization_id, project_id, environment_id, service_id)
    REFERENCES services(organization_id, project_id, environment_id, id),
  CHECK ((status <> 'APPROVED') OR
    (calibration_receipt_ref IS NOT NULL AND approved_by IS NOT NULL AND approved_at IS NOT NULL))
);

CREATE TABLE detection_evaluations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  rule_id text NOT NULL,
  rule_version integer NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  observed_value double precision NOT NULL,
  threshold_matched boolean NOT NULL,
  query_receipt_ref text NOT NULL,
  query_receipt_hash text NOT NULL,
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id,
    rule_id, rule_version, window_end),
  FOREIGN KEY (organization_id, project_id, environment_id, rule_id, rule_version)
    REFERENCES detection_rules(organization_id, project_id, environment_id, id, version),
  CHECK (window_end >= window_start),
  CHECK (observed_value NOT IN ('Infinity'::float8, '-Infinity'::float8)
    AND observed_value = observed_value)
);

CREATE INDEX detection_evaluations_streak_idx
  ON detection_evaluations
    (organization_id, project_id, environment_id, rule_id, rule_version, window_end DESC)
  WHERE threshold_matched;

CREATE TABLE confirmation_rules (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  incident_class text NOT NULL,
  required_observations_json jsonb NOT NULL,
  contradiction_policy text NOT NULL CHECK (contradiction_policy IN ('REJECT','ESCALATE')),
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RETIRED')),
  approved_by text,
  approved_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id, version),
  CHECK ((status <> 'APPROVED') OR (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);

CREATE UNIQUE INDEX confirmation_rules_one_approved_per_class
  ON confirmation_rules
    (organization_id, project_id, environment_id, incident_class)
  WHERE status = 'APPROVED';

CREATE TABLE reliability_cases (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rel_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  display_id text NOT NULL CHECK (display_id ~ '^REL-[0-9]{4,}$'),
  workflow_version bigint NOT NULL DEFAULT 1 CHECK (workflow_version > 0),
  evidence_version bigint NOT NULL DEFAULT 0 CHECK (evidence_version >= 0),
  state_machine_version text NOT NULL,
  state text NOT NULL CHECK (state IN
    ('OPEN','ROOT_CAUSE_ANALYSIS','BLOCKED','REPAIR_PLANNED',
     'REPAIR_IN_PROGRESS','AWAITING_REVIEW','READY_FOR_CANARY','CANARY_RUNNING',
     'READY_FOR_ROLLOUT','ROLLOUT_RUNNING','ROLLED_BACK','OBSERVING',
     'REOPENED','CLOSED_VERIFIED','CANCELLED')),
  originating_incident_id text,
  next_action_kind text,
  next_action_at timestamptz,
  blocked_owner text,
  next_review_at timestamptz,
  recovery_plan text,
  terminal_reason text,
  lease_owner text,
  lease_token uuid,
  lease_expires_at timestamptz,
  last_progress_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, display_id),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id),
  CHECK ((state <> 'BLOCKED') OR
    (blocked_owner IS NOT NULL AND next_review_at IS NOT NULL AND recovery_plan IS NOT NULL)),
  CHECK ((state NOT IN ('CLOSED_VERIFIED','CANCELLED')) OR terminal_reason IS NOT NULL),
  CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL))
);

CREATE TABLE incidents (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^inc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  display_id text NOT NULL CHECK (display_id ~ '^INC-[0-9]{4,}$'),
  workflow_version bigint NOT NULL DEFAULT 1 CHECK (workflow_version > 0),
  evidence_version bigint NOT NULL DEFAULT 0 CHECK (evidence_version >= 0),
  state_machine_version text NOT NULL,
  state text NOT NULL CHECK (state IN
    ('DETECTED','TRIAGING','INVESTIGATING','DIAGNOSING','MITIGATION_PROPOSED',
     'AWAITING_APPROVAL','MITIGATING','VERIFYING_MITIGATION','MITIGATED',
     'RESOLVED','ESCALATED','UNRESOLVABLE','FALSE_POSITIVE','CANCELLED')),
  severity text NOT NULL CHECK (severity IN ('SEV1','SEV2','SEV3','SEV4')),
  incident_class text NOT NULL,
  primary_service_id text NOT NULL,
  recurrence_of text,
  reliability_case_id text,
  production_graph_snapshot_id text NOT NULL,
  detected_at timestamptz NOT NULL,
  detection_rule_id text,
  detection_rule_version integer CHECK (detection_rule_version > 0),
  trigger_policy_key text,
  trigger_policy_version text,
  deduplication_key text NOT NULL,
  action_attempt_count integer NOT NULL DEFAULT 0 CHECK (action_attempt_count >= 0),
  action_budget integer NOT NULL CHECK (action_budget > 0),
  repeated_action_limit integer NOT NULL CHECK (repeated_action_limit > 0),
  cooldown_until timestamptz,
  last_action_signature text,
  suspected_root_cause_id text,
  confirmed_root_cause_id text,
  terminal_reason text,
  lease_owner text,
  lease_token uuid,
  lease_expires_at timestamptz,
  last_progress_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, display_id),
  FOREIGN KEY (organization_id, project_id, environment_id, primary_service_id)
    REFERENCES services(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, recurrence_of)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, production_graph_snapshot_id)
    REFERENCES production_graph_snapshots(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
    detection_rule_id, detection_rule_version)
    REFERENCES detection_rules(organization_id, project_id, environment_id, id, version),
  CHECK ((detection_rule_id IS NULL) = (detection_rule_version IS NULL)),
  CHECK ((trigger_policy_key IS NULL) = (trigger_policy_version IS NULL)),
  CHECK ((detection_rule_id IS NOT NULL) <> (trigger_policy_key IS NOT NULL)),
  CHECK ((state NOT IN
    ('RESOLVED','ESCALATED','UNRESOLVABLE','FALSE_POSITIVE','CANCELLED'))
    OR terminal_reason IS NOT NULL),
  CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL))
);

ALTER TABLE reliability_cases
  ADD CONSTRAINT reliability_cases_originating_incident_fk
  FOREIGN KEY (organization_id, project_id, environment_id, originating_incident_id)
  REFERENCES incidents(organization_id, project_id, environment_id, id)
  DEFERRABLE INITIALLY DEFERRED;

-- The same signal key attaches to an active incident. A terminal incident does
-- not prevent a later recurrence from opening a new incident with the same key.
CREATE UNIQUE INDEX incidents_one_active_dedup_key
  ON incidents (organization_id, project_id, environment_id, deduplication_key)
  WHERE state NOT IN
    ('RESOLVED','ESCALATED','UNRESOLVABLE','FALSE_POSITIVE','CANCELLED');

CREATE INDEX incidents_active_updated_idx
  ON incidents (organization_id, project_id, environment_id, updated_at DESC)
  WHERE state NOT IN
    ('RESOLVED','ESCALATED','UNRESOLVABLE','FALSE_POSITIVE','CANCELLED');

CREATE TABLE case_incidents (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  case_id text NOT NULL,
  incident_id text NOT NULL,
  relationship text NOT NULL CHECK (relationship IN ('ORIGINATING','RECURRENCE')),
  linked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, case_id, incident_id),
  FOREIGN KEY (organization_id, project_id, environment_id, case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id)
);

CREATE UNIQUE INDEX case_incidents_one_originating
  ON case_incidents (organization_id, project_id, environment_id, case_id)
  WHERE relationship = 'ORIGINATING';

CREATE TABLE state_transitions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^trn_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  entity_type text NOT NULL CHECK (entity_type IN ('INCIDENT','RELIABILITY_CASE')),
  entity_id text NOT NULL,
  from_state text NOT NULL,
  to_state text NOT NULL,
  from_workflow_version bigint NOT NULL,
  to_workflow_version bigint NOT NULL,
  transition_key text NOT NULL,
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  policy_decision_id text,
  reason_code text NOT NULL,
  rationale_summary text NOT NULL,
  evidence_refs_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  trace_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, entity_type, entity_id, transition_key),
  CHECK (to_workflow_version = from_workflow_version + 1)
);

CREATE TABLE inbox_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^evt_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  source text NOT NULL,
  source_event_id text NOT NULL,
  event_type text NOT NULL,
  payload_ref text NOT NULL,
  payload_hash text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  processing_state text NOT NULL DEFAULT 'PENDING' CHECK (processing_state IN
    ('PENDING','PROCESSING','COMPLETED','FAILED')),
  claimed_at timestamptz,
  claim_owner text,
  claim_token uuid,
  claim_expires_at timestamptz,
  processed_at timestamptz,
  result_ref text,
  error_class text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, source, source_event_id),
  CHECK ((processing_state <> 'PROCESSING') OR
    (claimed_at IS NOT NULL AND claim_owner IS NOT NULL AND claim_token IS NOT NULL
     AND claim_expires_at IS NOT NULL)),
  CHECK ((processing_state NOT IN ('COMPLETED','FAILED')) OR processed_at IS NOT NULL)
);

CREATE INDEX inbox_pending_claim_idx
  ON inbox_events (organization_id, project_id, environment_id, received_at)
  WHERE processing_state = 'PENDING';

CREATE INDEX inbox_expired_claim_idx
  ON inbox_events (organization_id, project_id, environment_id, claim_expires_at)
  WHERE processing_state = 'PROCESSING';

CREATE TABLE outbox_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^evt_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  aggregate_version bigint NOT NULL,
  topic text NOT NULL,
  event_type text NOT NULL,
  payload_json jsonb NOT NULL,
  idempotency_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  publish_attempts integer NOT NULL DEFAULT 0,
  claimed_at timestamptz,
  claim_owner text,
  claim_token uuid,
  claim_expires_at timestamptz,
  published_at timestamptz,
  quarantined_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, idempotency_key),
  CHECK ((claim_token IS NULL AND claim_expires_at IS NULL) OR
    (claimed_at IS NOT NULL AND claim_owner IS NOT NULL AND claim_token IS NOT NULL
     AND claim_expires_at IS NOT NULL)),
  -- A poison event is either published or quarantined, never both.
  CHECK (published_at IS NULL OR quarantined_at IS NULL)
);

CREATE INDEX outbox_unpublished_idx ON outbox_events
  (organization_id, project_id, environment_id, created_at)
  WHERE published_at IS NULL;

CREATE TABLE scheduled_wakeups (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^wak_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  case_id text NOT NULL,
  logical_step_key text NOT NULL,
  wake_at timestamptz NOT NULL,
  reason text NOT NULL,
  -- A wakeup carries the same bounded claim budget as an inbox event. A step
  -- whose handler dies on the same permanent fault every claim is parked as
  -- QUARANTINED instead of re-aborting the coordinator tick forever. Only a
  -- claim that actually processes the step spends an attempt; contention is
  -- refunded, so a busy case is never mistaken for a poisoned one.
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN
    ('PENDING','CLAIMED','COMPLETED','CANCELLED','QUARANTINED')),
  claimed_at timestamptz,
  claim_owner text,
  claim_token uuid,
  claim_expires_at timestamptz,
  completed_at timestamptz,
  quarantined_at timestamptz,
  outbox_event_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, outbox_event_id)
    REFERENCES outbox_events(organization_id, project_id, environment_id, id),
  CHECK ((status <> 'CLAIMED') OR
    (claimed_at IS NOT NULL AND claim_owner IS NOT NULL AND claim_token IS NOT NULL
     AND claim_expires_at IS NOT NULL)),
  CHECK ((status <> 'COMPLETED') OR completed_at IS NOT NULL),
  CHECK ((status = 'QUARANTINED') = (quarantined_at IS NOT NULL))
);

CREATE UNIQUE INDEX scheduled_wakeups_one_active_step
  ON scheduled_wakeups
    (organization_id, project_id, environment_id, case_id, logical_step_key)
  WHERE status IN ('PENDING','CLAIMED');

CREATE INDEX scheduled_wakeups_pending_claim_idx
  ON scheduled_wakeups
    (organization_id, project_id, environment_id, wake_at)
  WHERE status = 'PENDING';

CREATE TABLE agent_runs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^run_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  incident_id text,
  reliability_case_id text,
  repair_plan_id text,
  repair_plan_version integer CHECK (repair_plan_version IS NULL OR repair_plan_version > 0),
  action_id text,
  investigation_step_id text,
  logical_step_key text NOT NULL,
  agent_key text NOT NULL,
  agent_resource text NOT NULL,
  agent_revision text NOT NULL,
  session_id text,
  invocation_id text NOT NULL,
  runtime_operation_name text,
  runtime_input_ref text,
  runtime_output_ref text,
  workspace_id text,
  workspace_generation bigint CHECK
    (workspace_generation IS NULL OR workspace_generation > 0),
  workspace_task_kind text CHECK (workspace_task_kind IS NULL OR
    workspace_task_kind IN ('MAINTAIN_DOSSIER','FORENSICS','SYNTHESIZE_EVIDENCE',
      'REPRODUCE','BISECT','REPAIR','PREVALIDATE','REHEARSE','LEARN')),
  provider_request_id text,
  provider_request_hash text CHECK
    (provider_request_hash IS NULL OR
     provider_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  implementation_sdk_distribution_hash text CHECK
    (implementation_sdk_distribution_hash IS NULL OR
     implementation_sdk_distribution_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_artifact_digest text CHECK
    (provider_artifact_digest IS NULL OR
     provider_artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  provider_boot_hash text CHECK
    (provider_boot_hash IS NULL OR
     provider_boot_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_service_revision text,
  effective_tool_set_hash text CHECK
    (effective_tool_set_hash IS NULL OR
     effective_tool_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  effective_network_policy_hash text CHECK
    (effective_network_policy_hash IS NULL OR
     effective_network_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  workflow_version bigint NOT NULL,
  attempt integer NOT NULL CHECK (attempt > 0),
  status text NOT NULL CHECK (status IN
    ('CREATED','DISPATCHED','RUNNING','SUCCEEDED','FAILED','TIMED_OUT','CANCELLED','STALE')),
  deadline timestamptz NOT NULL,
  budget_json jsonb NOT NULL,
  input_ref text NOT NULL,
  input_context_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  input_hash text NOT NULL,
  output_ref text,
  output_hash text,
  error_class text,
  started_at timestamptz,
  completed_at timestamptz,
  trace_id text,
  span_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, logical_step_key, attempt),
  UNIQUE (organization_id, project_id, environment_id, invocation_id),
  UNIQUE (organization_id, project_id, environment_id, provider_request_id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  CONSTRAINT agent_runs_one_anchor_ck CHECK ((incident_id IS NOT NULL)::integer
    + (reliability_case_id IS NOT NULL)::integer
    + (workspace_id IS NOT NULL)::integer = 1),
  CHECK (action_id IS NULL OR agent_key IN ('execution-agent','verification-agent')),
  CHECK (workspace_id IS NULL OR agent_key = 'workspace-agent'),
  CHECK ((repair_plan_id IS NULL AND repair_plan_version IS NULL) OR
    (agent_key = 'workspace-agent' AND repair_plan_id IS NOT NULL AND
     repair_plan_version IS NOT NULL AND
     (workspace_task_kind IS NULL OR workspace_task_kind = 'REPAIR'))),
  CHECK ((workspace_id IS NULL AND workspace_generation IS NULL AND
          workspace_task_kind IS NULL AND provider_request_id IS NULL AND
          provider_request_hash IS NULL AND
          implementation_sdk_distribution_hash IS NULL AND
          provider_artifact_digest IS NULL AND
          effective_network_policy_hash IS NULL) OR
         (workspace_id IS NOT NULL AND workspace_generation IS NOT NULL AND
          workspace_task_kind IS NOT NULL AND provider_request_id IS NOT NULL AND
          provider_request_hash IS NOT NULL AND
          implementation_sdk_distribution_hash IS NOT NULL AND
          provider_artifact_digest IS NOT NULL AND effective_tool_set_hash IS NOT NULL AND
          effective_network_policy_hash IS NOT NULL)),
  CHECK ((provider_boot_hash IS NULL) = (provider_service_revision IS NULL)),
  CHECK (workspace_id IS NULL OR status <> 'SUCCEEDED' OR
    (provider_boot_hash IS NOT NULL AND provider_service_revision IS NOT NULL)),
  CHECK (trace_id IS NULL OR trace_id ~ '^[0-9a-f]{32}$'),
  CHECK (span_id IS NULL OR span_id ~ '^[0-9a-f]{16}$')
);

CREATE UNIQUE INDEX agent_runs_one_active_attempt
  ON agent_runs (organization_id, project_id, environment_id, logical_step_key)
  WHERE status IN ('CREATED','DISPATCHED','RUNNING');

CREATE TABLE repair_plans (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rep_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  reliability_case_id text NOT NULL,
  plan_version integer NOT NULL CHECK (plan_version > 0),
  repository_node_id text NOT NULL,
  repository_snapshot_uri text NOT NULL,
  repository_snapshot_hash text NOT NULL CHECK (repository_snapshot_hash ~ '^sha256:[0-9a-f]{64}$'),
  base_commit_sha text NOT NULL CHECK (base_commit_sha ~ '^[0-9a-f]{40}$'),
  reproduction_command text NOT NULL,
  allowed_file_globs_json jsonb NOT NULL,
  test_command text NOT NULL,
  artifact_output_uri text NOT NULL,
  confirmed_root_cause_id text NOT NULL,
  evidence_refs_json jsonb NOT NULL,
  provider text NOT NULL CHECK
    (provider IN ('GEMINI_ADK_AGENT_ENGINE','ANTIGRAVITY_SDK_CLOUD_RUN')),
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','SUPERSEDED','CANCELLED')),
  supersedes_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, reliability_case_id, plan_version),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, repository_node_id)
    REFERENCES production_graph_nodes(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, supersedes_id)
    REFERENCES repair_plans(organization_id, project_id, environment_id, id),
  CHECK (jsonb_typeof(allowed_file_globs_json) = 'array'
    AND jsonb_array_length(allowed_file_globs_json) > 0),
  CHECK (jsonb_typeof(evidence_refs_json) = 'array'
    AND jsonb_array_length(evidence_refs_json) > 0),
  CHECK ((plan_version = 1 AND supersedes_id IS NULL)
    OR (plan_version > 1 AND supersedes_id IS NOT NULL))
);

CREATE UNIQUE INDEX repair_plans_one_active
  ON repair_plans (organization_id, project_id, environment_id, reliability_case_id)
  WHERE status = 'ACTIVE';

ALTER TABLE agent_runs
  ADD FOREIGN KEY (organization_id, project_id, environment_id, repair_plan_id)
  REFERENCES repair_plans(organization_id, project_id, environment_id, id);

CREATE TABLE patch_artifacts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^pat_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  reliability_case_id text NOT NULL,
  repair_plan_id text NOT NULL,
  repair_plan_version integer NOT NULL CHECK (repair_plan_version > 0),
  agent_run_id text NOT NULL,
  sandbox_resource text NOT NULL,
  base_commit_sha text NOT NULL CHECK (base_commit_sha ~ '^[0-9a-f]{40}$'),
  unified_diff_ref text NOT NULL,
  unified_diff_hash text NOT NULL CHECK (unified_diff_hash ~ '^sha256:[0-9a-f]{64}$'),
  changed_paths_json jsonb NOT NULL,
  cognition_ref text NOT NULL CHECK (cognition_ref ~ '^gs://'),
  cognition_hash text NOT NULL CHECK (cognition_hash ~ '^sha256:[0-9a-f]{64}$'),
  mechanism text NOT NULL,
  hypotheses_json jsonb NOT NULL,
  reproduction_command text NOT NULL,
  reproduction_exit_code integer NOT NULL,
  reproduction_output_ref text NOT NULL CHECK (reproduction_output_ref ~ '^gs://'),
  reproduction_output_hash text NOT NULL CHECK
    (reproduction_output_hash ~ '^sha256:[0-9a-f]{64}$'),
  test_command text NOT NULL,
  test_exit_code integer NOT NULL,
  test_output_ref text NOT NULL,
  test_output_hash text NOT NULL CHECK (test_output_hash ~ '^sha256:[0-9a-f]{64}$'),
  residual_risks_json jsonb NOT NULL,
  provider text NOT NULL CHECK
    (provider IN ('GEMINI_ADK_AGENT_ENGINE','ANTIGRAVITY_SDK_CLOUD_RUN')),
  status text NOT NULL CHECK (status IN ('TESTS_PASSED','TESTS_FAILED','REJECTED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, agent_run_id),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, repair_plan_id)
    REFERENCES repair_plans(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES agent_runs(organization_id, project_id, environment_id, id),
  CHECK (jsonb_typeof(changed_paths_json) = 'array'
    AND jsonb_array_length(changed_paths_json) > 0),
  CHECK (jsonb_typeof(hypotheses_json) = 'array'
    AND jsonb_array_length(hypotheses_json) >= 2),
  CHECK (length(btrim(mechanism)) > 0),
  CHECK (length(btrim(reproduction_command)) > 0),
  CHECK (length(btrim(test_command)) > 0),
  CHECK (jsonb_typeof(residual_risks_json) = 'array'),
  CHECK ((status = 'TESTS_PASSED' AND reproduction_exit_code <> 0 AND test_exit_code = 0)
    OR (status = 'TESTS_FAILED' AND
      (reproduction_exit_code = 0 OR test_exit_code <> 0))
    OR status = 'REJECTED')
);

CREATE TABLE patch_reviews (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^prv_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  reliability_case_id text NOT NULL,
  patch_artifact_id text NOT NULL,
  decision_request_id text NOT NULL,
  patch_digest text NOT NULL CHECK (patch_digest ~ '^sha256:[0-9a-f]{64}$'),
  reviewer_principal text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVE','CHANGES_REQUESTED')),
  reason text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  applied_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, patch_artifact_id),
  UNIQUE (organization_id, project_id, environment_id, decision_request_id),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, patch_artifact_id)
    REFERENCES patch_artifacts(organization_id, project_id, environment_id, id),
  CHECK (length(reason) BETWEEN 1 AND 500)
);

-- ---------------------------------------------------------------------------
-- GitHub release provider. These rows model a bounded GitHub App integration;
-- they never contain tokens or private keys. Secrets remain Secret Manager
-- references and every external mutation is represented by an append-only
-- operation and receipt.
-- ---------------------------------------------------------------------------

CREATE TABLE github_repositories (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  installation_id bigint NOT NULL CHECK (installation_id > 0),
  owner text NOT NULL CHECK (owner ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'),
  name text NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,100}$'),
  default_branch text NOT NULL CHECK (default_branch ~ '^[A-Za-z0-9._/-]{1,255}$'),
  api_base_url text NOT NULL CHECK (api_base_url ~ '^https://'),
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  credential_secret_ref text NOT NULL CHECK
    (credential_secret_ref ~ '^projects/[^/]+/secrets/[^/]+/versions/[^/]+$'),
  webhook_secret_ref text NOT NULL CHECK
    (webhook_secret_ref ~ '^projects/[^/]+/secrets/[^/]+/versions/[^/]+$'),
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  allowed_operations_json jsonb NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK
    (status IN ('PENDING','ACTIVE','DEGRADED','REVOKED')),
  last_probe_at timestamptz,
  last_probe_result text CHECK (last_probe_result IS NULL OR
    last_probe_result IN ('SUCCEEDED','FAILED')),
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, owner, name),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id),
  CHECK (jsonb_typeof(allowed_operations_json) = 'array'
    AND jsonb_array_length(allowed_operations_json) > 0),
  CHECK ((status <> 'ACTIVE') OR last_probe_result = 'SUCCEEDED')
);

CREATE TABLE github_webhook_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ghe_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_id text NOT NULL,
  delivery_id text NOT NULL CHECK (length(delivery_id) BETWEEN 8 AND 128),
  event_name text NOT NULL CHECK (event_name ~ '^[a-z_]{1,64}$'),
  action text CHECK (action IS NULL OR action ~ '^[a-z_]{1,64}$'),
  sender_login text,
  installation_id bigint CHECK (installation_id IS NULL OR installation_id > 0),
  payload_hash text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  signature_verified boolean NOT NULL,
  pull_request_number integer CHECK (pull_request_number IS NULL OR pull_request_number > 0),
  pull_request_head_sha text CHECK
    (pull_request_head_sha IS NULL OR pull_request_head_sha ~ '^[0-9a-f]{40}$'),
  pull_request_base_sha text CHECK
    (pull_request_base_sha IS NULL OR pull_request_base_sha ~ '^[0-9a-f]{40}$'),
  pull_request_merged boolean,
  processing_status text NOT NULL DEFAULT 'RECEIVED' CHECK
    (processing_status IN ('RECEIVED','PROCESSED','IGNORED','FAILED')),
  error_class text,
  received_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, delivery_id),
  FOREIGN KEY (organization_id, project_id, environment_id, repository_id)
    REFERENCES github_repositories(organization_id, project_id, environment_id, id),
  CHECK (signature_verified),
  CHECK ((processing_status IN ('FAILED')) = (error_class IS NOT NULL))
);

CREATE TABLE github_pull_requests (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ghp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_id text NOT NULL,
  patch_artifact_id text NOT NULL,
  patch_digest text NOT NULL CHECK (patch_digest ~ '^sha256:[0-9a-f]{64}$'),
  external_number integer NOT NULL CHECK (external_number > 0),
  html_url text NOT NULL CHECK (html_url ~ '^https://'),
  branch_name text NOT NULL CHECK (branch_name ~ '^solvan/[a-z0-9][a-z0-9._/-]{1,100}$'),
  base_commit_sha text NOT NULL CHECK (base_commit_sha ~ '^[0-9a-f]{40}$'),
  head_commit_sha text NOT NULL CHECK (head_commit_sha ~ '^[0-9a-f]{40}$'),
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
  status text NOT NULL CHECK (status IN
    ('PROPOSED','OPEN','CHANGES_REQUESTED','APPROVED','MERGED','CLOSED','DEPLOYED','FAILED')),
  mergeable_state text,
  latest_checks_state text NOT NULL DEFAULT 'UNKNOWN' CHECK
    (latest_checks_state IN ('UNKNOWN','PENDING','PASSING','FAILING')),
  merge_commit_sha text CHECK
    (merge_commit_sha IS NULL OR merge_commit_sha ~ '^[0-9a-f]{40}$'),
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, repository_id, external_number),
  UNIQUE (organization_id, project_id, environment_id, patch_artifact_id),
  FOREIGN KEY (organization_id, project_id, environment_id, repository_id)
    REFERENCES github_repositories(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, patch_artifact_id)
    REFERENCES patch_artifacts(organization_id, project_id, environment_id, id)
);

CREATE TABLE github_check_runs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ghc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  pull_request_id text NOT NULL,
  external_id bigint NOT NULL CHECK (external_id > 0),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  status text NOT NULL CHECK (status IN ('QUEUED','IN_PROGRESS','COMPLETED','UNKNOWN')),
  conclusion text,
  head_commit_sha text NOT NULL CHECK (head_commit_sha ~ '^[0-9a-f]{40}$'),
  details_url text CHECK (details_url IS NULL OR details_url ~ '^https://'),
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, pull_request_id, external_id),
  FOREIGN KEY (organization_id, project_id, environment_id, pull_request_id)
    REFERENCES github_pull_requests(organization_id, project_id, environment_id, id)
);

CREATE TABLE github_operations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gho_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_id text NOT NULL,
  pull_request_id text,
  patch_review_id text,
  operation text NOT NULL CHECK (operation IN
    ('CREATE_PULL_REQUEST','SYNC_PULL_REQUEST','MERGE_PULL_REQUEST','CLOSE_PULL_REQUEST')),
  status text NOT NULL CHECK (status IN
    ('CREATED','DISPATCHED','SUCCEEDED','FAILED','REJECTED','STALE')),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  expected_head_commit_sha text CHECK
    (expected_head_commit_sha IS NULL OR expected_head_commit_sha ~ '^[0-9a-f]{40}$'),
  external_number integer CHECK (external_number IS NULL OR external_number > 0),
  response_hash text CHECK (response_hash IS NULL OR response_hash ~ '^sha256:[0-9a-f]{64}$'),
  receipt_ref text,
  error_class text,
  actor_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, idempotency_key),
  FOREIGN KEY (organization_id, project_id, environment_id, repository_id)
    REFERENCES github_repositories(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, pull_request_id)
    REFERENCES github_pull_requests(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, patch_review_id)
    REFERENCES patch_reviews(organization_id, project_id, environment_id, id),
  CHECK ((status IN ('FAILED','REJECTED','STALE')) = (error_class IS NOT NULL)),
  CHECK ((operation = 'MERGE_PULL_REQUEST') = (patch_review_id IS NOT NULL))
);

CREATE TABLE investigation_plans (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ipl_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  incident_id text NOT NULL,
  plan_version integer NOT NULL CHECK (plan_version > 0),
  objective text NOT NULL,
  completion_condition text NOT NULL,
  uncertainties_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  content_hash text NOT NULL,
  status text NOT NULL CHECK (status IN
    ('ACCEPTED','SUPERSEDED','COMPLETED','ABANDONED')),
  created_by_agent_run_id text NOT NULL,
  supersedes_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, incident_id, plan_version),
  UNIQUE (organization_id, project_id, environment_id, incident_id,
    created_by_agent_run_id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, created_by_agent_run_id)
    REFERENCES agent_runs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, supersedes_id)
    REFERENCES investigation_plans(organization_id, project_id, environment_id, id),
  CHECK ((plan_version = 1 AND supersedes_id IS NULL)
    OR (plan_version > 1 AND supersedes_id IS NOT NULL))
);

CREATE UNIQUE INDEX investigation_plans_one_current
  ON investigation_plans
    (organization_id, project_id, environment_id, incident_id)
  WHERE status = 'ACCEPTED';

CREATE TABLE investigation_steps (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ist_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  plan_id text NOT NULL,
  step_key text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  kind text NOT NULL CHECK (kind IN ('INVOKE_AGENT','COORDINATOR_CHECK')),
  agent_key text,
  agent_resource text,
  agent_revision text,
  current_agent_run_id text,
  allowed_tool_names_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  scope_ref text NOT NULL,
  purpose text NOT NULL,
  required boolean NOT NULL DEFAULT true,
  depends_on_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  budget_json jsonb NOT NULL,
  status text NOT NULL CHECK (status IN
    ('PLANNED','READY','DISPATCHED','RUNNING','SUCCEEDED','FAILED','STALE','SKIPPED')),
  result_ref text,
  evidence_delta_count integer NOT NULL DEFAULT 0 CHECK (evidence_delta_count >= 0),
  fallback_ref text,
  retry_not_before timestamptz,
  started_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, plan_id, step_key),
  UNIQUE (organization_id, project_id, environment_id, plan_id, ordinal),
  FOREIGN KEY (organization_id, project_id, environment_id, plan_id)
    REFERENCES investigation_plans(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, current_agent_run_id)
    REFERENCES agent_runs(organization_id, project_id, environment_id, id),
  CHECK ((kind = 'INVOKE_AGENT') = (agent_key IS NOT NULL)),
  CHECK ((kind = 'INVOKE_AGENT') = (agent_resource IS NOT NULL)),
  CHECK ((kind = 'INVOKE_AGENT') = (agent_revision IS NOT NULL)),
  CHECK ((completed_at IS NULL) OR started_at IS NOT NULL),
  CHECK ((completed_at IS NULL) OR completed_at >= started_at)
);

ALTER TABLE agent_runs
  ADD FOREIGN KEY (organization_id, project_id, environment_id,
    investigation_step_id)
  REFERENCES investigation_steps(organization_id, project_id, environment_id, id);

CREATE TABLE evidence_items (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^evd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  incident_id text NOT NULL,
  source_kind text NOT NULL,
  source_resource text NOT NULL,
  query_spec_json jsonb NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  observed_at timestamptz NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  content_ref text NOT NULL,
  content_hash text NOT NULL,
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  residency text NOT NULL,
  armor_verdict_id text,
  redaction_manifest_ref text NOT NULL,
  provenance_json jsonb NOT NULL,
  freshness_expires_at timestamptz NOT NULL,
  created_by_agent_run_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  CHECK (window_end >= window_start)
);

CREATE TABLE tool_calls (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^tcl_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  agent_run_id text NOT NULL,
  invocation_id text NOT NULL,
  tool_name text NOT NULL,
  arguments_hash text NOT NULL CHECK (arguments_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('RESERVED','SUCCEEDED','FAILED')),
  request_count integer NOT NULL DEFAULT 1 CHECK (request_count > 0),
  evidence_item_id text,
  error_class text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_requested_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id,
    agent_run_id, tool_name, arguments_hash),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES agent_runs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, evidence_item_id)
    REFERENCES evidence_items(organization_id, project_id, environment_id, id),
  CHECK ((status = 'SUCCEEDED') = (evidence_item_id IS NOT NULL)),
  CHECK ((status = 'FAILED') = (error_class IS NOT NULL)),
  CHECK ((status = 'RESERVED') = (completed_at IS NULL))
);

CREATE TABLE findings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^fnd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  incident_id text NOT NULL,
  agent_run_id text NOT NULL,
  finding_key text NOT NULL,
  revision integer NOT NULL CHECK (revision > 0),
  kind text NOT NULL CHECK (kind IN ('OBSERVATION','INFERENCE')),
  statement text NOT NULL,
  confidence_score numeric(5,4) CHECK
    (confidence_score IS NULL OR confidence_score BETWEEN 0 AND 1),
  content_hash text NOT NULL,
  supersedes_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id,
    incident_id, finding_key, revision),
  UNIQUE (organization_id, project_id, environment_id, supersedes_id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES agent_runs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, supersedes_id)
    REFERENCES findings(organization_id, project_id, environment_id, id),
  CHECK ((revision = 1 AND supersedes_id IS NULL) OR
    (revision > 1 AND supersedes_id IS NOT NULL))
);

CREATE UNIQUE INDEX findings_one_root
  ON findings (organization_id, project_id, environment_id, incident_id, finding_key)
  WHERE supersedes_id IS NULL;

CREATE TABLE finding_evidence (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  finding_id text NOT NULL,
  evidence_id text NOT NULL,
  relationship text NOT NULL CHECK (relationship IN ('SUPPORTS','CONTRADICTS')),
  cited_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id,
    finding_id, evidence_id, relationship),
  FOREIGN KEY (organization_id, project_id, environment_id, finding_id)
    REFERENCES findings(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, evidence_id)
    REFERENCES evidence_items(organization_id, project_id, environment_id, id)
);

CREATE TABLE hypotheses (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^hyp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  incident_id text NOT NULL,
  statement text NOT NULL,
  normalized_cause_key text NOT NULL,
  revision integer NOT NULL CHECK (revision > 0),
  status text NOT NULL CHECK (status IN
    ('PROPOSED','SUPPORTED','CONTRADICTED','CONFIRMED','REJECTED')),
  supporting_evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  contradicting_evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  confidence_score numeric(5,4) CHECK
    (confidence_score IS NULL OR confidence_score BETWEEN 0 AND 1),
  confirmation_rule_id text NOT NULL,
  confirmation_rule_version integer NOT NULL,
  confirmed_at timestamptz,
  supersedes_id text,
  created_by_run_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
    confirmation_rule_id, confirmation_rule_version)
    REFERENCES confirmation_rules
      (organization_id, project_id, environment_id, id, version),
  FOREIGN KEY (organization_id, project_id, environment_id, supersedes_id)
    REFERENCES hypotheses(organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id,
    incident_id, normalized_cause_key, revision),
  UNIQUE (organization_id, project_id, environment_id, supersedes_id),
  CHECK ((revision = 1 AND supersedes_id IS NULL) OR
    (revision > 1 AND supersedes_id IS NOT NULL)),
  CHECK ((status <> 'CONFIRMED') OR confirmed_at IS NOT NULL)
);

CREATE UNIQUE INDEX hypotheses_one_root
  ON hypotheses
    (organization_id, project_id, environment_id, incident_id, normalized_cause_key)
  WHERE supersedes_id IS NULL;

CREATE TABLE policy_decisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^pol_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  policy_kind text NOT NULL,
  policy_version text NOT NULL,
  input_ref text,
  input_hash text NOT NULL,
  decision text NOT NULL CHECK (decision IN
    ('ALLOW','REQUIRE_APPROVAL','DENY')),
  reason_code text NOT NULL,
  advisory_verdict_ref text,
  receipt_ref text,
  receipt_hash text CHECK
    (receipt_hash IS NULL OR receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, id,
    policy_kind, decision),
  CHECK (policy_kind <> 'PROVIDER_ELIGIBILITY' OR
    (input_ref IS NOT NULL AND receipt_ref IS NOT NULL AND receipt_hash IS NOT NULL))
);

-- Optional Antigravity demonstration seam. These dormant tables are part of
-- the canonical schema but do not add an MSR promotion requirement.
CREATE TABLE workspaces (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^wsp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  kind text NOT NULL CHECK (kind IN ('SERVICE','INCIDENT')),
  service_id text NOT NULL,
  reliability_case_id text,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  provider text NOT NULL CHECK
    (provider IN ('GEMINI_ADK_AGENT_ENGINE','ANTIGRAVITY_SDK_CLOUD_RUN')),
  implementation_sdk text NOT NULL CHECK
    (implementation_sdk IN ('google-adk','google-antigravity')),
  implementation_sdk_version text NOT NULL CHECK
    (length(implementation_sdk_version) > 0),
  provider_revision text NOT NULL CHECK (length(provider_revision) > 0),
  registry_agent_key text NOT NULL,
  provider_agent_resource text NOT NULL,
  provider_service_identity text NOT NULL,
  implementation_sdk_distribution_hash text NOT NULL CHECK
    (implementation_sdk_distribution_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_artifact_digest text NOT NULL CHECK
    (provider_artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  effective_network_policy_hash text NOT NULL CHECK
    (effective_network_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  synthetic boolean NOT NULL,
  synthetic_attestation_ref text CHECK
    (synthetic_attestation_ref IS NULL OR synthetic_attestation_ref ~ '^gs://'),
  synthetic_attestation_hash text CHECK
    (synthetic_attestation_hash IS NULL OR
     synthetic_attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_eligibility_decision_id text NOT NULL,
  provider_eligibility_policy_kind text NOT NULL
    DEFAULT 'PROVIDER_ELIGIBILITY'
    CHECK (provider_eligibility_policy_kind = 'PROVIDER_ELIGIBILITY'),
  provider_eligibility_result text NOT NULL DEFAULT 'ALLOW'
    CHECK (provider_eligibility_result = 'ALLOW'),
  artifact_prefix text NOT NULL CHECK (artifact_prefix ~ '^gs://'),
  input_manifest_ref text NOT NULL CHECK (input_manifest_ref ~ '^gs://'),
  input_manifest_hash text NOT NULL CHECK
    (input_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK
    (status IN ('OPEN','HIBERNATED','BLOCKED','CLOSED')),
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, id, generation),
  FOREIGN KEY (organization_id, project_id, environment_id, service_id)
    REFERENCES services(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
    provider_eligibility_decision_id, provider_eligibility_policy_kind,
    provider_eligibility_result)
    REFERENCES policy_decisions
      (organization_id, project_id, environment_id, id, policy_kind, decision),
  CHECK ((kind = 'INCIDENT') = (reliability_case_id IS NOT NULL)),
  CHECK (updated_at >= created_at),
  CHECK (provider <> 'ANTIGRAVITY_SDK_CLOUD_RUN' OR
    (classification = 'PUBLIC' AND synthetic = true AND
     implementation_sdk = 'google-antigravity' AND
     synthetic_attestation_ref IS NOT NULL AND
     synthetic_attestation_hash IS NOT NULL)),
  CHECK (provider <> 'GEMINI_ADK_AGENT_ENGINE' OR
    implementation_sdk = 'google-adk')
);

CREATE UNIQUE INDEX workspaces_one_active_incident_case
  ON workspaces
    (organization_id, project_id, environment_id, reliability_case_id)
  WHERE kind = 'INCIDENT' AND status IN ('OPEN','HIBERNATED','BLOCKED');

CREATE UNIQUE INDEX workspaces_one_active_service
  ON workspaces
    (organization_id, project_id, environment_id, service_id)
  WHERE kind = 'SERVICE' AND status IN ('OPEN','HIBERNATED','BLOCKED');

CREATE TABLE workspace_checkpoints (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^wck_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  workspace_id text NOT NULL,
  workspace_generation bigint NOT NULL CHECK (workspace_generation > 0),
  sequence_no integer NOT NULL CHECK (sequence_no > 0),
  event_kind text NOT NULL CHECK (event_kind IN ('CHECKPOINT','REHYDRATION')),
  parent_checkpoint_id text,
  provider text NOT NULL CHECK
    (provider IN ('GEMINI_ADK_AGENT_ENGINE','ANTIGRAVITY_SDK_CLOUD_RUN')),
  implementation_sdk text NOT NULL CHECK
    (implementation_sdk IN ('google-adk','google-antigravity')),
  implementation_sdk_version text NOT NULL CHECK
    (length(implementation_sdk_version) > 0),
  implementation_sdk_distribution_hash text NOT NULL CHECK
    (implementation_sdk_distribution_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_artifact_digest text NOT NULL CHECK
    (provider_artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  provider_revision text NOT NULL CHECK (length(provider_revision) > 0),
  provider_request_hash text NOT NULL CHECK
    (provider_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_receipt_ref text NOT NULL CHECK (provider_receipt_ref ~ '^gs://'),
  provider_receipt_hash text NOT NULL CHECK
    (provider_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_boot_hash text NOT NULL CHECK
    (provider_boot_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_service_revision text NOT NULL CHECK
    (length(provider_service_revision) > 0),
  input_manifest_ref text NOT NULL CHECK (input_manifest_ref ~ '^gs://'),
  input_manifest_hash text NOT NULL CHECK
    (input_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  artifact_manifest_ref text NOT NULL CHECK (artifact_manifest_ref ~ '^gs://'),
  artifact_manifest_hash text NOT NULL CHECK
    (artifact_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  effective_tool_set_hash text NOT NULL CHECK
    (effective_tool_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  effective_network_policy_hash text NOT NULL CHECK
    (effective_network_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id,
    workspace_id, workspace_generation, sequence_no),
  FOREIGN KEY (organization_id, project_id, environment_id, workspace_id)
    REFERENCES workspaces
      (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
    parent_checkpoint_id)
    REFERENCES workspace_checkpoints
      (organization_id, project_id, environment_id, id),
  CHECK ((event_kind = 'CHECKPOINT' AND parent_checkpoint_id IS NULL) OR
    (event_kind = 'REHYDRATION' AND parent_checkpoint_id IS NOT NULL)),
  CHECK ((provider = 'ANTIGRAVITY_SDK_CLOUD_RUN' AND
          implementation_sdk = 'google-antigravity') OR
         (provider = 'GEMINI_ADK_AGENT_ENGINE' AND
          implementation_sdk = 'google-adk'))
);

ALTER TABLE agent_runs
  ADD FOREIGN KEY (organization_id, project_id, environment_id, workspace_id)
  REFERENCES workspaces(organization_id, project_id, environment_id, id);

CREATE OR REPLACE FUNCTION enforce_workspace_checkpoint_lineage()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  workspace_row solvan.workspaces%ROWTYPE;
  parent_row solvan.workspace_checkpoints%ROWTYPE;
BEGIN
  SELECT * INTO workspace_row
  FROM solvan.workspaces
  WHERE organization_id = NEW.organization_id
    AND project_id = NEW.project_id
    AND environment_id = NEW.environment_id
    AND id = NEW.workspace_id;

  IF workspace_row.id IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = '23503',
      MESSAGE = 'workspace checkpoint references an unknown workspace';
  END IF;

  IF NEW.workspace_generation <> workspace_row.generation
     OR NEW.provider <> workspace_row.provider
     OR NEW.implementation_sdk <> workspace_row.implementation_sdk
     OR NEW.implementation_sdk_version <> workspace_row.implementation_sdk_version
     OR NEW.implementation_sdk_distribution_hash <>
        workspace_row.implementation_sdk_distribution_hash
     OR NEW.provider_artifact_digest <> workspace_row.provider_artifact_digest
     OR NEW.provider_revision <> workspace_row.provider_revision THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      MESSAGE = 'workspace checkpoint does not match its workspace generation/provider';
  END IF;

  IF NEW.event_kind = 'REHYDRATION' THEN
    SELECT * INTO parent_row
    FROM solvan.workspace_checkpoints
    WHERE organization_id = NEW.organization_id
      AND project_id = NEW.project_id
      AND environment_id = NEW.environment_id
      AND id = NEW.parent_checkpoint_id;

    IF parent_row.id IS NULL THEN
      RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'workspace rehydration requires an existing parent checkpoint';
    END IF;

    IF parent_row.workspace_id <> NEW.workspace_id
       OR parent_row.workspace_generation <> NEW.workspace_generation
       OR parent_row.sequence_no >= NEW.sequence_no
       OR parent_row.input_manifest_hash <> NEW.input_manifest_hash
       OR parent_row.artifact_manifest_hash <> NEW.artifact_manifest_hash
       OR parent_row.implementation_sdk_distribution_hash <>
          NEW.implementation_sdk_distribution_hash
       OR parent_row.provider_artifact_digest <> NEW.provider_artifact_digest
       OR parent_row.effective_tool_set_hash <> NEW.effective_tool_set_hash
       OR parent_row.effective_network_policy_hash <> NEW.effective_network_policy_hash
       OR parent_row.provider_boot_hash = NEW.provider_boot_hash
       OR parent_row.provider_service_revision = NEW.provider_service_revision THEN
      RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'invalid workspace rehydration lineage';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_checkpoint_lineage_guard
BEFORE INSERT ON workspace_checkpoints
FOR EACH ROW EXECUTE FUNCTION enforce_workspace_checkpoint_lineage();

CREATE TABLE standing_preauthorizations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  action_type text NOT NULL CHECK (action_type = 'PAYMENTS_POOL_RECYCLE'),
  service_id text NOT NULL,
  incident_class text NOT NULL,
  maximum_risk_class text NOT NULL CHECK (maximum_risk_class IN ('LOW','MEDIUM')),
  payload_constraints_json jsonb NOT NULL,
  maximum_attempts integer NOT NULL CHECK (maximum_attempts = 1),
  cooldown_ms bigint NOT NULL CHECK (cooldown_ms >= 600000),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','REVOKED','EXPIRED')),
  approved_by text,
  approved_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id, version),
  FOREIGN KEY (organization_id, project_id, environment_id, service_id)
    REFERENCES services(organization_id, project_id, environment_id, id),
  CHECK (valid_until > valid_from),
  CHECK ((status <> 'APPROVED') OR (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);

CREATE TABLE actions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^act_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  display_id text NOT NULL CHECK (display_id ~ '^ACT-[0-9]{4,}$'),
  incident_id text,
  reliability_case_id text,
  workflow_version bigint NOT NULL CHECK (workflow_version > 0),
  evidence_version bigint NOT NULL CHECK (evidence_version >= 0),
  action_type text NOT NULL CHECK (action_type IN
    ('PAYMENTS_POOL_RECYCLE','CLOUD_RUN_TRAFFIC_ROLLBACK')),
  normalized_signature text NOT NULL,
  target_key text NOT NULL,
  expected_target_version text NOT NULL,
  expected_target_epoch bigint NOT NULL CHECK (expected_target_epoch >= 0),
  payload_json jsonb NOT NULL,
  payload_digest text NOT NULL,
  expected_effect_json jsonb NOT NULL,
  expected_effect_hash text NOT NULL
    CHECK (expected_effect_hash ~ '^sha256:[0-9a-f]{64}$'),
  risk_class text NOT NULL CHECK (risk_class IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  reversible boolean NOT NULL,
  rollback_plan_json jsonb NOT NULL,
  verification_profile_id text NOT NULL,
  verification_profile_version integer NOT NULL CHECK (verification_profile_version > 0),
  policy_decision_id text NOT NULL,
  proposer_principal text NOT NULL,
  standing_preauthorization_id text,
  standing_preauthorization_version integer,
  requires_approval boolean NOT NULL,
  status text NOT NULL CHECK (status IN
    ('PROPOSED','AWAITING_APPROVAL','AUTHORIZED','EXECUTING','RECONCILING',
     'SUCCEEDED','FAILED','AMBIGUOUS','DRY_RUN_MISMATCH','INVALIDATED','CANCELLED')),
  idempotency_key text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, display_id),
  UNIQUE (organization_id, project_id, environment_id, idempotency_key),
  UNIQUE (organization_id, project_id, environment_id, id, expected_effect_hash),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, policy_decision_id)
    REFERENCES policy_decisions(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
    standing_preauthorization_id, standing_preauthorization_version)
    REFERENCES standing_preauthorizations
      (organization_id, project_id, environment_id, id, version),
  CHECK ((incident_id IS NOT NULL) <> (reliability_case_id IS NOT NULL)),
  CHECK (jsonb_typeof(expected_effect_json) = 'object'
    AND expected_effect_json <> '{}'::jsonb),
  CHECK ((requires_approval AND standing_preauthorization_id IS NULL AND
          standing_preauthorization_version IS NULL) OR
         (NOT requires_approval AND standing_preauthorization_id IS NOT NULL AND
          standing_preauthorization_version IS NOT NULL))
);

ALTER TABLE agent_runs
  ADD FOREIGN KEY (organization_id, project_id, environment_id, action_id)
  REFERENCES actions(organization_id, project_id, environment_id, id);

CREATE TABLE approvals (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^apr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  action_id text NOT NULL,
  sequence_no integer NOT NULL CHECK (sequence_no > 0),
  action_digest text NOT NULL,
  target_key text NOT NULL,
  expected_target_version text NOT NULL,
  expected_target_epoch bigint NOT NULL,
  evidence_version bigint NOT NULL,
  policy_version text NOT NULL,
  approver_principal text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVE','REJECT','REVOKE')),
  reason text NOT NULL,
  decision_request_id text,
  decided_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  supersedes_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, action_id)
    REFERENCES actions(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, supersedes_id)
    REFERENCES approvals(organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, action_id, sequence_no),
  UNIQUE (organization_id, project_id, environment_id, decision_request_id),
  UNIQUE (organization_id, project_id, environment_id, supersedes_id),
  CHECK ((sequence_no = 1 AND supersedes_id IS NULL) OR
    (sequence_no > 1 AND supersedes_id IS NOT NULL)),
  CHECK ((decision <> 'REVOKE') OR supersedes_id IS NOT NULL),
  CHECK (expires_at > decided_at)
);

CREATE UNIQUE INDEX approvals_one_root
  ON approvals (organization_id, project_id, environment_id, action_id)
  WHERE supersedes_id IS NULL;

CREATE TABLE target_epochs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  target_key text NOT NULL,
  epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
  last_observed_version text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, target_key)
);

CREATE TABLE target_reservations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rsv_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  target_key text NOT NULL,
  reservation_epoch bigint NOT NULL,
  expected_target_epoch bigint NOT NULL,
  action_id text NOT NULL,
  owner_identity text NOT NULL,
  lease_token uuid NOT NULL,
  acquired_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  released_at timestamptz,
  release_reason text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, action_id)
    REFERENCES actions(organization_id, project_id, environment_id, id),
  CHECK (reservation_epoch = expected_target_epoch + 1),
  CHECK (expires_at > acquired_at),
  CHECK (released_at IS NULL OR released_at >= acquired_at),
  CHECK ((released_at IS NULL) = (release_reason IS NULL))
);

CREATE UNIQUE INDEX target_reservations_one_active
  ON target_reservations
    (organization_id, project_id, environment_id, target_key)
  WHERE released_at IS NULL;

CREATE TABLE execution_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rcp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  action_id text NOT NULL,
  attempt integer NOT NULL CHECK (attempt > 0),
  connector_request_id text,
  idempotency_key text NOT NULL,
  before_state_ref text NOT NULL,
  after_state_ref text,
  observed_target_version text,
  started_at timestamptz NOT NULL,
  connector_returned_at timestamptz,
  reconciled_at timestamptz,
  result text NOT NULL CHECK (result IN ('SUCCEEDED','FAILED','AMBIGUOUS')),
  error_class text,
  actor_identity text NOT NULL,
  trace_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, action_id, attempt),
  FOREIGN KEY (organization_id, project_id, environment_id, action_id)
    REFERENCES actions(organization_id, project_id, environment_id, id)
);

CREATE TABLE verification_profiles (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RETIRED')),
  owner text NOT NULL,
  warmup_ms bigint NOT NULL CHECK (warmup_ms >= 0),
  observation_ms bigint NOT NULL CHECK (observation_ms > 0),
  required_signals_json jsonb NOT NULL,
  guardrails_json jsonb NOT NULL,
  inconclusive_policy text NOT NULL CHECK (inconclusive_policy IN ('ESCALATE')),
  content_hash text NOT NULL,
  approved_by text,
  approved_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id, version),
  CHECK ((status <> 'APPROVED') OR
    (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);

ALTER TABLE actions
  ADD CONSTRAINT actions_verification_profile_fk
  FOREIGN KEY (organization_id, project_id, environment_id,
    verification_profile_id, verification_profile_version)
  REFERENCES verification_profiles
    (organization_id, project_id, environment_id, id, version);

CREATE TABLE verification_profile_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  production_graph_snapshot_id text NOT NULL,
  service_id text NOT NULL,
  incident_class text NOT NULL,
  profile_id text NOT NULL,
  profile_version integer NOT NULL,
  effective_at timestamptz NOT NULL,
  superseded_at timestamptz,
  policy_owner text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id,
    service_id, incident_class, effective_at),
  FOREIGN KEY (organization_id, project_id, environment_id, service_id)
    REFERENCES services(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, production_graph_snapshot_id)
    REFERENCES production_graph_snapshots(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, profile_id, profile_version)
    REFERENCES verification_profiles(organization_id, project_id, environment_id, id, version)
);

CREATE UNIQUE INDEX verification_binding_one_current
  ON verification_profile_bindings
    (organization_id, project_id, environment_id, service_id, incident_class)
  WHERE superseded_at IS NULL;

CREATE TABLE verification_runs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ver_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  purpose text NOT NULL CHECK (purpose IN ('MITIGATION_ACTION','CASE_OBSERVATION')),
  incident_id text,
  reliability_case_id text,
  action_id text,
  profile_id text NOT NULL,
  profile_version integer NOT NULL,
  resolved_binding_ref text NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  signal_results_json jsonb NOT NULL,
  synthetic_receipt_ref text,
  verdict text NOT NULL CHECK (verdict IN ('VERIFIED','FAILED','INCONCLUSIVE')),
  rationale_codes jsonb NOT NULL,
  agent_run_id text,
  completed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, reliability_case_id)
    REFERENCES reliability_cases(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, action_id)
    REFERENCES actions(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, profile_id, profile_version)
    REFERENCES verification_profiles(organization_id, project_id, environment_id, id, version),
  CHECK ((incident_id IS NOT NULL) <> (reliability_case_id IS NOT NULL)),
  CHECK ((purpose <> 'MITIGATION_ACTION') OR
    (incident_id IS NOT NULL AND action_id IS NOT NULL)),
  CHECK ((purpose <> 'CASE_OBSERVATION') OR reliability_case_id IS NOT NULL),
  CHECK (window_end >= window_start)
);

CREATE UNIQUE INDEX verification_runs_one_mitigation_result
  ON verification_runs
    (organization_id, project_id, environment_id, action_id)
  WHERE purpose = 'MITIGATION_ACTION';

CREATE TABLE memory_candidates (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^memc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  scope_json jsonb NOT NULL,
  purpose text NOT NULL,
  candidate_type text NOT NULL CHECK (candidate_type IN
    ('ROOT_CAUSE','MITIGATION_OUTCOME','PERMANENT_REPAIR_OUTCOME',
     'TEAM_PREFERENCE','RUNBOOK_FACT','PATTERN')),
  fact_text text NOT NULL,
  content_hash text NOT NULL,
  source_refs jsonb NOT NULL,
  source_hashes jsonb NOT NULL,
  confirmation_status text NOT NULL CHECK (confirmation_status IN
    ('CONFIRMED','VERIFIED','HUMAN_APPROVED','OWNER_APPROVED','SAMPLE_CONFIRMED',
     'UNCONFIRMED','INCONCLUSIVE','CONTRADICTED')),
  verification_ref text,
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  residency text NOT NULL,
  redaction_manifest_ref text NOT NULL,
  armor_verdict_ref text NOT NULL,
  provenance_json jsonb NOT NULL,
  policy_version text NOT NULL,
  review_requirement text NOT NULL CHECK (review_requirement IN
    ('AUTOMATIC','HUMAN','PROHIBITED')),
  status text NOT NULL CHECK (status IN
    ('PENDING','QUARANTINED','APPROVED','PROMOTING','REJECTED','PROMOTED','EXPIRED')),
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, id)
);

CREATE TABLE memory_promotions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^memp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  candidate_id text NOT NULL,
  memory_resource text NOT NULL,
  memory_revision text,
  exact_scope_json jsonb NOT NULL,
  promoter_identity text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('PROMOTED','PURGED')),
  content_hash text NOT NULL,
  retention_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, candidate_id)
    REFERENCES memory_candidates(organization_id, project_id, environment_id, id)
);

CREATE TABLE security_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^sec_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  event_type text NOT NULL,
  control text NOT NULL CHECK (control IN
    ('MODEL_ARMOR','AGENT_GATEWAY','IAM','SCOPE','REGION','MEMORY_GATE','INPUT_VALIDATOR')),
  severity text NOT NULL CHECK (severity IN ('INFO','WARNING','HIGH','CRITICAL')),
  actor_principal text,
  destination_ref text,
  incident_id text,
  safe_summary text NOT NULL,
  payload_hash text,
  policy_ref text,
  trace_id text,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id)
);

CREATE TABLE audit_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  sequence_id bigint GENERATED ALWAYS AS IDENTITY,
  id text NOT NULL CHECK (id ~ '^aud_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  stream_type text NOT NULL,
  stream_id text NOT NULL,
  event_type text NOT NULL,
  actor_principal text NOT NULL,
  decision_ref text,
  input_refs_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  payload_hash text NOT NULL,
  trace_id text,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, sequence_id),
  UNIQUE (organization_id, project_id, environment_id, id)
);

CREATE INDEX audit_events_stream_idx
  ON audit_events
    (organization_id, project_id, environment_id, stream_type, stream_id, sequence_id);

-- Consequential append-only rows create their audit record in the same
-- transaction. The trigger is security-definer so runtime workloads never need
-- direct INSERT, UPDATE, or DELETE authority on the ledger itself.
CREATE FUNCTION append_audit_event() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, solvan
AS $$
DECLARE
  row_json jsonb := to_jsonb(NEW);
  source_id text := row_json ->> 'id';
  stream_id_value text;
  actor_value text;
  decision_value text;
  input_refs_value jsonb;
  payload_hash_value text;
  occurred_value timestamptz;
BEGIN
  stream_id_value := COALESCE(NULLIF(row_json ->> TG_ARGV[1], ''), source_id);
  actor_value := COALESCE(NULLIF(row_json ->> TG_ARGV[3], ''), 'system:database-trigger');
  decision_value := NULLIF(row_json ->> TG_ARGV[4], '');
  input_refs_value := COALESCE(row_json -> TG_ARGV[5], '[]'::jsonb);
  IF jsonb_typeof(input_refs_value) <> 'array' THEN
    input_refs_value := '[]'::jsonb;
  END IF;
  payload_hash_value := COALESCE(
    NULLIF(row_json ->> TG_ARGV[6], ''),
    'source-row:' || TG_TABLE_NAME || ':' || source_id
  );
  occurred_value := COALESCE((row_json ->> TG_ARGV[7])::timestamptz, now());

  INSERT INTO solvan.audit_events
    (organization_id, project_id, environment_id, id, stream_type, stream_id,
     event_type, actor_principal, decision_ref, input_refs_json, payload_hash,
     trace_id, occurred_at)
  VALUES
    (NEW.organization_id, NEW.project_id, NEW.environment_id,
     'aud_0' || substring(upper(md5(TG_TABLE_NAME || ':' || source_id)) from 1 for 25),
     TG_ARGV[0], stream_id_value, TG_ARGV[2], actor_value, decision_value,
     input_refs_value, payload_hash_value, NULLIF(row_json ->> 'trace_id', ''),
     occurred_value);
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION append_audit_event() FROM PUBLIC;

CREATE TRIGGER state_transitions_audit
AFTER INSERT ON state_transitions FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'WORKFLOW', 'entity_id', 'STATE_TRANSITION_RECORDED', 'actor_id',
  'policy_decision_id', 'evidence_refs_json', '', 'occurred_at');

CREATE TRIGGER agent_runs_audit
AFTER INSERT ON agent_runs FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'AGENT_RUN', 'id', 'AGENT_RUN_CREATED', 'agent_key', '', 'budget_json',
  'input_hash', 'started_at');

CREATE TRIGGER policy_decisions_audit
AFTER INSERT ON policy_decisions FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'POLICY_DECISION', 'id', 'POLICY_DECISION_RECORDED', '', 'id', '',
  'input_hash', 'created_at');

CREATE TRIGGER workspaces_audit
AFTER INSERT ON workspaces FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'WORKSPACE', 'id', 'WORKSPACE_CREATED', 'created_by_principal',
  'provider_eligibility_decision_id', '', 'input_manifest_hash', 'created_at');

CREATE TRIGGER workspace_checkpoints_audit
AFTER INSERT ON workspace_checkpoints FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'WORKSPACE', 'workspace_id', 'WORKSPACE_CHECKPOINT_RECORDED',
  'created_by_principal', 'parent_checkpoint_id', '',
  'artifact_manifest_hash', 'created_at');

CREATE TRIGGER actions_audit
AFTER INSERT ON actions FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'ACTION', 'id', 'ACTION_PROPOSED', 'proposer_principal', 'policy_decision_id', '',
  'payload_digest', 'created_at');

CREATE TRIGGER approvals_audit
AFTER INSERT ON approvals FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'ACTION', 'action_id', 'APPROVAL_DECISION_RECORDED', 'approver_principal',
  'action_digest', '', 'action_digest', 'decided_at');

CREATE TRIGGER execution_receipts_audit
AFTER INSERT ON execution_receipts FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'ACTION', 'action_id', 'EXECUTION_RECEIPT_RECORDED', 'actor_identity', '', '',
  'idempotency_key', 'reconciled_at');

CREATE TRIGGER verification_runs_audit
AFTER INSERT ON verification_runs FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'VERIFICATION', 'id', 'VERIFICATION_COMPLETED', 'agent_run_id',
  'resolved_binding_ref', 'rationale_codes', 'resolved_binding_ref', 'completed_at');

CREATE TRIGGER patch_reviews_audit
AFTER INSERT ON patch_reviews FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'RELIABILITY_CASE', 'reliability_case_id', 'PATCH_REVIEW_RECORDED',
  'reviewer_principal', 'patch_digest', '', 'patch_digest', 'decided_at');

CREATE TRIGGER github_webhook_events_audit
AFTER INSERT ON github_webhook_events FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'GITHUB_WEBHOOK', 'id', 'GITHUB_WEBHOOK_ACCEPTED', 'sender_login', '', '',
  'payload_hash', 'received_at');

CREATE TRIGGER github_pull_requests_audit
AFTER INSERT ON github_pull_requests FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'GITHUB_PULL_REQUEST', 'id', 'GITHUB_PULL_REQUEST_RECORDED', 'created_by_principal',
  'patch_artifact_id', '', 'patch_digest', 'created_at');

CREATE TRIGGER github_operations_audit
AFTER INSERT ON github_operations FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'GITHUB_OPERATION', 'id', 'GITHUB_OPERATION_RECORDED', 'actor_principal',
  'patch_review_id', '', 'request_hash', 'created_at');

CREATE TRIGGER memory_promotions_audit
AFTER INSERT ON memory_promotions FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'MEMORY_CANDIDATE', 'candidate_id', 'MEMORY_PROMOTED', 'promoter_identity',
  'memory_resource', '', 'content_hash', 'created_at');

CREATE TRIGGER security_events_audit
AFTER INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION append_audit_event(
  'SECURITY_EVENT', 'id', 'SECURITY_EVENT_RECORDED', 'actor_principal',
  'policy_ref', '', 'payload_hash', 'occurred_at');

-- ---------------------------------------------------------------------------
-- Tenant integration (specification 13). Observe and actuate across customer
-- estates. These tables carry the three scope columns, so the row-level
-- security loop below enables isolation on them automatically.
-- ---------------------------------------------------------------------------

-- A registered read or execute relationship with one customer system.
CREATE TABLE tenant_connections (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  display_name text NOT NULL CHECK (length(display_name) > 0),
  kind text NOT NULL CHECK (kind IN ('GCP_NATIVE','VENDOR_API','COLLECTOR')),
  provider text NOT NULL CHECK (provider IN
    ('CLOUD_MONITORING','CLOUD_LOGGING','CLOUD_TRACE','CLOUD_AUDIT',
     'ERROR_REPORTING','ASSET_INVENTORY','MANAGED_PROMETHEUS','CLOUD_RUN',
     'CLOUD_SQL','CLOUD_BUILD','GITHUB','PRODUCTION_GRAPH','SOLVAN_ACTUATOR',
     'SOLVAN_VERIFIER','WORKSPACE_SNAPSHOT','ANTIGRAVITY',
     'DATADOG','PROMETHEUS','GRAFANA','NEW_RELIC','KUBERNETES','SOLVAN_COLLECTOR')),

  -- Credential posture is data, not prose (specification 13 §3.3).
  credential_posture text NOT NULL CHECK (credential_posture IN
    ('FEDERATED_SHORT_LIVED','STORED_LONG_LIVED','CUSTOMER_SIDE_NONE')),
  authentication_mode text NOT NULL DEFAULT 'CUSTOMER_SIDE_NONE' CHECK (authentication_mode IN
    ('GCP_SERVICE_ACCOUNT_IMPERSONATION','STORED_SECRET_REFERENCE',
     'CUSTOMER_SIDE_NONE')),
  solvan_delegator_principal text,
  customer_reader_principal text,
  delegation_condition_digest text CHECK
    (delegation_condition_digest IS NULL OR
     delegation_condition_digest ~ '^sha256:[0-9a-f]{64}$'),
  token_lifetime_seconds integer CHECK
    (token_lifetime_seconds IS NULL OR token_lifetime_seconds BETWEEN 1 AND 900),
  credential_secret_ref text CHECK
  -- A pinned numeric version, never an alias. A version's payload is
  -- immutable, so the key whose scope was proved read-only is the key every
  -- later read resolves; `versions/latest` would follow whatever payload was
  -- added most recently and let a write-capable key replace a verified one.
    (credential_secret_ref IS NULL OR
     credential_secret_ref ~ '^projects/[^/]+/secrets/[^/]+/versions/[0-9]+$'),
  credential_cmek_key_ref text,
  -- Whether a stored key is read-only is an observation, not an assertion.
  -- This was a plain boolean a caller supplied, so the constraint below proved
  -- only that somebody had set it. The state carries how it was established,
  -- and the boolean is generated from it so no writer can set it directly.
  read_only_scope_state text NOT NULL DEFAULT 'UNVERIFIABLE' CHECK (read_only_scope_state IN
    ('VERIFIED_READ_ONLY','REFUSED_WRITE_SCOPE','UNVERIFIABLE')),
  read_only_scope_reason_code text CHECK (read_only_scope_reason_code IS NULL OR
    read_only_scope_reason_code IN
      ('WRITE_SCOPE_PRESENT','SCOPE_NOT_RECOGNIZED','SCOPES_NOT_REPORTED',
       'NO_SCOPE_INTROSPECTION','VENDOR_ENDPOINT_UNKNOWN','INTROSPECTION_REFUSED',
       'VENDOR_UNREACHABLE','CREDENTIAL_UNREADABLE','VERIFIER_UNAVAILABLE')),
  read_only_scope_verified_at timestamptz,
  read_only_scope_evidence_ref text,
  read_only_scope_verified boolean NOT NULL GENERATED ALWAYS AS
    (read_only_scope_state = 'VERIFIED_READ_ONLY') STORED,
  credential_rotated_at timestamptz,
  credential_expires_at timestamptz,

  residency_region text NOT NULL,
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  connection_epoch bigint NOT NULL DEFAULT 1 CHECK (connection_epoch > 0),

  -- Specification 13 §4. Two separate facts. `lifecycle` is authored: what an
  -- administrator decided about this connection. `availability` is derived from
  -- the newest non-superseded probe and that lifecycle: what Solvan can
  -- actually do right now. Collapsing them loses the difference between "not
  -- set up yet" and "set up and refused".
  lifecycle text NOT NULL DEFAULT 'PENDING' CHECK (lifecycle IN
    ('PENDING','ENABLED','DISABLED','REVOKED')),
  availability text NOT NULL DEFAULT 'NOT_CONFIGURED' CHECK (availability IN
    ('NOT_CONFIGURED','PROBING','READY','DEGRADED','MISCONFIGURED',
     'DENIED','UNREACHABLE','STALE','DISABLED')),

  -- Every non-READY availability explains itself, or an operator is told only
  -- that something failed. Secret values and provider response bodies are never
  -- stored here.
  -- The defaults describe a newly registered connection, which is not a state
  -- without a reason: it has never been probed. They match what
  -- `derive_availability` returns for no observations, so the database and the
  -- application cannot disagree about what an unprobed connection means.
  availability_reason_code text DEFAULT 'NEVER_PROBED'
    CHECK (availability_reason_code IS NULL OR
           availability_reason_code ~ '^[A-Z][A-Z0-9_]{2,47}$'),
  availability_explanation text
    DEFAULT 'this connection has never been probed, so nothing about it is proven'
    CHECK (availability_explanation IS NULL OR
           length(availability_explanation) BETWEEN 1 AND 400),
  availability_missing_grant text,
  availability_remediation_kind text DEFAULT 'RETRY_PROBE'
    CHECK (availability_remediation_kind IS NULL OR
           availability_remediation_kind IN
             ('GRANT_ROLE','ENABLE_API','FIX_CONFIGURATION','REGISTER_CREDENTIAL',
              'RETRY_PROBE','REENABLE_CONNECTION','CONTACT_PROVIDER')),
  availability_reference text,
  availability_receipt_ref text DEFAULT 'probe://absent',

  last_probe_at timestamptz,
  last_probe_result text CHECK (last_probe_result IS NULL OR
    last_probe_result IN ('SUCCEEDED','PARTIAL','FAILED')),
  last_success_at timestamptz,
  proof_expires_at timestamptz,
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, provider, display_name),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id),

  -- Direct Google Cloud reads use only a short-lived token minted by the
  -- exact Cloud Run reader identity for the exact customer reader account.
  -- Workload-identity pool fields are intentionally absent: this is a
  -- Google-to-Google delegation path, not external WIF.
  CHECK ((credential_posture <> 'FEDERATED_SHORT_LIVED') OR
         (authentication_mode = 'GCP_SERVICE_ACCOUNT_IMPERSONATION'
          AND kind = 'GCP_NATIVE'
          AND solvan_delegator_principal ~ '^serviceAccount:[^@ ]+@[^@ ]+$'
          AND customer_reader_principal ~ '^serviceAccount:[^@ ]+@[^@ ]+$'
          AND delegation_condition_digest IS NOT NULL
          AND token_lifetime_seconds BETWEEN 1 AND 900
          AND credential_secret_ref IS NULL)),
  -- Stored keys are Secret Manager references under CMEK.
  CHECK ((credential_posture <> 'STORED_LONG_LIVED') OR
         (authentication_mode = 'STORED_SECRET_REFERENCE'
          AND credential_secret_ref IS NOT NULL AND credential_cmek_key_ref IS NOT NULL)),
  -- An unverified stored key may exist so its refusal is legible to an
  -- operator, but it can never be READY. Refusing the row instead would leave
  -- the operator with a rejected request and no record of why.
  CHECK ((credential_posture <> 'STORED_LONG_LIVED') OR availability <> 'READY'
         OR read_only_scope_state = 'VERIFIED_READ_ONLY'),
  -- A refusal states its reason; a verification states when and against what.
  CHECK ((credential_posture <> 'STORED_LONG_LIVED')
         OR read_only_scope_state = 'VERIFIED_READ_ONLY'
         OR read_only_scope_reason_code IS NOT NULL),
  CHECK ((read_only_scope_state <> 'VERIFIED_READ_ONLY') OR
         (read_only_scope_reason_code IS NULL
          AND read_only_scope_verified_at IS NOT NULL
          AND read_only_scope_evidence_ref IS NOT NULL)),
  -- A posture that holds no key has nothing to verify.
  CHECK ((credential_posture = 'STORED_LONG_LIVED') OR
         (read_only_scope_state = 'UNVERIFIABLE'
          AND read_only_scope_reason_code IS NULL
          AND read_only_scope_verified_at IS NULL
          AND read_only_scope_evidence_ref IS NULL)),
  -- Customer-side collectors hand Solvan nothing at all.
  CHECK ((credential_posture <> 'CUSTOMER_SIDE_NONE') OR
         (authentication_mode = 'CUSTOMER_SIDE_NONE'
          AND credential_secret_ref IS NULL AND solvan_delegator_principal IS NULL
          AND customer_reader_principal IS NULL AND delegation_condition_digest IS NULL
          AND token_lifetime_seconds IS NULL)),
  CHECK ((credential_posture = 'FEDERATED_SHORT_LIVED') OR
         (solvan_delegator_principal IS NULL AND customer_reader_principal IS NULL
          AND delegation_condition_digest IS NULL AND token_lifetime_seconds IS NULL)),
  -- A connection that has never probed successfully cannot be READY.
  CHECK ((availability <> 'READY') OR last_probe_result = 'SUCCEEDED'),
  -- Every non-READY availability carries a stable reason code, a safe
  -- explanation, a remediation kind, and the receipt it was derived from.
  CHECK (availability = 'READY' OR
         (availability_reason_code IS NOT NULL
          AND availability_explanation IS NOT NULL
          AND availability_remediation_kind IS NOT NULL
          AND availability_receipt_ref IS NOT NULL)),
  -- A READY connection has nothing to remediate, so it carries no reason.
  CHECK (availability <> 'READY' OR
         (availability_reason_code IS NULL
          AND availability_remediation_kind IS NULL
          AND availability_missing_grant IS NULL)),
  -- An administrator's decision to stop using a connection is not something a
  -- probe can override.
  CHECK ((lifecycle NOT IN ('DISABLED','REVOKED')) OR availability = 'DISABLED'),
  -- A connection that has never succeeded has no success instant to show.
  CHECK ((last_success_at IS NULL) OR last_probe_at IS NOT NULL)
);

-- Capability is observed by probe, never assumed from configuration.
CREATE TABLE connection_capabilities (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  connection_id text NOT NULL,
  capability text NOT NULL,
  available boolean NOT NULL,
  -- Specification 13 §4. Why the probe answered as it did, typed. The probe
  -- already distinguishes a refused permission from an unreachable provider
  -- from a disabled API; recording only a sentence throws that away and leaves
  -- an operator unable to tell which of them to act on.
  outcome text NOT NULL CHECK (outcome IN
    ('GRANTED','DENIED','UNREACHABLE','MISCONFIGURED','NOT_PROBED')),
  missing_grant text,
  observed_at timestamptz NOT NULL DEFAULT now(),
  probe_receipt_ref text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, connection_id, capability),
  FOREIGN KEY (organization_id, project_id, environment_id, connection_id)
    REFERENCES tenant_connections(organization_id, project_id, environment_id, id),
  -- An unavailable capability must say exactly what is missing.
  CHECK (available OR missing_grant IS NOT NULL),
  -- Availability and outcome are two views of one probe answer and cannot
  -- disagree: only a granted capability is available.
  CHECK (available = (outcome = 'GRANTED'))
);

-- A customer-deployed actuator instance and the posture it is permitted.
CREATE TABLE actuator_registrations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^atr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  connection_id text NOT NULL,

  host_kind text NOT NULL CHECK (host_kind IN
    ('CLOUD_RUN','GKE','ONPREM_FEDERATED','ONPREM_KEYFILE','DEV_LOCAL')),
  production_eligible boolean NOT NULL,
  risk_acceptance_ref text,

  -- Verified OIDC identity. Never accepted from a header or request body.
  principal_email text NOT NULL CHECK (position('@' in principal_email) > 1),
  expected_audience text NOT NULL CHECK (expected_audience ~ '^https://'),

  posture text NOT NULL CHECK (posture IN ('COLLECTOR','REMEDIATE')),
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  actuator_version text NOT NULL,
  policy_hash text CHECK (policy_hash IS NULL OR policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  policy_source_ref text,
  customer_audit_sink_ref text,
  kill_switch_engaged boolean NOT NULL DEFAULT false,

  status text NOT NULL DEFAULT 'REGISTERED' CHECK (status IN
    ('REGISTERED','ACTIVE','DISABLED','REVOKED')),
  last_poll_at timestamptz,
  registered_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, principal_email),
  FOREIGN KEY (organization_id, project_id, environment_id, connection_id)
    REFERENCES tenant_connections(organization_id, project_id, environment_id, id),

  -- INV-T-09: development hosts can never be production eligible. Stated as an
  -- implication, not an equality: the equality also *forced* every non-dev host
  -- eligible, so a key-file host could not be registered as ineligible even
  -- though specification 13 says such a host is not eligible by default.
  CHECK (NOT production_eligible OR host_kind <> 'DEV_LOCAL'),
  -- INV-T-10: a key-file host requires a recorded, explicit risk acceptance.
  CHECK ((host_kind <> 'ONPREM_KEYFILE') OR risk_acceptance_ref IS NOT NULL),
  -- Mutation posture requires production eligibility, a customer policy, and
  -- a customer-owned audit sink for dual-written receipts.
  CHECK ((posture <> 'REMEDIATE') OR
         (production_eligible AND policy_hash IS NOT NULL
          AND customer_audit_sink_ref IS NOT NULL))
);

CREATE UNIQUE INDEX actuator_one_active_per_connection
  ON actuator_registrations
    (organization_id, project_id, environment_id, connection_id)
  WHERE status = 'ACTIVE';

-- One outstanding dispatch per actuator bounds customer-side concurrency.
CREATE TABLE actuator_dispatches (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^dsp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  actuator_id text NOT NULL,
  action_id text NOT NULL,
  reservation_id text NOT NULL,

  dispatched_at timestamptz NOT NULL DEFAULT now(),
  lease_expires_at timestamptz NOT NULL,
  lease_owner text NOT NULL,
  lease_token uuid NOT NULL,
  dispatch_policy_hash text NOT NULL,
  expected_effect_hash text NOT NULL
    CHECK (expected_effect_hash ~ '^sha256:[0-9a-f]{64}$'),
  connector_revision text NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  mutation_started_at timestamptz,
  connector_request_id text,
  connector_returned_at timestamptz,
  trace_id text,

  status text NOT NULL DEFAULT 'PREPARED' CHECK (status IN
    ('PREPARED','MUTATION_ISSUED','RECONCILING','EXECUTED','AMBIGUOUS',
     'REFUSED','DRY_RUN_MISMATCH','EXPIRED')),
  refusal_reason text CHECK (refusal_reason IS NULL OR refusal_reason IN
    ('OUTSIDE_ALLOWLIST','OUTSIDE_TARGET_SELECTOR','BUDGET_EXCEEDED',
     'KILL_SWITCH_ENGAGED','APPROVAL_EXPIRED','NOT_REVERSIBLE',
     'POLICY_HASH_DRIFT','TARGET_PRECONDITION_FAILED')),
  settled_at timestamptz,

  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, action_id),
  FOREIGN KEY (organization_id, project_id, environment_id, actuator_id)
    REFERENCES actuator_registrations(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, action_id)
    REFERENCES actions(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, reservation_id)
    REFERENCES target_reservations(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
    action_id, expected_effect_hash)
    REFERENCES actions
      (organization_id, project_id, environment_id, id, expected_effect_hash),

  CHECK (lease_expires_at > dispatched_at),
  CHECK ((status <> 'REFUSED') OR refusal_reason IS NOT NULL),
  CHECK ((status IN ('PREPARED','MUTATION_ISSUED','RECONCILING'))
    = (settled_at IS NULL)),
  CHECK ((status = 'PREPARED') = (mutation_started_at IS NULL)),
  CHECK (trace_id IS NULL OR trace_id ~ '^[0-9a-f]{32}$')
);

CREATE UNIQUE INDEX actuator_one_outstanding_dispatch
  ON actuator_dispatches
    (organization_id, project_id, environment_id, actuator_id)
  WHERE status IN ('PREPARED','MUTATION_ISSUED','RECONCILING');

CREATE INDEX actuator_dispatch_lease_idx
  ON actuator_dispatches (lease_expires_at)
  WHERE status IN ('PREPARED','MUTATION_ISSUED','RECONCILING');

-- Dry-run evidence and the observed-pre-state undo plan, per attempt.
-- Extends execution_receipts rather than replacing it.
CREATE TABLE actuator_effect_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aef_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  dispatch_id text NOT NULL,
  execution_receipt_id text,

  policy_hash text NOT NULL,
  before_state_ref text NOT NULL,
  before_state_hash text NOT NULL CHECK (before_state_hash ~ '^sha256:[0-9a-f]{64}$'),
  predicted_effect_hash text NOT NULL
    CHECK (predicted_effect_hash ~ '^sha256:[0-9a-f]{64}$'),
  effect_matched_expectation boolean NOT NULL,
  undo_plan_json jsonb NOT NULL,
  undo_derived_from text NOT NULL DEFAULT 'OBSERVED_PRE_STATE'
    CHECK (undo_derived_from = 'OBSERVED_PRE_STATE'),
  after_state_ref text,
  customer_audit_written boolean NOT NULL DEFAULT false,
  customer_audit_ref text,

  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  error_class text,

  PRIMARY KEY (organization_id, project_id, environment_id, id),
  -- INV-T-08: receipts are idempotent on the dispatch.
  UNIQUE (organization_id, project_id, environment_id, dispatch_id),
  FOREIGN KEY (organization_id, project_id, environment_id, dispatch_id)
    REFERENCES actuator_dispatches(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, execution_receipt_id)
    REFERENCES execution_receipts(organization_id, project_id, environment_id, id),

  -- INV-T-06: a mutation may only reconcile when its predicted effect matched.
  CHECK (effect_matched_expectation OR execution_receipt_id IS NULL),
  -- INV-T-14: a completed mutation must record its customer-side audit write.
  CHECK ((execution_receipt_id IS NULL) OR customer_audit_written),
  CHECK ((customer_audit_written = false) OR customer_audit_ref IS NOT NULL)
);

-- Isolated competition workload. These tables are provisioned by migration,
-- never created by the runtime service account.
CREATE TABLE fixture_payments (
  idempotency_key text PRIMARY KEY,
  payment_id text NOT NULL,
  fixture_tenant text NOT NULL CHECK (fixture_tenant = 'solvan-synthetic'),
  amount_minor integer NOT NULL CHECK (amount_minor > 0),
  revision text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE fixture_admin_actions (
  idempotency_key text PRIMARY KEY,
  action_id text NOT NULL UNIQUE,
  request_id text NOT NULL,
  before_generation text NOT NULL,
  after_generation text NOT NULL,
  result text NOT NULL CHECK (result = 'EFFECT_CONFIRMED'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE fixture_runtime_state (
  state_key text PRIMARY KEY CHECK (state_key = 'pool_generation'),
  state_value bigint NOT NULL CHECK (state_value > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO fixture_runtime_state (state_key, state_value)
VALUES ('pool_generation', 1);

CREATE TABLE database_scope_bindings (
  database_role name PRIMARY KEY,
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES environments(organization_id, project_id, id)
);

CREATE FUNCTION scope_permitted(
  requested_role name,
  requested_organization_id text,
  requested_project_id text,
  requested_environment_id text
) RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = solvan, pg_temp
AS $scope_function$
  SELECT EXISTS (
    SELECT 1 FROM database_scope_bindings binding
    WHERE binding.database_role = requested_role
      AND binding.organization_id = requested_organization_id
      AND binding.project_id = requested_project_id
      AND binding.environment_id = requested_environment_id
  )
$scope_function$;

REVOKE ALL ON FUNCTION scope_permitted(name, text, text, text) FROM PUBLIC;

-- Every full-scope table is protected in the database as well as application
-- queries. The immutable database-role binding is not client-settable.
DO $scope_policies$
DECLARE
  scoped_table record;
BEGIN
  FOR scoped_table IN
    SELECT table_name
    FROM information_schema.columns
    WHERE table_schema = 'solvan'
      AND column_name IN ('organization_id', 'project_id', 'environment_id')
      AND table_name <> 'database_scope_bindings'
    GROUP BY table_name
    HAVING count(DISTINCT column_name) = 3
  LOOP
    EXECUTE format('ALTER TABLE solvan.%I ENABLE ROW LEVEL SECURITY', scoped_table.table_name);
    EXECUTE format('ALTER TABLE solvan.%I FORCE ROW LEVEL SECURITY', scoped_table.table_name);
    EXECUTE format(
      'CREATE POLICY scope_isolation ON solvan.%I '
      'USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))',
      scoped_table.table_name
    );
  END LOOP;
END
$scope_policies$;

COMMIT;
