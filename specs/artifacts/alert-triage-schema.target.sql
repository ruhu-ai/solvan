-- Solvan Alert Triage target schema for specification 21, Phase 1.
--
-- This is intentionally separate from the fixed competition release schema.
-- It implements durable Cloud Monitoring intake, source continuity, semantic
-- provider generations, policy matching, and policy-owned alert episodes.

BEGIN;
CREATE SCHEMA solvan_alerts;
SET search_path TO solvan_alerts, public;

CREATE FUNCTION reject_alert_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'alert history is append-only' USING ERRCODE = '23951';
END $$;

CREATE TABLE alert_provider_source_identities (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^asi_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  provider_kind text NOT NULL CHECK (provider_kind = 'CLOUD_MONITORING'),
  initial_connection_id text NOT NULL,
  initial_connection_epoch bigint NOT NULL CHECK (initial_connection_epoch > 0),
  scoping_project_id text NOT NULL CHECK (scoping_project_id ~ '^[a-z][a-z0-9-]{4,61}$'),
  topic_name text NOT NULL CHECK (topic_name ~ '^projects/[^/]+/topics/[^/]+$'),
  topic_binding_receipt_ref text NOT NULL,
  subscription_name text NOT NULL CHECK
    (subscription_name ~ '^projects/[^/]+/subscriptions/[^/]+$'),
  push_principal text NOT NULL CHECK (push_principal ~ '^[^@ ]+@[^@ ]+$'),
  oidc_audience text NOT NULL CHECK (length(oidc_audience) BETWEEN 8 AND 512),
  payload_schema_version text NOT NULL CHECK (payload_schema_version = '1.2'),
  source_material_hash text NOT NULL CHECK (source_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_AUDIT',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,id,provider_kind,
          scoping_project_id,topic_name,subscription_name,payload_schema_version),
  FOREIGN KEY (organization_id,project_id,environment_id,initial_connection_id)
    REFERENCES solvan.tenant_connections(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id)
    REFERENCES solvan.environments(organization_id,project_id,id),
  CHECK ((purge_tombstone_ref IS NULL) OR (legal_hold_ref IS NULL))
);

CREATE TABLE alert_provider_source_epoch_memberships (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^asm_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  source_identity_id text NOT NULL,
  continuity_epoch bigint NOT NULL CHECK (continuity_epoch > 0),
  expected_predecessor_membership_id text,
  predecessor_connection_id text,
  predecessor_connection_epoch bigint,
  successor_connection_id text NOT NULL,
  successor_connection_epoch bigint NOT NULL CHECK (successor_connection_epoch > 0),
  compared_material_hash text NOT NULL CHECK (compared_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  decision text NOT NULL CHECK (decision IN ('CONTINUITY_ACCEPTED','NEW_IDENTITY_REQUIRED')),
  decision_ref text NOT NULL,
  actor_principal text NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_AUDIT',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,source_identity_id,continuity_epoch),
  UNIQUE (organization_id,project_id,environment_id,successor_connection_id,
          successor_connection_epoch),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key,request_hash),
  UNIQUE (organization_id,project_id,environment_id,id,source_identity_id,
          continuity_epoch,successor_connection_id,successor_connection_epoch,decision),
  FOREIGN KEY (organization_id,project_id,environment_id,source_identity_id)
    REFERENCES alert_provider_source_identities(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,successor_connection_id)
    REFERENCES solvan.tenant_connections(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,expected_predecessor_membership_id)
    REFERENCES alert_provider_source_epoch_memberships(organization_id,project_id,environment_id,id),
  CHECK ((continuity_epoch = 1 AND expected_predecessor_membership_id IS NULL AND
          predecessor_connection_id IS NULL AND predecessor_connection_epoch IS NULL) OR
         (continuity_epoch > 1 AND expected_predecessor_membership_id IS NOT NULL AND
          predecessor_connection_id IS NOT NULL AND predecessor_connection_epoch > 0)),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE TABLE alert_provider_source_current_memberships (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  source_identity_id text NOT NULL,
  membership_id text NOT NULL,
  continuity_epoch bigint NOT NULL CHECK (continuity_epoch > 0),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  decision text NOT NULL DEFAULT 'CONTINUITY_ACCEPTED'
    CHECK (decision = 'CONTINUITY_ACCEPTED'),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_PROJECTION',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,source_identity_id),
  UNIQUE (organization_id,project_id,environment_id,connection_id,connection_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,membership_id,
               source_identity_id,continuity_epoch,connection_id,connection_epoch,decision)
    REFERENCES alert_provider_source_epoch_memberships
      (organization_id,project_id,environment_id,id,source_identity_id,
       continuity_epoch,successor_connection_id,successor_connection_epoch,decision),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE FUNCTION guard_alert_source_current_membership() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'current source membership cannot be deleted'
      USING ERRCODE='23962';
  END IF;
  IF NEW.continuity_epoch <> OLD.continuity_epoch+1 OR
     NEW.row_version <> OLD.row_version+1 OR
     NEW.source_identity_id <> OLD.source_identity_id OR
     NEW.classification <> OLD.classification OR
     NEW.retention_policy_revision <> OLD.retention_policy_revision OR
     NEW.membership_id = OLD.membership_id THEN
    RAISE EXCEPTION 'source membership replacement lost its exact epoch fence'
      USING ERRCODE='23963';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER alert_source_current_membership_fence
BEFORE UPDATE OR DELETE ON alert_provider_source_current_memberships
FOR EACH ROW EXECUTE FUNCTION guard_alert_source_current_membership();

CREATE TABLE alert_ingress_deliveries (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ald_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  provider_kind text NOT NULL CHECK (provider_kind = 'CLOUD_MONITORING'),
  provider_source_identity_id text NOT NULL,
  topic_binding_receipt_ref text NOT NULL,
  subscription_name text NOT NULL,
  authenticated_push_principal text,
  oidc_audience text NOT NULL,
  pubsub_message_id text NOT NULL CHECK (length(pubsub_message_id) BETWEEN 1 AND 256),
  publish_time timestamptz,
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  semantic_event_id text,
  outcome text NOT NULL CHECK (outcome IN ('COMMITTED','REFUSED','QUARANTINED')),
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  raw_payload_ref text,
  raw_payload_hash text CHECK (raw_payload_hash IS NULL OR raw_payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_INGRESS',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  committed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,connection_id,connection_epoch,
          subscription_name,pubsub_message_id),
  UNIQUE (organization_id,project_id,environment_id,id,semantic_event_id),
  FOREIGN KEY (organization_id,project_id,environment_id,connection_id)
    REFERENCES solvan.tenant_connections(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,placement_epoch,cell_id)
    REFERENCES solvan_scale.tenant_placements(organization_id,placement_epoch,cell_id),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_source_identity_id)
    REFERENCES alert_provider_source_identities(organization_id,project_id,environment_id,id),
  CHECK ((outcome = 'COMMITTED') = (semantic_event_id IS NOT NULL)),
  CHECK (outcome <> 'COMMITTED' OR authenticated_push_principal IS NOT NULL),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE TABLE alert_ingress_receive_attempts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ala_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  delivery_id text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  authenticated_identity text,
  authentication_result text NOT NULL CHECK
    (authentication_result IN ('VERIFIED','REFUSED')),
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  failure_reason_code text,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_AUDIT',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,delivery_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,delivery_id)
    REFERENCES alert_ingress_deliveries(organization_id,project_id,environment_id,id),
  CHECK (authentication_result<>'VERIFIED' OR authenticated_identity IS NOT NULL),
  CHECK ((authentication_result='REFUSED')=(failure_reason_code IS NOT NULL)),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE TABLE alert_ingress_response_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^alr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  delivery_id text NOT NULL,
  receive_attempt_id text NOT NULL,
  event_kind text NOT NULL CHECK (event_kind IN
    ('HTTP_SUCCESS_RESPONSE_SELECTED','HTTP_REFUSAL_RESPONSE_SELECTED',
     'HTTP_RESPONSE_WRITE_ATTEMPTED')),
  write_result text CHECK (write_result IN ('NOT_ATTEMPTED','SUCCEEDED','FAILED')),
  safe_reason_code text NOT NULL,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_AUDIT',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,delivery_id,receive_attempt_id,event_kind),
  FOREIGN KEY (organization_id,project_id,environment_id,delivery_id,receive_attempt_id)
    REFERENCES alert_ingress_receive_attempts
      (organization_id,project_id,environment_id,delivery_id,id),
  CHECK ((event_kind='HTTP_RESPONSE_WRITE_ATTEMPTED')=(write_result IS NOT NULL)),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE TABLE alert_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ale_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  first_admitted_delivery_id text NOT NULL,
  provider_source_identity_id text NOT NULL,
  observed_connection_id text NOT NULL,
  observed_connection_epoch bigint NOT NULL CHECK (observed_connection_epoch > 0),
  provider_incident_key text NOT NULL CHECK (length(provider_incident_key) BETWEEN 1 AND 256),
  lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('OPEN','CLOSED')),
  transition_discriminator text NOT NULL,
  transition_sequence bigint NOT NULL CHECK (transition_sequence > 0),
  started_at timestamptz NOT NULL,
  ended_at timestamptz,
  observed_at timestamptz NOT NULL,
  scoping_project_id text NOT NULL,
  monitored_resource_project_id text NOT NULL,
  resource_type text NOT NULL,
  resource_labels_json jsonb NOT NULL CHECK (jsonb_typeof(resource_labels_json)='object'),
  normalized_labels_json jsonb NOT NULL CHECK (jsonb_typeof(normalized_labels_json)='object'),
  provider_severity text NOT NULL,
  canonical_projection_version text NOT NULL CHECK (canonical_projection_version='cloud-monitoring/1.2'),
  canonical_event_hash text NOT NULL CHECK (canonical_event_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_EVENT',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,provider_source_identity_id,
          provider_incident_key,transition_discriminator),
  UNIQUE (organization_id,project_id,environment_id,id,provider_source_identity_id,
          provider_incident_key,started_at,lifecycle_state),
  FOREIGN KEY (organization_id,project_id,environment_id,first_admitted_delivery_id)
    REFERENCES alert_ingress_deliveries(organization_id,project_id,environment_id,id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (organization_id,project_id,environment_id,provider_source_identity_id)
    REFERENCES alert_provider_source_identities(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,placement_epoch,cell_id)
    REFERENCES solvan_scale.tenant_placements(organization_id,placement_epoch,cell_id),
  CHECK ((lifecycle_state='OPEN' AND ended_at IS NULL) OR
         (lifecycle_state='CLOSED' AND ended_at IS NOT NULL)),
  CHECK (ended_at IS NULL OR ended_at >= started_at),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

ALTER TABLE alert_ingress_deliveries
  ADD FOREIGN KEY (organization_id,project_id,environment_id,semantic_event_id)
  REFERENCES alert_events(organization_id,project_id,environment_id,id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE alert_provider_generations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^alg_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  provider_source_identity_id text NOT NULL,
  provider_incident_key text NOT NULL,
  started_at timestamptz NOT NULL,
  first_semantic_event_id text NOT NULL,
  last_semantic_event_id text NOT NULL,
  provider_state_projection text NOT NULL CHECK (provider_state_projection IN ('OPEN','CLOSED')),
  policy_projection_state text CHECK
    (policy_projection_state IN ('MATCHED','UNMATCHED','POLICY_CONFLICT')),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_GENERATION',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,provider_source_identity_id,
          provider_incident_key,started_at),
  UNIQUE (organization_id,project_id,environment_id,id,provider_source_identity_id,
          provider_incident_key,started_at),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_source_identity_id)
    REFERENCES alert_provider_source_identities(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,first_semantic_event_id)
    REFERENCES alert_events(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,last_semantic_event_id)
    REFERENCES alert_events(organization_id,project_id,environment_id,id),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE FUNCTION guard_alert_generation_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.row_version <> OLD.row_version+1 OR
     (OLD.provider_state_projection='CLOSED' AND NEW.provider_state_projection<>'CLOSED') OR
     (OLD.policy_projection_state IS NOT NULL AND
      NEW.policy_projection_state IS DISTINCT FROM OLD.policy_projection_state) OR
     (to_jsonb(NEW)-ARRAY['provider_state_projection','last_semantic_event_id',
                          'policy_projection_state','row_version','updated_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['provider_state_projection','last_semantic_event_id',
                          'policy_projection_state','row_version','updated_at']) THEN
    RAISE EXCEPTION 'provider generation projection update is not monotonic and fenced'
      USING ERRCODE='23964';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER alert_generation_projection_fence
BEFORE UPDATE ON alert_provider_generations
FOR EACH ROW EXECUTE FUNCTION guard_alert_generation_projection();

CREATE TABLE alert_provider_generation_occurrences (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aoc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  delivery_id text NOT NULL,
  semantic_event_id text NOT NULL,
  provider_generation_id text NOT NULL,
  observed_at timestamptz NOT NULL,
  source_state text NOT NULL CHECK (source_state IN ('OPEN','CLOSED')),
  occurrence_kind text NOT NULL CHECK (occurrence_kind IN ('TRANSITION','RENOTIFICATION','LATE_HISTORY')),
  safe_reason_code text NOT NULL,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_AUDIT',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,delivery_id,semantic_event_id,
          provider_generation_id,occurrence_kind),
  FOREIGN KEY (organization_id,project_id,environment_id,delivery_id)
    REFERENCES alert_ingress_deliveries(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,semantic_event_id)
    REFERENCES alert_events(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_generation_id)
    REFERENCES alert_provider_generations(organization_id,project_id,environment_id,id),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE TABLE alert_policy_revisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  policy_key text NOT NULL,
  policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  alert_material_hash text NOT NULL CHECK
    (alert_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  source_kind text NOT NULL CHECK (source_kind='CLOUD_MONITORING'),
  selector_json jsonb NOT NULL CHECK (jsonb_typeof(selector_json)='object'),
  target_mapping_json jsonb NOT NULL CHECK (jsonb_typeof(target_mapping_json)='object'),
  severity_mapping_json jsonb NOT NULL CHECK (jsonb_typeof(severity_mapping_json)='object'),
  mode text NOT NULL CHECK (mode IN ('TRIAGE','POLICY_ESCALATED','FULL_INCIDENT')),
  triage_profile_ref text NOT NULL CHECK (triage_profile_ref='alert-triage-read-compute-v1@1'),
  incident_profile_ref text NOT NULL,
  escalation_expression_json jsonb,
  full_incident_admission_expression_json jsonb,
  triage_budget_json jsonb NOT NULL CHECK (jsonb_typeof(triage_budget_json)='object'),
  incident_admission_budget_json jsonb NOT NULL CHECK
    (jsonb_typeof(incident_admission_budget_json)='object'),
  episode_horizon_ms bigint NOT NULL CHECK (episode_horizon_ms BETWEEN 1000 AND 7776000000),
  delivery_policy_ref text,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_POLICY',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,policy_key,policy_version),
  UNIQUE (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash),
  UNIQUE (organization_id,project_id,environment_id,policy_key,policy_version,
          alert_material_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash)
    REFERENCES solvan_operability.trigger_policy_revisions
      (organization_id,project_id,environment_id,policy_key,version,policy_hash),
  CHECK ((mode='TRIAGE' AND escalation_expression_json IS NULL AND
          full_incident_admission_expression_json IS NULL) OR
         (mode='POLICY_ESCALATED' AND escalation_expression_json IS NOT NULL AND
          full_incident_admission_expression_json IS NULL) OR
         (mode='FULL_INCIDENT' AND escalation_expression_json IS NULL AND
          full_incident_admission_expression_json IS NOT NULL)),
  CHECK (escalation_expression_json IS NULL OR jsonb_typeof(escalation_expression_json)='object'),
  CHECK (full_incident_admission_expression_json IS NULL OR
         jsonb_typeof(full_incident_admission_expression_json)='object'),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE FUNCTION require_alert_policy_authority_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE base_policy record;
BEGIN
  SELECT trigger_kind,target_selector_ref,profile_key,profile_version
    INTO base_policy
    FROM solvan_operability.trigger_policy_revisions
   WHERE (organization_id,project_id,environment_id,policy_key,version,policy_hash)=
         (NEW.organization_id,NEW.project_id,NEW.environment_id,
          NEW.policy_key,NEW.policy_version,NEW.policy_hash);
  IF base_policy IS NULL OR base_policy.trigger_kind <> 'ALERT_OPENED' OR
     base_policy.target_selector_ref <>
       ('selector://alert-policy/' || substring(NEW.alert_material_hash from 8) || '@1') OR
     (base_policy.profile_key || '@' || base_policy.profile_version) <>
       NEW.triage_profile_ref THEN
    RAISE EXCEPTION 'alert subtype is not bound by its trigger-policy approval digest'
      USING ERRCODE = '23961';
  END IF;
  RETURN NEW;
END $$;

CREATE CONSTRAINT TRIGGER alert_policy_authority_binding
AFTER INSERT OR UPDATE ON alert_policy_revisions
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION require_alert_policy_authority_binding();

CREATE TABLE alert_policy_matches (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^apm_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  provider_generation_id text NOT NULL,
  policy_key text NOT NULL,
  policy_version text NOT NULL,
  policy_hash text NOT NULL,
  selector_result text NOT NULL CHECK (selector_result IN ('MATCH','NO_MATCH','BLOCKED')),
  mapping_result text NOT NULL CHECK (mapping_result IN ('MATCH','NO_MATCH','BLOCKED')),
  reason_codes_json jsonb NOT NULL CHECK
    (jsonb_typeof(reason_codes_json)='array' AND jsonb_array_length(reason_codes_json)>0),
  cell_id text,
  placement_epoch bigint,
  graph_snapshot_id text,
  graph_snapshot_version bigint,
  graph_content_hash text,
  target_node_key text,
  target_node_version text,
  safe_input_summary_json jsonb NOT NULL CHECK (jsonb_typeof(safe_input_summary_json)='object'),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_DECISION',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,provider_generation_id,
          policy_key,policy_version),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_generation_id)
    REFERENCES alert_provider_generations(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash)
    REFERENCES alert_policy_revisions
      (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash),
  CHECK ((mapping_result='MATCH') =
    (cell_id IS NOT NULL AND placement_epoch IS NOT NULL AND graph_snapshot_id IS NOT NULL AND
     graph_snapshot_version IS NOT NULL AND graph_content_hash IS NOT NULL AND
     target_node_key IS NOT NULL AND target_node_version IS NOT NULL)),
  CHECK (graph_content_hash IS NULL OR graph_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE FUNCTION require_alert_match_graph_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.mapping_result='MATCH' AND NOT EXISTS (
    SELECT 1
      FROM solvan_graph.graph_snapshots snapshot
      JOIN solvan_graph.graph_nodes node
        ON (node.organization_id,node.project_id,node.environment_id,node.cell_id,
            node.placement_epoch,node.snapshot_id)=
           (snapshot.organization_id,snapshot.project_id,snapshot.environment_id,
            snapshot.cell_id,snapshot.placement_epoch,snapshot.snapshot_id)
     WHERE (snapshot.organization_id,snapshot.project_id,snapshot.environment_id,
            snapshot.cell_id,snapshot.placement_epoch,snapshot.snapshot_id,
            snapshot.snapshot_version,snapshot.content_hash,snapshot.status)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.cell_id,
            NEW.placement_epoch,NEW.graph_snapshot_id,NEW.graph_snapshot_version,
            NEW.graph_content_hash,'APPROVED')
       AND node.node_key=NEW.target_node_key
       AND node.node_id=NEW.target_node_version
  ) THEN
    RAISE EXCEPTION 'alert policy match does not bind an exact approved graph node'
      USING ERRCODE='23965';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER alert_match_graph_binding
AFTER INSERT OR UPDATE ON alert_policy_matches
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION require_alert_match_graph_binding();

CREATE TABLE alert_generation_outcomes (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aou_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  provider_generation_id text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('MATCHED','UNMATCHED','POLICY_CONFLICT')),
  candidate_match_ids text[] NOT NULL,
  selected_policy_match_id text,
  safe_reason_code text NOT NULL,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_DECISION',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,provider_generation_id),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_generation_id)
    REFERENCES alert_provider_generations(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,selected_policy_match_id)
    REFERENCES alert_policy_matches(organization_id,project_id,environment_id,id),
  CHECK ((outcome='MATCHED')=(selected_policy_match_id IS NOT NULL)),
  CHECK ((outcome='POLICY_CONFLICT' AND cardinality(candidate_match_ids)>=2) OR
         (outcome='MATCHED' AND cardinality(candidate_match_ids)>=1) OR
         outcome='UNMATCHED'),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE FUNCTION require_alert_generation_candidates() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE candidate_count integer; distinct_count integer;
BEGIN
  SELECT count(*),count(DISTINCT candidate_id)
    INTO candidate_count,distinct_count
    FROM unnest(NEW.candidate_match_ids) AS candidate_id
    JOIN alert_policy_matches matched
      ON (matched.organization_id,matched.project_id,matched.environment_id,matched.id,
          matched.provider_generation_id)=
         (NEW.organization_id,NEW.project_id,NEW.environment_id,candidate_id,
          NEW.provider_generation_id);
  IF candidate_count <> cardinality(NEW.candidate_match_ids) OR
     distinct_count <> candidate_count OR
     (NEW.selected_policy_match_id IS NOT NULL AND
      NOT NEW.selected_policy_match_id=ANY(NEW.candidate_match_ids)) THEN
    RAISE EXCEPTION 'generation outcome candidates are not exact same-generation matches'
      USING ERRCODE='23966';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER alert_generation_candidates_exact
AFTER INSERT OR UPDATE ON alert_generation_outcomes
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION require_alert_generation_candidates();

CREATE TABLE alert_episodes (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aep_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  provider_generation_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  graph_snapshot_id text NOT NULL,
  graph_snapshot_version bigint NOT NULL CHECK (graph_snapshot_version>0),
  graph_content_hash text NOT NULL CHECK (graph_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  target_node_key text NOT NULL,
  target_node_version text NOT NULL,
  provider_source_identity_id text NOT NULL,
  provider_incident_key text NOT NULL,
  started_at timestamptz NOT NULL,
  fingerprint text NOT NULL CHECK (fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  policy_key text NOT NULL,
  policy_version text NOT NULL,
  policy_hash text NOT NULL,
  activation_id text NOT NULL,
  head_epoch bigint NOT NULL CHECK (head_epoch>0),
  episode_generation bigint NOT NULL CHECK (episode_generation>0),
  recurrence_of_episode_id text,
  state text NOT NULL CHECK (state IN
    ('OPEN','WAITING','TRIAGING','TRIAGED','SUPPRESSED','BLOCKED','ESCALATED',
     'ATTACHED','PROVIDER_REPORTED_CLEARED','EXPIRED')),
  first_source_time timestamptz NOT NULL,
  last_source_time timestamptz NOT NULL,
  last_event_id text NOT NULL,
  provider_state_projection text NOT NULL CHECK (provider_state_projection IN ('OPEN','CLOSED')),
  current_disposition text CHECK (current_disposition IN
    ('SUPPRESSED','TRIAGED_HOLD','ESCALATED_NEW','ESCALATED_ATTACHED','MANUAL_REVIEW','BLOCKED')),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version>0),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_EPISODE',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,provider_generation_id,target_node_key),
  UNIQUE (organization_id,project_id,environment_id,id,episode_generation),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_generation_id,
               provider_source_identity_id,provider_incident_key,started_at)
    REFERENCES alert_provider_generations
      (organization_id,project_id,environment_id,id,provider_source_identity_id,
       provider_incident_key,started_at),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash)
    REFERENCES alert_policy_revisions
      (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,activation_id,policy_key,
               policy_version,policy_hash,head_epoch)
    REFERENCES solvan_operability.trigger_policy_activations
      (organization_id,project_id,environment_id,id,policy_key,policy_version,policy_hash,head_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,
               graph_snapshot_id,target_node_key)
    REFERENCES solvan_graph.graph_nodes
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,node_key),
  FOREIGN KEY (organization_id,project_id,environment_id,last_event_id)
    REFERENCES alert_events(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,recurrence_of_episode_id)
    REFERENCES alert_episodes(organization_id,project_id,environment_id,id),
  CHECK (last_source_time>=first_source_time),
  CHECK ((episode_generation=1 AND recurrence_of_episode_id IS NULL) OR
         (episode_generation>1 AND recurrence_of_episode_id IS NOT NULL)),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE TABLE alert_episode_occurrences (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aec_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  delivery_id text NOT NULL,
  semantic_event_id text NOT NULL,
  episode_id text NOT NULL,
  episode_generation bigint NOT NULL,
  observed_at timestamptz NOT NULL,
  source_state text NOT NULL CHECK (source_state IN ('OPEN','CLOSED')),
  occurrence_kind text NOT NULL CHECK (occurrence_kind IN ('TRANSITION','RENOTIFICATION','LATE_HISTORY')),
  safe_reason_code text NOT NULL,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_AUDIT',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,delivery_id,semantic_event_id,
          episode_id,episode_generation,occurrence_kind),
  FOREIGN KEY (organization_id,project_id,environment_id,delivery_id)
    REFERENCES alert_ingress_deliveries(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,semantic_event_id)
    REFERENCES alert_events(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id,episode_generation)
    REFERENCES alert_episodes(organization_id,project_id,environment_id,id,episode_generation),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE TABLE alert_admissions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aad_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  provider_generation_id text NOT NULL,
  episode_id text NOT NULL,
  episode_generation bigint NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ADMITTED','SUPPRESSED','BLOCKED','PENDING')),
  reason_code text NOT NULL,
  budget_receipt_ref text,
  cooldown_until timestamptz,
  due_at timestamptz,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_class text NOT NULL DEFAULT 'ALERT_DECISION',
  retention_policy_revision text NOT NULL,
  legal_hold_ref text,
  purge_eligible_at timestamptz,
  purge_tombstone_ref text,
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,provider_generation_id),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_generation_id)
    REFERENCES alert_provider_generations(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id,episode_generation)
    REFERENCES alert_episodes(organization_id,project_id,environment_id,id,episode_generation),
  CHECK (purge_tombstone_ref IS NULL OR legal_hold_ref IS NULL)
);

CREATE INDEX alert_ingress_cursor_idx ON alert_ingress_deliveries
  (organization_id,project_id,environment_id,committed_at DESC,id);
CREATE INDEX alert_events_generation_idx ON alert_events
  (organization_id,project_id,environment_id,provider_source_identity_id,
   provider_incident_key,started_at,observed_at,id);
CREATE INDEX alert_generations_policy_queue_idx ON alert_provider_generations
  (organization_id,project_id,environment_id,policy_projection_state,updated_at,id);
CREATE INDEX alert_episodes_active_queue_idx ON alert_episodes
  (organization_id,project_id,environment_id,state,last_source_time DESC,id)
  WHERE state IN ('OPEN','WAITING','TRIAGING','TRIAGED','ESCALATED','ATTACHED');
CREATE INDEX alert_retention_due_idx ON alert_ingress_deliveries
  (organization_id,project_id,environment_id,purge_eligible_at)
  WHERE purge_tombstone_ref IS NULL AND legal_hold_ref IS NULL;

DO $alert_scope_policies$
DECLARE scoped_table record;
BEGIN
  FOR scoped_table IN
    SELECT table_name
      FROM information_schema.columns
     WHERE table_schema='solvan_alerts'
       AND column_name IN ('organization_id','project_id','environment_id')
     GROUP BY table_name
    HAVING count(DISTINCT column_name)=3
  LOOP
    EXECUTE format('ALTER TABLE solvan_alerts.%I ENABLE ROW LEVEL SECURITY',scoped_table.table_name);
    EXECUTE format('ALTER TABLE solvan_alerts.%I FORCE ROW LEVEL SECURITY',scoped_table.table_name);
    EXECUTE format(
      'CREATE POLICY alert_scope_isolation ON solvan_alerts.%I '
      'USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))',
      scoped_table.table_name);
  END LOOP;
END
$alert_scope_policies$;

DO $alert_history_guards$
DECLARE history_table text;
BEGIN
  FOREACH history_table IN ARRAY ARRAY[
    'alert_provider_source_identities','alert_provider_source_epoch_memberships',
    'alert_ingress_deliveries','alert_ingress_receive_attempts',
    'alert_ingress_response_events','alert_events',
    'alert_provider_generation_occurrences','alert_policy_revisions',
    'alert_policy_matches','alert_generation_outcomes','alert_episode_occurrences',
    'alert_admissions'
  ]
  LOOP
    EXECUTE format(
      'CREATE TRIGGER reject_history_mutation BEFORE UPDATE OR DELETE ON solvan_alerts.%I '
      'FOR EACH ROW EXECUTE FUNCTION solvan_alerts.reject_alert_history_mutation()',
      history_table);
  END LOOP;
END
$alert_history_guards$;

COMMIT;
