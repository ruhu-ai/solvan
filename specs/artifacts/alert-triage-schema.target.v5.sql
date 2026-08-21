-- Alert decision explanations, policy simulation, templates, and recommendations.
BEGIN;

ALTER TABLE solvan_alerts.alert_policy_revisions
  ADD COLUMN template_ref text,
  ADD COLUMN calibration_receipt_refs_json jsonb NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(calibration_receipt_refs_json)='array'),
  ADD COLUMN recommendation_ref text;

CREATE INDEX alert_incident_links_incident_cursor_idx
  ON solvan_alerts.alert_incident_links
    (organization_id,project_id,environment_id,incident_id,linked_at,episode_id);

CREATE TABLE solvan_alerts.alert_policy_templates (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  template_key text NOT NULL, template_version text NOT NULL,
  publisher_ref text NOT NULL,
  policy_skeleton_json jsonb NOT NULL CHECK (jsonb_typeof(policy_skeleton_json)='object'),
  calibration_slots_json jsonb NOT NULL CHECK
    (jsonb_typeof(calibration_slots_json)='array' AND
     jsonb_array_length(calibration_slots_json)>0),
  example_values_json jsonb NOT NULL CHECK (jsonb_typeof(example_values_json)='object'),
  compatibility_range text NOT NULL,
  content_digest text NOT NULL CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
  lifecycle text NOT NULL CHECK (lifecycle IN ('ACTIVE','RETIRED')),
  retired_at timestamptz,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_policy_revision text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,template_key,template_version),
  UNIQUE (organization_id,project_id,environment_id,content_digest),
  CHECK ((lifecycle='RETIRED')=(retired_at IS NOT NULL))
);

CREATE TABLE solvan_alerts.alert_policy_simulation_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^sim_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  requesting_principal text NOT NULL CHECK (length(requesting_principal) BETWEEN 3 AND 512),
  draft_policy_key text NOT NULL, draft_version text NOT NULL,
  draft_digest text NOT NULL CHECK (draft_digest ~ '^sha256:[0-9a-f]{64}$'),
  sample_provider_generation_id text NOT NULL,
  sample_digest text NOT NULL CHECK (sample_digest ~ '^sha256:[0-9a-f]{64}$'),
  evaluator_key text NOT NULL, evaluator_version text NOT NULL,
  expression_digest text CHECK (expression_digest IS NULL OR
    expression_digest ~ '^sha256:[0-9a-f]{64}$'),
  result text NOT NULL CHECK (result IN
    ('WOULD_ESCALATE','WOULD_NOT_ESCALATE','WOULD_HOLD',
     'WOULD_REQUIRE_REVIEW','WOULD_BLOCK')),
  summary_template_id text NOT NULL,
  typed_values_json jsonb NOT NULL CHECK (jsonb_typeof(typed_values_json)='object'),
  authorized_node_summaries_json jsonb NOT NULL CHECK
    (jsonb_typeof(authorized_node_summaries_json)='array'),
  input_refs_json jsonb NOT NULL CHECK (jsonb_typeof(input_refs_json)='array'),
  access_set_hash text NOT NULL CHECK (access_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  response_digest text NOT NULL CHECK (response_digest ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,requesting_principal,idempotency_key),
  FOREIGN KEY (organization_id,project_id,environment_id,draft_policy_key,
               draft_version,draft_digest)
    REFERENCES solvan_alerts.alert_policy_revisions
      (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,sample_provider_generation_id)
    REFERENCES solvan_alerts.alert_provider_generations
      (organization_id,project_id,environment_id,id),
  CHECK (retention_until>created_at)
);

CREATE TABLE solvan_alerts.alert_policy_recommendations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rec_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  source_incident_id text NOT NULL, source_outcome_ref text NOT NULL,
  policy_key text NOT NULL, predecessor_version text NOT NULL,
  model_ref text NOT NULL, prompt_revision text NOT NULL,
  evidence_window_start timestamptz NOT NULL, evidence_window_end timestamptz NOT NULL,
  rationale_template_id text NOT NULL,
  rationale_values_json jsonb NOT NULL CHECK (jsonb_typeof(rationale_values_json)='object'),
  rate_budget_receipt_ref text NOT NULL,
  recommendation_digest text NOT NULL CHECK
    (recommendation_digest ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  region text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,recommendation_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,source_incident_id)
    REFERENCES solvan.incidents (organization_id,project_id,environment_id,id),
  CHECK (evidence_window_end>evidence_window_start AND expires_at>created_at)
);

CREATE TABLE solvan_alerts.alert_policy_recommendation_decisions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ard_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  recommendation_id text NOT NULL, recommendation_digest text NOT NULL,
  decision_epoch bigint NOT NULL CHECK (decision_epoch>0),
  decision_kind text NOT NULL CHECK
    (decision_kind IN ('DISMISSED','EXPIRED','DRAFT_CREATED')),
  actor_principal text NOT NULL CHECK (length(actor_principal) BETWEEN 3 AND 512),
  actor_role text NOT NULL CHECK (actor_role IN ('TRIGGER_POLICY_AUTHOR','OPERABILITY_ADMIN')),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,127}$'),
  resulting_draft_ref text, resulting_draft_digest text CHECK
    (resulting_draft_digest IS NULL OR resulting_draft_digest ~ '^sha256:[0-9a-f]{64}$'),
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,recommendation_id,decision_epoch),
  UNIQUE (organization_id,project_id,environment_id,actor_principal,idempotency_key),
  FOREIGN KEY (organization_id,project_id,environment_id,recommendation_id)
    REFERENCES solvan_alerts.alert_policy_recommendations
      (organization_id,project_id,environment_id,id),
  CHECK ((decision_kind='DRAFT_CREATED')=
    (resulting_draft_ref IS NOT NULL AND resulting_draft_digest IS NOT NULL))
);

CREATE TABLE solvan_alerts.alert_recovery_verification_links (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^arv_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  episode_id text NOT NULL, incident_id text NOT NULL, verification_run_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL CHECK (placement_epoch>0),
  projection_service_ref text NOT NULL,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_policy_revision text NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,episode_id,verification_run_id),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id)
    REFERENCES solvan_alerts.alert_episodes
      (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,incident_id)
    REFERENCES solvan.incidents (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,verification_run_id)
    REFERENCES solvan.verification_runs (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,placement_epoch,cell_id)
    REFERENCES solvan_scale.tenant_placements
      (organization_id,placement_epoch,cell_id)
);

CREATE INDEX alert_policy_recommendations_open_idx
  ON solvan_alerts.alert_policy_recommendations
    (organization_id,project_id,environment_id,expires_at,id);
CREATE INDEX alert_policy_recommendation_decisions_latest_idx
  ON solvan_alerts.alert_policy_recommendation_decisions
    (organization_id,project_id,environment_id,recommendation_id,decision_epoch DESC);
CREATE INDEX alert_recovery_verification_incident_idx
  ON solvan_alerts.alert_recovery_verification_links
    (organization_id,project_id,environment_id,incident_id,linked_at,episode_id);

DO $alert_phase_five_rls$
DECLARE scoped_table text;
BEGIN
  FOREACH scoped_table IN ARRAY ARRAY[
    'alert_policy_templates','alert_policy_simulation_receipts',
    'alert_policy_recommendations','alert_policy_recommendation_decisions',
    'alert_recovery_verification_links'
  ] LOOP
    EXECUTE format('ALTER TABLE solvan_alerts.%I ENABLE ROW LEVEL SECURITY',scoped_table);
    EXECUTE format('ALTER TABLE solvan_alerts.%I FORCE ROW LEVEL SECURITY',scoped_table);
    EXECUTE format(
      'CREATE POLICY alert_scope_isolation ON solvan_alerts.%I USING '
      '(solvan.scope_permitted(current_user,organization_id,project_id,environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))',
      scoped_table);
    EXECUTE format(
      'CREATE TRIGGER reject_history_mutation BEFORE UPDATE OR DELETE ON solvan_alerts.%I '
      'FOR EACH ROW EXECUTE FUNCTION solvan_alerts.reject_alert_history_mutation()', scoped_table);
  END LOOP;
END
$alert_phase_five_rls$;

COMMIT;
