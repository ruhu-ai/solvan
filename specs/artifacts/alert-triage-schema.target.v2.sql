-- Alert Triage phase-2 scheduling, Agent-run anchoring, and disposition ledger.

BEGIN;

ALTER TABLE solvan.agent_runs
  ADD COLUMN IF NOT EXISTS alert_episode_id text;
DO $agent_run_anchor_upgrade$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid='solvan.agent_runs'::regclass
       AND conname='agent_runs_one_anchor_ck'
  ) THEN
    ALTER TABLE solvan.agent_runs DROP CONSTRAINT agent_runs_one_anchor_ck;
  ELSIF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid='solvan.agent_runs'::regclass
       AND conname='agent_runs_check'
       AND pg_get_constraintdef(oid) LIKE '%reliability_case_id%workspace_id%'
  ) THEN
    ALTER TABLE solvan.agent_runs DROP CONSTRAINT agent_runs_check;
  ELSE
    RAISE EXCEPTION 'known Agent-run anchor constraint is absent' USING ERRCODE='55000';
  END IF;
END
$agent_run_anchor_upgrade$;
ALTER TABLE solvan.agent_runs
  ADD CONSTRAINT agent_runs_one_anchor_ck CHECK (
    (incident_id IS NOT NULL)::integer
    + (reliability_case_id IS NOT NULL)::integer
    + (workspace_id IS NOT NULL)::integer
    + (alert_episode_id IS NOT NULL)::integer = 1
  );
ALTER TABLE solvan.agent_runs
  DROP CONSTRAINT IF EXISTS agent_runs_alert_episode_fk,
  ADD CONSTRAINT agent_runs_alert_episode_fk
  FOREIGN KEY (organization_id,project_id,environment_id,alert_episode_id)
  REFERENCES solvan_alerts.alert_episodes
    (organization_id,project_id,environment_id,id);

ALTER TABLE solvan_alerts.alert_admissions
  DROP CONSTRAINT alert_admissions_organization_id_project_id_environment_id__key;
ALTER TABLE solvan_alerts.alert_admissions
  ADD COLUMN decision_sequence bigint NOT NULL DEFAULT 1 CHECK (decision_sequence>0),
  ADD COLUMN previous_admission_id text,
  ADD COLUMN work_kind text CHECK (work_kind IS NULL OR work_kind='AGENT_RUN'),
  ADD COLUMN work_id text,
  ADD COLUMN capacity_reservation_id text,
  ADD COLUMN capacity_request_hash text CHECK
    (capacity_request_hash IS NULL OR capacity_request_hash ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE solvan_alerts.alert_admissions
  ADD CONSTRAINT alert_admissions_generation_sequence_uk
  UNIQUE (organization_id,project_id,environment_id,provider_generation_id,decision_sequence),
  ADD CONSTRAINT alert_admissions_generation_sequence_id_uk
  UNIQUE (organization_id,project_id,environment_id,provider_generation_id,
          decision_sequence,id),
  ADD CONSTRAINT alert_admissions_id_episode_uk
  UNIQUE (organization_id,project_id,environment_id,id,episode_id),
  ADD CONSTRAINT alert_admissions_previous_fk
  FOREIGN KEY (organization_id,project_id,environment_id,previous_admission_id)
  REFERENCES solvan_alerts.alert_admissions
    (organization_id,project_id,environment_id,id),
  ADD CONSTRAINT alert_admissions_work_fk
  FOREIGN KEY (organization_id,project_id,environment_id,work_kind,work_id)
  REFERENCES solvan_scale.tenant_work_registry
    (organization_id,project_id,environment_id,work_kind,work_id),
  ADD CONSTRAINT alert_admissions_capacity_fk
  FOREIGN KEY (organization_id,project_id,environment_id,capacity_reservation_id)
  REFERENCES solvan_scale.tenant_capacity_reservations
    (organization_id,project_id,environment_id,reservation_id),
  ADD CONSTRAINT alert_admissions_decision_shape_ck CHECK (
    (decision='ADMITTED' AND work_kind='AGENT_RUN' AND work_id IS NOT NULL
      AND capacity_reservation_id IS NOT NULL
      AND capacity_request_hash IS NOT NULL AND budget_receipt_ref=capacity_reservation_id) OR
    (decision='PENDING' AND work_kind='AGENT_RUN' AND work_id IS NOT NULL
      AND capacity_reservation_id IS NULL
      AND capacity_request_hash IS NOT NULL AND due_at IS NOT NULL
      AND budget_receipt_ref IS NULL) OR
    (decision IN ('SUPPRESSED','BLOCKED') AND work_kind IS NULL AND work_id IS NULL
      AND capacity_reservation_id IS NULL AND capacity_request_hash IS NULL
      AND budget_receipt_ref IS NULL)
  ),
  ADD CONSTRAINT alert_admissions_sequence_shape_ck CHECK (
    (decision_sequence=1 AND previous_admission_id IS NULL) OR
    (decision_sequence>1 AND previous_admission_id IS NOT NULL)
  );

CREATE TABLE solvan_alerts.alert_admission_current (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  provider_generation_id text NOT NULL,
  admission_id text NOT NULL,
  decision_sequence bigint NOT NULL CHECK (decision_sequence>0),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version>0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,provider_generation_id),
  FOREIGN KEY (organization_id,project_id,environment_id,provider_generation_id,
               decision_sequence,admission_id)
    REFERENCES solvan_alerts.alert_admissions
      (organization_id,project_id,environment_id,provider_generation_id,
       decision_sequence,id)
);

ALTER TABLE solvan_scale.tenant_capacity_reservations
  DROP CONSTRAINT IF EXISTS tenant_capacity_reservation_work_uk,
  ADD CONSTRAINT tenant_capacity_reservation_work_uk
  UNIQUE (organization_id,project_id,environment_id,reservation_id,work_kind,work_id);

CREATE TABLE solvan_alerts.alert_triage_runs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aru_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  episode_id text NOT NULL,
  episode_generation bigint NOT NULL,
  admission_id text NOT NULL,
  semantic_event_id text NOT NULL,
  policy_key text NOT NULL,
  policy_version text NOT NULL,
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch>0),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch>0),
  graph_snapshot_id text NOT NULL,
  graph_snapshot_version bigint NOT NULL CHECK (graph_snapshot_version>0),
  graph_content_hash text NOT NULL CHECK (graph_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  target_node_key text NOT NULL,
  target_node_version text NOT NULL,
  plan_json jsonb NOT NULL CHECK (jsonb_typeof(plan_json)='object'),
  plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[0-9a-f]{64}$'),
  profile_ref text NOT NULL CHECK (profile_ref='alert-triage-read-compute-v1@1'),
  effective_tool_set_hash text NOT NULL CHECK
    (effective_tool_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  agent_run_id text NOT NULL,
  work_kind text NOT NULL DEFAULT 'AGENT_RUN' CHECK (work_kind='AGENT_RUN'),
  work_id text NOT NULL,
  capacity_reservation_id text NOT NULL,
  claim_token uuid,
  claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch>=0),
  claim_expires_at timestamptz,
  status text NOT NULL CHECK
    (status IN ('QUEUED','CLAIMED','DISPATCHED','RUNNING','SUCCEEDED','FAILED',
                'TIMED_OUT','CANCELLED','STALE')),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,episode_id,admission_id),
  UNIQUE (organization_id,project_id,environment_id,agent_run_id),
  UNIQUE (organization_id,project_id,environment_id,id,episode_id),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id,episode_generation)
    REFERENCES solvan_alerts.alert_episodes
      (organization_id,project_id,environment_id,id,episode_generation),
  FOREIGN KEY (organization_id,project_id,environment_id,admission_id,episode_id)
    REFERENCES solvan_alerts.alert_admissions
      (organization_id,project_id,environment_id,id,episode_id),
  FOREIGN KEY (organization_id,project_id,environment_id,semantic_event_id)
    REFERENCES solvan_alerts.alert_events
      (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash)
    REFERENCES solvan_alerts.alert_policy_revisions
      (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,agent_run_id)
    REFERENCES solvan.agent_runs(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,work_kind,work_id)
    REFERENCES solvan_scale.tenant_work_registry
      (organization_id,project_id,environment_id,work_kind,work_id),
  FOREIGN KEY (organization_id,project_id,environment_id,capacity_reservation_id,
               work_kind,work_id)
    REFERENCES solvan_scale.tenant_capacity_reservations
      (organization_id,project_id,environment_id,reservation_id,work_kind,work_id),
  CHECK ((status IN ('CLAIMED','DISPATCHED','RUNNING'))=
         (claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CHECK ((status IN ('SUCCEEDED','FAILED','TIMED_OUT','CANCELLED','STALE'))
         =(completed_at IS NOT NULL))
);

CREATE INDEX alert_triage_runs_claimable_idx
  ON solvan_alerts.alert_triage_runs
    (cell_id,status,created_at,id) WHERE status='QUEUED';
CREATE INDEX alert_triage_runs_expired_claim_idx
  ON solvan_alerts.alert_triage_runs
    (cell_id,claim_expires_at)
    WHERE status IN ('CLAIMED','DISPATCHED','RUNNING');

CREATE TABLE solvan_alerts.alert_predicate_results (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^apr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  triage_run_id text NOT NULL,
  predicate_node_id text NOT NULL,
  predicate_kind text NOT NULL,
  input_refs_json jsonb NOT NULL CHECK (jsonb_typeof(input_refs_json)='array'),
  input_hash text NOT NULL CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
  result text NOT NULL CHECK (result IN ('TRUE','FALSE','INCONCLUSIVE')),
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,127}$'),
  evaluated_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,triage_run_id,predicate_node_id),
  FOREIGN KEY (organization_id,project_id,environment_id,triage_run_id)
    REFERENCES solvan_alerts.alert_triage_runs
      (organization_id,project_id,environment_id,id)
);

CREATE TABLE solvan_alerts.alert_dispositions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ads_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  episode_id text NOT NULL,
  triage_run_id text,
  disposition text NOT NULL CHECK (disposition IN
    ('SUPPRESSED','TRIAGED_HOLD','ESCALATED_NEW','ESCALATED_ATTACHED',
     'MANUAL_REVIEW','BLOCKED')),
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,127}$'),
  explanation_template_ref text NOT NULL,
  explanation_variables_json jsonb NOT NULL CHECK
    (jsonb_typeof(explanation_variables_json)='object'),
  evidence_refs_json jsonb NOT NULL CHECK (jsonb_typeof(evidence_refs_json)='array'),
  next_owner text NOT NULL,
  next_review_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,id,episode_id),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id)
    REFERENCES solvan_alerts.alert_episodes
      (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,triage_run_id,episode_id)
    REFERENCES solvan_alerts.alert_triage_runs
      (organization_id,project_id,environment_id,id,episode_id)
);

CREATE TABLE solvan_alerts.alert_incident_links (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  episode_id text NOT NULL,
  disposition_id text NOT NULL,
  incident_id text NOT NULL,
  link_kind text NOT NULL CHECK (link_kind IN ('CREATED','ATTACHED')),
  deduplication_decision text NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,episode_id,disposition_id),
  UNIQUE (organization_id,project_id,environment_id,disposition_id),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id)
    REFERENCES solvan_alerts.alert_episodes
      (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,disposition_id,episode_id)
    REFERENCES solvan_alerts.alert_dispositions
      (organization_id,project_id,environment_id,id,episode_id),
  FOREIGN KEY (organization_id,project_id,environment_id,incident_id)
    REFERENCES solvan.incidents(organization_id,project_id,environment_id,id)
);

DO $alert_phase_two_rls$
DECLARE scoped_table text;
BEGIN
  FOREACH scoped_table IN ARRAY ARRAY[
    'alert_admission_current','alert_triage_runs','alert_predicate_results',
    'alert_dispositions','alert_incident_links'
  ] LOOP
    EXECUTE format('ALTER TABLE solvan_alerts.%I ENABLE ROW LEVEL SECURITY',scoped_table);
    EXECUTE format('ALTER TABLE solvan_alerts.%I FORCE ROW LEVEL SECURITY',scoped_table);
    EXECUTE format(
      'CREATE POLICY alert_scope_isolation ON solvan_alerts.%I '
      'USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))',
      scoped_table);
  END LOOP;
END
$alert_phase_two_rls$;

CREATE TRIGGER reject_history_mutation
  BEFORE UPDATE OR DELETE ON solvan_alerts.alert_predicate_results
  FOR EACH ROW EXECUTE FUNCTION solvan_alerts.reject_alert_history_mutation();
CREATE TRIGGER reject_history_mutation
  BEFORE UPDATE OR DELETE ON solvan_alerts.alert_dispositions
  FOR EACH ROW EXECUTE FUNCTION solvan_alerts.reject_alert_history_mutation();
CREATE TRIGGER reject_history_mutation
  BEFORE UPDATE OR DELETE ON solvan_alerts.alert_incident_links
  FOR EACH ROW EXECUTE FUNCTION solvan_alerts.reject_alert_history_mutation();

COMMIT;
