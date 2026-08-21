-- Alert Triage operator commands, feedback, and bounded channel delivery.
BEGIN;

CREATE TABLE solvan_alerts.alert_operator_requests (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aor_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  episode_id text NOT NULL,
  request_kind text NOT NULL CHECK (request_kind IN ('RETRIAGE','INCIDENT_CONTINUATION')),
  expected_row_version bigint NOT NULL CHECK (expected_row_version>0),
  request_reason_code text NOT NULL CHECK (request_reason_code IN
    ('NEED_MORE_EVIDENCE','POSSIBLE_CUSTOMER_IMPACT','POSSIBLE_SECURITY_IMPACT','OPERATOR_REVIEW')),
  actor_principal text NOT NULL CHECK (length(actor_principal) BETWEEN 3 AND 512),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  outcome text NOT NULL CHECK (outcome IN ('ACCEPTED','REFUSED')),
  refusal_code text CHECK (refusal_code IS NULL OR refusal_code IN
    ('STALE_ROW','POLICY_INELIGIBLE','CAPACITY_UNAVAILABLE','TERMINAL_EPISODE',
     'INCIDENT_ALREADY_LINKED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,actor_principal,idempotency_key),
  UNIQUE (organization_id,project_id,environment_id,id,episode_id),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id)
    REFERENCES solvan_alerts.alert_episodes (organization_id,project_id,environment_id,id),
  CHECK ((outcome='REFUSED')=(refusal_code IS NOT NULL))
);
CREATE INDEX alert_operator_requests_pending_idx ON solvan_alerts.alert_operator_requests
  (organization_id,project_id,environment_id,created_at,id) WHERE outcome='ACCEPTED';

CREATE TABLE solvan_alerts.alert_operator_request_consumptions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  request_id text NOT NULL, episode_id text NOT NULL,
  outcome text NOT NULL CHECK
    (outcome IN ('ENQUEUED','INCIDENT_CREATED','INCIDENT_ATTACHED','REFUSED')),
  result_ref text,
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,127}$'),
  consumed_by text NOT NULL CHECK (length(consumed_by) BETWEEN 3 AND 512),
  consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,request_id),
  FOREIGN KEY (organization_id,project_id,environment_id,request_id,episode_id)
    REFERENCES solvan_alerts.alert_operator_requests
      (organization_id,project_id,environment_id,id,episode_id)
);

CREATE TABLE solvan_alerts.alert_feedback (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^afb_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  episode_id text NOT NULL,
  category text NOT NULL CHECK
    (category IN ('HELPFUL','NOT_HELPFUL','MISSING_EVIDENCE','INCORRECT_CAUSE','OTHER')),
  note_ref text CHECK (note_ref IS NULL OR note_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  actor_principal text NOT NULL CHECK (length(actor_principal) BETWEEN 3 AND 512),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  target_policy_key text NOT NULL, target_policy_version text NOT NULL,
  target_triage_run_id text,
  classification text NOT NULL CHECK
    (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,actor_principal,idempotency_key),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id)
    REFERENCES solvan_alerts.alert_episodes (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,target_triage_run_id,episode_id)
    REFERENCES solvan_alerts.alert_triage_runs
      (organization_id,project_id,environment_id,id,episode_id)
);

CREATE TABLE solvan_alerts.alert_channel_delivery_attempts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^acd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  episode_id text NOT NULL, disposition_id text NOT NULL,
  channel_binding_id text NOT NULL, binding_epoch bigint NOT NULL CHECK (binding_epoch>0),
  audience_hash text NOT NULL CHECK (audience_hash ~ '^sha256:[0-9a-f]{64}$'),
  payload_ref text NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  delivery_state text NOT NULL CHECK (delivery_state IN ('DELIVERED','FAILED','REFUSED')),
  provider_receipt_ref text, safe_failure_code text,
  delivered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,disposition_id,
          channel_binding_id,binding_epoch,payload_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,episode_id)
    REFERENCES solvan_alerts.alert_episodes (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,disposition_id,episode_id)
    REFERENCES solvan_alerts.alert_dispositions
      (organization_id,project_id,environment_id,id,episode_id),
  CHECK ((delivery_state='DELIVERED')=(provider_receipt_ref IS NOT NULL)),
  CHECK ((delivery_state IN ('FAILED','REFUSED'))=(safe_failure_code IS NOT NULL))
);
CREATE INDEX alert_channel_delivery_episode_idx ON solvan_alerts.alert_channel_delivery_attempts
  (organization_id,project_id,environment_id,episode_id,delivered_at DESC,id DESC);

DO $alert_phase_three_rls$
DECLARE scoped_table text;
BEGIN
  FOREACH scoped_table IN ARRAY ARRAY[
    'alert_operator_requests','alert_operator_request_consumptions',
    'alert_feedback','alert_channel_delivery_attempts'
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
$alert_phase_three_rls$;

COMMIT;
