-- Specifications 13 §3.5 and 21 §5.2: a polling detection rule reads only
-- through one exact current connection revision selected through Integrations.
BEGIN;
SET search_path TO solvan_onboarding, solvan, public;

CREATE TABLE detection_rule_connection_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  detection_rule_id text NOT NULL,
  detection_rule_version integer NOT NULL CHECK (detection_rule_version > 0),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  bound_by_principal text NOT NULL,
  decision_ref text NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,
               detection_rule_id,detection_rule_version),
  UNIQUE (organization_id,project_id,environment_id,idempotency_key),
  FOREIGN KEY (organization_id,project_id,environment_id,
               detection_rule_id,detection_rule_version)
    REFERENCES solvan.detection_rules
      (organization_id,project_id,environment_id,id,version),
  FOREIGN KEY (organization_id,project_id,environment_id,connection_id)
    REFERENCES solvan.tenant_connections
      (organization_id,project_id,environment_id,id)
);

CREATE FUNCTION detection_binding_is_eligible() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE observed record;
BEGIN
  SELECT provider,kind,authentication_mode,connection_epoch
    INTO observed
    FROM solvan.tenant_connections
   WHERE (organization_id,project_id,environment_id,id)=
         (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.connection_id);
  IF observed IS NULL OR observed.provider <> 'CLOUD_MONITORING'
     OR observed.kind <> 'GCP_NATIVE'
     OR observed.authentication_mode <> 'GCP_SERVICE_ACCOUNT_IMPERSONATION'
     OR observed.connection_epoch <> NEW.connection_epoch THEN
    RAISE EXCEPTION 'detection rule requires the exact current direct Cloud Monitoring connection'
      USING ERRCODE = '23931';
  END IF;
  RETURN NEW;
END $$;

CREATE CONSTRAINT TRIGGER detection_binding_is_eligible
  AFTER INSERT ON detection_rule_connection_bindings
  FOR EACH ROW EXECUTE FUNCTION detection_binding_is_eligible();

ALTER TABLE detection_rule_connection_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rule_connection_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY detection_rule_connection_binding_scope_isolation
  ON detection_rule_connection_bindings
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));

COMMIT;
