-- Make the qualified Relay providers representable in governed Tool profiles.
-- This is a closed pair expansion, not a generic external-source escape hatch.
BEGIN;
SET search_path TO solvan_operability, solvan, public;

DO $$
DECLARE constraint_name text;
BEGIN
  SELECT conname INTO constraint_name
    FROM pg_constraint
   WHERE conrelid = 'solvan_operability.tool_profile_connection_requirements'::regclass
     AND contype = 'c'
     AND pg_get_constraintdef(oid) LIKE '%binding_kind = ''COMPUTE_ONLY''%';
  IF constraint_name IS NULL THEN
    RAISE EXCEPTION 'profile source-pair constraint is absent';
  END IF;
  EXECUTE format('ALTER TABLE tool_profile_connection_requirements DROP CONSTRAINT %I', constraint_name);
END $$;
ALTER TABLE tool_profile_connection_requirements
  ADD CONSTRAINT tool_profile_connection_requirements_closed_source_pair CHECK (
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
  );

DO $$
DECLARE constraint_name text;
BEGIN
  SELECT conname INTO constraint_name
    FROM pg_constraint
   WHERE conrelid = 'solvan_operability.agent_run_accepted_tool_bindings'::regclass
     AND contype = 'c'
     AND pg_get_constraintdef(oid) LIKE '%binding_kind = ''COMPUTE_ONLY''%';
  IF constraint_name IS NULL THEN
    RAISE EXCEPTION 'accepted binding source-pair constraint is absent';
  END IF;
  EXECUTE format('ALTER TABLE agent_run_accepted_tool_bindings DROP CONSTRAINT %I', constraint_name);
END $$;
ALTER TABLE agent_run_accepted_tool_bindings
  ADD CONSTRAINT accepted_tool_bindings_closed_source_pair CHECK (
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
  );
COMMIT;
