-- Freeze repair-command selectors and their exact base-tree resolution.
--
-- Hash-only declarations could not prove that an approved command's inputs
-- still existed in a newly frozen repository snapshot. Existing definitions
-- and plan-local catalogs are failed closed during this forward migration;
-- an administrator must register a new definition carrying selectors.

BEGIN;

ALTER TABLE solvan_delivery.repair_plan_command_definitions
  ADD COLUMN declared_inputs_json jsonb,
  ADD COLUMN declared_outputs_json jsonb;

UPDATE solvan_delivery.repair_plan_command_definitions
   SET lifecycle='REVOKED', declared_inputs_json='[]'::jsonb,
       declared_outputs_json='[]'::jsonb;

ALTER TABLE solvan_delivery.repair_plan_command_definitions
  ALTER COLUMN declared_inputs_json SET NOT NULL,
  ALTER COLUMN declared_outputs_json SET NOT NULL,
  ADD CONSTRAINT repair_command_declared_inputs_shape_ck CHECK (
    jsonb_typeof(declared_inputs_json)='array'
    AND ((lifecycle='APPROVED' AND jsonb_array_length(declared_inputs_json) BETWEEN 1 AND 64)
         OR (lifecycle IN ('RETIRED','REVOKED')
             AND jsonb_array_length(declared_inputs_json) BETWEEN 0 AND 64))
  ),
  ADD CONSTRAINT repair_command_declared_outputs_shape_ck CHECK (
    jsonb_typeof(declared_outputs_json)='array'
    AND jsonb_array_length(declared_outputs_json) BETWEEN 0 AND 64
  );

ALTER TABLE solvan_delivery.repair_plan_command_catalogs
  ADD COLUMN resolved_inputs_json jsonb,
  ADD COLUMN resolved_inputs_hash text;

UPDATE solvan_delivery.repair_plan_command_catalogs
   SET status='RETIRED', resolved_inputs_json='[]'::jsonb,
       resolved_inputs_hash='sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

ALTER TABLE solvan_delivery.repair_plan_command_catalogs
  ALTER COLUMN resolved_inputs_json SET NOT NULL,
  ALTER COLUMN resolved_inputs_hash SET NOT NULL,
  ADD CONSTRAINT repair_catalog_resolved_inputs_shape_ck CHECK (
    jsonb_typeof(resolved_inputs_json)='array'
    AND ((status='RESOLVED' AND jsonb_array_length(resolved_inputs_json)>0)
         OR status IN ('UNRESOLVED','RETIRED'))
  ),
  ADD CONSTRAINT repair_catalog_resolved_inputs_hash_ck CHECK (
    resolved_inputs_hash ~ '^sha256:[0-9a-f]{64}$'
  );

CREATE FUNCTION solvan_delivery.delivery_guard_repair_command_definition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'REPAIR_COMMAND_DEFINITION_DELETE_FORBIDDEN' USING ERRCODE='23981';
  END IF;
  IF ROW(NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id,
         NEW.repository_binding_id,NEW.command_hash,NEW.command_kind,NEW.argv_json,
         NEW.working_directory,NEW.declared_inputs_hash,NEW.declared_outputs_hash,
         NEW.timeout_ms,NEW.cpu_millis,NEW.memory_mib,NEW.output_byte_limit,
         NEW.network_mode,NEW.catalog_hash,NEW.approved_ref,NEW.created_at,
         NEW.declared_inputs_json,NEW.declared_outputs_json)
     IS DISTINCT FROM
     ROW(OLD.organization_id,OLD.project_id,OLD.environment_id,OLD.id,
         OLD.repository_binding_id,OLD.command_hash,OLD.command_kind,OLD.argv_json,
         OLD.working_directory,OLD.declared_inputs_hash,OLD.declared_outputs_hash,
         OLD.timeout_ms,OLD.cpu_millis,OLD.memory_mib,OLD.output_byte_limit,
         OLD.network_mode,OLD.catalog_hash,OLD.approved_ref,OLD.created_at,
         OLD.declared_inputs_json,OLD.declared_outputs_json)
     OR NOT (OLD.lifecycle='APPROVED' AND NEW.lifecycle IN ('RETIRED','REVOKED')) THEN
    RAISE EXCEPTION 'REPAIR_COMMAND_DEFINITION_IMMUTABLE' USING ERRCODE='23982';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER delivery_repair_command_definition_fence
BEFORE UPDATE OR DELETE ON solvan_delivery.repair_plan_command_definitions
FOR EACH ROW EXECUTE FUNCTION solvan_delivery.delivery_guard_repair_command_definition();

CREATE TRIGGER delivery_repair_command_definition_no_truncate
BEFORE TRUNCATE ON solvan_delivery.repair_plan_command_definitions
FOR EACH STATEMENT EXECUTE FUNCTION solvan_delivery.delivery_reject_history_mutation();

CREATE TRIGGER delivery_repair_command_catalog_append_only
BEFORE UPDATE OR DELETE ON solvan_delivery.repair_plan_command_catalogs
FOR EACH ROW EXECUTE FUNCTION solvan_delivery.delivery_reject_history_mutation();

CREATE TRIGGER delivery_repair_command_catalog_no_truncate
BEFORE TRUNCATE ON solvan_delivery.repair_plan_command_catalogs
FOR EACH STATEMENT EXECUTE FUNCTION solvan_delivery.delivery_reject_history_mutation();

CREATE UNIQUE INDEX workspace_candidate_command_input_once
  ON solvan_delivery.workspace_candidate_generations
    (organization_id,project_id,environment_id,agent_run_id,input_hash);

COMMIT;
