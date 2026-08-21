-- Bind Workspace private commands to one server-assigned call ordinal.
--
-- The generic command ledger previously stored the payload only in GCS. That
-- made a transactional per-run/per-tool budget impossible to prove in Cloud
-- SQL. These immutable projection columns expose no model-authored content;
-- they duplicate only the closed revision key and Coordinator-owned ordinal.

BEGIN;

ALTER TABLE solvan_delivery.private_command_dispatches
  ADD COLUMN operation_key text,
  ADD COLUMN operation_ordinal integer,
  ADD CONSTRAINT private_command_operation_shape_ck CHECK (
    (command_kind='WORKSPACE_TOOL_INVOKE'
      AND operation_key IN (
        'workspace.code-repair.read-artifact@1',
        'workspace.code-repair.write-candidate-artifact@1',
        'workspace.code-repair.run-in-sandbox@1'
      )
      AND operation_ordinal BETWEEN 1 AND 104)
    OR
    (command_kind<>'WORKSPACE_TOOL_INVOKE'
      AND operation_key IS NULL AND operation_ordinal IS NULL)
  );

CREATE UNIQUE INDEX private_command_workspace_call_ordinal
  ON solvan_delivery.private_command_dispatches
    (organization_id,project_id,environment_id,subject_id,operation_ordinal)
  WHERE command_kind='WORKSPACE_TOOL_INVOKE';

CREATE INDEX private_command_workspace_budget
  ON solvan_delivery.private_command_dispatches
    (organization_id,project_id,environment_id,subject_id,operation_key)
  WHERE command_kind='WORKSPACE_TOOL_INVOKE';

CREATE FUNCTION solvan_delivery.delivery_guard_private_command_operation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.operation_key IS DISTINCT FROM OLD.operation_key
     OR NEW.operation_ordinal IS DISTINCT FROM OLD.operation_ordinal THEN
    RAISE EXCEPTION 'PRIVATE_COMMAND_OPERATION_IMMUTABLE' USING ERRCODE='23999';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER delivery_private_command_operation_fence
BEFORE UPDATE ON solvan_delivery.private_command_dispatches
FOR EACH ROW EXECUTE FUNCTION solvan_delivery.delivery_guard_private_command_operation();

COMMIT;
