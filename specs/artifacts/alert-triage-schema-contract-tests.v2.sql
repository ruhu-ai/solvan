-- Hostile Phase-2 Alert Triage schema oracles (specification 21).
SET search_path TO solvan_alerts, public;
BEGIN;

DO $phase_two_shape$
DECLARE
  anchor_definition text;
  admission_definition text;
  immutable_count integer;
  scoped_count integer;
  forced_count integer;
BEGIN
  SELECT count(DISTINCT table_name) INTO scoped_count
    FROM information_schema.columns
   WHERE table_schema='solvan_alerts'
     AND column_name IN ('organization_id','project_id','environment_id');
  SELECT count(*) INTO forced_count
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
   WHERE namespace.nspname='solvan_alerts' AND relation.relkind='r'
     AND relation.relrowsecurity AND relation.relforcerowsecurity;
  IF scoped_count < 20 OR forced_count < 20 THEN
    RAISE EXCEPTION 'all Phase-2 Alert Triage tables must force RLS; scoped %, forced %',
      scoped_count,forced_count;
  END IF;
  SELECT pg_get_constraintdef(oid) INTO anchor_definition
    FROM pg_constraint
   WHERE conrelid='solvan.agent_runs'::regclass
     AND conname='agent_runs_one_anchor_ck';
  IF anchor_definition IS NULL OR
     position('alert_episode_id' IN anchor_definition)=0 OR
     position('= 1' IN anchor_definition)=0 THEN
    RAISE EXCEPTION 'Agent run does not enforce exactly one Alert/Incident/Case/Workspace anchor';
  END IF;

  SELECT pg_get_constraintdef(oid) INTO admission_definition
    FROM pg_constraint
   WHERE conrelid='solvan_alerts.alert_admissions'::regclass
     AND conname='alert_admissions_decision_shape_ck';
  IF admission_definition IS NULL OR
     position('capacity_reservation_id IS NOT NULL' IN admission_definition)=0 OR
     position('due_at IS NOT NULL' IN admission_definition)=0 OR
     position('work_kind IS NULL' IN admission_definition)=0 THEN
    RAISE EXCEPTION 'Alert admission decision shapes are not closed';
  END IF;

  SELECT count(*) INTO immutable_count
    FROM pg_trigger trigger
    JOIN pg_class relation ON relation.oid=trigger.tgrelid
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
   WHERE namespace.nspname='solvan_alerts'
     AND relation.relname IN
       ('alert_predicate_results','alert_dispositions','alert_incident_links')
     AND trigger.tgname='reject_history_mutation'
     AND NOT trigger.tgisinternal;
  IF immutable_count <> 3 THEN
    RAISE EXCEPTION 'all Phase-2 history ledgers must reject mutation; found %',immutable_count;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
     WHERE schemaname='solvan_alerts'
       AND indexname='alert_triage_runs_claimable_idx'
       AND indexdef LIKE '%WHERE (status = ''QUEUED''%'
  ) THEN
    RAISE EXCEPTION 'claimable Alert Triage run index is absent or unbounded';
  END IF;
END
$phase_two_shape$;

ROLLBACK;
