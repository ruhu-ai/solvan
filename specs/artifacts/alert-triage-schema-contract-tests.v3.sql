-- Hostile Phase-3 Alert Triage schema oracles (specification 21).
SET search_path TO solvan_alerts, public;
BEGIN;
DO $phase_three_shape$
DECLARE scoped_count integer; forced_count integer; immutable_count integer;
BEGIN
  SELECT count(DISTINCT table_name) INTO scoped_count FROM information_schema.columns
   WHERE table_schema='solvan_alerts'
     AND column_name IN ('organization_id','project_id','environment_id');
  SELECT count(*) INTO forced_count FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
   WHERE namespace.nspname='solvan_alerts' AND relation.relkind='r'
     AND relation.relrowsecurity AND relation.relforcerowsecurity;
  IF scoped_count < 24 OR forced_count <> scoped_count THEN
    RAISE EXCEPTION 'all Alert Triage tables must force RLS; expected at least 24, scoped %, forced %',
      scoped_count,forced_count;
  END IF;
  SELECT count(*) INTO immutable_count FROM pg_trigger trigger
    JOIN pg_class relation ON relation.oid=trigger.tgrelid
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
   WHERE namespace.nspname='solvan_alerts'
     AND relation.relname IN ('alert_operator_requests','alert_operator_request_consumptions',
       'alert_feedback','alert_channel_delivery_attempts')
     AND trigger.tgname='reject_history_mutation' AND NOT trigger.tgisinternal;
  IF immutable_count <> 4 THEN
    RAISE EXCEPTION 'all Phase-3 Alert histories must reject mutation; found %',immutable_count;
  END IF;
END
$phase_three_shape$;
ROLLBACK;
