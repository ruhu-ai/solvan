-- Alert evidence is first-class and can never masquerade as Incident evidence.
SET search_path TO solvan_alerts, public;
BEGIN;
DO $alert_evidence_anchor$
DECLARE definition text; incident_nullable text; alert_nullable text; version_nullable text;
BEGIN
  SELECT pg_get_constraintdef(oid) INTO definition
    FROM pg_constraint
   WHERE conrelid='solvan.evidence_items'::regclass
     AND conname='evidence_items_one_anchor_ck';
  IF definition IS NULL OR definition NOT LIKE '%incident_id IS NOT NULL%'
     OR definition NOT LIKE '%alert_episode_id IS NOT NULL%'
     OR definition NOT LIKE '%= 1%' THEN
    RAISE EXCEPTION 'evidence items do not enforce exactly one durable anchor';
  END IF;
  SELECT is_nullable INTO incident_nullable FROM information_schema.columns
   WHERE table_schema='solvan' AND table_name='evidence_items' AND column_name='incident_id';
  SELECT is_nullable INTO alert_nullable FROM information_schema.columns
   WHERE table_schema='solvan' AND table_name='evidence_items' AND column_name='alert_episode_id';
  SELECT is_nullable INTO version_nullable FROM information_schema.columns
   WHERE table_schema='solvan_alerts' AND table_name='alert_episodes'
     AND column_name='evidence_version';
  IF incident_nullable<>'YES' OR alert_nullable<>'YES' OR version_nullable<>'NO' THEN
    RAISE EXCEPTION 'Alert evidence anchor nullability drifted';
  END IF;
END
$alert_evidence_anchor$;
ROLLBACK;
