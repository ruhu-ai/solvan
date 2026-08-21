-- Forward-only Alert-record support for the shared conversational ledger.

BEGIN;

DO $drop_record_type_check$
DECLARE constraint_name text;
BEGIN
  SELECT conname INTO constraint_name
    FROM pg_constraint
   WHERE conrelid='solvan_liaison.liaison_record_directory'::regclass
     AND contype='c'
     AND pg_get_constraintdef(oid) LIKE '%record_type%';
  IF constraint_name IS NULL THEN
    RAISE EXCEPTION 'liaison record-type constraint is missing';
  END IF;
  EXECUTE format(
    'ALTER TABLE solvan_liaison.liaison_record_directory DROP CONSTRAINT %I',
    constraint_name
  );
END
$drop_record_type_check$;

ALTER TABLE solvan_liaison.liaison_record_directory
  ADD CONSTRAINT liaison_record_directory_type_ck CHECK (record_type IN
    ('incident','reliability_case','action','evidence_item','verification_run',
     'patch_artifact','workspace','tenant_connection','alert_episode'));

COMMIT;
