\set ON_ERROR_STOP on

BEGIN;

INSERT INTO solvan_liaison.liaison_record_directory
  (organization_id,project_id,environment_id,record_type,record_id,classification)
VALUES
  ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','alert_episode',
   'aep_01K00000000000000000000000','INTERNAL');

DO $invalid_record_type$
BEGIN
  BEGIN
    INSERT INTO solvan_liaison.liaison_record_directory
      (organization_id,project_id,environment_id,record_type,record_id,classification)
    VALUES
      ('org_00000000000000000000000000','prj_00000000000000000000000000',
       'env_00000000000000000000000000','unknown_record','record-1','INTERNAL');
    RAISE EXCEPTION 'invalid Liaison record type unexpectedly committed';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$invalid_record_type$;

ROLLBACK;
