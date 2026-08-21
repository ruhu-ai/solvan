-- Forward-only hardening migration for the governed operability target.
-- The baseline remains immutable; this version makes its scoped tables
-- resistant to owner/bypass-role access as required by the isolation contract.
BEGIN;

DO $scope_force$
DECLARE
  scoped_table record;
BEGIN
  FOR scoped_table IN
    SELECT table_name
      FROM information_schema.columns
     WHERE table_schema = 'solvan_operability'
       AND column_name IN ('organization_id','project_id','environment_id')
     GROUP BY table_name
    HAVING count(DISTINCT column_name) = 3
  LOOP
    EXECUTE format('ALTER TABLE solvan_operability.%I ENABLE ROW LEVEL SECURITY',
                   scoped_table.table_name);
    EXECUTE format('ALTER TABLE solvan_operability.%I FORCE ROW LEVEL SECURITY',
                   scoped_table.table_name);
  END LOOP;
END
$scope_force$;

COMMIT;
