-- Specification 13 §4.1 / §4.2: workload location is an explicit authority
-- fact. `tenant_connections.residency_region` remains control-plane residency;
-- it is never a substitute for provider reach.
BEGIN;
SET search_path TO solvan_onboarding, solvan, public;

ALTER TABLE connection_external_resource_scopes
  ADD COLUMN workload_region text NOT NULL DEFAULT 'europe-west1'
    CHECK (workload_region ~ '^[a-z]+(?:-[a-z0-9]+)*$');

ALTER TABLE environment_external_project_bindings
  ADD COLUMN workload_region text NOT NULL DEFAULT 'europe-west1'
    CHECK (workload_region ~ '^[a-z]+(?:-[a-z0-9]+)*$');

DROP INDEX one_current_external_project_binding;
CREATE UNIQUE INDEX one_current_external_project_region_binding
  ON environment_external_project_bindings
    (organization_id, external_project_id, workload_region)
  WHERE is_current;

ALTER TABLE connection_external_project_coverage
  ADD COLUMN workload_region text NOT NULL DEFAULT 'europe-west1'
    CHECK (workload_region ~ '^[a-z]+(?:-[a-z0-9]+)*$');

ALTER TABLE evidence_resource_attribution
  ADD COLUMN observed_workload_region text NOT NULL DEFAULT 'europe-west1'
    CHECK (observed_workload_region ~ '^[a-z]+(?:-[a-z0-9]+)*$');

CREATE OR REPLACE FUNCTION evidence_project_is_authorized() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM environment_external_project_bindings b
   WHERE (b.organization_id,b.project_id,b.environment_id,b.external_project_id,
          b.workload_region) =
         (NEW.organization_id,NEW.project_id,NEW.environment_id,
          NEW.observed_project_id,NEW.observed_workload_region)
     AND b.is_current;
  IF NOT FOUND THEN
    RAISE EXCEPTION
      'evidence observed project % in workload region % without current environment authorization',
      NEW.observed_project_id, NEW.observed_workload_region USING ERRCODE = '23901';
  END IF;
  RETURN NEW;
END $$;

COMMIT;
