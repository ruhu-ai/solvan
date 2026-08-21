-- Specification 13 §4.3 / INV-T-23: a binding epoch is scoped to one external
-- project and one workload region, which is exactly how
-- `bind_environment_external_project` computes the next one: it looks for the
-- current binding of that project in that region and increments it, starting
-- at one when none exists.
--
-- The v2 delta made current-ness per project and region
-- (`one_current_external_project_region_binding`) but left the primary key
-- project-wide. A second region's first binding therefore computed epoch one
-- and collided with the first region's epoch one: rebinding one external
-- project into a second authorized region was refused with a duplicate key,
-- and the API reported it as a duplicate connection. Observed live: ruhu-dev
-- bound in europe-west2 could not also be bound in europe-west1.
BEGIN;
SET search_path TO solvan_onboarding, solvan, public;

ALTER TABLE environment_external_project_bindings
  DROP CONSTRAINT environment_external_project_bindings_pkey;
ALTER TABLE environment_external_project_bindings
  ADD PRIMARY KEY (organization_id, project_id, environment_id,
                   external_project_id, workload_region, binding_epoch);

COMMIT;
