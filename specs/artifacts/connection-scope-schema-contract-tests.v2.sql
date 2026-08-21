-- Specification 13 INV-T-23: a workload region is explicit authority, not a
-- synonym for the tenant's control-plane residency.
SET search_path TO solvan_onboarding, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION workload_region_must_violate(sql_text text, expected_state text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    EXECUTE sql_text;
  EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE <> expected_state THEN
      RAISE EXCEPTION 'expected SQLSTATE %, got %: %', expected_state, SQLSTATE, SQLERRM;
    END IF;
    RETURN;
  END;
  RAISE EXCEPTION 'statement unexpectedly succeeded';
END $$;

INSERT INTO organizations (id, display_name)
VALUES ('org_00000000000000000000000000', 'Workload region contract org');
INSERT INTO projects (organization_id, id, display_name, gcp_project_id)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'Workload region contract project', 'cross-region-prod');
INSERT INTO environments
  (organization_id, project_id, id, display_name, region, classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','Workload region contract environment',
        'europe-west1','INTERNAL');

-- The old, project-only uniqueness constraint is deliberately gone: two
-- separately authorized workload regions are valid, but duplicate current
-- authorization for the same project and region is not.
INSERT INTO environment_external_project_bindings
  (organization_id,project_id,environment_id,external_project_id,workload_region,
   binding_epoch,deciding_principal,decision_ref,is_current)
VALUES
  ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','cross-region-prod','europe-west1',1,
   'user:operator@example.com','decision://region/west1',true),
  ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','cross-region-prod','europe-west2',2,
   'user:operator@example.com','decision://region/west2',true);

SELECT workload_region_must_violate($$
  INSERT INTO environment_external_project_bindings
    (organization_id,project_id,environment_id,external_project_id,workload_region,
     binding_epoch,deciding_principal,decision_ref,is_current)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','cross-region-prod','europe-west2',3,
    'user:operator@example.com','decision://region/duplicate',true)
$$, '23505');

SELECT workload_region_must_violate($$
  INSERT INTO environment_external_project_bindings
    (organization_id,project_id,environment_id,external_project_id,workload_region,
     binding_epoch,deciding_principal,decision_ref,is_current)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','cross-region-invalid','Europe West 2',1,
    'user:operator@example.com','decision://region/invalid',true)
$$, '23514');

ROLLBACK;
