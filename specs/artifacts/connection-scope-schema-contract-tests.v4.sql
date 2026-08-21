-- Specification 13 INV-T-23 follow-up: the epoch sequence is per external
-- project and workload region, so two regions of one project each open at
-- epoch one. The v2 project-wide primary key made the second region's first
-- binding a duplicate-key refusal; these oracles pin the per-region key.
SET search_path TO solvan_onboarding, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION binding_epoch_must_violate(
  statement text, expected_state text, label text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE <> expected_state THEN
      RAISE EXCEPTION 'oracle % got SQLSTATE % (expected %)',label,SQLSTATE,expected_state;
    END IF;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %',label;
END $$;

INSERT INTO organizations (id,display_name)
VALUES ('org_00000000000000000000000000','Binding epoch contract org');
INSERT INTO projects (organization_id,id,display_name,gcp_project_id)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'Binding epoch contract project','epoch-scope-prod');
INSERT INTO environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','Binding epoch contract environment',
        'europe-west1','INTERNAL');

-- Must pass: one external project, two authorized regions, each opening at
-- epoch one — the exact inserts two first bindings through
-- bind_environment_external_project produce.
INSERT INTO environment_external_project_bindings
  (organization_id,project_id,environment_id,external_project_id,workload_region,
   binding_epoch,deciding_principal,decision_ref,is_current)
VALUES
  ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','epoch-scope-prod','europe-west1',1,
   'user:operator@example.com','decision://epoch/west1',true),
  ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','epoch-scope-prod','europe-west2',1,
   'user:operator@example.com','decision://epoch/west2',true);

-- Must fail: one region never holds the same epoch twice.
SELECT binding_epoch_must_violate($$
  INSERT INTO environment_external_project_bindings
    (organization_id,project_id,environment_id,external_project_id,workload_region,
     binding_epoch,deciding_principal,decision_ref,is_current)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','epoch-scope-prod','europe-west1',1,
    'user:operator@example.com','decision://epoch/replay',false)
$$,'23505','one region never repeats an epoch');

-- Must fail: one project and region hold exactly one current binding, however
-- the epochs differ.
SELECT binding_epoch_must_violate($$
  INSERT INTO environment_external_project_bindings
    (organization_id,project_id,environment_id,external_project_id,workload_region,
     binding_epoch,deciding_principal,decision_ref,is_current)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','epoch-scope-prod','europe-west1',2,
    'user:operator@example.com','decision://epoch/second-current',true)
$$,'23505','one region holds one current binding');

ROLLBACK;
