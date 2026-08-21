-- Exact negative oracles for specification 13 §4.1.
--
-- Each oracle asserts SQLSTATE and constraint name where a named constraint
-- exists, so a statement failing for an unrelated NOT NULL, foreign key, or
-- check cannot pass as the constraint under test.

SET search_path TO solvan_onboarding, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION scope_must_violate(
  statement text, expected_state text, label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE observed_state text;
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS observed_state = RETURNED_SQLSTATE;
    IF observed_state IS DISTINCT FROM expected_state THEN
      RAISE EXCEPTION 'oracle % got SQLSTATE % (expected %)',
        label, observed_state, expected_state;
    END IF;
    RAISE NOTICE 'ok (%): %', observed_state, label;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END $$;

-- §4.1: reach above one project comes from a configured metrics scope, so a
-- folder or organization scope must name one and a project scope must not.
-- Both directions are asserted because either silently changes what a metric
-- read actually covers.
SELECT scope_must_violate($$
  INSERT INTO connection_external_resource_scopes
    (organization_id, project_id, environment_id, connection_id,
     resource_kind, resource_id, metrics_scoping_project_id,
     authored_by_principal, decision_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','con_01J4QZK8Q4J8Q6B95KQY4M9R2T',
     'GCP_FOLDER','folders/123456',NULL,'user:operator@example.com','ref://1')
$$, '23514', 'a folder scope must name its metrics scoping project');

SELECT scope_must_violate($$
  INSERT INTO connection_external_resource_scopes
    (organization_id, project_id, environment_id, connection_id,
     resource_kind, resource_id, metrics_scoping_project_id,
     authored_by_principal, decision_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','con_01J4QZK8Q4J8Q6B95KQY4M9R2T',
     'GCP_PROJECT','projects/customer-prod','scoping-project',
     'user:operator@example.com','ref://2')
$$, '23514', 'a project scope cannot carry a metrics scoping project');

-- A scoping project identifier is a Google Cloud project id, not free text.
SELECT scope_must_violate($$
  INSERT INTO connection_external_resource_scopes
    (organization_id, project_id, environment_id, connection_id,
     resource_kind, resource_id, metrics_scoping_project_id,
     authored_by_principal, decision_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','con_01J4QZK8Q4J8Q6B95KQY4M9R2T',
     'GCP_ORGANIZATION','organizations/999','Not A Project',
     'user:operator@example.com','ref://3')
$$, '23514', 'a metrics scoping project must be a Google Cloud project id');

-- §4.1: a resource scope belongs to a real connection. A scope naming an
-- absent connection would grant reach no probe ever proved.
SELECT scope_must_violate($$
  INSERT INTO connection_external_resource_scopes
    (organization_id, project_id, environment_id, connection_id,
     resource_kind, resource_id, authored_by_principal, decision_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','con_01J4QZK8Q4J8Q6B95KQY4M9R99',
     'GCP_PROJECT','projects/customer-prod','user:operator@example.com','ref://4')
$$, '23503', 'a resource scope requires an existing connection');

-- §4.3: environment is authored, never inferred.
SELECT scope_must_violate($$
  INSERT INTO environment_external_project_bindings
    (organization_id, project_id, environment_id,
     external_project_id, binding_epoch, deciding_principal, decision_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','Customer-Prod',1,
     'user:operator@example.com','ref://5')
$$, '23514', 'an external project id must be a Google Cloud project id');

SELECT scope_must_violate($$
  INSERT INTO environment_external_project_bindings
    (organization_id, project_id, environment_id,
     external_project_id, binding_epoch, deciding_principal, decision_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','customer-prod',0,
     'user:operator@example.com','ref://6')
$$, '23514', 'a binding epoch is positive');

-- §4.3: coverage is recorded per capability class, because one connection
-- answers differently for logs and for metrics. An unknown class would let a
-- read claim reach no probe ever measured.
SELECT scope_must_violate($$
  INSERT INTO connection_external_project_coverage
    (organization_id, project_id, environment_id, connection_id,
     capability_class, external_project_id, connection_epoch, observed_at,
     probe_receipt_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','con_01J4QZK8Q4J8Q6B95KQY4M9R2T',
     'EVERYTHING','customer-prod',1,now(),'receipt://1')
$$, '23514', 'coverage names a known capability class');

-- §4.1 makes rebinding a new generation rather than an edit, so two generations
-- of one external project must coexist and exactly one may be current. This is
-- a positive oracle: it caught a foreign key that silently forbade the
-- generation model, and it is kept so a later key cannot reintroduce it.
INSERT INTO organizations (id, display_name)
VALUES ('org_00000000000000000000000000', 'Scope Org');
INSERT INTO projects (organization_id, id, display_name, gcp_project_id)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'Scope Project', 'customer-prod');
INSERT INTO environments
  (organization_id, project_id, id, display_name, region, classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','Scope Environment','europe-west1','INTERNAL');

-- The attribution oracles below must reach their trigger rather than stop at a
-- foreign key, so the evidence item they name has to exist.
INSERT INTO solvan.services
  (organization_id, project_id, environment_id, id, service_key, display_name,
   platform_kind, platform_resource, owner_department)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','svc_00000000000000000000000000','payments-api',
   'Payments API','CLOUD_RUN_SERVICE',
   'projects/customer-prod/locations/europe-west1/services/payments-api','payments');
INSERT INTO solvan.production_graph_snapshots
  (organization_id, project_id, environment_id, id, version, status,
   source_manifest_ref, content_hash, effective_at, approved_by, approved_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','pgs_00000000000000000000000000',1,'APPROVED',
   'fixture://graph','sha256:graph',now(),'scope-owner',now());
-- Anchored on a detection rule rather than a trigger policy: the governed
-- operability delta adds a foreign key from a policy-triggered incident into
-- its own schema, and this fixture must stand on the release schema alone.
INSERT INTO solvan.detection_rules
  (organization_id, project_id, environment_id, id, version, service_id,
   incident_class, signal_kind, query_json, evaluation_interval_ms, comparator,
   threshold, sustained_windows, severity, deduplication_dimension,
   action_budget, repeated_action_limit, status, calibration_receipt_ref,
   approved_by, approved_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','payments-http-5xx',1,
   'svc_00000000000000000000000000','availability','HTTP_5XX_RATIO','{}'::jsonb,
   25000,'GT',0.05,2,'SEV2','http-5xx',1,1,'APPROVED','fixture://calibration',
   'scope-owner',now());
INSERT INTO solvan.incidents
  (organization_id, project_id, environment_id, id, display_id,
   state_machine_version, state, severity, incident_class, primary_service_id,
   production_graph_snapshot_id, detected_at, deduplication_key, action_budget,
   repeated_action_limit, detection_rule_id, detection_rule_version)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','inc_00000000000000000000000000','INC-0001',
   'v1','DETECTED','SEV2','availability','svc_00000000000000000000000000',
   'pgs_00000000000000000000000000',now(),'scope-dedup',1,1,'payments-http-5xx',1);
INSERT INTO solvan.evidence_items
  (organization_id, project_id, environment_id, id, incident_id, source_kind,
   source_resource, query_spec_json, window_start, window_end, observed_at,
   content_ref, content_hash, classification, residency, redaction_manifest_ref,
   provenance_json, freshness_expires_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','evd_00000000000000000000000000',
   'inc_00000000000000000000000000','CLOUD_MONITORING','projects/customer-prod',
   '{}'::jsonb,now(),now(),now(),'gs://evidence','sha256:evidence','INTERNAL',
   'europe-west1','gs://redaction','{}'::jsonb,now());

INSERT INTO environment_external_project_bindings
  (organization_id, project_id, environment_id,
   external_project_id, binding_epoch, deciding_principal, decision_ref, is_current)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','customer-prod',1,
   'user:operator@example.com','ref://7',false),
  ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','customer-prod',2,
   'user:operator@example.com','ref://8',true);
DO $$ BEGIN
  RAISE NOTICE 'ok: a superseded generation coexists with the current one';
END $$;

-- §4.3: one external project holds at most one current binding per
-- organization. A second environment claiming it is the blast-radius overlap
-- that project-wide Logging and Monitoring APIs cannot isolate.
INSERT INTO solvan.environments
  (organization_id, project_id, id, display_name, region, classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000001','Second Environment','europe-west1','INTERNAL');
SELECT scope_must_violate($$
  INSERT INTO environment_external_project_bindings
    (organization_id, project_id, environment_id,
     external_project_id, binding_epoch, deciding_principal, decision_ref)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000001','customer-prod',1,
     'user:operator@example.com','ref://9')
$$, '23505', 'one external project holds one current environment binding');

-- §4.2: an observed project is a Google Cloud project id, not free text. The
-- format rule is asserted before the authorization rule so a malformed value
-- cannot pass as an authorization failure.
SELECT scope_must_violate($$
  INSERT INTO evidence_resource_attribution
    (organization_id, project_id, environment_id, evidence_item_id,
     observed_project_id, observed_resource_type)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','evd_00000000000000000000000000',
     'Customer Prod','cloud_run_revision')
$$, '23514', 'an observed project is a Google Cloud project id');

-- §4.2 limb 2: evidence whose observed project this environment does not
-- currently authorize means the read reached an estate no authored decision
-- admitted. The fixture authorizes customer-prod only.
SELECT scope_must_violate($$
  INSERT INTO evidence_resource_attribution
    (organization_id, project_id, environment_id, evidence_item_id,
     observed_project_id, observed_resource_type)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','evd_00000000000000000000000000',
     'customer-staging','cloud_run_revision')
$$, '23901', 'evidence refuses a project the environment does not authorize');

-- The positive case must also hold, or the rule above would pass by refusing
-- everything.
INSERT INTO evidence_resource_attribution
  (organization_id, project_id, environment_id, evidence_item_id,
   observed_project_id, observed_resource_type, observed_labels_json)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','evd_00000000000000000000000000',
   'customer-prod','cloud_run_revision','{"revision_name":"payments-004"}'::jsonb);
DO $$ BEGIN
  RAISE NOTICE 'ok: an authorized observed project is accepted';
END $$;
DELETE FROM evidence_resource_attribution;

-- §4.2: the remaining labels are provenance, so they must be an object rather
-- than a scalar a reader would have to interpret.
SELECT scope_must_violate($$
  INSERT INTO evidence_resource_attribution
    (organization_id, project_id, environment_id, evidence_item_id,
     observed_project_id, observed_resource_type, observed_labels_json)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
     'env_00000000000000000000000000','evd_00000000000000000000000000',
     'customer-prod','cloud_run_revision','"europe-west1"'::jsonb)
$$, '23514', 'observed provenance is an object of labels');

ROLLBACK;
