-- Specifications 13 INV-T-24 and 21 §5.2: polling detection authority names
-- one exact current direct Cloud Monitoring connection revision.
SET search_path TO solvan_onboarding, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION detection_binding_must_violate(
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
VALUES ('org_00000000000000000000000000','Local connection contract');
INSERT INTO projects (organization_id,id,display_name,gcp_project_id)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'Local connection contract','solvan-dev');
INSERT INTO environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','Local connected','europe-west1','INTERNAL');
INSERT INTO services
  (organization_id,project_id,environment_id,id,service_key,display_name,
   platform_kind,platform_resource,owner_department)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','svc_00000000000000000000000000',
        'ruhu-atlas-challenge','Ruhu Atlas','CLOUD_RUN_SERVICE',
        'projects/ruhu-dev/locations/europe-west2/services/ruhu-atlas-challenge','platform');
INSERT INTO detection_rules
  (organization_id,project_id,environment_id,id,version,service_id,incident_class,
   signal_kind,query_json,evaluation_interval_ms,comparator,threshold,
   sustained_windows,severity,deduplication_dimension,action_budget,
   repeated_action_limit,status,calibration_receipt_ref,approved_by,approved_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','ruhu-http-5xx',1,
        'svc_00000000000000000000000000','availability','HTTP_5XX_RATIO',
        '{"gcp_project_id":"ruhu-dev","resource_name":"ruhu-atlas-challenge"}',
        25000,'GT',0.05,2,'SEV2','http-5xx',1,1,'APPROVED',
        'local-development://calibration','user:operator@example.com',now());

INSERT INTO tenant_connections
  (organization_id,project_id,environment_id,id,display_name,kind,provider,
   credential_posture,authentication_mode,solvan_delegator_principal,
   customer_reader_principal,delegation_condition_digest,token_lifetime_seconds,
   residency_region,classification,connection_epoch,lifecycle,availability,
   availability_reason_code,availability_explanation,availability_remediation_kind,
   availability_receipt_ref,last_probe_at,last_probe_result,last_success_at,
   proof_expires_at,created_by_principal)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','con_00000000000000000000000001',
        'ruhu metrics','GCP_NATIVE','CLOUD_MONITORING','FEDERATED_SHORT_LIVED',
        'GCP_SERVICE_ACCOUNT_IMPERSONATION',
        'serviceAccount:solvan-probe@solvan-dev.iam.gserviceaccount.com',
        'serviceAccount:solvan-reader@ruhu-dev.iam.gserviceaccount.com',
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',900,
        'europe-west1','INTERNAL',3,'ENABLED','READY',NULL,NULL,NULL,
        'probe://cloud-monitoring/metrics.read',now(),'SUCCEEDED',now(),now()+interval '1 hour',
        'user:operator@example.com');

INSERT INTO detection_rule_connection_bindings
  (organization_id,project_id,environment_id,detection_rule_id,
   detection_rule_version,connection_id,connection_epoch,bound_by_principal,decision_ref,
   idempotency_key,request_hash)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','ruhu-http-5xx',1,
        'con_00000000000000000000000001',3,'user:operator@example.com',
        'local-development://connection-binding','bind-1',
        'sha256:2222222222222222222222222222222222222222222222222222222222222222');

SELECT detection_binding_must_violate($$
  INSERT INTO detection_rule_connection_bindings
    (organization_id,project_id,environment_id,detection_rule_id,
     detection_rule_version,connection_id,connection_epoch,bound_by_principal,decision_ref,
     idempotency_key,request_hash)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
          'env_00000000000000000000000000','ruhu-http-5xx',1,
          'con_00000000000000000000000001',2,'user:operator@example.com','ref://stale',
          'bind-duplicate','sha256:3333333333333333333333333333333333333333333333333333333333333333')
$$,'23505','one detection rule version has one immutable connection binding');

INSERT INTO detection_rules
  (organization_id,project_id,environment_id,id,version,service_id,incident_class,
   signal_kind,query_json,evaluation_interval_ms,comparator,threshold,
   sustained_windows,severity,deduplication_dimension,action_budget,
   repeated_action_limit,status,calibration_receipt_ref,approved_by,approved_at)
SELECT organization_id,project_id,environment_id,'ruhu-http-5xx-stale',version,service_id,
       incident_class,signal_kind,query_json,evaluation_interval_ms,comparator,threshold,
       sustained_windows,severity,deduplication_dimension,action_budget,
       repeated_action_limit,status,calibration_receipt_ref,approved_by,approved_at
  FROM detection_rules WHERE id='ruhu-http-5xx';

SELECT detection_binding_must_violate($$
  INSERT INTO detection_rule_connection_bindings
    (organization_id,project_id,environment_id,detection_rule_id,
     detection_rule_version,connection_id,connection_epoch,bound_by_principal,decision_ref,
     idempotency_key,request_hash)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
          'env_00000000000000000000000000','ruhu-http-5xx-stale',1,
          'con_00000000000000000000000001',2,'user:operator@example.com','ref://stale',
          'bind-stale','sha256:4444444444444444444444444444444444444444444444444444444444444444')
$$,'23931','a stale connection epoch cannot be bound');

ROLLBACK;
