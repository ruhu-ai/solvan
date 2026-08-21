-- Negative constraint oracles for specification 22 target DDL.
SET search_path TO solvan_relay, solvan, public;
BEGIN;

INSERT INTO solvan.organizations(id,display_name)
VALUES ('org_00000000000000000000000000','Relay contract');
INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'Relay contract','solvan-relay-contract');
INSERT INTO solvan.environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','Relay contract','europe-west1','INTERNAL');
INSERT INTO solvan.tenant_connections
  (organization_id,project_id,environment_id,id,display_name,kind,provider,
   credential_posture,authentication_mode,residency_region,classification,lifecycle,availability,
   availability_reason_code,availability_explanation,
   availability_remediation_kind,availability_receipt_ref,last_probe_at,
   last_probe_result,last_success_at,proof_expires_at,created_by_principal)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','con_00000000000000000000000001',
        'Relay transport','RELAY','SOLVAN_RELAY',
        'CUSTOMER_SIDE_NONE','CUSTOMER_SIDE_NONE','europe-west1','INTERNAL','ENABLED','READY',
        NULL,NULL,NULL,'probe://relay-contract',now(),'SUCCEEDED',now(),
        now()+interval '1 hour','contract');

INSERT INTO solvan_scale.cell_eligibility_profiles
  (eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,
   support_access_allowed,allowed_recovery_regions,approved_ref)
VALUES ('sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
        'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        false,ARRAY['europe-west1'],'ref_relay_cell');
INSERT INTO solvan_scale.tenant_eligibility_requirements
  (organization_id,requirement_hash,allowed_classifications,
   allowed_residency_regions,allowed_provider_launch_stages,
   encryption_profile_hash,support_access_allowed,allowed_recovery_regions,
   approved_ref)
VALUES ('org_00000000000000000000000000',
        'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
        'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        false,ARRAY['europe-west1'],'ref_relay_tenant');
INSERT INTO solvan_scale.cells
  (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
   capacity_profile_hash,data_policy_hash,eligibility_profile_hash,
   deployment_manifest_hash)
VALUES ('cell_relay_contract','OSS_SINGLE_TENANT','europe-west1',
        'project://relay-contract','READY',1,
        'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        'sha256:abababababababababababababababababababababababababababababababab',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        'sha256:acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac');
INSERT INTO solvan_scale.tenant_placements
  (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
   home_region,classification_ceiling,eligibility_requirement_hash,policy_hash,
   encryption_profile_hash,activated_at)
VALUES ('org_00000000000000000000000000',1,'cell_relay_contract','ACTIVE',true,
        'OSS_SINGLE_TENANT','europe-west1','INTERNAL',
        'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        now());

CREATE OR REPLACE FUNCTION relay_must_fail(statement text, label text)
RETURNS void AS $$
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN others THEN
    RAISE NOTICE 'ok: %', label;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END
$$ LANGUAGE plpgsql;

SELECT relay_must_fail($$
  INSERT INTO relay_signing_key_revisions
    (key_id,kms_key_version_ref,public_key_digest,algorithm,region,lifecycle,
     valid_from,issue_until,verify_until)
  VALUES ('bad','kms://bad',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'RS256','europe-west1','ACTIVE',now(),now()+interval '1 hour',now()+interval '2 hours')
$$, 'unsupported signing algorithm');

INSERT INTO relay_signing_key_revisions
  (key_id,kms_key_version_ref,public_key_digest,algorithm,region,lifecycle,
   valid_from,issue_until,verify_until)
VALUES ('relay-key-v1','projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
  'sha256:1111111111111111111111111111111111111111111111111111111111111111',
  'ECDSA_P256_SHA256','europe-west1','ACTIVE',
  now(),now()+interval '1 hour',now()+interval '2 hours');

SELECT relay_must_fail($$
  INSERT INTO relay_image_attestations
    (id,image_digest,source_commit,build_provenance_ref,build_provenance_digest,
     sbom_ref,sbom_digest,vulnerability_scan_ref,vulnerability_scan_digest,
     signer_principal,signing_key_id,decision,issued_at,expires_at)
  VALUES ('ria_00000000000000000000000001',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','gcs://proof/provenance',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    'gcs://proof/sbom','sha256:4444444444444444444444444444444444444444444444444444444444444444',
    'gcs://proof/scan','sha256:5555555555555555555555555555555555555555555555555555555555555555',
    'builder@example.com','relay-key-v1','ALLOW',now(),now()-interval '1 second')
$$, 'image attestation cannot expire before issue');

INSERT INTO relay_image_attestations
  (id,image_digest,source_commit,build_provenance_ref,build_provenance_digest,
   sbom_ref,sbom_digest,vulnerability_scan_ref,vulnerability_scan_digest,
   signer_principal,signing_key_id,decision,issued_at,expires_at)
VALUES ('ria_00000000000000000000000002',
  'sha256:2222222222222222222222222222222222222222222222222222222222222222',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','gcs://proof/provenance',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',
  'gcs://proof/sbom','sha256:4444444444444444444444444444444444444444444444444444444444444444',
  'gcs://proof/scan','sha256:5555555555555555555555555555555555555555555555555555555555555555',
  'builder@example.com','relay-key-v1','ALLOW',now(),now()+interval '1 hour');

SELECT relay_must_fail($$
  INSERT INTO relay_enrollments
    (organization_id,project_id,environment_id,id,relay_connection_id,enrollment_epoch,
     placement_epoch,cell_id,host_kind,production_eligible,principal_subject,
     principal_issuer,expected_audience,image_digest,image_attestation_id,
     local_policy_digest,connector_catalog_digest,redaction_revision,region,
     classification_ceiling,relay_version,lifecycle,safe_reason_code,
     created_by_principal)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','ren_00000000000000000000000001',
    'con_00000000000000000000000001',1,1,'cell_relay_contract','DEV_LOCAL',true,'dev@example.com',
    'https://accounts.google.com','https://relay.example',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'ria_00000000000000000000000002',
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    'sha256:7777777777777777777777777777777777777777777777777777777777777777',
    'relay-redaction.v1','europe-west1','INTERNAL','1.0.0','REGISTERED','NOT_READY','test')
$$, 'developer host cannot be production eligible');

SELECT relay_must_fail($$
  INSERT INTO relay_retention_controls
    (organization_id,project_id,environment_id,object_kind,object_id,
     storage_region,classification,retention_until,legal_hold_ref,
     deletion_state,deletion_job_ref,deleted_at)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','EVIDENCE_OBJECT','object-1',
    'europe-west1','INTERNAL',now(),'hold-1','DELETED','delete-1',now())
$$, 'legal-held object cannot be deleted');

DO $$
DECLARE actual text;
BEGIN
  SELECT relay_resource_binding_hash(
    1,
    'org_00000000000000000000000000',
    'prj_00000000000000000000000000',
    'env_00000000000000000000000000',
    'cell_graph',
    1,
    'pgs_00000000000000000000000001',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'pgn_00000000000000000000000001',
    'payments',
    'SERVICE',
    'run://payments',
    'customer-payments-prod',
    'INTERNAL',
    'europe-west1',
    'INSTRUMENTED',
    'obs_app',
    'app_hub',
    1
  ) INTO actual;
  IF actual <> 'sha256:4fb9b048c579197a2cf5ef151c1f1c7f7c08cd386b038a10478a6ecd428d037d' THEN
    RAISE EXCEPTION 'resource binding hash vector drifted: %', actual;
  END IF;
  RAISE NOTICE 'ok: resource binding hash matches the checked-in vector';
END $$;

-- Disable referential triggers for this single oracle so the receipt's own
-- success-binding CHECK is what rejects the row.  The transaction rolls this
-- harness-only setting back with every other fixture change.
ALTER TABLE relay_receipts DISABLE TRIGGER ALL;
SELECT relay_must_fail($$
  INSERT INTO relay_receipts
    (organization_id,project_id,environment_id,id,collection_job_id,job_digest,
     attempt_id,attempt_number,claim_token,process_boot_id,
     receipt_nonce,receipt_hash,result,error_class,input_hash,attempt_outcome_hash,
     local_result_hash,
     item_count,page_count,byte_count,call_count,started_at,completed_at)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','rrc_00000000000000000000000002',
    'rcj_00000000000000000000000001',
    'sha256:8888888888888888888888888888888888888888888888888888888888',
    'rat_00000000000000000000000001',1,
    '00000000-0000-4000-8000-000000000001','boot-1','nonce-2',
    'sha256:9999999999999999999999999999999999999999999999999999999998',
    'FAILED_RETRYABLE','UPSTREAM_UNAVAILABLE',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    0,0,0,1,now(),now())
$$, 'retryable failure is an attempt outcome, never a final receipt');
SELECT relay_must_fail($$
  INSERT INTO relay_receipts
    (organization_id,project_id,environment_id,id,collection_job_id,job_digest,
     attempt_id,attempt_number,claim_token,process_boot_id,
     receipt_nonce,receipt_hash,result,input_hash,attempt_outcome_hash,
     local_result_hash,
     item_count,page_count,byte_count,call_count,started_at,completed_at)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','rrc_00000000000000000000000001',
    'rcj_00000000000000000000000001',
    'sha256:8888888888888888888888888888888888888888888888888888888888888888',
    'rat_00000000000000000000000001',1,
    '00000000-0000-4000-8000-000000000001','boot-1','nonce-1',
    'sha256:9999999999999999999999999999999999999999999999999999999999999999',
    'SUCCEEDED',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    1,1,100,1,now(),now())
$$, 'successful receipt requires complete evidence binding');
ALTER TABLE relay_receipts ENABLE TRIGGER ALL;

-- Positive success-path oracle. The setup bypasses unrelated target-authority
-- foreign keys only while constructing a minimal already-authorized job. The
-- success command and every Relay success-bundle trigger remain enabled. This
-- catches deferred-trigger timing errors that negative row checks cannot see.
INSERT INTO solvan.outbox_events
  (organization_id,project_id,environment_id,id,aggregate_type,aggregate_id,
   aggregate_version,topic,event_type,payload_json,idempotency_key)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','evt_00000000000000000000000020',
  'RELAY_COLLECTION_JOB','rcj_00000000000000000000000020',0,
  'relay.job.ready','RELAY_JOB_READY','{}','relay-job-ready:positive');

ALTER TABLE solvan.agent_runs DISABLE TRIGGER ALL;
INSERT INTO solvan.agent_runs
  (organization_id,project_id,environment_id,id,incident_id,logical_step_key,
   agent_key,agent_resource,agent_revision,invocation_id,workflow_version,
   attempt,status,deadline,budget_json,input_ref,input_context_json,input_hash)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','run_00000000000000000000000020',
  'inc_00000000000000000000000020','relay-positive-step','evidence-agent',
  'agents/evidence-agent','1','relay-positive-agent-run',1,1,'RUNNING',
  now()+interval '5 minutes','{}','ref://relay-positive','{}',
  'sha256:1919191919191919191919191919191919191919191919191919191919191919');
ALTER TABLE solvan.agent_runs ENABLE TRIGGER ALL;

ALTER TABLE solvan.tool_calls DISABLE TRIGGER ALL;
INSERT INTO solvan.tool_calls
  (organization_id,project_id,environment_id,id,agent_run_id,invocation_id,
   tool_name,arguments_hash,status)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','tcl_00000000000000000000000020',
  'run_00000000000000000000000020','relay-positive-invocation',
  'cloud_monitoring_metric_read',
  'sha256:2020202020202020202020202020202020202020202020202020202020202020',
  'RESERVED');
ALTER TABLE solvan.tool_calls ENABLE TRIGGER ALL;

ALTER TABLE collection_jobs DISABLE TRIGGER ALL;
INSERT INTO collection_jobs
  (schema_version,canonicalization_version,organization_id,project_id,
   environment_id,id,enrollment_id,enrollment_epoch,relay_connection_id,
   relay_connection_epoch,source_binding_id,source_connection_id,
   source_connection_epoch,placement_epoch,cell_id,agent_run_id,tool_call_id,
   tool_arguments_hash,incident_id,profile_key,profile_version,
   profile_material_hash,profile_ordinal,tool_key,tool_version,
   capability_receipt_id,capability_receipt_hash,connector_catalog_key,
   connector_catalog_revision,connector_catalog_digest,adapter_key,
   adapter_revision,operation,typed_parameters_json,parameters_hash,
   resource_binding_id,graph_snapshot_id,resource_binding_hash,maximum_pages,
   maximum_items,maximum_bytes,maximum_calls,maximum_attempts,
   redaction_revision,classification_ceiling,residency_region,input_hash,
   job_digest,job_nonce,signing_key_id,signature_base64,
   job_wakeup_outbox_event_id,state,workflow_version,claim_request_nonce,
   claim_token,lease_owner,lease_expires_at,issued_at,expires_at)
VALUES
  (1,1,'org_00000000000000000000000000','prj_00000000000000000000000000',
   'env_00000000000000000000000000','rcj_00000000000000000000000020',
   'ren_00000000000000000000000020',1,'con_00000000000000000000000001',1,
   'rsb_00000000000000000000000020','con_00000000000000000000000020',1,
   1,'cell_relay_contract','run_00000000000000000000000020',
   'tcl_00000000000000000000000020',
   'sha256:2020202020202020202020202020202020202020202020202020202020202020',
   'inc_00000000000000000000000020','evidence.gcp-core.v1','1',
   'sha256:2121212121212121212121212121212121212121212121212121212121212121',
   1,'cloud_monitoring_metric_read','1','cpr_positive',
   'sha256:2222222222222222222222222222222222222222222222222222222222222222',
   'gcp-observe.v1',1,
   'sha256:2323232323232323232323232323232323232323232323232323232323232323',
   'cloud-monitoring.v1','1','monitoring.time-series.read.v1','{}',
   'sha256:2424242424242424242424242424242424242424242424242424242424242424',
   'pgn_00000000000000000000000020','pgs_00000000000000000000000020',
   'sha256:2525252525252525252525252525252525252525252525252525252525252525',
   1,10,10000,1,2,'relay-redaction.v1','INTERNAL','europe-west1',
   'sha256:2626262626262626262626262626262626262626262626262626262626262626',
   'sha256:2727272727272727272727272727272727272727272727272727272727272727',
   'positive-job','relay-key-v1','signature',
   'evt_00000000000000000000000020','RESULT_STORED',4,'positive-claim',
   '00000000-0000-4000-8000-000000000020','relay-positive',
   now()+interval '1 minute',now(),now()+interval '90 seconds');
-- Restore the success-bundle transition trigger immediately. Unrelated
-- authority/FK triggers remain disabled only because their full prerequisite
-- graphs are outside this focused transaction oracle.
ALTER TABLE collection_jobs ENABLE TRIGGER collection_job_transition_recorded;
INSERT INTO relay_attempts
  (organization_id,project_id,environment_id,id,collection_job_id,job_digest,
   attempt_number,claim_token,process_boot_id,adapter_revision,state,
   outcome_hash,local_result_hash,started_at,local_result_stored_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','rat_00000000000000000000000020',
  'rcj_00000000000000000000000020',
  'sha256:2727272727272727272727272727272727272727272727272727272727272727',
  1,'00000000-0000-4000-8000-000000000020','boot-positive','1','UPLOADED',
  'sha256:2828282828282828282828282828282828282828282828282828282828282828',
  'sha256:2929292929292929292929292929292929292929292929292929292929292929',
  now(),now());

INSERT INTO relay_upload_grants
  (organization_id,project_id,environment_id,id,collection_job_id,job_digest,
   attempt_id,attempt_number,claim_token,request_digest,grant_digest,object_ref,
   object_generation_match,content_hash,evidence_manifest_hash,
   redaction_manifest_hash,resource_binding_hash,classification,
   residency_region,content_type,content_length,cmek_digest,issued_at,expires_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','rug_00000000000000000000000020',
  'rcj_00000000000000000000000020',
  'sha256:2727272727272727272727272727272727272727272727272727272727272727',
  'rat_00000000000000000000000020',1,
  '00000000-0000-4000-8000-000000000020',
  'sha256:3030303030303030303030303030303030303030303030303030303030303030',
  'sha256:3131313131313131313131313131313131313131313131313131313131313131',
  'gs://relay-contract/positive','0',
  'sha256:3232323232323232323232323232323232323232323232323232323232323232',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',
  'sha256:3434343434343434343434343434343434343434343434343434343434343434',
  'sha256:2525252525252525252525252525252525252525252525252525252525252525',
  'INTERNAL','europe-west1','application/json',100,
  'sha256:3535353535353535353535353535353535353535353535353535353535353535',
  now(),now()+interval '2 minutes');

SELECT relay_must_fail($$
  INSERT INTO relay_receipts
    (organization_id,project_id,environment_id,id,collection_job_id,job_digest,
     attempt_id,attempt_number,claim_token,process_boot_id,receipt_nonce,
     receipt_hash,result,input_hash,attempt_outcome_hash,local_result_hash,
     evidence_object_ref,evidence_content_hash,evidence_manifest_hash,
     redaction_manifest_hash,resource_binding_hash,upload_grant_id,
     upload_grant_digest,object_generation,object_metadata_hash,classification,
     residency_region,item_count,page_count,byte_count,call_count,started_at,
     completed_at)
  VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','rrc_00000000000000000000000021',
    'rcj_00000000000000000000000020',
    'sha256:2727272727272727272727272727272727272727272727272727272727272727',
    'rat_00000000000000000000000020',1,
    '00000000-0000-4000-8000-000000000020','boot-positive','bad-outcome',
    'sha256:3939393939393939393939393939393939393939393939393939393939393939',
    'SUCCEEDED',
    'sha256:2626262626262626262626262626262626262626262626262626262626262626',
    'sha256:4040404040404040404040404040404040404040404040404040404040404040',
    'sha256:2929292929292929292929292929292929292929292929292929292929292929',
    'gs://relay-contract/positive',
    'sha256:3232323232323232323232323232323232323232323232323232323232323232',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    'sha256:3434343434343434343434343434343434343434343434343434343434343434',
    'sha256:2525252525252525252525252525252525252525252525252525252525252525',
    'rug_00000000000000000000000020',
    'sha256:3131313131313131313131313131313131313131313131313131313131313131',
    '1','sha256:3737373737373737373737373737373737373737373737373737373737373737',
    'INTERNAL','europe-west1',1,1,100,1,now(),now())
$$, 'receipt outcome hash must equal its exact attempt outcome');

ALTER TABLE solvan.evidence_items DISABLE TRIGGER ALL;
SELECT relay_commit_success_v1(
  jsonb_populate_record(NULL::relay_receipts, jsonb_build_object(
    'organization_id','org_00000000000000000000000000',
    'project_id','prj_00000000000000000000000000',
    'environment_id','env_00000000000000000000000000',
    'id','rrc_00000000000000000000000020',
    'collection_job_id','rcj_00000000000000000000000020',
    'job_digest','sha256:2727272727272727272727272727272727272727272727272727272727272727',
    'attempt_id','rat_00000000000000000000000020','attempt_number',1,
    'claim_token','00000000-0000-4000-8000-000000000020','process_boot_id','boot-positive',
    'receipt_nonce','positive-receipt','receipt_hash','sha256:3636363636363636363636363636363636363636363636363636363636363636',
    'result','SUCCEEDED','input_hash','sha256:2626262626262626262626262626262626262626262626262626262626262626',
    'attempt_outcome_hash','sha256:2828282828282828282828282828282828282828282828282828282828282828',
    'local_result_hash','sha256:2929292929292929292929292929292929292929292929292929292929292929',
    'evidence_object_ref','gs://relay-contract/positive',
    'evidence_content_hash','sha256:3232323232323232323232323232323232323232323232323232323232323232',
    'evidence_manifest_hash','sha256:3333333333333333333333333333333333333333333333333333333333333333',
    'redaction_manifest_hash','sha256:3434343434343434343434343434343434343434343434343434343434343434',
    'resource_binding_hash','sha256:2525252525252525252525252525252525252525252525252525252525252525',
    'upload_grant_id','rug_00000000000000000000000020',
    'upload_grant_digest','sha256:3131313131313131313131313131313131313131313131313131313131313131',
    'object_generation','1','object_metadata_hash','sha256:3737373737373737373737373737373737373737373737373737373737373737',
    'classification','INTERNAL','residency_region','europe-west1',
    'item_count',1,'page_count',1,'byte_count',100,'call_count',1,
    'started_at',now(),'completed_at',now(),'committed_at',now())),
  jsonb_populate_record(NULL::solvan.evidence_items, jsonb_build_object(
    'organization_id','org_00000000000000000000000000','project_id','prj_00000000000000000000000000',
    'environment_id','env_00000000000000000000000000','id','evd_00000000000000000000000020',
    'incident_id','inc_00000000000000000000000020','source_kind','SOLVAN_RELAY',
    'source_resource','relay://rcj_00000000000000000000000020','query_spec_json','{}'::jsonb,
    'window_start',now(),'window_end',now(),'observed_at',now(),'ingested_at',now(),
    'content_ref','gs://relay-contract/positive','content_hash','sha256:3232323232323232323232323232323232323232323232323232323232323232',
    'classification','INTERNAL','residency','europe-west1','redaction_manifest_ref','sha256:3434343434343434343434343434343434343434343434343434343434343434',
    'provenance_json',jsonb_build_object('schema_version',1,'collection_job_id','rcj_00000000000000000000000020','job_digest','sha256:2727272727272727272727272727272727272727272727272727272727272727','relay_receipt_id','rrc_00000000000000000000000020','receipt_hash','sha256:3636363636363636363636363636363636363636363636363636363636363636','upload_grant_id','rug_00000000000000000000000020','upload_grant_digest','sha256:3131313131313131313131313131313131313131313131313131313131313131','object_generation','1','object_metadata_hash','sha256:3737373737373737373737373737373737373737373737373737373737373737','evidence_manifest_hash','sha256:3333333333333333333333333333333333333333333333333333333333333333','redaction_manifest_hash','sha256:3434343434343434343434343434343434343434343434343434343434343434','resource_binding_hash','sha256:2525252525252525252525252525252525252525252525252525252525252525','source_binding_id','rsb_00000000000000000000000020','source_connection_id','con_00000000000000000000000020','source_connection_epoch',1,'enrollment_id','ren_00000000000000000000000020','enrollment_epoch',1,'adapter_key','cloud-monitoring.v1','adapter_revision','1','operation','monitoring.time-series.read.v1'),
    'freshness_expires_at',now()+interval '5 minutes','created_by_agent_run_id','run_00000000000000000000000020')),
  jsonb_populate_record(NULL::relay_evidence_acceptances, jsonb_build_object(
    'organization_id','org_00000000000000000000000000','project_id','prj_00000000000000000000000000','environment_id','env_00000000000000000000000000','collection_job_id','rcj_00000000000000000000000020','relay_receipt_id','rrc_00000000000000000000000020','evidence_item_id','evd_00000000000000000000000020','incident_id','inc_00000000000000000000000020','accepted_by_principal','relay-control','acceptance_policy_hash','sha256:3838383838383838383838383838383838383838383838383838383838383838','accepted_outbox_event_id','evt_00000000000000000000000021','accepted_at',now())),
  jsonb_populate_record(NULL::collection_job_transitions, jsonb_build_object(
    'organization_id','org_00000000000000000000000000','project_id','prj_00000000000000000000000000','environment_id','env_00000000000000000000000000','id','rjt_00000000000000000000000020','collection_job_id','rcj_00000000000000000000000020','workflow_version',5,'machine','collection_job','from_state','RESULT_STORED','event','RECEIPT_ACCEPTED','to_state','ACCEPTED','reason_code','SUCCESS_BUNDLE','claim_token','00000000-0000-4000-8000-000000000020','principal','relay-control','occurred_at',now())),
  jsonb_populate_record(NULL::solvan.outbox_events, jsonb_build_object(
    'organization_id','org_00000000000000000000000000','project_id','prj_00000000000000000000000000','environment_id','env_00000000000000000000000000','id','evt_00000000000000000000000021','aggregate_type','RELAY_COLLECTION_JOB','aggregate_id','rcj_00000000000000000000000020','aggregate_version',5,'topic','relay.evidence.accepted','event_type','RELAY_EVIDENCE_ACCEPTED','payload_json',jsonb_build_object('collection_job_id','rcj_00000000000000000000000020','relay_receipt_id','rrc_00000000000000000000000020','evidence_item_id','evd_00000000000000000000000020','tool_call_id','tcl_00000000000000000000000020'),'idempotency_key','relay-evidence-accepted:rcj_00000000000000000000000020','created_at',now(),'publish_attempts',0))
);
ALTER TABLE solvan.evidence_items ENABLE TRIGGER ALL;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE collection_jobs ENABLE TRIGGER ALL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM collection_jobs j
    JOIN relay_attempts a ON
      (a.organization_id,a.project_id,a.environment_id,a.collection_job_id)=
      (j.organization_id,j.project_id,j.environment_id,j.id)
    JOIN relay_evidence_acceptances x ON
      (x.organization_id,x.project_id,x.environment_id,x.collection_job_id)=
      (j.organization_id,j.project_id,j.environment_id,j.id)
    JOIN solvan.tool_calls t ON
      (t.organization_id,t.project_id,t.environment_id,t.id)=
      (j.organization_id,j.project_id,j.environment_id,j.tool_call_id)
    WHERE j.id='rcj_00000000000000000000000020' AND j.state='ACCEPTED'
      AND a.state='ACKNOWLEDGED' AND t.status='SUCCEEDED'
  ) THEN RAISE EXCEPTION 'positive Relay success bundle did not settle'; END IF;
  RAISE NOTICE 'ok: relay success command commits one complete positive bundle';
END $$;

ROLLBACK;
