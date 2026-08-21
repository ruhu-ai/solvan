-- Hostile Phase-1 Alert Triage schema oracles (specification 21).
SET search_path TO solvan_alerts, public;
BEGIN;

CREATE FUNCTION alert_must_fail(
  statement text, expected_state text, expected_message text, label text
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE observed_state text; observed_message text;
BEGIN
  BEGIN EXECUTE statement;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS observed_state=RETURNED_SQLSTATE, observed_message=MESSAGE_TEXT;
    IF observed_state IS DISTINCT FROM expected_state OR
       position(expected_message IN observed_message)=0 THEN
      RAISE EXCEPTION 'oracle % got state %, message %',label,observed_state,observed_message;
    END IF;
    RAISE NOTICE 'ok [%]: %',observed_state,label; RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %',label;
END $$;

DO $rls_oracle$
DECLARE scoped_count integer; forced_count integer;
BEGIN
  SELECT count(DISTINCT table_name) INTO scoped_count
    FROM information_schema.columns
   WHERE table_schema='solvan_alerts'
     AND column_name IN ('organization_id','project_id','environment_id');
  SELECT count(*) INTO forced_count
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='solvan_alerts' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity;
  IF scoped_count <> 15 OR forced_count <> 15 THEN
    RAISE EXCEPTION 'all 15 Alert Triage tables must force RLS; scoped %, forced %',
      scoped_count,forced_count;
  END IF;
END
$rls_oracle$;

INSERT INTO solvan.organizations(id,display_name)
VALUES ('org_00000000000000000000000000','Alert contract organization');
INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'Alert contract project','alert-contract');
INSERT INTO solvan.environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','Alert contract','europe-west1','INTERNAL');
INSERT INTO solvan.tenant_connections
  (organization_id,project_id,environment_id,id,display_name,kind,provider,
   credential_posture,authentication_mode,residency_region,classification,
   connection_epoch,lifecycle,availability,availability_reason_code,
   availability_explanation,availability_remediation_kind,availability_receipt_ref,
   solvan_delegator_principal,customer_reader_principal,delegation_condition_digest,
   token_lifetime_seconds,last_probe_at,last_probe_result,last_success_at,
   created_by_principal)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','con_00000000000000000000000001',
        'Cloud Monitoring push','GCP_NATIVE','CLOUD_MONITORING','FEDERATED_SHORT_LIVED',
        'GCP_SERVICE_ACCOUNT_IMPERSONATION','europe-west1','INTERNAL',1,'ENABLED','READY',NULL,NULL,NULL,
        'probe://alert-contract','serviceAccount:reader@solvan.iam.gserviceaccount.com',
        'serviceAccount:reader@metrics-scope.iam.gserviceaccount.com','sha256:'||repeat('d',64),900,
        now(),'SUCCEEDED',now(),
        'admin@example.com');

-- Operability v6 made both of these a revision history with a current head, and
-- the head's composite foreign key refuses material that was never published.
-- Seed the revision first, exactly as publication does, or this load aborts.
INSERT INTO solvan_operability.catalog_principal_revisions
  (principal_key,version,display_name,registry_kind,execution_role,model_backed,
   manifest_hash)
VALUES ('evidence-agent',1,'Evidence Agent','AGENT','SPECIALIST',true,
        'sha256:'||repeat('e',64));
INSERT INTO solvan_operability.catalog_principals
  (principal_key,display_name,registry_kind,execution_role,model_backed,manifest_hash)
VALUES ('evidence-agent','Evidence Agent','AGENT','SPECIALIST',true,
        'sha256:'||repeat('e',64));
INSERT INTO solvan_operability.tool_definition_revisions
  (tool_key,version,display_name,owner_department)
VALUES ('cloud_monitoring_query',1,'Cloud Monitoring query','Reliability Platform');
INSERT INTO solvan_operability.tool_definitions
  (tool_key,display_name,owner_department)
VALUES ('cloud_monitoring_query','Cloud Monitoring query','Reliability Platform');
INSERT INTO solvan_operability.tool_revisions
  (tool_key,version,description,permission_class,implementation_kind,
   required_capabilities_json,required_connection_providers_json,input_schema_ref,
   input_schema_hash,output_schema_ref,output_schema_hash,use_cases_json,
   anti_use_cases_json,evidence_kind,output_semantics_json,
   supported_retrieval_controls_json,no_data_semantics,failure_taxonomy_json,
   supported_data_classes_json,runtime_regions_json,registry_resource,
   gateway_destination,model_armor_coverage,network_policy_hash,timeout_ms,
   max_input_bytes,max_output_bytes,default_call_budget,idempotency,lifecycle,
   approval_ref,evaluation_ref,content_hash)
VALUES ('cloud_monitoring_query','1','Bounded metric read','READ','CONNECTOR',
  '["monitoring.timeSeries.list"]','["CLOUD_MONITORING"]','schema://input',
  'sha256:'||repeat('1',64),'schema://output','sha256:'||repeat('2',64),
  '["bounded alert triage"]','["arbitrary queries"]','METRICS',
  '["typed result"]','["bounded_window"]','UNKNOWN','["NO_DATA"]',
  '["INTERNAL"]','["europe-west1"]','registry://cloud-monitoring-query',
  'monitoring.googleapis.com','NOT_SUPPORTED','sha256:'||repeat('3',64),30000,
  65536,262144,3,'SOLVAN_RECONCILED','APPROVED','approval://tool','evaluation://tool',
  'sha256:'||repeat('4',64));
INSERT INTO solvan_operability.tool_revision_requesters
VALUES ('cloud_monitoring_query','1','evidence-agent');
INSERT INTO solvan_operability.tool_profile_revisions
  (schema_version,canonicalization_version,profile_key,version,purpose,
   allowed_agent_key,maximum_total_calls,maximum_parallel_calls,
   maximum_read_window_ms,maximum_aggregate_evidence_bytes,
   data_classification_ceiling,runtime_region,lifecycle,profile_material_hash,
   approval_ref,evaluation_ref)
VALUES (2,1,'alert-triage-read-compute-v1','1','ALERT_TRIAGE','evidence-agent',
        12,2,86400000,1048576,'CONFIDENTIAL','POLICY_BOUND','APPROVED',
        'sha256:'||repeat('5',64),'approval://profile','evaluation://profile');
INSERT INTO solvan_operability.tool_profile_members
VALUES ('alert-triage-read-compute-v1','1',1,'cloud_monitoring_query','1');
INSERT INTO solvan_operability.tool_profile_connection_requirements
VALUES ('alert-triage-read-compute-v1','1',1,'cloud_monitoring_query','1',
        'POLICY_SOURCE_CONNECTION','CLOUD_MONITORING','METRIC_READ',
        'TARGET_RESOURCE_PROJECT');

INSERT INTO solvan_operability.trigger_policy_revisions
  (organization_id,project_id,environment_id,policy_key,version,owner_department,
   trigger_kind,source_connection_id,source_connection_epoch,source_tool_key,
   source_tool_version,source_agent_key,source_identity_ref,source_capability_class,
   target_selector_ref,incident_class,severity,deduplication_dimension,action_budget,
   repeated_action_limit,profile_key,profile_version,delay_ms,cooldown_ms,
   maximum_pending_per_target,supersession,region,classification_ceiling,lifecycle,
   author_principal,policy_hash)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','payments.http-errors','1','Payments SRE',
  'ALERT_OPENED','con_00000000000000000000000001',1,'cloud_monitoring_query','1',
  'evidence-agent','identity://evidence-agent/1','METRIC_READ',
  'selector://alert-policy/'||repeat('6',64)||'@1','service_error_rate','SEV1',
  'alert_policy_fingerprint',1,1,'alert-triage-read-compute-v1','1',0,60000,3,
  'LATEST_WAITING_PER_TARGET','europe-west1','INTERNAL','DRAFT',
  'user:author@example.com','sha256:'||repeat('7',64));
INSERT INTO alert_policy_revisions
  (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash,
   alert_material_hash,source_kind,selector_json,target_mapping_json,
   severity_mapping_json,mode,triage_profile_ref,incident_profile_ref,
   triage_budget_json,incident_admission_budget_json,episode_horizon_ms,
   classification,retention_policy_revision)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','payments.http-errors','1',
  'sha256:'||repeat('7',64),'sha256:'||repeat('6',64),'CLOUD_MONITORING',
  '{"schema_version":1,"combine":"ALL_OF","clauses":[{"field":"SOURCE_STATE","key":null,"values":["OPEN"]}],"fingerprint_fields":["resource_identifier"]}',
  '{"schema_version":1,"kind":"EXACT_NODE","node_key":"service/payments","node_kind":null,"resource_label":null}',
  '{"schema_version":1,"entries":[{"provider_value":"CRITICAL","solvan_severity":"SEV1"}],"unknown_behavior":"BLOCKED"}',
  'TRIAGE','alert-triage-read-compute-v1@1','incident-investigation-v1@1',
  '{}','{}',86400000,'INTERNAL','retention/alert-policy-v1');

SELECT alert_must_fail($$
 INSERT INTO alert_policy_revisions
  (organization_id,project_id,environment_id,policy_key,policy_version,policy_hash,
   alert_material_hash,source_kind,selector_json,target_mapping_json,
   severity_mapping_json,mode,triage_profile_ref,incident_profile_ref,
   triage_budget_json,incident_admission_budget_json,episode_horizon_ms,
   classification,retention_policy_revision)
 SELECT organization_id,project_id,environment_id,'payments.http-errors-copy','1',
   policy_hash,'sha256:'||repeat('8',64),source_kind,selector_json,target_mapping_json,
   severity_mapping_json,mode,triage_profile_ref,incident_profile_ref,
   triage_budget_json,incident_admission_budget_json,episode_horizon_ms,
   classification,retention_policy_revision
 FROM alert_policy_revisions WHERE policy_key='payments.http-errors'
$$,'23503','violates foreign key constraint','an Alert subtype needs an exact generic revision');

INSERT INTO solvan_scale.cell_eligibility_profiles
  (eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES ('sha256:'||repeat('1',64),ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
        'sha256:'||repeat('2',64),false,ARRAY['europe-west1'],'ref_alert_cell');
INSERT INTO solvan_scale.cells
  (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
   capacity_profile_hash,data_policy_hash,eligibility_profile_hash,deployment_manifest_hash)
VALUES ('cell_alert','OSS_SINGLE_TENANT','europe-west1','alert-contract','READY',1,
        'sha256:'||repeat('3',64),'sha256:'||repeat('4',64),'sha256:'||repeat('1',64),
        'sha256:'||repeat('5',64));
INSERT INTO solvan_scale.tenant_eligibility_requirements
  (organization_id,requirement_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES ('org_00000000000000000000000000','sha256:'||repeat('6',64),
        ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],'sha256:'||repeat('2',64),
        false,ARRAY['europe-west1'],'ref_alert_tenant');
INSERT INTO solvan_scale.tenant_placements
  (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
   home_region,classification_ceiling,eligibility_requirement_hash,policy_hash,
   encryption_profile_hash,activated_at)
VALUES ('org_00000000000000000000000000',1,'cell_alert','ACTIVE',true,
        'OSS_SINGLE_TENANT','europe-west1','INTERNAL','sha256:'||repeat('6',64),
        'sha256:'||repeat('7',64),'sha256:'||repeat('2',64),now());

INSERT INTO alert_provider_source_identities
  (organization_id,project_id,environment_id,id,provider_kind,initial_connection_id,
   initial_connection_epoch,scoping_project_id,topic_name,subscription_name,
   topic_binding_receipt_ref,push_principal,oidc_audience,payload_schema_version,source_material_hash,
   classification,retention_policy_revision)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','asi_00000000000000000000000001',
        'CLOUD_MONITORING','con_00000000000000000000000001',1,'metrics-scope',
        'projects/metrics-scope/topics/alerts',
        'projects/metrics-scope/subscriptions/solvan-alerts',
        'ref_topic_binding',
        'push@metrics-scope.iam.gserviceaccount.com','https://alerts.example/internal',
        '1.2','sha256:'||repeat('8',64),'INTERNAL','retention/alert-v1');

INSERT INTO alert_provider_source_epoch_memberships
  (organization_id,project_id,environment_id,id,source_identity_id,continuity_epoch,
   successor_connection_id,successor_connection_epoch,compared_material_hash,decision,
   decision_ref,actor_principal,idempotency_key,request_hash,classification,
   retention_policy_revision)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','asm_00000000000000000000000001',
        'asi_00000000000000000000000001',1,'con_00000000000000000000000001',1,
        'sha256:'||repeat('8',64),'CONTINUITY_ACCEPTED','ref_initial_membership',
        'connection-lifecycle','initial-membership-0001','sha256:'||repeat('9',64),
        'INTERNAL','retention/alert-v1');
INSERT INTO alert_provider_source_current_memberships
  (organization_id,project_id,environment_id,source_identity_id,membership_id,
   continuity_epoch,connection_id,connection_epoch,classification,retention_policy_revision)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','asi_00000000000000000000000001',
        'asm_00000000000000000000000001',1,'con_00000000000000000000000001',1,
        'INTERNAL','retention/alert-v1');

SELECT alert_must_fail($$
 UPDATE alert_provider_source_identities SET scoping_project_id='attacker-project'
$$,'23951','alert history is append-only','source identity cannot be rewritten');

SELECT alert_must_fail($$
 INSERT INTO alert_provider_source_current_memberships
  (organization_id,project_id,environment_id,source_identity_id,membership_id,
   continuity_epoch,connection_id,connection_epoch,classification,retention_policy_revision)
 VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','asi_00000000000000000000000001',
  'asm_00000000000000000000000001',2,'con_00000000000000000000000001',1,
  'INTERNAL','retention/alert-v1')
$$,'23505','duplicate key value','one current source membership exists');

SET CONSTRAINTS ALL DEFERRED;
INSERT INTO alert_ingress_deliveries
  (organization_id,project_id,environment_id,id,cell_id,placement_epoch,connection_id,
   connection_epoch,provider_kind,provider_source_identity_id,topic_binding_receipt_ref,
   subscription_name,authenticated_push_principal,oidc_audience,pubsub_message_id,
   publish_time,envelope_hash,semantic_event_id,outcome,reason_code,raw_payload_hash,
   classification,retention_policy_revision)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','ald_00000000000000000000000001','cell_alert',1,
  'con_00000000000000000000000001',1,'CLOUD_MONITORING',
  'asi_00000000000000000000000001','ref_topic_binding',
  'projects/metrics-scope/subscriptions/solvan-alerts',
  'push@metrics-scope.iam.gserviceaccount.com','https://alerts.example/internal','message-1',
  now(),'sha256:'||repeat('a',64),'ale_00000000000000000000000001','COMMITTED',
  'SEMANTIC_EVENT_COMMITTED','sha256:'||repeat('b',64),'INTERNAL','retention/alert-v1');
INSERT INTO alert_events
  (organization_id,project_id,environment_id,id,cell_id,placement_epoch,
   first_admitted_delivery_id,provider_source_identity_id,observed_connection_id,
   observed_connection_epoch,provider_incident_key,lifecycle_state,
   transition_discriminator,transition_sequence,started_at,observed_at,
   scoping_project_id,monitored_resource_project_id,resource_type,
   resource_labels_json,normalized_labels_json,provider_severity,
   canonical_projection_version,canonical_event_hash,classification,
   retention_policy_revision)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','ale_00000000000000000000000001','cell_alert',1,
  'ald_00000000000000000000000001','asi_00000000000000000000000001',
  'con_00000000000000000000000001',1,'incident-1','OPEN',
  'OPEN:2026-08-13T00:00:00Z',1,'2026-08-13T00:00:00Z','2026-08-13T00:00:00Z',
  'metrics-scope','workload-project','cloud_run_revision','{}','{}','CRITICAL',
  'cloud-monitoring/1.2','sha256:'||repeat('c',64),'INTERNAL','retention/alert-v1');
SET CONSTRAINTS ALL IMMEDIATE;

SELECT alert_must_fail($$
 UPDATE alert_events SET provider_incident_key='rewritten'
$$,'23951','alert history is append-only','semantic event cannot be rewritten');

SELECT alert_must_fail($$
 INSERT INTO alert_ingress_deliveries
  (organization_id,project_id,environment_id,id,cell_id,placement_epoch,connection_id,
   connection_epoch,provider_kind,provider_source_identity_id,topic_binding_receipt_ref,
   subscription_name,authenticated_push_principal,oidc_audience,pubsub_message_id,
   envelope_hash,semantic_event_id,outcome,reason_code,classification,retention_policy_revision)
 VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','ald_00000000000000000000000002','cell_alert',1,
  'con_00000000000000000000000001',1,'CLOUD_MONITORING',
  'asi_00000000000000000000000001','ref_topic_binding',
  'projects/metrics-scope/subscriptions/solvan-alerts',
  'push@metrics-scope.iam.gserviceaccount.com','https://alerts.example/internal','message-1',
  'sha256:'||repeat('d',64),'ale_00000000000000000000000001','COMMITTED',
  'SEMANTIC_EVENT_COMMITTED','INTERNAL','retention/alert-v1')
$$,'23505','duplicate key value','transport identity is idempotent per connection epoch');

ROLLBACK;
