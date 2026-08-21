-- Exact negative oracles for code-change-release-schema.target.sql.
-- Load schema.sql followed by code-change-release-schema.target.sql first.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

CREATE OR REPLACE FUNCTION delivery_must_violate(
  statement text, expected_state text, expected_constraint text, label text
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE observed_state text; observed_constraint text;
BEGIN
  BEGIN EXECUTE statement;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS observed_state=RETURNED_SQLSTATE,
      observed_constraint=CONSTRAINT_NAME;
    IF observed_state IS DISTINCT FROM expected_state
       OR (expected_constraint IS NOT NULL AND observed_constraint IS DISTINCT FROM expected_constraint) THEN
      RAISE EXCEPTION 'oracle % got state %, constraint %',
        label,observed_state,observed_constraint;
    END IF;
    RAISE NOTICE 'ok: %',label; RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %',label;
END $$;

INSERT INTO solvan.organizations(id,display_name)
VALUES ('org_00000000000000000000000000','Delivery contract organization');
INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'Delivery contract project','delivery-contract');
INSERT INTO solvan.environments(organization_id,project_id,id,display_name,region,classification)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000',
        'env_00000000000000000000000000','Delivery contract environment','europe-west1','INTERNAL');
INSERT INTO solvan.github_repositories
 (organization_id,project_id,environment_id,id,installation_id,owner,name,default_branch,
  api_base_url,classification,credential_secret_ref,webhook_secret_ref,policy_hash,
  allowed_operations_json,status,last_probe_at,last_probe_result,created_by_principal)
VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','ghr_00000000000000000000000000',1,'Solvan','delivery',
  'main','https://api.github.com','INTERNAL','projects/p/secrets/key/versions/1',
  'projects/p/secrets/webhook/versions/1','sha256:'||repeat('0',64),'["READ"]',
  'ACTIVE',now(),'SUCCEEDED','principal:contract');

DO $$
BEGIN
  IF delivery_transition_allowed('PATCH_VALIDATED','MERGED') OR
     NOT delivery_transition_allowed('PATCH_VALIDATED','PR_CREATION_APPROVAL_PENDING') OR
     NOT delivery_transition_allowed('VERIFYING','BLOCKED') OR
     NOT delivery_transition_allowed('BLOCKED','ABANDONED') THEN
    RAISE EXCEPTION 'INV-CCR-00 code-change transition graph is not closed';
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
      JOIN information_schema.columns column_info
        ON column_info.table_schema=namespace.nspname
       AND column_info.table_name=relation.relname
     WHERE namespace.nspname='solvan_delivery' AND relation.relkind='r'
     GROUP BY relation.oid,relation.relname,relation.relrowsecurity,relation.relforcerowsecurity
    HAVING count(DISTINCT column_info.column_name) FILTER (
             WHERE column_info.column_name IN ('organization_id','project_id','environment_id')
           )=3
       AND (NOT bool_or(relation.relrowsecurity) OR NOT bool_or(relation.relforcerowsecurity)
            OR NOT EXISTS (SELECT 1 FROM pg_policies policy
                             WHERE policy.schemaname='solvan_delivery'
                               AND policy.tablename=relation.relname
                               AND policy.policyname='delivery_scope_isolation'))
  ) THEN
    RAISE EXCEPTION 'INV-CCR-00A delivery scope isolation is not forced on every scoped relation';
  END IF;
END $$;

INSERT INTO repair_plan_command_definitions
 (organization_id,project_id,environment_id,id,repository_binding_id,command_hash,
  command_kind,argv_json,working_directory,declared_inputs_hash,declared_outputs_hash,
  timeout_ms,cpu_millis,memory_mib,output_byte_limit,network_mode,catalog_hash,lifecycle,
  approved_ref,declared_inputs_json,declared_outputs_json)
VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','rcd_00000000000000000000000001','ghr_00000000000000000000000000','sha256:'||repeat('1',64),
  'REPRODUCTION','["pytest","-q"]','.', 'sha256:'||repeat('2',64),'sha256:'||repeat('3',64),
  1000,100,128,1024,'NONE','sha256:'||repeat('4',64),'APPROVED','approval_1',
  '["tests/**"]','[]');

SELECT delivery_must_violate($$
  INSERT INTO repair_plan_command_definitions
   (organization_id,project_id,environment_id,id,repository_binding_id,command_hash,
    command_kind,argv_json,working_directory,declared_inputs_hash,declared_outputs_hash,
    timeout_ms,cpu_millis,memory_mib,output_byte_limit,network_mode,catalog_hash,lifecycle,
    approved_ref,declared_inputs_json,declared_outputs_json)
  VALUES
   ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','rcd_00000000000000000000000009','not-a-repository','sha256:'||repeat('5',64),
    'REPRODUCTION','["pytest"]','.', 'sha256:'||repeat('6',64),'sha256:'||repeat('7',64),
    1000,100,128,1024,'NONE','sha256:'||repeat('8',64),'APPROVED','approval_2',
    '["tests/**"]','[]')
$$,'23514','repair_plan_command_definitions_repository_binding_id_check',
 'INV-CCR-01A repository binding is typed');

SELECT delivery_must_violate($$
  INSERT INTO repair_plan_command_definitions
   (organization_id,project_id,environment_id,id,repository_binding_id,command_hash,
    command_kind,argv_json,working_directory,declared_inputs_hash,declared_outputs_hash,
    timeout_ms,cpu_millis,memory_mib,output_byte_limit,network_mode,catalog_hash,lifecycle,
    approved_ref,declared_inputs_json,declared_outputs_json)
  VALUES
   ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','rcd_00000000000000000000000002','ghr_00000000000000000000000000','sha256:'||repeat('5',64),
    'REPRODUCTION','["pytest"]','.', 'sha256:'||repeat('6',64),'sha256:'||repeat('7',64),
    1000,100,128,1024,'EGRESS','sha256:'||repeat('8',64),'APPROVED','approval_2',
    '["tests/**"]','[]')
$$,'23514','repair_plan_command_definitions_network_mode_check',
 'INV-CCR-01 repair catalog has no egress mode');

SELECT delivery_must_violate($$
  UPDATE repair_plan_command_definitions SET argv_json='["sh"]'
   WHERE id='rcd_00000000000000000000000001'
$$,'23982',NULL,'INV-CCR-01B repair command material is immutable');

INSERT INTO github_oauth_client_profiles
 (organization_id,project_id,environment_id,id,provider_kind,github_app_client_id,client_secret_ref,
  authorization_endpoint,token_endpoint,api_base_url,callback_uri,protocol_version,
  token_expiration_required,configuration_hash,status,activated_at)
VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','gop_00000000000000000000000001',
  'GITHUB_APP_USER_TO_SERVER','cid_1','projects/p/secrets/s/versions/1',
  'https://github.com/login/oauth/authorize','https://github.com/login/oauth/access_token',
  'https://api.github.com','https://console.example.com/github/oauth/callback','1',true,
  'sha256:'||repeat('9',64),'ACTIVE',now());

SELECT delivery_must_violate($$
  INSERT INTO github_oauth_client_profiles
   (organization_id,project_id,environment_id,id,provider_kind,github_app_client_id,client_secret_ref,
    authorization_endpoint,token_endpoint,api_base_url,callback_uri,protocol_version,
    token_expiration_required,configuration_hash,status,activated_at)
  VALUES
   ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','gop_00000000000000000000000002',
    'GITHUB_APP_USER_TO_SERVER','cid_2','projects/p/secrets/s/versions/2',
    'https://github.com/login/oauth/authorize','https://github.com/login/oauth/access_token',
    'https://api.github.com','https://console.example.com/github/oauth/callback','1',true,
    'sha256:'||repeat('a',64),'ACTIVE',now())
$$,'23505','github_one_active_oauth_profile',
 'INV-CCR-02 one active OAuth profile per scope');

SELECT delivery_must_violate($$
  INSERT INTO github_identity_link_transactions
   (organization_id,project_id,environment_id,id,oauth_client_profile_id,repository_binding_id,
    solvan_principal,solvan_session_binding_hash,state_hash,pkce_verifier_ciphertext,
    pkce_key_version,requested_permission_hash,status,expires_at,consumed_at)
  VALUES
   ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','glt_00000000000000000000000001',
    'gop_00000000000000000000000001','ghr_00000000000000000000000000','principal:one','sha256:'||repeat('d',64),
    'sha256:'||repeat('e',64),'ciphertext','v1','sha256:'||repeat('f',64),'PENDING',now(),now())
$$,'23514','github_identity_link_transaction_material',
 'INV-CCR-03 pending OAuth transaction has no consumed timestamp');

SELECT delivery_must_violate($$
  UPDATE github_oauth_client_profiles SET github_app_client_id='changed'
   WHERE id='gop_00000000000000000000000001'
$$,'P0001',NULL,'INV-CCR-03A active OAuth client material is immutable');

SELECT delivery_must_violate($$
  INSERT INTO github_oauth_client_profiles
   (organization_id,project_id,environment_id,id,provider_kind,github_app_client_id,client_secret_ref,
    authorization_endpoint,token_endpoint,api_base_url,callback_uri,protocol_version,
    token_expiration_required,configuration_hash,status,revoked_at)
  VALUES
   ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','gop_00000000000000000000000003',
    'GITHUB_APP_USER_TO_SERVER','cid_3','projects/p/secrets/s/versions/3',
    'https://attacker.example/authorize','https://attacker.example/token',
    'https://attacker.example','https://console.example.com/github/oauth/callback','1',true,
    'sha256:'||repeat('b',64),'REVOKED',now())
$$,'23514','github_oauth_official_endpoint_boundary',
 'INV-CCR-03B OAuth profile cannot introduce an arbitrary egress origin');

SELECT delivery_must_violate($$
  TRUNCATE code_change_transitions
$$,'23981',NULL, 'INV-CCR-04 delivery transition history cannot be truncated');

SELECT delivery_must_violate($$
  INSERT INTO private_command_dispatches
   (id,organization_id,project_id,environment_id,command_kind,subject_id,material_hash,
    idempotency_key,payload_ref,payload_hash,payload_schema_hash,admitted_caller_identity,
    admitted_audience_hash,deadline,status)
  VALUES
   ('cmd_00000000000000000000000001','org_00000000000000000000000000',
    'prj_00000000000000000000000000','env_00000000000000000000000000',
    'CREATE_PR','ccr_00000000000000000000000001','sha256:'||repeat('a',64),
    'contract-command-1','gs://contract/command.json','sha256:'||repeat('b',64),
    'sha256:'||repeat('c',64),'serviceAccount:provider@example','sha256:'||repeat('d',64),
    now()+interval '1 hour','SUCCEEDED')
$$,'23999',NULL, 'INV-CCR-04A private command cannot begin completed');

DO $$
BEGIN
  IF (SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
      WHERE c.conrelid='repair_plan_guidance_selections'::regclass
        AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%rgi_%') IS NULL OR
     (SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
      WHERE c.conrelid='deployment_rollout_operations'::regclass
        AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%dgo_%') IS NULL THEN
    RAISE EXCEPTION 'INV-CCR-05 delivery identifiers do not have unique type prefixes';
  END IF;
END $$;

INSERT INTO private_command_dispatches
 (id,organization_id,project_id,environment_id,command_kind,subject_id,material_hash,
  idempotency_key,payload_ref,payload_hash,payload_schema_hash,admitted_caller_identity,
  admitted_audience_hash,deadline,status)
VALUES
 ('cmd_00000000000000000000000002','org_00000000000000000000000000',
  'prj_00000000000000000000000000','env_00000000000000000000000000',
  'QUALIFY_CODE_CHANGE','cqi_00000000000000000000000001','sha256:'||repeat('1',64),
  'contract-qualification-1','gs://contract/qualification.json','sha256:'||repeat('2',64),
  'sha256:'||repeat('3',64),'serviceAccount:coordinator@example','sha256:'||repeat('4',64),
  now()+interval '1 hour','PREPARED');

SELECT delivery_must_violate($$
  TRUNCATE code_change_qualification_receipts CASCADE
$$,'23981',NULL, 'INV-CCR-06 qualification receipt history cannot be truncated');

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
     WHERE tgrelid='code_change_requests'::regclass
       AND tgname='delivery_qualified_code_change_request_fence'
       AND NOT tgisinternal
  ) OR EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='solvan_delivery' AND table_name='code_change_requests'
       AND column_name IN ('qualification_receipt_id','code_delivery_profile_id')
       AND is_nullable<>'NO'
  ) THEN
    RAISE EXCEPTION 'INV-CCR-07 request creation is not qualification-fenced';
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='solvan_delivery' AND table_name='code_change_decisions'
       AND column_name='decision_request_id' AND is_nullable='NO'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_indexes
     WHERE schemaname='solvan_delivery' AND tablename='code_change_decision_challenges'
       AND indexname='code_change_one_pending_decision_challenge'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_trigger
     WHERE tgrelid='code_change_decision_challenges'::regclass
       AND tgname='delivery_decision_challenge_no_truncate' AND NOT tgisinternal
  ) THEN
    RAISE EXCEPTION 'INV-CCR-08 decision session/idempotency boundary is incomplete';
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='solvan_delivery' AND table_name='release_candidates'
       AND column_name='provenance_ref' AND is_nullable='NO'
  ) OR NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='solvan_delivery' AND table_name='release_candidates'
       AND column_name='build_invocation_hash' AND is_nullable='NO'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_trigger
     WHERE tgrelid='release_candidates'::regclass
       AND tgname='delivery_release_candidate_authority_fence' AND NOT tgisinternal
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_trigger
     WHERE tgrelid='deployment_rollouts'::regclass
       AND tgname='delivery_rollout_target_profile_fence' AND NOT tgisinternal
  ) THEN
    RAISE EXCEPTION 'INV-CCR-09 release candidate or target authority is incomplete';
  END IF;
END $$;

INSERT INTO release_verifier_keys
 (organization_id,project_id,environment_id,id,verifier_identity,key_version,
  public_verification_ref,verifier_policy_hash,status,activated_at)
VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','rvk_00000000000000000000000001',
  'serviceAccount:release-verifier@delivery-contract.iam.gserviceaccount.com',
  'projects/delivery-contract/locations/europe-west1/keyRings/releases/cryptoKeys/release-verifier/cryptoKeyVersions/1',
  'projects/delivery-contract/locations/europe-west1/keyRings/releases/cryptoKeys/release-verifier/cryptoKeyVersions/1',
  'sha256:'||repeat('5',64),'ACTIVE',now());

INSERT INTO release_target_profiles
 (organization_id,project_id,environment_id,id,target_key,provider_kind,
  service_resource_name,external_project_id,location,service_name,
  expected_target_epoch,runtime_service_account,deployment_manifest_profile_ref,
  deployment_manifest_profile_hash,rollout_policy_ref,rollout_policy_hash,
  canary_percentages,observation_windows_seconds,rollout_deadline_seconds,
  maximum_concurrent_rollouts,verification_profile_id,verification_profile_version,
  verifier_identity,verifier_key_version,
  verification_profile_ref,verification_profile_hash,profile_hash,status,
  approved_by_principal,approved_at)
VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000',
  'env_00000000000000000000000000','rtp_00000000000000000000000001',
  'cloud-run:delivery-contract:europe-west1:payments-api','GCP_CLOUD_RUN_V2',
  'projects/delivery-contract/locations/europe-west1/services/payments-api',
  'delivery-contract','europe-west1','payments-api',1,
  'payments-runtime@delivery-contract.iam.gserviceaccount.com',
  'gs://contract/manifest-profile.json','sha256:'||repeat('1',64),
  'gs://contract/rollout-policy.json','sha256:'||repeat('2',64),
  ARRAY[10,50,100]::smallint[],ARRAY[60,120,300],3600,1,
  'cloud-run-health','1',
  'serviceAccount:release-verifier@delivery-contract.iam.gserviceaccount.com',
  'projects/delivery-contract/locations/europe-west1/keyRings/releases/cryptoKeys/release-verifier/cryptoKeyVersions/1',
  'gs://contract/verification-profile.json',
  'sha256:'||repeat('3',64),'sha256:'||repeat('4',64),'ACTIVE',
  'principal:release-admin',now());

SELECT delivery_must_violate($$
  UPDATE release_target_profiles SET service_name='attacker-service'
   WHERE id='rtp_00000000000000000000000001'
$$,'P0001',NULL,'INV-CCR-09A active target profile material is immutable');

SELECT delivery_must_violate($$
  INSERT INTO release_target_profiles
   (organization_id,project_id,environment_id,id,target_key,provider_kind,
    service_resource_name,external_project_id,location,service_name,
    expected_target_epoch,runtime_service_account,deployment_manifest_profile_ref,
    deployment_manifest_profile_hash,rollout_policy_ref,rollout_policy_hash,
    canary_percentages,observation_windows_seconds,rollout_deadline_seconds,
    maximum_concurrent_rollouts,verification_profile_id,verification_profile_version,
    verifier_identity,verifier_key_version,
    verification_profile_ref,verification_profile_hash,profile_hash,status,
    approved_by_principal,approved_at)
  VALUES
   ('org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','rtp_00000000000000000000000002',
    'cloud-run:attacker','GCP_CLOUD_RUN_V2',
    'projects/attacker-project/locations/us-central1/services/attacker-service',
    'delivery-contract','europe-west1','payments-api',2,
    'payments-runtime@delivery-contract.iam.gserviceaccount.com',
    'gs://contract/manifest-profile.json','sha256:'||repeat('1',64),
    'gs://contract/rollout-policy.json','sha256:'||repeat('2',64),
    ARRAY[10,100]::smallint[],ARRAY[60,120],3600,1,
    'cloud-run-health','1',
    'serviceAccount:release-verifier@delivery-contract.iam.gserviceaccount.com',
    'projects/delivery-contract/locations/europe-west1/keyRings/releases/cryptoKeys/release-verifier/cryptoKeyVersions/1',
    'gs://contract/verification-profile.json',
    'sha256:'||repeat('3',64),'sha256:'||repeat('4',64),'ACTIVE',
    'principal:release-admin',now())
$$,'23514','release_target_profiles_check',
 'INV-CCR-09B target profile cannot disagree with its exact resource name');

ROLLBACK;
