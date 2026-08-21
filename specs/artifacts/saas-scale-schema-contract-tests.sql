-- Hostile constraint/RLS oracles for specification 19 target DDL.
SET search_path TO solvan_scale, public;
BEGIN;

CREATE FUNCTION scale_must_fail(
  statement text, expected_sqlstate text, expected_marker text, label text)
RETURNS void AS $$
DECLARE actual_sqlstate text; actual_constraint text; actual_message text;
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS actual_sqlstate = RETURNED_SQLSTATE,
      actual_constraint = CONSTRAINT_NAME, actual_message = MESSAGE_TEXT;
    IF actual_sqlstate <> expected_sqlstate THEN
      RAISE EXCEPTION 'wrong failure for %: expected %, got %',
        label, expected_sqlstate, actual_sqlstate;
    END IF;
    IF actual_constraint IS DISTINCT FROM expected_marker AND
       position(expected_marker IN actual_message) = 0 THEN
      RAISE EXCEPTION 'wrong failure target for %: expected %, got constraint=% message=%',
        label, expected_marker, actual_constraint, actual_message;
    END IF;
    RAISE NOTICE 'ok [%]: %', actual_sqlstate, label;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END
$$ LANGUAGE plpgsql;

INSERT INTO cell_eligibility_profiles
  (eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES
  ('sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY['europe-west1'],ARRAY['GA'],
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
   false,ARRAY['europe-west1'],'ref_shared_eligibility'),
  ('sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED'],ARRAY['europe-west1'],
   ARRAY['GA','PREVIEW'],
   'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
   true,ARRAY['europe-west1'],'ref_dedicated_eligibility');

INSERT INTO tenant_eligibility_requirements
  (organization_id,requirement_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES
  ('org_0000000000000000000000000A','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY['europe-west1'],ARRAY['GA'],
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
   false,ARRAY['europe-west1'],'ref_org_a_eligibility'),
  ('org_0000000000000000000000000B','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY['europe-west1'],ARRAY['GA'],
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
   false,ARRAY['europe-west1'],'ref_org_b_eligibility'),
  ('org_0000000000000000000000000D','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED'],ARRAY['europe-west1'],
   ARRAY['GA','PREVIEW'],
   'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
   true,ARRAY['europe-west1'],'ref_org_d_eligibility'),
  ('org_0000000000000000000000000E','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY['europe-west1'],ARRAY['GA'],
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
   false,ARRAY['europe-west1'],'ref_org_epoch_eligibility'),
  ('org_0000000000000000000000000F','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY['europe-west1'],ARRAY['GA'],
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
   false,ARRAY['europe-west1'],'ref_org_reactivate_eligibility'),
  ('org_0000000000000000000000000G','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],ARRAY['europe-west1'],ARRAY['GA'],
   'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
   false,ARRAY['europe-west1'],'ref_org_ineligible');

INSERT INTO cells
  (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
   capacity_profile_hash,data_policy_hash,eligibility_profile_hash,deployment_manifest_hash)
VALUES
  ('cell_shared','SHARED_CELL','europe-west1','projects/shared','READY',3,
   'sha256:1111111111111111111111111111111111111111111111111111111111111111',
   'sha256:2222222222222222222222222222222222222222222222222222222222222222',
   'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
   'sha256:3333333333333333333333333333333333333333333333333333333333333333'),
  ('cell_dedicated','DEDICATED_CELL','europe-west1','projects/dedicated','READY',1,
   'sha256:4444444444444444444444444444444444444444444444444444444444444444',
   'sha256:5555555555555555555555555555555555555555555555555555555555555555',
   'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
   'sha256:6666666666666666666666666666666666666666666666666666666666666666');

SELECT scale_must_fail($$
  INSERT INTO cells VALUES
    ('cell_bad','DEDICATED_CELL','europe-west1','p','READY',2,
     'sha256:1111111111111111111111111111111111111111111111111111111111111111',
     'sha256:2222222222222222222222222222222222222222222222222222222222222222',
     'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
     'sha256:7777777777777777777777777777777777777777777777777777777777777777',now(),NULL)
$$, '23514', 'cells_profile_capacity_ck',
    'dedicated cell has exactly one organization');

INSERT INTO tenant_placements
  (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
   home_region,classification_ceiling,eligibility_requirement_hash,policy_hash,
   encryption_profile_hash,activated_at)
VALUES
  ('org_0000000000000000000000000A',1,'cell_shared','ACTIVE',true,'SHARED_CELL','europe-west1','CONFIDENTIAL',
   'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   'sha256:1111111111111111111111111111111111111111111111111111111111111111',
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',now()),
  ('org_0000000000000000000000000B',1,'cell_shared','ACTIVE',true,'SHARED_CELL','europe-west1','CONFIDENTIAL',
   'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   'sha256:3333333333333333333333333333333333333333333333333333333333333333',
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',now()),
  ('org_0000000000000000000000000D',1,'cell_dedicated','ACTIVE',true,'DEDICATED_CELL','europe-west1','RESTRICTED',
   'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   'sha256:5555555555555555555555555555555555555555555555555555555555555555',
   'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',now()),
  ('org_0000000000000000000000000E',9,'cell_shared','SUSPENDED',true,'SHARED_CELL','europe-west1','INTERNAL',
   'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   'sha256:7777777777777777777777777777777777777777777777777777777777777777',
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',now());

SELECT scale_must_fail($$
  INSERT INTO tenant_placements
    (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
     home_region,classification_ceiling,eligibility_requirement_hash,policy_hash,
     encryption_profile_hash,activated_at)
  VALUES ('org_0000000000000000000000000G',1,'cell_shared','ACTIVE',true,'SHARED_CELL','europe-west1',
   'CONFIDENTIAL','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   'sha256:0101010101010101010101010101010101010101010101010101010101010101',
   'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',now())
$$, '23514', 'placement is ineligible for cell profile',
    'tenant eligibility must be compatible with the cell profile');

SELECT scale_must_fail($$
  INSERT INTO tenant_placements
    (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
     home_region,classification_ceiling,eligibility_requirement_hash,policy_hash,
     encryption_profile_hash,activated_at)
  VALUES ('org_0000000000000000000000000E',1,'cell_shared','SUSPENDED',false,'SHARED_CELL','europe-west1','INTERNAL',
   'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   'sha256:7777777777777777777777777777777777777777777777777777777777777777',
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',now())
$$, '23514', 'placement epoch must increase', 'placement epochs strictly increase');

INSERT INTO tenant_placements
  (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
   home_region,classification_ceiling,eligibility_requirement_hash,policy_hash,
   encryption_profile_hash,activated_at)
VALUES
 ('org_0000000000000000000000000F',1,'cell_shared','SUSPENDED',false,'SHARED_CELL','europe-west1','CONFIDENTIAL',
 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
 'sha256:3434343434343434343434343434343434343434343434343434343434343434',
 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',now()),
 ('org_0000000000000000000000000F',2,'cell_shared','SUSPENDED',false,'SHARED_CELL','europe-west1','CONFIDENTIAL',
 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
 'sha256:1212121212121212121212121212121212121212121212121212121212121212',
 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',now());
SELECT scale_must_fail($$
  UPDATE tenant_placements SET is_current=true
   WHERE organization_id='org_0000000000000000000000000F' AND placement_epoch=1
$$, '23514', 'only the highest placement epoch may be current',
    'an obsolete placement epoch cannot become current');

UPDATE tenant_placements SET lifecycle='DELETING'
 WHERE organization_id='org_0000000000000000000000000E' AND placement_epoch=9;
UPDATE tenant_placements SET lifecycle='DELETED', is_current=false, retired_at=now()
 WHERE organization_id='org_0000000000000000000000000E' AND placement_epoch=9;
SELECT scale_must_fail($$
  UPDATE tenant_placements SET lifecycle='ACTIVE', is_current=true, retired_at=NULL
   WHERE organization_id='org_0000000000000000000000000E' AND placement_epoch=9
$$, '23514', 'deleted placement is terminal', 'deleted tenant cannot be resurrected');

-- A denied spoof can be audited without a valid placement FK.
INSERT INTO routing_grant_audits
  (audit_id,organization_id,grant_jti_hash,cell_id,placement_epoch,principal_hash,
   request_hash,audience_hash,outcome,reason_code,occurred_at,expires_at)
VALUES ('audit_spoof','org_0000000000000000000000000H',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'cell_missing',999,
  'sha256:1111111111111111111111111111111111111111111111111111111111111111',
  'sha256:2222222222222222222222222222222222222222222222222222222222222222',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',
  'DENIED','PLACEMENT_UNKNOWN',clock_timestamp(),clock_timestamp()+interval '1 minute');

CREATE ROLE scale_broker_role NOLOGIN;
CREATE ROLE scale_other_role NOLOGIN;
INSERT INTO scale_database_roles(database_role,cell_id,role_kind) VALUES
  ('scale_broker_role','cell_shared','ACCESS_BROKER'),
  ('scale_other_role','cell_shared','ACCESS_BROKER');
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM scale_database_privilege_manifest
     WHERE object_name='routing_grant_sessions'
       AND (role_kind<>'ACCESS_BROKER' OR privilege_name='SELECT')
  ) THEN
    RAISE EXCEPTION 'privilege manifest exposes live routing sessions';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM scale_database_privilege_manifest
     WHERE role_kind='AUDIT' AND object_name='routing_grant_audits'
       AND privilege_name='SELECT'
  ) THEN
    RAISE EXCEPTION 'audit role lacks credential-free audit projection';
  END IF;
END $$;

INSERT INTO routing_grant_audits
  (audit_id,organization_id,grant_jti_hash,cell_id,placement_epoch,principal_hash,
   request_hash,audience_hash,outcome,occurred_at,expires_at)
VALUES ('audit_accept','org_0000000000000000000000000A',
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'cell_shared',1,
  'sha256:1111111111111111111111111111111111111111111111111111111111111111',
  'sha256:2222222222222222222222222222222222222222222222222222222222222222',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',
  'ACCEPTED',clock_timestamp(),clock_timestamp()+interval '1 minute');

INSERT INTO tenant_work_registry
  (organization_id,project_id,environment_id,work_kind,work_id,state)
VALUES
  ('org_0000000000000000000000000A','prj_a','env_prod','CONVERSATION_TURN','wrk_a','PENDING'),
  ('org_0000000000000000000000000A','prj_other','env_prod','CONVERSATION_TURN','wrk_a_other','PENDING'),
  ('org_0000000000000000000000000B','prj_b','env_prod','CONVERSATION_TURN','wrk_b','PENDING'),
  ('org_0000000000000000000000000A','prj_a','env_prod','SECURITY_RECONCILIATION','wrk_security','PENDING'),
  ('org_0000000000000000000000000A','prj_a','env_prod','SECURITY_RECONCILIATION','wrk_reconcile','PENDING'),
  ('org_0000000000000000000000000A','prj_a','env_prod','LIFECYCLE_JOB','wrk_deletion','PENDING');

INSERT INTO tenant_dispatch_queue
  (organization_id,project_id,environment_id,work_id,cell_id,placement_epoch,
   work_kind,work_class,resource_kind,cost_units,tenant_sequence,state,available_at)
VALUES
  ('org_0000000000000000000000000A','prj_a','env_prod','wrk_a','cell_shared',1,'CONVERSATION_TURN',
   'INTERACTIVE_ASK','MODEL_REQUEST',1,1,'READY',now()),
  ('org_0000000000000000000000000A','prj_other','env_prod','wrk_a_other','cell_shared',1,'CONVERSATION_TURN',
   'INTERACTIVE_ASK','MODEL_REQUEST',1,2,'READY',now()),
  ('org_0000000000000000000000000B','prj_b','env_prod','wrk_b','cell_shared',1,'CONVERSATION_TURN',
   'INTERACTIVE_ASK','MODEL_REQUEST',1,1,'READY',now()),
  ('org_0000000000000000000000000A','prj_a','env_prod','wrk_security','cell_shared',1,'SECURITY_RECONCILIATION',
   'SECURITY','SECURITY_CHECK',1,3,'READY',now()),
  ('org_0000000000000000000000000A','prj_a','env_prod','wrk_reconcile','cell_shared',1,'SECURITY_RECONCILIATION',
   'RECONCILIATION','RECONCILIATION_CHECK',1,4,'READY',now()),
  ('org_0000000000000000000000000A','prj_a','env_prod','wrk_deletion','cell_shared',1,'LIFECYCLE_JOB',
   'DELETION','DELETION_CHECK',1,5,'READY',now());

-- Simulate the broker-created live session. Its binding includes this backend
-- and this exact transaction, not merely a handle.
INSERT INTO routing_grant_sessions
  (context_id,grant_jti_hash,organization_id,project_id,environment_id,cell_id,
   placement_epoch,database_role,principal_hash,request_hash,audience_hash,
   backend_pid,transaction_id,expires_at)
VALUES
  ('11111111-1111-4111-8111-111111111111',
   'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
   'org_0000000000000000000000000A','prj_a','env_prod','cell_shared',1,'scale_broker_role',
   'sha256:1111111111111111111111111111111111111111111111111111111111111111',
   'sha256:2222222222222222222222222222222222222222222222222222222222222222',
   'sha256:3333333333333333333333333333333333333333333333333333333333333333',
   pg_backend_pid(),pg_current_xact_id(),clock_timestamp()+interval '30 seconds');

GRANT USAGE ON SCHEMA solvan_scale TO scale_broker_role,scale_other_role;
GRANT SELECT ON tenant_dispatch_queue TO scale_broker_role,scale_other_role;
GRANT EXECUTE ON FUNCTION scope_permitted(text,text,text) TO scale_broker_role,scale_other_role;

SET ROLE scale_broker_role;
SET LOCAL solvan.routing_context_id='11111111-1111-4111-8111-111111111111';
DO $$ BEGIN
  IF (SELECT count(*) FROM tenant_dispatch_queue) <> 4 THEN
    RAISE EXCEPTION 'exact broker session did not expose exactly one scope and its control classes';
  END IF;
END $$;
RESET ROLE;

-- Ordinary tenant reads stop before the lifecycle leaves ACTIVE. Lifecycle
-- work uses separate least-privilege functions and never this tenant RLS path.
UPDATE tenant_placements SET lifecycle='SUSPENDING'
 WHERE organization_id='org_0000000000000000000000000A' AND placement_epoch=1;
SET ROLE scale_broker_role;
SET LOCAL solvan.routing_context_id='11111111-1111-4111-8111-111111111111';
DO $$ BEGIN
  IF (SELECT count(*) FROM tenant_dispatch_queue) <> 0 THEN
    RAISE EXCEPTION 'suspending placement retained ordinary tenant visibility';
  END IF;
END $$;
RESET ROLE;
UPDATE tenant_placements SET lifecycle='SUSPENDED'
 WHERE organization_id='org_0000000000000000000000000A' AND placement_epoch=1;
SET ROLE scale_broker_role;
SET LOCAL solvan.routing_context_id='11111111-1111-4111-8111-111111111111';
DO $$ BEGIN
  IF (SELECT count(*) FROM tenant_dispatch_queue) <> 0 THEN
    RAISE EXCEPTION 'suspended placement retained ordinary tenant visibility';
  END IF;
END $$;
RESET ROLE;
UPDATE tenant_placements SET lifecycle='ACTIVE'
 WHERE organization_id='org_0000000000000000000000000A' AND placement_epoch=1;

-- Same backend/transaction and stolen context ID still fails for another role.
SET ROLE scale_other_role;
SET LOCAL solvan.routing_context_id='11111111-1111-4111-8111-111111111111';
DO $$ BEGIN
  IF (SELECT count(*) FROM tenant_dispatch_queue) <> 0 THEN
    RAISE EXCEPTION 'stolen routing context exposed another tenant';
  END IF;
END $$;
RESET ROLE;

-- Terminalization written before a hypothetical later acceptance disables the
-- already-created session regardless of audit timestamp ordering.
INSERT INTO routing_grant_audits
  (audit_id,organization_id,grant_jti_hash,cell_id,placement_epoch,principal_hash,
   request_hash,audience_hash,outcome,reason_code,occurred_at,expires_at)
VALUES ('audit_revoke_first','org_0000000000000000000000000A',
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'cell_shared',1,
  'sha256:1111111111111111111111111111111111111111111111111111111111111111',
  'sha256:2222222222222222222222222222222222222222222222222222222222222222',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',
  'REVOKED','COMPROMISE',clock_timestamp()-interval '10 seconds',clock_timestamp()+interval '1 minute');
SELECT scale_must_fail($$
  INSERT INTO routing_grant_audits
    (audit_id,organization_id,grant_jti_hash,cell_id,placement_epoch,principal_hash,
     request_hash,audience_hash,outcome,occurred_at,expires_at)
  VALUES ('audit_late_accept','org_0000000000000000000000000A',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'cell_shared',1,
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    'ACCEPTED',clock_timestamp(),clock_timestamp()+interval '1 minute')
$$, '23514', 'terminal grant cannot be accepted', 'revoked grant cannot later be accepted');
SET ROLE scale_broker_role;
SET LOCAL solvan.routing_context_id='11111111-1111-4111-8111-111111111111';
DO $$ BEGIN
  IF (SELECT count(*) FROM tenant_dispatch_queue) <> 0 THEN
    RAISE EXCEPTION 'revoke-before-accept retained visibility';
  END IF;
END $$;
RESET ROLE;

SELECT scale_must_fail($$
  UPDATE routing_grant_audits SET reason_code='CHANGED' WHERE audit_id='audit_spoof'
$$, '55000', 'immutable scale history', 'routing audit is append-only');

INSERT INTO tenant_quota_policy_revisions
 (organization_id,version,policy_hash,approval_ref,effective_at)
VALUES ('org_0000000000000000000000000A',1,
 'sha256:9999999999999999999999999999999999999999999999999999999999999999',
 'ref_quota_approval',now());
INSERT INTO tenant_quota_policy_bindings
 (organization_id,binding_epoch,decision,policy_version,decision_ref)
VALUES ('org_0000000000000000000000000A',1,'ACTIVATE',1,'ref_quota_activate');
INSERT INTO tenant_quota_limits
 (organization_id,policy_version,resource_kind,window_seconds,sustained_limit,
  burst_limit,maximum_concurrent,exhaustion_behavior)
VALUES ('org_0000000000000000000000000A',1,'MODEL_REQUEST',60,30,60,1,'WAIT');
INSERT INTO tenant_quota_counters
 (organization_id,policy_version,resource_kind,token_nanounits,refill_at,counter_epoch)
VALUES ('org_0000000000000000000000000A',1,'MODEL_REQUEST',60000000000,now(),1);
INSERT INTO tenant_work_registry
 (organization_id,project_id,environment_id,work_kind,work_id,state)
VALUES ('org_0000000000000000000000000A','prj_a','env_prod','AGENT_RUN','wrk_agent','PENDING');
INSERT INTO cell_capacity_receipts
 (cell_id,receipt_id,resource_kind,project_ref,region,observed_limit,reserved_headroom,
  deployment_manifest_hash,source_ref,source_hash,provider_model_resource,
  provider_endpoint_ref,provider_profile_hash,observed_at,expires_at)
VALUES ('cell_shared','cap_model','MODEL_REQUEST','projects/shared','europe-west1',1000,100,
 'sha256:3333333333333333333333333333333333333333333333333333333333333333',
 'ref_model_limit','sha256:0101010101010101010101010101010101010101010101010101010101010101',
 'gemini-3.6-flash','https://aiplatform.eu.rep.googleapis.com',
 'sha256:0202020202020202020202020202020202020202020202020202020202020202',
 now(),now()+interval '1 hour');
INSERT INTO cell_capacity_bindings
 (cell_id,resource_kind,binding_epoch,decision,receipt_id,project_ref,region,
  deployment_manifest_hash,provider_model_resource,provider_endpoint_ref,
  provider_profile_hash,decision_ref)
VALUES ('cell_shared','MODEL_REQUEST',1,'QUALIFY','cap_model','projects/shared',
 'europe-west1','sha256:3333333333333333333333333333333333333333333333333333333333333333',
 'gemini-3.6-flash','https://aiplatform.eu.rep.googleapis.com',
 'sha256:0202020202020202020202020202020202020202020202020202020202020202',
 'ref_model_bind');
INSERT INTO tenant_capacity_reservations
 (organization_id,project_id,environment_id,reservation_id,cell_id,placement_epoch,
  policy_version,resource_kind,capacity_binding_epoch,capacity_receipt_id,
  units,work_kind,work_id,idempotency_key,request_hash,
  reservation_token,capacity_class,status,expires_at)
VALUES ('org_0000000000000000000000000A','prj_a','env_prod','res_one','cell_shared',1,1,'MODEL_REQUEST',1,
 'cap_model',1,'AGENT_RUN','wrk_agent',
 'agent-1','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
 '22222222-2222-4222-8222-222222222222','ORDINARY','HELD',now()+interval '1 minute');
SELECT scale_must_fail($$
  INSERT INTO tenant_capacity_reservations
   (organization_id,project_id,environment_id,reservation_id,cell_id,placement_epoch,
    policy_version,resource_kind,capacity_binding_epoch,capacity_receipt_id,
    units,work_kind,work_id,idempotency_key,request_hash,
    reservation_token,capacity_class,status,expires_at)
  VALUES ('org_0000000000000000000000000A','prj_a','env_prod','res_two','cell_shared',1,1,'MODEL_REQUEST',1,
   'cap_model',1,'AGENT_RUN','wrk_agent',
   'agent-1','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
   '33333333-3333-4333-8333-333333333333','ORDINARY','HELD',now()+interval '1 minute')
$$, '23505', 'tenant_capacity_reservation_idempotency_uk',
    'idempotency key rejects changed request');
SELECT scale_must_fail($$
  INSERT INTO tenant_capacity_reservations
   (organization_id,project_id,environment_id,reservation_id,cell_id,placement_epoch,
    policy_version,resource_kind,capacity_binding_epoch,capacity_receipt_id,
    units,work_kind,work_id,idempotency_key,request_hash,
    reservation_token,capacity_class,status,expires_at)
  VALUES ('org_0000000000000000000000000A','prj_a','env_prod','res_control','cell_shared',1,1,'MODEL_REQUEST',1,
   'cap_model',1,'AGENT_RUN','wrk_agent',
   'agent-control','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
   '44444444-4444-4444-8444-444444444444','CONTROL','HELD',now()+interval '1 minute')
$$, '23514', 'tenant_capacity_control_reserve_ck',
    'control reserve cannot start model work');

INSERT INTO cell_capacity_receipts
 (cell_id,receipt_id,resource_kind,project_ref,region,observed_limit,reserved_headroom,
  deployment_manifest_hash,source_ref,source_hash,observed_at,expires_at)
VALUES ('cell_shared','cap_sql','CLOUD_SQL_CONNECTION','projects/shared','europe-west1',100,20,
 'sha256:3333333333333333333333333333333333333333333333333333333333333333',
 'ref_sql_limit','sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
 now(),now()+interval '1 hour');
INSERT INTO cell_capacity_bindings
 (cell_id,resource_kind,binding_epoch,decision,receipt_id,project_ref,region,
  deployment_manifest_hash,decision_ref)
VALUES ('cell_shared','CLOUD_SQL_CONNECTION',2,'QUALIFY','cap_sql','projects/shared',
 'europe-west1','sha256:3333333333333333333333333333333333333333333333333333333333333333',
 'ref_cap_bind');
SELECT scale_must_fail($$
  INSERT INTO cell_capacity_bindings
   (cell_id,resource_kind,binding_epoch,decision,receipt_id,project_ref,region,
    deployment_manifest_hash,decision_ref)
  VALUES ('cell_shared','CLOUD_SQL_CONNECTION',1,'QUALIFY','cap_sql','projects/shared',
   'europe-west1','sha256:3333333333333333333333333333333333333333333333333333333333333333',
   'ref_old_bind')
$$, '23514', 'binding epoch must increase', 'capacity binding epochs increase');
SELECT scale_must_fail($$
  INSERT INTO cell_capacity_bindings
   (cell_id,resource_kind,binding_epoch,decision,receipt_id,project_ref,region,
    deployment_manifest_hash,decision_ref)
  VALUES ('cell_shared','MEMORY_READ',3,'QUALIFY','cap_sql','projects/shared',
   'europe-west1','sha256:3333333333333333333333333333333333333333333333333333333333333333',
   'ref_wrong_resource')
$$, '23503', 'capacity_binding_receipt_fk',
    'a capacity receipt cannot qualify a different resource');
SELECT scale_must_fail($$
  INSERT INTO cell_capacity_receipts
   (cell_id,receipt_id,resource_kind,project_ref,region,observed_limit,reserved_headroom,
    deployment_manifest_hash,source_ref,source_hash,observed_at,expires_at)
  VALUES ('cell_shared','cap_wrong_project','MEMORY_READ','projects/wrong','europe-west1',10,1,
   'sha256:3333333333333333333333333333333333333333333333333333333333333333',
   'ref_wrong_project','sha256:0303030303030303030303030303030303030303030303030303030303030303',
   now(),now()+interval '1 hour')
$$, '23503', 'capacity_receipt_cell_deployment_fk',
    'a capacity receipt must match the cell project and region');

INSERT INTO scope_sequencer_leases
 (organization_id,project_id,environment_id,cell_id,placement_epoch,next_scope_sequence)
VALUES ('org_0000000000000000000000000A','prj_a','env_prod','cell_shared',1,8);
SELECT scale_must_fail($$
 UPDATE scope_sequencer_leases SET next_scope_sequence=7
 WHERE organization_id='org_0000000000000000000000000A' AND project_id='prj_a' AND environment_id='env_prod'
$$, '23514', 'scope sequence cannot decrease', 'scope sequence cannot decrease');
INSERT INTO cell_event_ingress
 (organization_id,project_id,environment_id,event_id,cell_id,placement_epoch,
  event_ref,event_hash,sequencing_state,scope_sequence,sequenced_at)
VALUES ('org_0000000000000000000000000A','prj_a','env_prod','evt_cursor_1','cell_shared',1,'ref_cursor_event',
 'sha256:acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac',
 'SEQUENCED',1,now());
SELECT recover_scope_event_cursor(
 'org_0000000000000000000000000A','prj_a','env_prod','cur_reader','sha256:0101010101010101010101010101010101010101010101010101010101010101',
 'cell_shared',1,2,3,0,
 'sha256:0202020202020202020202020202020202020202020202020202020202020202');
SELECT scale_must_fail($$
 SELECT recover_scope_event_cursor(
  'org_0000000000000000000000000A','prj_a','env_prod','cur_bad','sha256:0303030303030303030303030303030303030303030303030303030303030303',
  'cell_shared',1,2,3,99,
  'sha256:0404040404040404040404040404040404040404040404040404040404040404')
$$, '23514', 'cursor recovery high-water exceeds feed',
    'cursor recovery cannot invent high-water');
SELECT advance_scope_event_cursor('org_0000000000000000000000000A','prj_a','env_prod','cur_reader',0,1);
INSERT INTO cell_event_ingress
 (organization_id,project_id,environment_id,event_id,cell_id,placement_epoch,
  event_ref,event_hash,sequencing_state,attempt_count,error_ref)
VALUES ('org_0000000000000000000000000A','prj_a','env_prod','evt_poison','cell_shared',1,'ref_event',
 'sha256:abababababababababababababababababababababababababababababababab',
 'QUARANTINED',3,'ref_bad_event');
SELECT scale_must_fail($$
 SELECT advance_scope_event_cursor('org_0000000000000000000000000A','prj_a','env_prod','cur_reader',1,2)
$$, '55000', 'quarantined event blocks cursor advancement',
    'poison event blocks cursor advancement');

INSERT INTO tenant_lifecycle_jobs
 (organization_id,job_id,job_kind,expected_placement_epoch,source_cell_id,state,
  request_hash,legal_hold_ref,unsettled_mutation_count)
VALUES ('org_0000000000000000000000000A','job_delete','DELETE',1,'cell_shared','VERIFYING',
 'sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
 'ref_legal_hold',0);
SELECT scale_must_fail($$
 UPDATE tenant_lifecycle_jobs SET state='COMPLETED',completed_at=now(),
 completion_proof_hash='sha256:edededededededededededededededededededededededededededededededededededed'
 WHERE organization_id='org_0000000000000000000000000A' AND job_id='job_delete'
$$, '23514', 'tenant_lifecycle_delete_completion_ck',
    'legal hold blocks deletion completion');

INSERT INTO tenant_lifecycle_jobs
 (organization_id,job_id,job_kind,expected_placement_epoch,source_cell_id,state,
  request_hash,completion_proof_hash)
VALUES ('org_0000000000000000000000000A','job_move_direct','MOVE',1,'cell_shared','VERIFYING',
 'sha256:cececececececececececececececececececececececececececececececece',
 'sha256:abababababababababababababababababababababababababababababababab');
SELECT scale_must_fail($$
 UPDATE tenant_lifecycle_jobs SET state='COMPLETED',completed_at=now()
 WHERE organization_id='org_0000000000000000000000000A' AND job_id='job_move_direct'
$$, '23514', 'move completion requires the committed cutover',
    'movement cannot complete before its committed cutover');

ROLLBACK;
