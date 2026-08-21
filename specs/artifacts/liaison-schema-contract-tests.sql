-- Constraint oracle for the target conversational schema.
--
-- Each block asserts that a rule *rejects* what it is supposed to reject. A
-- CHECK nobody has tried to violate is a comment; these make them contracts.
-- Every statement runs inside a savepoint so one expected failure does not
-- abandon the transaction.

SET search_path TO solvan_liaison, public;

BEGIN;

INSERT INTO solvan_scale.cell_eligibility_profiles
  (eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES ('sha256:' || repeat('9',64),ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],
        ARRAY['europe-west1'],ARRAY['GA'],'sha256:' || repeat('0',64),false,
        ARRAY['europe-west1'],'ref_liaison_contract');

INSERT INTO solvan_scale.tenant_eligibility_requirements
  (organization_id,requirement_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES ('org_0000000000000000000000000J','sha256:' || repeat('8',64),ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL'],
        ARRAY['europe-west1'],ARRAY['GA'],'sha256:' || repeat('0',64),false,
        ARRAY['europe-west1'],'ref_liaison_tenant');

INSERT INTO solvan_scale.cells
  (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
   capacity_profile_hash,data_policy_hash,eligibility_profile_hash,deployment_manifest_hash)
VALUES ('cell_eu_1','OSS_SINGLE_TENANT','europe-west1','projects/solvan-test',
        'READY',1,'sha256:' || repeat('1',64),'sha256:' || repeat('2',64),
        'sha256:' || repeat('9',64),
        'sha256:' || repeat('3',64));

INSERT INTO solvan_scale.tenant_placements
  (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,
   home_region,classification_ceiling,eligibility_requirement_hash,policy_hash,
   encryption_profile_hash,activated_at)
VALUES ('org_0000000000000000000000000J',1,'cell_eu_1','ACTIVE',true,'OSS_SINGLE_TENANT','europe-west1',
        'CONFIDENTIAL','sha256:' || repeat('8',64),'sha256:' || repeat('4',64),
        'sha256:' || repeat('0',64),now());

CREATE OR REPLACE FUNCTION test_manifest(message_ref text, expires timestamptz)
RETURNS jsonb AS $$
  SELECT jsonb_build_object(
    'schema_version', 2,
    'reader_principal', 'operator@example.com',
    'scope', jsonb_build_object(
      'organization_id','org_0000000000000000000000000J','project_id','prj_x','environment_id','env_x'),
    'cell_id','cell_eu_1','placement_epoch',1,
    'purpose','incident-investigation','classification_ceiling','CONFIDENTIAL',
    'region','europe-west1','source_versions',jsonb_build_array(
      jsonb_build_object('record_type','incident','record_id','INC-1042',
                         'version','1','digest','sha256:' || repeat('a',64))),
    'working_context',jsonb_build_object(
      'compiler_version','liaison-context-v2',
      'compiler_binding_epoch',1,
      'compiler_digest','sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82',
      'tokenizer_digest','sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67',
      'model_resource','gemini-3.6-flash',
      'template_registry_digest','sha256:' || repeat('a',64),
      'tool_registry_digest','sha256:' || repeat('b',64),
      'read_grant_digest','sha256:' || repeat('c',64),
      'stable_prefix_digest','sha256:' || repeat('d',64),
      'variable_suffix_digest','sha256:' || repeat('e',64),
      'context_digest','sha256:' || repeat('b',64),
      'expires_at',expires::text),
    'liaison_message_id',message_ref)
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION liaison_assert_expected_failure(
  label text, actual_sqlstate text, actual_constraint text, actual_message text)
RETURNS void AS $$
DECLARE
  expected jsonb := jsonb_build_object(
    'a scope anchor may not retain a service key',ARRAY['23514','liaison_threads_check'],
    'a record anchor may not retain a window bound',ARRAY['23514','liaison_threads_check'],
    'a service window must end after it starts',ARRAY['23514','liaison_threads_check'],
    'an author-only part must name its author',ARRAY['23514','liaison_message_parts_check'],
    'a participant-scoped part must name its membership epoch',
      ARRAY['23514','liaison_message_parts_check1'],
    'a completed part cannot be edited',
      ARRAY['55000','completed liaison message parts are immutable'],
    'an access reference must point at a directory record',
      ARRAY['23503','liaison_part_access_organization_id_project_id_environmen_fkey1'],
    'a user message must name its author',ARRAY['23514','liaison_messages_check'],
    'a record selection reserves the first owner membership epoch',
      ARRAY['23514','liaison_selection_membership_epoch_ck'],
    'a consumed record selection must name its exact thread and time',
      ARRAY['23514','liaison_selection_consumed_shape_ck'],
    'a service selection window cannot exceed twenty-four hours',
      ARRAY['23514','liaison_service_selection_window_width_ck'],
    'a consumed service selection must name its exact thread and time',
      ARRAY['23514','liaison_service_selection_consumed_shape_ck'],
    'only a Liaison message may be mid-turn',ARRAY['23514','liaison_messages_check1'],
    'a parked turn must hold no lease',ARRAY['23514','liaison_turns_check6'],
    'a provider request cannot change its bound input',
      ARRAY['55000','liaison provider request identity is immutable'],
    'a provider request cannot complete before dispatch',
      ARRAY['23514','illegal liaison provider request transition PREPARED -> COMPLETED'],
    'only one attempt may be active for a message',
      ARRAY['23505','liaison_turn_one_nonterminal_attempt'],
    'a social turn cannot acquire an Ask route',ARRAY['23514','liaison_turns_check'],
    'a queued turn must have a durable queue position',ARRAY['23514','liaison_turns_check5'],
    'queue positions are unique and never reused within a thread',
      ARRAY['23505','liaison_turns_organization_id_project_id_environment_id_thr_key'],
    'a thread may have only one RUNNING or READY execution lane',
      ARRAY['23505','liaison_turn_one_thread_lane'],
    'a read grant cannot exist without its exact turn attempt and generation',
      ARRAY['23503','liaison_grant_receipts_organization_id_project_id_environm_fkey'],
    'one turn attempt has exactly one immutable input manifest',
      ARRAY['23505','liaison_turn_input_manifests_pkey'],
    'an input manifest cannot be edited in place',
      ARRAY['55000','liaison compiler history and turn input manifests are immutable'],
    'a dispatchable turn cannot lose its input manifest',
      ARRAY['23514','nonterminal liaison turn has no input manifest'],
    'message and current turn state cannot diverge',
      ARRAY['23514','liaison message state READY disagrees with current turn state QUEUED'],
    'every dispatchable attempt must commit an input manifest',
      ARRAY['23514','nonterminal liaison turn has no input manifest'],
    'terminal reasons come from the closed status-compatible domain',
      ARRAY['23514','liaison_turns_check10'],
    'a turn event must fence attempt with generation and name its author-only audience',
      ARRAY['23514','liaison_stream_events_check'],
    'a claimed inbound event must hold a complete lease',
      ARRAY['23514','liaison_inbound_events_check3'],
    'a pull-only MCP binding cannot receive a subscription',
      ARRAY['23514','liaison_subscriptions_channel_kind_check'],
    'a scope subscription must carry an expiry',
      ARRAY['23514','liaison_subscriptions_check1'],
    'a subscription scheduler claim must be complete',
      ARRAY['23514','liaison_subscriptions_check4'],
    'a direct delivery must name its source message',
      ARRAY['23514','liaison_deliveries_check'],
    'a subscription delivery must name its sequence interval',
      ARRAY['23514','liaison_deliveries_check1'],
    'a pending delivery may not retain a stale sender lease',
      ARRAY['23514','liaison_deliveries_check4'],
    'a completed operation must record its response',
      ARRAY['23514','liaison_operation_ledger_check'],
    'a steer grant must name the decision it was minted for',
      ARRAY['23514','liaison_steer_grant_shape_ck'],
    'email enrollment must name the exact intended address',
      ARRAY['23514','liaison_enrollment_email_identity_ck'],
    'a dispatched enrollment must record when dispatch happened',
      ARRAY['23514','liaison_enrollment_dispatch_time_ck'],
    'a consumed provider-derived enrollment must bind the exact signed identity',
      ARRAY['23514','liaison_enrollment_consumed_identity_ck'],
    'a provider health receipt must expire after its deployed-path check',
      ARRAY['23514','liaison_provider_health_time_ck'],
    'a provider health receipt cannot outlive its bounded qualification window',
      ARRAY['23514','liaison_provider_health_validity_ck'],
    'a provider health receipt must bind an immutable evidence object',
      ARRAY['23514','liaison_provider_health_receipt_ref_ck'],
    'a provider health receipt must bind the exact evidence digest',
      ARRAY['23514','liaison_provider_health_receipt_hash_ck']
  );
  target jsonb := expected -> label;
  expected_state text;
  expected_marker text;
BEGIN
  IF target IS NULL THEN
    RAISE EXCEPTION 'negative oracle has no exact expectation: %',label;
  END IF;
  expected_state := target ->> 0;
  expected_marker := target ->> 1;
  IF actual_sqlstate <> expected_state THEN
    RAISE EXCEPTION 'wrong SQLSTATE for %: expected %, got %',
      label,expected_state,actual_sqlstate;
  END IF;
  IF COALESCE(actual_constraint,'') <> expected_marker AND actual_message <> expected_marker THEN
    RAISE EXCEPTION 'wrong failure target for %: expected %, got constraint=% message=%',
      label,expected_marker,actual_constraint,actual_message;
  END IF;
  RAISE NOTICE 'ok [%/%]: %',actual_sqlstate,expected_marker,label;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION must_fail(statement text, label text) RETURNS void AS $$
DECLARE actual_sqlstate text; actual_constraint text; actual_message text;
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS actual_sqlstate=RETURNED_SQLSTATE,
      actual_constraint=CONSTRAINT_NAME,actual_message=MESSAGE_TEXT;
    PERFORM liaison_assert_expected_failure(
      label,actual_sqlstate,actual_constraint,actual_message);
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION must_fail_deferred(statement text, label text) RETURNS void AS $$
DECLARE actual_sqlstate text; actual_constraint text; actual_message text;
BEGIN
  BEGIN
    EXECUTE statement;
    SET CONSTRAINTS ALL IMMEDIATE;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS actual_sqlstate=RETURNED_SQLSTATE,
      actual_constraint=CONSTRAINT_NAME,actual_message=MESSAGE_TEXT;
    SET CONSTRAINTS ALL DEFERRED;
    PERFORM liaison_assert_expected_failure(
      label,actual_sqlstate,actual_constraint,actual_message);
    RETURN;
  END;
  SET CONSTRAINTS ALL DEFERRED;
  RAISE EXCEPTION 'deferred constraint did not hold: %', label;
END;
$$ LANGUAGE plpgsql;

-- Fixtures -----------------------------------------------------------------
INSERT INTO liaison_record_directory
  (organization_id, project_id, environment_id, record_type, record_id, classification)
VALUES ('org_0000000000000000000000000J', 'prj_x', 'env_x', 'incident', 'INC-1042', 'INTERNAL');

INSERT INTO liaison_threads
  (organization_id, project_id, environment_id, id, anchor_kind,
   anchor_record_type, anchor_record_id, visibility, status, created_by_principal)
VALUES ('org_0000000000000000000000000J', 'prj_x', 'env_x', 'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S', 'RECORD',
        'incident', 'INC-1042', 'SCOPE', 'OPEN', 'operator@example.com');

INSERT INTO liaison_thread_participants
  (organization_id,project_id,environment_id,thread_id,principal,
   membership_epoch,role,added_by_principal)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','thr_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'operator@example.com',1,'OWNER','operator@example.com');

INSERT INTO liaison_messages
  (organization_id, project_id, environment_id, id, thread_id, role,
   author_principal, classification, turn_state, purge_after, completed_at)
VALUES ('org_0000000000000000000000000J', 'prj_x', 'env_x', 'lms_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S', 'USER', 'operator@example.com',
        'CONFIDENTIAL', 'COMPLETED', now() + interval '30 days', now());

INSERT INTO liaison_channel_bindings
  (organization_id, project_id, environment_id, id, channel_kind, channel_identity,
   principal, identity_proof_ref, enrolled_at, classification_ceiling, status)
VALUES ('org_0000000000000000000000000J', 'prj_x', 'env_x', 'chb_01J4QZK8Q4J8Q6B95KQY4M9R2S', 'MCP',
        'mcp-client-1', 'operator@example.com', 'audit://enrol/1', now(),
        'INTERNAL', 'ACTIVE');

-- Anchors ------------------------------------------------------------------
-- A SCOPE anchor is valid. (The first draft of this constraint rejected it,
-- because `false = true` is false for every scope thread.)
INSERT INTO liaison_threads
  (organization_id, project_id, environment_id, id, anchor_kind, visibility,
   status, created_by_principal)
VALUES ('org_0000000000000000000000000J', 'prj_x', 'env_x', 'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T', 'SCOPE',
        'SCOPE', 'OPEN', 'operator@example.com');

SELECT must_fail($$
  INSERT INTO liaison_threads
    (organization_id, project_id, environment_id, id, anchor_kind,
     anchor_service_key, visibility, status, created_by_principal)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','thr_01J4QZK8Q4J8Q6B95KQY4M9R2U','SCOPE',
          'payments-api','SCOPE','OPEN','operator@example.com')
$$, 'a scope anchor may not retain a service key');

SELECT must_fail($$
  INSERT INTO liaison_threads
    (organization_id, project_id, environment_id, id, anchor_kind,
     anchor_record_type, anchor_record_id, anchor_window_end, visibility,
     status, created_by_principal)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','thr_01J4QZK8Q4J8Q6B95KQY4M9R2V','RECORD',
          'incident','INC-1042', now(), 'SCOPE','OPEN','operator@example.com')
$$, 'a record anchor may not retain a window bound');

SELECT must_fail($$
  INSERT INTO liaison_threads
    (organization_id, project_id, environment_id, id, anchor_kind,
     anchor_service_key, anchor_window_start, anchor_window_end, visibility,
     status, created_by_principal)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','thr_01J4QZK8Q4J8Q6B95KQY4M9R2W','SERVICE_WINDOW',
          'payments-api', now(), now() - interval '1 hour', 'SCOPE','OPEN','o@e.com')
$$, 'a service window must end after it starts');

-- Parts and access ---------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_message_parts
    (organization_id, project_id, environment_id, id, message_id, sequence, kind,
     schema_version, status, classification, access_mode, payload_json, completed_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','prt_1','lms_01J4QZK8Q4J8Q6B95KQY4M9R2S',0,'text',
          1,'COMPLETED','INTERNAL','AUTHOR_ONLY','{}'::jsonb, now())
$$, 'an author-only part must name its author');

SELECT must_fail($$
  INSERT INTO liaison_message_parts
    (organization_id, project_id, environment_id, id, message_id, sequence, kind,
     schema_version, status, classification, access_mode, payload_json, completed_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','prt_2','lms_01J4QZK8Q4J8Q6B95KQY4M9R2S',1,'text',
          1,'COMPLETED','INTERNAL','PARTICIPANTS_AT_EPOCH','{}'::jsonb, now())
$$, 'a participant-scoped part must name its membership epoch');

INSERT INTO liaison_message_parts
  (organization_id, project_id, environment_id, id, message_id, sequence, kind,
   schema_version, status, classification, access_mode, payload_json, completed_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','prt_ok','lms_01J4QZK8Q4J8Q6B95KQY4M9R2S',2,'claim',
        1,'COMPLETED','INTERNAL','RECORD_SET','{}'::jsonb, now());

SELECT must_fail($$
  UPDATE liaison_message_parts SET payload_json='{"edited":true}'::jsonb
   WHERE organization_id='org_0000000000000000000000000J' AND project_id='prj_x' AND environment_id='env_x'
     AND id='prt_ok'
$$, 'a completed part cannot be edited');

SELECT must_fail($$
  INSERT INTO liaison_part_access
    (organization_id, project_id, environment_id, part_id, record_type, record_id, relation)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','prt_ok','incident','INC-9999','CITES')
$$, 'an access reference must point at a directory record');

-- Messages -----------------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_messages
    (organization_id, project_id, environment_id, id, thread_id, role,
     classification, turn_state, purge_after)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R2X',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','USER','INTERNAL','COMPLETED',
          now() + interval '30 days')
$$, 'a user message must name its author');

SELECT must_fail($$
  INSERT INTO liaison_messages
    (organization_id, project_id, environment_id, id, thread_id, role,
     author_principal, classification, turn_state, purge_after, completed_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R2Y',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','USER','o@e.com','INTERNAL','STREAMING',
          now() + interval '30 days', now())
$$, 'only a Liaison message may be mid-turn');

-- Turns --------------------------------------------------------------------
INSERT INTO liaison_messages
  (organization_id, project_id, environment_id, id, thread_id, role,
   in_reply_to_message_id, classification, turn_state, purge_after)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R30',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','LIAISON','lms_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'INTERNAL','RUNNING', now() + interval '30 days');

SELECT must_fail($$
  INSERT INTO liaison_turns
    (organization_id, project_id, environment_id, message_id, thread_id, request_hash,
     conversation_intent, authority_route, attempt, generation, lease_owner,
     lease_token, lease_expires_at, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R30',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:x',
          'LEDGER_QUERY','ASK',1, 1, 'runner-1', gen_random_uuid(),
          now() + interval '1 minute', 'PARKED')
$$, 'a parked turn must hold no lease');

INSERT INTO liaison_turns
  (organization_id, project_id, environment_id, message_id, thread_id, request_hash,
   conversation_intent, authority_route, attempt, generation, lease_owner,
   lease_token, lease_expires_at, status, started_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R30',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:x',
        'LEDGER_QUERY','ASK',1, 1, 'runner-1', gen_random_uuid(),
        now() + interval '1 minute', 'RUNNING', now());

INSERT INTO liaison_grant_receipts
  (organization_id,project_id,environment_id,id,grant_kind,principal,thread_id,
   message_id,attempt,generation,purpose,classification_ceiling,membership_epoch,
   audience,allowed_projection_methods,grant_digest,request_hash,policy_epoch,
   issued_at,expires_at,audit_ref)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','grant-running','CONVERSATION_READ',
        'operator@example.com','thr_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R30',1,1,'incident-investigation',
        'CONFIDENTIAL',1,'PROJECTION_API',ARRAY['read_projection'],
        'sha256:' || repeat('c',64),'sha256:' || repeat('1',64),1,now(),
        '2099-01-01T00:05:00Z','audit://grant/running');

INSERT INTO liaison_turn_input_manifests
  (organization_id,project_id,environment_id,message_id,attempt,generation,schema_version,
   manifest_json,manifest_hash,reader_principal,read_grant_id,compiler_version,
   compiler_binding_epoch,compiler_digest,tokenizer_digest,model_resource,
   template_registry_digest,tool_registry_digest,read_grant_digest,
   stable_prefix_digest,variable_suffix_digest,context_digest,cell_id,placement_epoch,
   purpose,classification_ceiling,region,policy_epoch,membership_epoch,
   scope_sequence_high_water,expires_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R30',1,1,2,
        test_manifest('lms_01J4QZK8Q4J8Q6B95KQY4M9R30','2099-01-01T00:05:00Z'),
        'sha256:' || repeat('8',64),'operator@example.com','grant-running',
        'liaison-context-v2',1,
        'sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82',
        'sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67',
        'gemini-3.6-flash','sha256:' || repeat('a',64),'sha256:' || repeat('b',64),
        'sha256:' || repeat('c',64),'sha256:' || repeat('d',64),
        'sha256:' || repeat('e',64),'sha256:' || repeat('b',64),'cell_eu_1',1,
        'incident-investigation','CONFIDENTIAL','europe-west1',1,1,
        0,'2099-01-01T00:05:00Z');

INSERT INTO liaison_manifest_sources
  (organization_id,project_id,environment_id,message_id,attempt,record_type,
   record_id,source_version,source_digest,access_verdict_ref)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R30',1,
        'incident','INC-1042','1','sha256:' || repeat('a',64),'verdict://record/1');

INSERT INTO liaison_provider_requests
  (organization_id,project_id,environment_id,id,message_id,attempt,generation,
   manifest_hash,provider_input_digest,provider_input_bytes,model_resource,
   service_revision,process_boot_id,state)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','prq_01J4QZK8Q4J8Q6B95KQY4M9R3A',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R30',1,1,'sha256:' || repeat('8',64),
        'sha256:' || repeat('b',64),128,'gemini-3.6-flash','revision-test',
        'boot-test','PREPARED');

SELECT must_fail($$
  UPDATE liaison_provider_requests SET provider_input_bytes=1
   WHERE id='prq_01J4QZK8Q4J8Q6B95KQY4M9R3A'
$$, 'a provider request cannot change its bound input');

SELECT must_fail($$
  UPDATE liaison_provider_requests SET state='COMPLETED',terminal_at=now()
   WHERE id='prq_01J4QZK8Q4J8Q6B95KQY4M9R3A'
$$, 'a provider request cannot complete before dispatch');

UPDATE liaison_provider_requests
   SET state='DISPATCHED',dispatched_at=now(),dispatch_count=dispatch_count+1
 WHERE id='prq_01J4QZK8Q4J8Q6B95KQY4M9R3A';
UPDATE liaison_provider_requests
   SET state='COMPLETED',terminal_at=now()
 WHERE id='prq_01J4QZK8Q4J8Q6B95KQY4M9R3A';

SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;

SELECT must_fail($$
  INSERT INTO liaison_turns
    (organization_id, project_id, environment_id, message_id, thread_id, request_hash,
     conversation_intent, authority_route, attempt, generation, lease_owner,
     lease_token, lease_expires_at, status, started_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R30',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:x',
          'LEDGER_QUERY','ASK',2, 2, 'runner-2', gen_random_uuid(),
          now() + interval '1 minute', 'RUNNING', now())
$$, 'only one attempt may be active for a message');

SELECT must_fail($$
  INSERT INTO liaison_turns
    (organization_id, project_id, environment_id, message_id, thread_id, request_hash,
     conversation_intent, authority_route, attempt, generation, status,
     terminal_reason, started_at, ended_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R30',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:y',
          'SOCIAL','ASK',3,3,'FAILED','TURN_ERROR',now(),now())
$$, 'a social turn cannot acquire an Ask route');

-- A second accepted send may queue behind the running lane, but queue
-- positions are durable, unique, and mandatory for QUEUED attempts.
INSERT INTO liaison_messages
  (organization_id, project_id, environment_id, id, thread_id, role,
   author_principal, classification, turn_state, purge_after, completed_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R31',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','USER','operator@example.com',
        'INTERNAL','COMPLETED',now() + interval '30 days',now());

INSERT INTO liaison_messages
  (organization_id, project_id, environment_id, id, thread_id, role,
   in_reply_to_message_id, classification, turn_state, purge_after)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R32',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','LIAISON',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R31','INTERNAL','QUEUED',
        now() + interval '30 days');

INSERT INTO liaison_turns
  (organization_id, project_id, environment_id, message_id, thread_id,
   request_hash, conversation_intent, authority_route, attempt, generation,
   queue_sequence, queued_at, status)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R32',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:queued',
        'FOLLOW_UP','ASK',1,1,1,now(),'QUEUED');

INSERT INTO liaison_grant_receipts
  (organization_id,project_id,environment_id,id,grant_kind,principal,thread_id,
   message_id,attempt,generation,purpose,classification_ceiling,membership_epoch,
   audience,allowed_projection_methods,grant_digest,request_hash,policy_epoch,
   issued_at,expires_at,audit_ref)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','grant-queued','CONVERSATION_READ',
        'operator@example.com','thr_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R32',1,1,'incident-investigation',
        'CONFIDENTIAL',1,'PROJECTION_API',ARRAY['read_projection'],
        'sha256:' || repeat('c',64),'sha256:' || repeat('2',64),1,now(),
        '2099-01-01T00:05:00Z','audit://grant/queued');

INSERT INTO liaison_turn_input_manifests
  (organization_id,project_id,environment_id,message_id,attempt,generation,schema_version,
   manifest_json,manifest_hash,reader_principal,read_grant_id,compiler_version,
   compiler_binding_epoch,compiler_digest,tokenizer_digest,model_resource,
   template_registry_digest,tool_registry_digest,read_grant_digest,
   stable_prefix_digest,variable_suffix_digest,context_digest,cell_id,placement_epoch,
   purpose,classification_ceiling,region,policy_epoch,membership_epoch,
   scope_sequence_high_water,expires_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R32',1,1,2,
        test_manifest('lms_01J4QZK8Q4J8Q6B95KQY4M9R32','2099-01-01T00:05:00Z'),
        'sha256:' || repeat('9',64),'operator@example.com','grant-queued',
        'liaison-context-v2',1,
        'sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82',
        'sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67',
        'gemini-3.6-flash','sha256:' || repeat('a',64),'sha256:' || repeat('b',64),
        'sha256:' || repeat('c',64),'sha256:' || repeat('d',64),
        'sha256:' || repeat('e',64),'sha256:' || repeat('b',64),'cell_eu_1',1,
        'incident-investigation','CONFIDENTIAL','europe-west1',1,1,
        0,'2099-01-01T00:05:00Z');

INSERT INTO liaison_manifest_sources
  (organization_id,project_id,environment_id,message_id,attempt,record_type,
   record_id,source_version,source_digest,access_verdict_ref)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R32',1,
        'incident','INC-1042','1','sha256:' || repeat('a',64),'verdict://record/1');

SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;

INSERT INTO liaison_messages
  (organization_id, project_id, environment_id, id, thread_id, role,
   author_principal, classification, turn_state, purge_after, completed_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R33',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','USER','operator@example.com',
        'INTERNAL','COMPLETED',now() + interval '30 days',now());

INSERT INTO liaison_messages
  (organization_id, project_id, environment_id, id, thread_id, role,
   in_reply_to_message_id, classification, turn_state, purge_after)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R34',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','LIAISON',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R33','INTERNAL','QUEUED',
        now() + interval '30 days');

SELECT must_fail($$
  INSERT INTO liaison_turns
    (organization_id, project_id, environment_id, message_id, thread_id,
     request_hash, conversation_intent, authority_route, attempt, generation,
     status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R34',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:no-position',
          'FOLLOW_UP','ASK',1,1,'QUEUED')
$$, 'a queued turn must have a durable queue position');

SELECT must_fail($$
  INSERT INTO liaison_turns
    (organization_id, project_id, environment_id, message_id, thread_id,
     request_hash, conversation_intent, authority_route, attempt, generation,
     queue_sequence, queued_at, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R34',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:duplicate-position',
          'FOLLOW_UP','ASK',1,1,1,now(),'QUEUED')
$$, 'queue positions are unique and never reused within a thread');

SELECT must_fail($$
  INSERT INTO liaison_turns
    (organization_id, project_id, environment_id, message_id, thread_id,
     request_hash, conversation_intent, authority_route, attempt, generation,
     status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R34',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','sha256:second-lane',
          'FOLLOW_UP','ASK',1,1,'READY')
$$, 'a thread may have only one RUNNING or READY execution lane');

SELECT must_fail($$
  INSERT INTO liaison_grant_receipts
    (organization_id,project_id,environment_id,id,grant_kind,principal,thread_id,
     message_id,attempt,generation,purpose,classification_ceiling,membership_epoch,
     audience,allowed_projection_methods,grant_digest,request_hash,policy_epoch,
     issued_at,expires_at,audit_ref)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','grant-orphan','CONVERSATION_READ',
          'operator@example.com','thr_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'lms_01J4QZK8Q4J8Q6B95KQY4M9R34',99,99,'incident-investigation',
          'CONFIDENTIAL',1,'PROJECTION_API',ARRAY['read_projection'],
          'sha256:' || repeat('c',64),'sha256:' || repeat('3',64),1,now(),
          '2099-01-01T00:05:00Z','audit://grant/orphan')
$$, 'a read grant cannot exist without its exact turn attempt and generation');

SELECT must_fail($$
  INSERT INTO liaison_turn_input_manifests
    (organization_id,project_id,environment_id,message_id,attempt,generation,schema_version,
     manifest_json,manifest_hash,reader_principal,read_grant_id,compiler_version,
     compiler_binding_epoch,compiler_digest,tokenizer_digest,model_resource,
     template_registry_digest,tool_registry_digest,read_grant_digest,
     stable_prefix_digest,variable_suffix_digest,context_digest,cell_id,placement_epoch,
     purpose,classification_ceiling,region,policy_epoch,membership_epoch,
     scope_sequence_high_water,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R32',1,1,2,
          test_manifest('lms_01J4QZK8Q4J8Q6B95KQY4M9R32','2099-01-01T00:05:00Z'),
          'sha256:' || repeat('d',64),'operator@example.com','grant-queued',
          'liaison-context-v2',1,
        'sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82',
        'sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67',
          'gemini-3.6-flash','sha256:' || repeat('a',64),'sha256:' || repeat('b',64),
          'sha256:' || repeat('c',64),'sha256:' || repeat('d',64),
          'sha256:' || repeat('e',64),'sha256:' || repeat('b',64),'cell_eu_1',1,
          'incident-investigation','CONFIDENTIAL','europe-west1',1,1,
          0,'2099-01-01T00:05:00Z')
$$, 'one turn attempt has exactly one immutable input manifest');

SELECT must_fail($$
  UPDATE liaison_turn_input_manifests
     SET manifest_hash='sha256:' || repeat('e',64)
   WHERE organization_id='org_0000000000000000000000000J' AND project_id='prj_x' AND environment_id='env_x'
     AND message_id='lms_01J4QZK8Q4J8Q6B95KQY4M9R32' AND attempt=1
$$, 'an input manifest cannot be edited in place');

SELECT must_fail_deferred($$
  DELETE FROM liaison_turn_input_manifests
   WHERE organization_id='org_0000000000000000000000000J' AND project_id='prj_x' AND environment_id='env_x'
     AND message_id='lms_01J4QZK8Q4J8Q6B95KQY4M9R32' AND attempt=1
$$, 'a dispatchable turn cannot lose its input manifest');

SELECT must_fail_deferred($$
  UPDATE liaison_messages SET turn_state='READY'
   WHERE organization_id='org_0000000000000000000000000J' AND project_id='prj_x' AND environment_id='env_x'
     AND id='lms_01J4QZK8Q4J8Q6B95KQY4M9R32'
$$, 'message and current turn state cannot diverge');

INSERT INTO liaison_messages
  (organization_id,project_id,environment_id,id,thread_id,role,author_principal,
   classification,turn_state,purge_after,completed_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R35',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T','USER','operator@example.com',
        'INTERNAL','COMPLETED',now() + interval '30 days',now());

INSERT INTO liaison_messages
  (organization_id,project_id,environment_id,id,thread_id,role,
   in_reply_to_message_id,classification,turn_state,purge_after)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R36',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T','LIAISON',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R35','INTERNAL','READY',
        now() + interval '30 days');

SELECT must_fail_deferred($$
  INSERT INTO liaison_turns
    (organization_id,project_id,environment_id,message_id,thread_id,request_hash,
     conversation_intent,authority_route,attempt,generation,status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R36',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T','sha256:missing-manifest',
          'FOLLOW_UP','ASK',1,1,'READY')
$$, 'every dispatchable attempt must commit an input manifest');

SELECT must_fail($$
  INSERT INTO liaison_turns
    (organization_id,project_id,environment_id,message_id,thread_id,request_hash,
     conversation_intent,authority_route,attempt,generation,status,
     terminal_reason,started_at,ended_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R36',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T','sha256:bad-reason',
          'FOLLOW_UP','ASK',2,2,'FAILED','UNKNOWN_REASON',now(),now())
$$, 'terminal reasons come from the closed status-compatible domain');

INSERT INTO liaison_messages
  (organization_id,project_id,environment_id,id,thread_id,role,author_principal,
   classification,turn_state,purge_after,completed_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R37',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T','USER','operator@example.com',
        'INTERNAL','COMPLETED',now() + interval '30 days',now());

INSERT INTO liaison_messages
  (organization_id,project_id,environment_id,id,thread_id,role,
   in_reply_to_message_id,classification,turn_state,purge_after,completed_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R38',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T','LIAISON',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R37','INTERNAL','INTERRUPTED',
        now() + interval '30 days',now());

INSERT INTO liaison_turns
  (organization_id,project_id,environment_id,message_id,thread_id,request_hash,
   conversation_intent,authority_route,attempt,generation,status,
   terminal_reason,started_at,ended_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R38',
        'thr_01J4QZK8Q4J8Q6B95KQY4M9R2T','sha256:cascade',
        'FOLLOW_UP','ASK',1,1,'INTERRUPTED','USER_ABORTED',now(),now());

INSERT INTO liaison_grant_receipts
  (organization_id,project_id,environment_id,id,grant_kind,principal,thread_id,
   message_id,attempt,generation,purpose,classification_ceiling,membership_epoch,
   audience,allowed_projection_methods,grant_digest,request_hash,policy_epoch,
   issued_at,expires_at,audit_ref)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','grant-cascade','CONVERSATION_READ',
        'operator@example.com','thr_01J4QZK8Q4J8Q6B95KQY4M9R2T',
        'lms_01J4QZK8Q4J8Q6B95KQY4M9R38',1,1,'incident-investigation',
        'CONFIDENTIAL',1,'PROJECTION_API',ARRAY['read_projection'],
        'sha256:' || repeat('c',64),'sha256:' || repeat('4',64),1,now(),
        '2099-01-01T00:05:00Z','audit://grant/cascade');

INSERT INTO liaison_turn_input_manifests
  (organization_id,project_id,environment_id,message_id,attempt,generation,schema_version,
   manifest_json,manifest_hash,reader_principal,read_grant_id,compiler_version,
   compiler_binding_epoch,compiler_digest,tokenizer_digest,model_resource,
   template_registry_digest,tool_registry_digest,read_grant_digest,
   stable_prefix_digest,variable_suffix_digest,context_digest,cell_id,placement_epoch,
   purpose,classification_ceiling,region,policy_epoch,membership_epoch,
   scope_sequence_high_water,expires_at)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R38',1,1,2,
        test_manifest('lms_01J4QZK8Q4J8Q6B95KQY4M9R38','2099-01-01T00:05:00Z'),
        'sha256:' || repeat('f',64),'operator@example.com','grant-cascade',
        'liaison-context-v2',1,
        'sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82',
        'sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67',
        'gemini-3.6-flash','sha256:' || repeat('a',64),'sha256:' || repeat('b',64),
        'sha256:' || repeat('c',64),'sha256:' || repeat('d',64),
        'sha256:' || repeat('e',64),'sha256:' || repeat('b',64),'cell_eu_1',1,
        'incident-investigation','CONFIDENTIAL','europe-west1',1,1,
        0,'2099-01-01T00:05:00Z');

INSERT INTO liaison_manifest_sources
  (organization_id,project_id,environment_id,message_id,attempt,record_type,
   record_id,source_version,source_digest,access_verdict_ref)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','lms_01J4QZK8Q4J8Q6B95KQY4M9R38',1,
        'incident','INC-1042','1','sha256:' || repeat('a',64),'verdict://record/1');

DELETE FROM liaison_turns
 WHERE organization_id='org_0000000000000000000000000J' AND project_id='prj_x' AND environment_id='env_x'
   AND message_id='lms_01J4QZK8Q4J8Q6B95KQY4M9R38' AND attempt=1;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM liaison_turn_input_manifests
     WHERE organization_id='org_0000000000000000000000000J' AND project_id='prj_x' AND environment_id='env_x'
       AND message_id='lms_01J4QZK8Q4J8Q6B95KQY4M9R38' AND attempt=1
  ) THEN
    RAISE EXCEPTION 'turn deletion did not cascade to its input manifest';
  END IF;
  RAISE NOTICE 'ok: turn deletion cascades to its exact input manifest';
END;
$$;

-- Stream events -----------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_stream_events
    (organization_id, project_id, environment_id, thread_id, stream_sequence,
     event_id, event_type, schema_version, attempt, classification, access_mode,
     payload_json, payload_hash)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','thr_01J4QZK8Q4J8Q6B95KQY4M9R2S',1,
          'lev_01J4QZK8Q4J8Q6B95KQY4M9R2S','turn.activity',1,1,'INTERNAL',
          'AUTHOR_ONLY','{}','sha256:event')
$$, 'a turn event must fence attempt with generation and name its author-only audience');

-- Channel ingress ----------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_record_selection_receipts
    (organization_id,project_id,environment_id,id,principal,anchor_kind,
     record_type,record_id,record_revision,policy_epoch,membership_epoch,
     reader_grant_digest,request_hash,receipt_digest,status,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x',
          'rsl_01J4QZK8Q4J8Q6B95KQY4M9R2S','operator@example.com','RECORD',
          'incident','INC-1042','sha256:' || repeat('1',64),1,2,
          'sha256:' || repeat('2',64),'sha256:' || repeat('3',64),
          'sha256:' || repeat('4',64),'ISSUED',now()+interval '5 minutes')
$$, 'a record selection reserves the first owner membership epoch');

SELECT must_fail($$
  INSERT INTO liaison_record_selection_receipts
    (organization_id,project_id,environment_id,id,principal,anchor_kind,
     record_type,record_id,record_revision,policy_epoch,membership_epoch,
     reader_grant_digest,request_hash,receipt_digest,status,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x',
          'rsl_01J4QZK8Q4J8Q6B95KQY4M9R2T','operator@example.com','RECORD',
          'incident','INC-1042','sha256:' || repeat('5',64),1,1,
          'sha256:' || repeat('6',64),'sha256:' || repeat('7',64),
          'sha256:' || repeat('8',64),'CONSUMED',now()+interval '5 minutes')
$$, 'a consumed record selection must name its exact thread and time');

SELECT must_fail($$
  INSERT INTO liaison_service_selection_receipts
    (organization_id,project_id,environment_id,id,principal,service_key,
     window_start,window_end,entity_set_digest,policy_epoch,membership_epoch,
     reader_grant_digest,request_hash,receipt_digest,status,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x',
          'ssl_01J4QZK8Q4J8Q6B95KQY4M9R2S','operator@example.com','payments-api',
          now()-interval '25 hours',now(),'sha256:' || repeat('1',64),1,1,
          'sha256:' || repeat('2',64),'sha256:' || repeat('3',64),
          'sha256:' || repeat('4',64),'ISSUED',now()+interval '5 minutes')
$$, 'a service selection window cannot exceed twenty-four hours');

SELECT must_fail($$
  INSERT INTO liaison_service_selection_receipts
    (organization_id,project_id,environment_id,id,principal,service_key,
     window_start,window_end,entity_set_digest,policy_epoch,membership_epoch,
     reader_grant_digest,request_hash,receipt_digest,status,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x',
          'ssl_01J4QZK8Q4J8Q6B95KQY4M9R2T','operator@example.com','payments-api',
          now()-interval '1 hour',now(),'sha256:' || repeat('5',64),1,1,
          'sha256:' || repeat('6',64),'sha256:' || repeat('7',64),
          'sha256:' || repeat('8',64),'CONSUMED',now()+interval '5 minutes')
$$, 'a consumed service selection must name its exact thread and time');

SELECT must_fail($$
  INSERT INTO liaison_inbound_events
    (organization_id, project_id, environment_id, binding_id, binding_epoch,
     external_event_id, payload_hash, thread_id, message_id, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','chb_01J4QZK8Q4J8Q6B95KQY4M9R2S',1,
          'event-claimed-without-lease','sha256:x',
          'thr_01J4QZK8Q4J8Q6B95KQY4M9R2S','lms_01J4QZK8Q4J8Q6B95KQY4M9R2S','CLAIMED')
$$, 'a claimed inbound event must hold a complete lease');

-- Channel enrollment and provider qualification ---------------------------
SELECT must_fail($$
  INSERT INTO liaison_enrollment_challenges
    (organization_id,project_id,environment_id,id,principal,channel_kind,
     nonce_hash,callback_mechanism,console_authenticated_at,issued_at,expires_at,audit_ref)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','enr_email_missing',
          'o@e.com','EMAIL','sha256:x','signed reply',now(),now(),
          now()+interval '10 minutes','aud_x')
$$, 'email enrollment must name the exact intended address');

SELECT must_fail($$
  INSERT INTO liaison_enrollment_challenges
    (organization_id,project_id,environment_id,id,principal,channel_kind,
     nonce_hash,callback_mechanism,console_authenticated_at,issued_at,expires_at,
     status,dispatch_receipt_ref,audit_ref)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','enr_dispatch_missing',
          'o@e.com','SLACK','sha256:x','provider command',now(),now(),
          now()+interval '10 minutes','DISPATCHED','provider-command','aud_x')
$$, 'a dispatched enrollment must record when dispatch happened');

SELECT must_fail($$
  INSERT INTO liaison_enrollment_challenges
    (organization_id,project_id,environment_id,id,principal,channel_kind,
     nonce_hash,callback_mechanism,console_authenticated_at,issued_at,expires_at,
     status,dispatched_at,consumed_at,dispatch_receipt_ref,audit_ref)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','enr_consumed_no_identity',
          'o@e.com','DISCORD','sha256:x','provider command',now(),now(),
          now()+interval '10 minutes','CONSUMED',now(),now(),'provider-command','aud_x')
$$, 'a consumed provider-derived enrollment must bind the exact signed identity');

SELECT must_fail($$
  INSERT INTO liaison_channel_provider_health_receipts
    (organization_id,project_id,environment_id,id,channel_kind,deployment_id,
     service_revision,status,safe_reason_code,next_step_code,checked_at,expires_at,
     receipt_ref,receipt_hash)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','cph_invalid_expiry',
          'SLACK','dep-x','rev_x','AVAILABLE','QUALIFIED','NONE',now(),
          now()-interval '1 minute','gs://receipts/slack.json','sha256:' || repeat('1',64))
$$, 'a provider health receipt must expire after its deployed-path check');

SELECT must_fail($$
  INSERT INTO liaison_channel_provider_health_receipts
    (organization_id,project_id,environment_id,id,channel_kind,deployment_id,
     service_revision,status,safe_reason_code,next_step_code,checked_at,expires_at,
     receipt_ref,receipt_hash)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','cph_invalid_window',
          'SLACK','dep-x','rev_x','AVAILABLE','QUALIFIED','NONE',now(),
          now()+interval '25 hours','gs://receipts/slack.json','sha256:' || repeat('1',64))
$$, 'a provider health receipt cannot outlive its bounded qualification window');

SELECT must_fail($$
  INSERT INTO liaison_channel_provider_health_receipts
    (organization_id,project_id,environment_id,id,channel_kind,deployment_id,
     service_revision,status,safe_reason_code,next_step_code,checked_at,expires_at,
     receipt_ref,receipt_hash)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','cph_mutable_ref',
          'EMAIL','dep-x','rev_x','AVAILABLE','QUALIFIED','NONE',now(),
          now()+interval '1 hour','https://example.test/receipt.json','sha256:' || repeat('1',64))
$$, 'a provider health receipt must bind an immutable evidence object');

SELECT must_fail($$
  INSERT INTO liaison_channel_provider_health_receipts
    (organization_id,project_id,environment_id,id,channel_kind,deployment_id,
     service_revision,status,safe_reason_code,next_step_code,checked_at,expires_at,
     receipt_ref,receipt_hash)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','cph_invalid_hash',
          'DISCORD','dep-x','rev_x','AVAILABLE','QUALIFIED','NONE',now(),
          now()+interval '1 hour','gs://receipts/discord.json','sha256:not-a-digest')
$$, 'a provider health receipt must bind the exact evidence digest');

-- Subscriptions ------------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_subscriptions
    (organization_id, project_id, environment_id, id, principal, anchor_kind,
     anchor_record_type, anchor_record_id, channel_binding_id, channel_kind,
     cadence, consent_kind, consent_ref, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','sub_01J4QZK8Q4J8Q6B95KQY4M9R2S','o@e.com',
          'RECORD','incident','INC-1042','chb_01J4QZK8Q4J8Q6B95KQY4M9R2S','MCP',
          'ON_EVENT','CONSOLE_ACTION','audit://consent/1','ACTIVE')
$$, 'a pull-only MCP binding cannot receive a subscription');

SELECT must_fail($$
  INSERT INTO liaison_subscriptions
    (organization_id, project_id, environment_id, id, principal, anchor_kind,
     cadence, consent_kind, consent_ref, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','sub_01J4QZK8Q4J8Q6B95KQY4M9R2T','o@e.com',
          'SCOPE','DAILY_DIGEST','CONSOLE_ACTION','audit://consent/2','ACTIVE')
$$, 'a scope subscription must carry an expiry');

SELECT must_fail($$
  INSERT INTO liaison_subscriptions
    (organization_id, project_id, environment_id, id, principal, anchor_kind,
     anchor_record_type, anchor_record_id, cadence, consent_kind, consent_ref,
     claim_owner, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','sub_01J4QZK8Q4J8Q6B95KQY4M9R2U','o@e.com',
          'RECORD','incident','INC-1042','ON_EVENT','CONSOLE_ACTION',
          'audit://consent/3','scheduler-without-token','ACTIVE')
$$, 'a subscription scheduler claim must be complete');

-- Deliveries ---------------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_deliveries
    (organization_id, project_id, environment_id, id, delivery_kind, binding_id,
     binding_epoch, policy_epoch, payload_ref, payload_hash, classification,
     redaction_verdict_ref, access_set_hash, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','dlv_1','DIRECT_MESSAGE',
          'chb_01J4QZK8Q4J8Q6B95KQY4M9R2S',1,1,'gs://x','sha256:y','INTERNAL',
          'verdict://1','sha256:z','PENDING')
$$, 'a direct delivery must name its source message');

SELECT must_fail($$
  INSERT INTO liaison_deliveries
    (organization_id, project_id, environment_id, id, delivery_kind, subscription_id,
     binding_id, binding_epoch, policy_epoch, payload_ref, payload_hash,
     classification, redaction_verdict_ref, access_set_hash, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','dlv_2','SUBSCRIPTION_DELTA','sub_x',
          'chb_01J4QZK8Q4J8Q6B95KQY4M9R2S',1,1,'gs://x','sha256:y','INTERNAL',
          'verdict://1','sha256:z','PENDING')
$$, 'a subscription delivery must name its sequence interval');

SELECT must_fail($$
  INSERT INTO liaison_deliveries
    (organization_id, project_id, environment_id, id, delivery_kind,
     source_message_id, binding_id, binding_epoch, policy_epoch, payload_ref,
     payload_hash, classification, redaction_verdict_ref, access_set_hash,
     lease_owner, lease_token, lease_expires_at, status)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','dlv_3','DIRECT_MESSAGE',
          'lms_01J4QZK8Q4J8Q6B95KQY4M9R2S','chb_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          1,1,'gs://x','sha256:y','INTERNAL','verdict://1','sha256:z',
          'stale-owner',gen_random_uuid(),now() + interval '1 minute','PENDING')
$$, 'a pending delivery may not retain a stale sender lease');

-- Operation ledger ---------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_operation_ledger
    (organization_id, project_id, environment_id, idempotency_key, operation,
     request_hash, status, claim_token, expires_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','key-1','ask','sha256:r','COMPLETED',
          gen_random_uuid(), now() + interval '1 hour')
$$, 'a completed operation must record its response');

-- Grants -------------------------------------------------------------------
SELECT must_fail($$
  INSERT INTO liaison_grant_receipts
    (organization_id, project_id, environment_id, id, grant_kind, principal,
     audience,grant_digest,request_hash,policy_epoch,issued_at,expires_at,audit_ref)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','grt_1','STEER_SUBMISSION','o@e.com',
          'COORDINATOR_INBOX','sha256:' || repeat('a',64),
          'sha256:' || repeat('b',64),1,now(), now() + interval '5 minutes',
          'audit://grant/1')
$$, 'a steer grant must name the decision it was minted for');

ROLLBACK;
