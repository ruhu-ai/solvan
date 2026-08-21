\set ON_ERROR_STOP on

SET search_path TO solvan_liaison, public;

BEGIN;

-- Fixtures: one addressable record, one thread, one question, one answer.
INSERT INTO liaison_record_directory
  (organization_id,project_id,environment_id,record_type,record_id,classification)
VALUES ('org_0000000000000000000000000V','prj_v','env_v','incident','INC-2001','INTERNAL');

INSERT INTO liaison_threads
  (organization_id,project_id,environment_id,id,anchor_kind,
   anchor_record_type,anchor_record_id,visibility,status,created_by_principal)
VALUES ('org_0000000000000000000000000V','prj_v','env_v','thr_01V00000000000000000000000','RECORD',
        'incident','INC-2001','PARTICIPANTS','OPEN','operator@example.com');

INSERT INTO liaison_thread_participants
  (organization_id,project_id,environment_id,thread_id,principal,
   membership_epoch,role,added_by_principal)
VALUES ('org_0000000000000000000000000V','prj_v','env_v','thr_01V00000000000000000000000',
        'operator@example.com',1,'OWNER','operator@example.com');

INSERT INTO liaison_messages
  (organization_id,project_id,environment_id,id,thread_id,role,
   author_principal,classification,turn_state,purge_after,completed_at)
VALUES ('org_0000000000000000000000000V','prj_v','env_v','lms_01V00000000000000000000001',
        'thr_01V00000000000000000000000','USER','operator@example.com',
        'INTERNAL','COMPLETED',now() + interval '30 days',now());

INSERT INTO liaison_messages
  (organization_id,project_id,environment_id,id,thread_id,role,
   in_reply_to_message_id,classification,turn_state,purge_after,completed_at)
VALUES ('org_0000000000000000000000000V','prj_v','env_v','lms_01V00000000000000000000002',
        'thr_01V00000000000000000000000','LIAISON','lms_01V00000000000000000000001',
        'INTERNAL','COMPLETED',now() + interval '30 days',now());

-- A governed guidance selector is an ordinary read turn. Before this revision
-- the value could not be stored at all, so `/payments-sre/triage-latency` in a
-- conversation failed on insert rather than resolving a skill.
INSERT INTO liaison_turns
  (organization_id,project_id,environment_id,message_id,thread_id,request_hash,
   conversation_intent,authority_route,attempt,generation,status,
   started_at,ended_at,terminal_reason)
VALUES ('org_0000000000000000000000000V','prj_v','env_v','lms_01V00000000000000000000002',
        'thr_01V00000000000000000000000','sha256:v3',
        'GUIDANCE_REFERENCE','ASK',1,1,'COMPLETED',now(),now(),'ANSWER_COMPLETED');

-- Guidance is a read, never a free route. The pairing must refuse every other
-- authority route for it, exactly as it does for LEDGER_QUERY.
DO $guidance_must_not_steer$
BEGIN
  BEGIN
    INSERT INTO liaison_turns
      (organization_id,project_id,environment_id,message_id,thread_id,request_hash,
       conversation_intent,authority_route,attempt,generation,status,
       started_at,ended_at,terminal_reason)
    VALUES ('org_0000000000000000000000000V','prj_v','env_v','lms_01V00000000000000000000002',
            'thr_01V00000000000000000000000','sha256:v3b',
            'GUIDANCE_REFERENCE','STEER',2,1,'COMPLETED',now(),now(),'ANSWER_COMPLETED');
    RAISE EXCEPTION 'a guidance reference unexpectedly acquired the Steer route';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$guidance_must_not_steer$;

-- A zero-authority intent still cannot spend a route, and an intent outside
-- the closed registry still cannot be stored under any route.
DO $closed_registry_holds$
BEGIN
  BEGIN
    INSERT INTO liaison_turns
      (organization_id,project_id,environment_id,message_id,thread_id,request_hash,
       conversation_intent,authority_route,attempt,generation,status,
       started_at,ended_at,terminal_reason)
    VALUES ('org_0000000000000000000000000V','prj_v','env_v','lms_01V00000000000000000000002',
            'thr_01V00000000000000000000000','sha256:v3c',
            'OUT_OF_SCOPE','ASK',3,1,'COMPLETED',now(),now(),'ANSWER_COMPLETED');
    RAISE EXCEPTION 'an out-of-scope turn unexpectedly acquired the Ask route';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    INSERT INTO liaison_turns
      (organization_id,project_id,environment_id,message_id,thread_id,request_hash,
       conversation_intent,authority_route,attempt,generation,status,
       started_at,ended_at,terminal_reason)
    VALUES ('org_0000000000000000000000000V','prj_v','env_v','lms_01V00000000000000000000002',
            'thr_01V00000000000000000000000','sha256:v3d',
            'INVENTED_INTENT','ASK',4,1,'COMPLETED',now(),now(),'ANSWER_COMPLETED');
    RAISE EXCEPTION 'an unregistered conversation intent unexpectedly committed';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$closed_registry_holds$;

ROLLBACK;
