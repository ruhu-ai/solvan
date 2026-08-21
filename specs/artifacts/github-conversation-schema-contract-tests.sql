-- Specification 24 oracles: the conversation surface cannot be widened by a
-- well-formed row. These prove in the database what the application also
-- enforces, so a direct writer, a future migration, or a repaired backup
-- cannot produce authority the code refuses to grant.
SET search_path TO solvan_conversation, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION conversation_must_violate(
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

INSERT INTO solvan.organizations (id,display_name)
VALUES ('org_0000000000000000000000000C','Conversation contract org');
INSERT INTO solvan.projects (organization_id,id,display_name,gcp_project_id)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'Conversation contract project','conversation-contract');
INSERT INTO solvan.environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','Conversation contract environment',
        'europe-west1','INTERNAL');

INSERT INTO solvan.github_repositories
  (organization_id,project_id,environment_id,id,installation_id,owner,name,
   default_branch,api_base_url,classification,credential_secret_ref,
   webhook_secret_ref,policy_hash,allowed_operations_json,status,
   last_probe_result,created_by_principal)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','ghr_0000000000000000000000000C',
        4242,'acme','platform','main','https://api.github.com','INTERNAL',
        'projects/p/secrets/s/versions/1','projects/p/secrets/w/versions/1',
        'sha256:' || repeat('a',64),
        '["POST_ISSUE_COMMENT"]'::jsonb,'ACTIVE','SUCCEEDED',
        'user:operator@example.com');

-- ---------------------------------------------------------------------------
-- Participants: admission is never implicit.
-- ---------------------------------------------------------------------------

-- Must pass: a parked sighting names no admitting operator, because nobody
-- admitted it. This is the row an unlisted mention produces.
INSERT INTO github_conversation_participants
  (organization_id,project_id,environment_id,id,repository_id,login,
   account_node_id,admission)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','ghm_0000000000000000000000000A',
        'ghr_0000000000000000000000000C','outsider','MDQ6VXNlcjE=','PARKED');

-- Must fail: an admitted participant with no admitting operator. Admission by
-- omission is the failure this table exists to prevent.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_participants
    (organization_id,project_id,environment_id,id,repository_id,login,
     account_node_id,admission)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','ghm_0000000000000000000000000B',
          'ghr_0000000000000000000000000C','ghost','MDQ6VXNlcjI=','ADMITTED');
$$,'23514','admitted participant requires a named admitting operator');

INSERT INTO github_conversation_participants
  (organization_id,project_id,environment_id,id,repository_id,login,
   account_node_id,admission,admitted_by_principal,admitted_at)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','ghm_0000000000000000000000000C',
        'ghr_0000000000000000000000000C','maintainer','MDQ6VXNlcjM=','ADMITTED',
        'user:operator@example.com',now());

-- Must fail: one login cannot hold two admissions on one repository, so a
-- second row cannot quietly override a dismissal.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_participants
    (organization_id,project_id,environment_id,id,repository_id,login,
     account_node_id,admission,admitted_by_principal,admitted_at)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','ghm_0000000000000000000000000D',
          'ghr_0000000000000000000000000C','maintainer','MDQ6VXNlcjM=','ADMITTED',
          'user:operator@example.com',now());
$$,'23505','a login holds one admission per repository');

-- ---------------------------------------------------------------------------
-- Threads.
-- ---------------------------------------------------------------------------

INSERT INTO github_conversation_threads
  (organization_id,project_id,environment_id,id,repository_id,thread_kind,
   external_number,html_url,title,state,observation_hash)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','ght_0000000000000000000000000A',
        'ghr_0000000000000000000000000C','ISSUE',7,
        'https://github.com/acme/platform/issues/7','Checkout latency','OPEN',
        'sha256:' || repeat('b',64));

INSERT INTO github_conversation_threads
  (organization_id,project_id,environment_id,id,repository_id,thread_kind,
   external_number,html_url,title,state,head_commit_sha,observation_hash)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','ght_0000000000000000000000000B',
        'ghr_0000000000000000000000000C','PULL_REQUEST',8,
        'https://github.com/acme/platform/pull/8','Bound the retry','OPEN',
        repeat('c',40),'sha256:' || repeat('d',64));

-- Must fail: an issue has no code, so it cannot carry a head commit.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_threads
    (organization_id,project_id,environment_id,id,repository_id,thread_kind,
     external_number,html_url,title,state,head_commit_sha,observation_hash)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','ght_0000000000000000000000000E',
          'ghr_0000000000000000000000000C','ISSUE',9,
          'https://github.com/acme/platform/issues/9','No code here','OPEN',
          repeat('e',40),'sha256:' || repeat('f',64));
$$,'23514','an issue thread carries no head commit');

-- ---------------------------------------------------------------------------
-- Actions: the publication gate.
-- ---------------------------------------------------------------------------

-- Must pass: a pending comment on an open thread.
INSERT INTO github_conversation_actions
  (organization_id,project_id,environment_id,id,repository_id,thread_id,
   operation,body,body_hash,template_registry_digest,template_ids_json,
   proposal_hash,expected_thread_state,state,expires_at)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','gha_0000000000000000000000000A',
        'ghr_0000000000000000000000000C','ght_0000000000000000000000000A',
        'POST_ISSUE_COMMENT','Latency rose after revision 41.',
        'sha256:' || repeat('1',64),'sha256:' || repeat('2',64),
        '["github.comment.observation"]'::jsonb,'sha256:' || repeat('3',64),
        'OPEN','APPROVAL_PENDING',now() + interval '1 hour');

-- Must fail: APPROVE is not in the review-event domain at all. A row cannot
-- carry it and be read back later as approving authority.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_actions
    (organization_id,project_id,environment_id,id,repository_id,thread_id,
     operation,review_event,body,body_hash,template_registry_digest,
     template_ids_json,proposal_hash,expected_head_commit_sha,state,expires_at)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','gha_0000000000000000000000000B',
          'ghr_0000000000000000000000000C','ght_0000000000000000000000000B',
          'SUBMIT_PULL_REQUEST_REVIEW','APPROVE','Looks good.',
          'sha256:' || repeat('4',64),'sha256:' || repeat('2',64),
          '["github.review.observation"]'::jsonb,'sha256:' || repeat('5',64),
          repeat('c',40),'APPROVAL_PENDING',now() + interval '1 hour');
$$,'23514','Solvan cannot record an approving review');

-- Must fail: a review must name the head commit it reviewed, so it never lands
-- on code the approver did not see.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_actions
    (organization_id,project_id,environment_id,id,repository_id,thread_id,
     operation,review_event,body,body_hash,template_registry_digest,
     template_ids_json,proposal_hash,state,expires_at)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','gha_0000000000000000000000000C',
          'ghr_0000000000000000000000000C','ght_0000000000000000000000000B',
          'SUBMIT_PULL_REQUEST_REVIEW','REQUEST_CHANGES','Bound this retry.',
          'sha256:' || repeat('6',64),'sha256:' || repeat('2',64),
          '["github.review.observation"]'::jsonb,'sha256:' || repeat('7',64),
          'APPROVAL_PENDING',now() + interval '1 hour');
$$,'23514','a review binds the exact head commit it reviewed');

-- Must fail: a comment with no thread has nowhere to land.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_actions
    (organization_id,project_id,environment_id,id,repository_id,operation,body,
     body_hash,template_registry_digest,template_ids_json,proposal_hash,state,
     expires_at)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','gha_0000000000000000000000000D',
          'ghr_0000000000000000000000000C','POST_ISSUE_COMMENT','Orphaned.',
          'sha256:' || repeat('8',64),'sha256:' || repeat('2',64),
          '["github.comment.observation"]'::jsonb,'sha256:' || repeat('9',64),
          'APPROVAL_PENDING',now() + interval '1 hour');
$$,'23514','a comment names the thread it lands in');

-- Must fail: an approved action with no decider. An approval that names nobody
-- is the same as no approval.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_actions
    (organization_id,project_id,environment_id,id,repository_id,thread_id,
     operation,body,body_hash,template_registry_digest,template_ids_json,
     proposal_hash,expected_thread_state,state,expires_at)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','gha_0000000000000000000000000E',
          'ghr_0000000000000000000000000C','ght_0000000000000000000000000A',
          'POST_ISSUE_COMMENT','Unapproved.','sha256:' || repeat('a',64),
          'sha256:' || repeat('2',64),'["github.comment.observation"]'::jsonb,
          'sha256:' || repeat('b',64),'OPEN','APPROVED',now() + interval '1 hour');
$$,'23514','an approved action names its decider');

-- Must fail: a published action with no external identity cannot be
-- reconciled, so it could be published a second time.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_actions
    (organization_id,project_id,environment_id,id,repository_id,thread_id,
     operation,body,body_hash,template_registry_digest,template_ids_json,
     proposal_hash,expected_thread_state,state,decision_digest,
     decided_by_principal,decided_at,expires_at)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','gha_0000000000000000000000000F',
          'ghr_0000000000000000000000000C','ght_0000000000000000000000000A',
          'POST_ISSUE_COMMENT','Published nowhere.','sha256:' || repeat('c',64),
          'sha256:' || repeat('2',64),'["github.comment.observation"]'::jsonb,
          'sha256:' || repeat('d',64),'OPEN','PUBLISHED',
          'sha256:' || repeat('e',64),'user:operator@example.com',now(),
          now() + interval '1 hour');
$$,'23514','a published action carries what it published');

-- Must fail: the same proposal cannot become two action rows, so one agent
-- proposal cannot be approved twice under different identifiers.
SELECT conversation_must_violate($$
  INSERT INTO github_conversation_actions
    (organization_id,project_id,environment_id,id,repository_id,thread_id,
     operation,body,body_hash,template_registry_digest,template_ids_json,
     proposal_hash,expected_thread_state,state,expires_at)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','gha_000000000000000000000000AA',
          'ghr_0000000000000000000000000C','ght_0000000000000000000000000A',
          'POST_ISSUE_COMMENT','Duplicate proposal.','sha256:' || repeat('f',64),
          'sha256:' || repeat('2',64),'["github.comment.observation"]'::jsonb,
          'sha256:' || repeat('3',64),'OPEN','APPROVAL_PENDING',
          now() + interval '1 hour');
$$,'23505','one proposal becomes at most one action');

-- Must pass: the new operation kinds are admissible on github_operations.
INSERT INTO solvan.github_operations
  (organization_id,project_id,environment_id,id,repository_id,operation,status,
   idempotency_key,request_hash,actor_principal)
VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
        'env_0000000000000000000000000C','gho_0000000000000000000000000A',
        'ghr_0000000000000000000000000C','POST_ISSUE_COMMENT','CREATED',
        'conversation-comment-1','sha256:' || repeat('1',64),
        'serviceAccount:coordinator@example.iam.gserviceaccount.com');

-- Must fail: an approving review is not an operation kind either.
SELECT conversation_must_violate($$
  INSERT INTO solvan.github_operations
    (organization_id,project_id,environment_id,id,repository_id,operation,status,
     idempotency_key,request_hash,actor_principal)
  VALUES ('org_0000000000000000000000000C','prj_0000000000000000000000000C',
          'env_0000000000000000000000000C','gho_0000000000000000000000000B',
          'ghr_0000000000000000000000000C','APPROVE_PULL_REQUEST','CREATED',
          'conversation-approve-1','sha256:' || repeat('2',64),
          'serviceAccount:coordinator@example.iam.gserviceaccount.com');
$$,'23514','approving a pull request is not an operation Solvan has');

ROLLBACK;
