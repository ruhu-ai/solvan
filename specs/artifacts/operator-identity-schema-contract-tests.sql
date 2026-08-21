-- Negative constraint oracle for the operator identity target DDL.
--
-- Each case names a way authority could be transferred, replayed, or granted to
-- something that is not a person, and asserts the database refuses it rather
-- than trusting an application to remember.

SET search_path TO solvan_identity, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION identity_must_fail(
  statement text,
  label text,
  expected_state text
)
RETURNS void AS $$
DECLARE
  actual_state text;
  actual_message text;
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS
      actual_state = RETURNED_SQLSTATE, actual_message = MESSAGE_TEXT;
    IF actual_state IS DISTINCT FROM expected_state THEN
      RAISE EXCEPTION 'wrong refusal for %: expected %, got % (%)',
        label, expected_state, actual_state, actual_message;
    END IF;
    RAISE NOTICE 'ok [%]: %', actual_state, label;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END;
$$ LANGUAGE plpgsql;

INSERT INTO solvan.organizations(id,display_name)
VALUES ('org_01J00000000000000000000000','Oracle') ON CONFLICT DO NOTHING;
INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id)
VALUES ('org_01J00000000000000000000000','prj_01J00000000000000000000000','Oracle','solvan-oracle')
ON CONFLICT DO NOTHING;
INSERT INTO solvan.environments(organization_id,project_id,id,display_name,region,classification)
VALUES ('org_01J00000000000000000000000','prj_01J00000000000000000000000',
        'env_01J00000000000000000000000','Oracle','europe-west1','INTERNAL')
ON CONFLICT DO NOTHING;

INSERT INTO actors(actor_id) VALUES
  ('act_01J00000000000000000000000'), ('act_01J00000000000000000000001');

INSERT INTO external_identities
  (provider,canonical_issuer,subject,actor_id,email)
VALUES ('GOOGLE','accounts.google.com','108000000000000000001',
        'act_01J00000000000000000000000','operator@example.com');

-- Email proves recent possession only after Google sign-in; it is never a
-- second identity issuer or a route that can create an actor/session.
SELECT identity_must_fail($$
  INSERT INTO external_identities(provider,canonical_issuer,subject,actor_id,email)
  VALUES ('EMAIL','solvan','operator@example.com',
          'act_01J00000000000000000000000','operator@example.com')
$$, 'Google is the only human identity issuer', '23514');

-- An issuer stored with a scheme or trailing slash is a second spelling of the
-- same issuer, and would make one person two actors holding separate roles.
SELECT identity_must_fail($$
  INSERT INTO external_identities(provider,canonical_issuer,subject,actor_id,email)
  VALUES ('GOOGLE','https://accounts.google.com','108000000000000000002',
          'act_01J00000000000000000000001','other@example.com')
$$, 'an issuer must be canonical before it is stored', '23514');

-- The same provider subject resolving to a second actor is an account takeover
-- expressed as an insert.
SELECT identity_must_fail($$
  INSERT INTO external_identities(provider,canonical_issuer,subject,actor_id,email)
  VALUES ('GOOGLE','accounts.google.com','108000000000000000001',
          'act_01J00000000000000000000001','attacker@example.com')
$$, 'one provider subject resolves to one actor', '23505');

-- Membership names an actor. An email cannot hold a role, so a rename or a
-- reassigned address transfers nothing.
SELECT identity_must_fail($$
  INSERT INTO actor_memberships(organization_id,project_id,environment_id,
    actor_id,role,granted_by_actor_id)
  VALUES ('org_01J00000000000000000000000','prj_01J00000000000000000000000',
          'env_01J00000000000000000000000','operator@example.com','APPROVER',
          'act_01J00000000000000000000000')
$$, 'a role is granted to an actor, never to an email', '23503');

SELECT identity_must_fail($$
  INSERT INTO actor_memberships(organization_id,project_id,environment_id,
    actor_id,role,granted_by_actor_id)
  VALUES ('org_01J00000000000000000000000','prj_01J00000000000000000000000',
          'env_01J00000000000000000000000','act_01J00000000000000000000000','ROOT',
          'act_01J00000000000000000000000')
$$, 'roles are a closed set', '23514');

-- An invitation without an expiry is claimable forever, including by whoever
-- next holds a reassigned address.
SELECT identity_must_fail($$
  INSERT INTO actor_invitations(id,organization_id,project_id,environment_id,email,
    admitted_domain,role,invited_by_actor_id,expires_at)
  VALUES ('inv_01J00000000000000000000000','org_01J00000000000000000000000',
          'prj_01J00000000000000000000000','env_01J00000000000000000000000',
          'newcomer@example.com','example.com','OPERATOR',
          'act_01J00000000000000000000000',NULL)
$$, 'an invitation carries an expiry', '23502');

INSERT INTO actor_invitations(id,organization_id,project_id,environment_id,email,
  admitted_domain,role,invited_by_actor_id,expires_at)
VALUES ('inv_01J00000000000000000000000','org_01J00000000000000000000000',
        'prj_01J00000000000000000000000','env_01J00000000000000000000000',
        'newcomer@example.com','example.com','OPERATOR',
        'act_01J00000000000000000000000', now() + interval '7 days');

SELECT identity_must_fail($$
  UPDATE actor_invitations SET consumed_at = now()
   WHERE id = 'inv_01J00000000000000000000000'
$$, 'consumption records both when and by whom', '23514');

-- Two open invitations for the same grant would let one be redeemed twice over.
SELECT identity_must_fail($$
  INSERT INTO actor_invitations(id,organization_id,project_id,environment_id,email,
    admitted_domain,role,invited_by_actor_id,expires_at)
  VALUES ('inv_01J00000000000000000000001','org_01J00000000000000000000000',
          'prj_01J00000000000000000000000','env_01J00000000000000000000000',
          'newcomer@example.com','example.com','OPERATOR',
          'act_01J00000000000000000000000', now() + interval '7 days')
$$, 'one open invitation exists per exact grant', '23505');

INSERT INTO authentication_events(id,actor_id,canonical_issuer,subject,audience,
  authenticated_at)
VALUES ('aev_01J00000000000000000000000','act_01J00000000000000000000000',
        'accounts.google.com','108000000000000000001',
        '111111111111-abc.apps.googleusercontent.com', now());

-- An idle window wider than the absolute ceiling is a ceiling that caps nothing.
SELECT identity_must_fail($$
  INSERT INTO operator_sessions(id,actor_id,credential_hash,authentication_event_id,
    idle_expires_at,absolute_expires_at)
  VALUES ('ses_01J00000000000000000000000','act_01J00000000000000000000000',
          'sha256:' || repeat('a',64), 'aev_01J00000000000000000000000',
          now() + interval '30 days', now() + interval '1 hour')
$$, 'an absolute ceiling bounds the idle window', '23514');

INSERT INTO operator_sessions(id,actor_id,credential_hash,authentication_event_id,
  idle_expires_at,absolute_expires_at)
VALUES ('ses_01J00000000000000000000000','act_01J00000000000000000000000',
        'sha256:' || repeat('a',64), 'aev_01J00000000000000000000000',
        now() + interval '30 minutes', now() + interval '8 hours');

-- A session credential stored in the clear would make reading this table
-- equivalent to holding every operator's session.
SELECT identity_must_fail($$
  INSERT INTO operator_sessions(id,actor_id,credential_hash,authentication_event_id,
    idle_expires_at,absolute_expires_at)
  VALUES ('ses_01J00000000000000000000001','act_01J00000000000000000000000',
          'a-raw-session-token', 'aev_01J00000000000000000000000',
          now() + interval '30 minutes', now() + interval '8 hours')
$$, 'a session stores a hash, never a credential', '23514');

INSERT INTO step_up_transactions(id,requesting_session_id,actor_id,operation,
  organization_id,project_id,environment_id,material_digest,expires_at)
VALUES ('stu_01J00000000000000000000000','ses_01J00000000000000000000000',
        'act_01J00000000000000000000000','estate.connect',
        'org_01J00000000000000000000000','prj_01J00000000000000000000000',
        'env_01J00000000000000000000000','sha256:' || repeat('b',64),
        now() + interval '5 minutes');

INSERT INTO operator_sessions(id,actor_id,credential_hash,authentication_event_id,
  idle_expires_at,absolute_expires_at,rotated_from_session_id)
VALUES ('ses_01J00000000000000000000002','act_01J00000000000000000000000',
        'sha256:' || repeat('e',64), 'aev_01J00000000000000000000000',
        now() + interval '30 minutes', now() + interval '8 hours',
        'ses_01J00000000000000000000000');

INSERT INTO operator_step_up_codes(id,step_up_transaction_id,requesting_session_id,
  actor_id,organization_id,project_id,environment_id,email,verifier_hmac,
  delivery_status,delivery_receipt,delivered_at,expires_at,status,consumed_at)
VALUES ('sup_01J00000000000000000000000','stu_01J00000000000000000000000',
        'ses_01J00000000000000000000000','act_01J00000000000000000000000',
        'org_01J00000000000000000000000','prj_01J00000000000000000000000',
        'env_01J00000000000000000000000','operator@example.com',
        'hmac-sha256:' || repeat('d',64),'DELIVERED','test:delivery',now(),
        now() + interval '5 minutes','CONSUMED',now());

SELECT identity_must_fail($$
  UPDATE operator_step_up_codes SET verifier_hmac = 'sha256:' || repeat('d',64)
   WHERE id = 'sup_01J00000000000000000000000'
$$, 'a numeric code cannot be protected by an offline-brute-forceable digest', '23514');

INSERT INTO step_up_presence_events(id,step_up_transaction_id,code_id,actor_id,
  requesting_session_id,resulting_session_id,method)
VALUES ('pev_01J00000000000000000000000','stu_01J00000000000000000000000',
        'sup_01J00000000000000000000000','act_01J00000000000000000000000',
        'ses_01J00000000000000000000000','ses_01J00000000000000000000002',
        'EMAIL_OTP');

INSERT INTO action_challenges(id,step_up_transaction_id,session_id,actor_id,
  presence_event_id,operation,organization_id,project_id,environment_id,
  material_digest,csrf_token_hash,expires_at)
VALUES ('chl_01J00000000000000000000000','stu_01J00000000000000000000000',
        'ses_01J00000000000000000000002','act_01J00000000000000000000000',
        'pev_01J00000000000000000000000','estate.connect',
        'org_01J00000000000000000000000','prj_01J00000000000000000000000',
        'env_01J00000000000000000000000','sha256:' || repeat('b',64),
        'sha256:' || repeat('c',64), now() + interval '5 minutes');

-- One step-up authorizes one decision. A second challenge against the same
-- frozen material is the replay this design exists to refuse.
SELECT identity_must_fail($$
  INSERT INTO action_challenges(id,step_up_transaction_id,session_id,actor_id,
    presence_event_id,operation,organization_id,project_id,environment_id,
    material_digest,csrf_token_hash,expires_at)
  VALUES ('chl_01J00000000000000000000001','stu_01J00000000000000000000000',
          'ses_01J00000000000000000000002','act_01J00000000000000000000000',
          'pev_01J00000000000000000000000','estate.connect',
          'org_01J00000000000000000000000','prj_01J00000000000000000000000',
          'env_01J00000000000000000000000','sha256:' || repeat('b',64),
          'sha256:' || repeat('c',64), now() + interval '5 minutes')
$$, 'one step-up yields one challenge', '23505');

-- Consumed without a timestamp records that authority was spent and not when.
SELECT identity_must_fail($$
  UPDATE action_challenges SET status = 'CONSUMED'
   WHERE id = 'chl_01J00000000000000000000000'
$$, 'a consumed challenge records when', '23514');

SELECT identity_must_fail($$
  UPDATE action_challenges SET status = 'TERMINAL'
   WHERE id = 'chl_01J00000000000000000000000'
$$, 'a terminal challenge records why', '23514');

SELECT identity_must_fail($$
  UPDATE action_challenges SET status = 'TERMINAL', terminal_reason = 'BECAUSE'
   WHERE id = 'chl_01J00000000000000000000000'
$$, 'terminal reasons are a closed set', '23514');

ROLLBACK;
