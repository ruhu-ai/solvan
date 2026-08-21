-- Specification 24 §9 oracles: an install intent cannot be replayed, cannot
-- outlive itself, and cannot claim to have completed without saying what it
-- produced. These hold in the database because the redirect that consumes an
-- intent arrives as an ordinary browser GET, where the application's own
-- checks are the only other thing standing in the way.
SET search_path TO solvan_conversation, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION intent_must_violate(
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
VALUES ('org_0000000000000000000000000J','Install intent contract org');
INSERT INTO solvan.projects (organization_id,id,display_name,gcp_project_id)
VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
        'Install intent contract project','install-intent-contract');
INSERT INTO solvan.environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
        'env_0000000000000000000000000J','Install intent contract environment',
        'europe-west1','INTERNAL');

-- Must pass: one pending intent, minted with an expiry ahead of its creation.
INSERT INTO github_installation_intents
  (organization_id,project_id,environment_id,id,state_hash,classification,
   actor_principal,challenge_id,expires_at)
VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
        'env_0000000000000000000000000J','ghi_0000000000000000000000000A',
        'sha256:' || repeat('1',64),'INTERNAL','user:operator@example.com',
        'ach_0000000000000000000000000A',now() + interval '10 minutes');

-- Must fail: the same state cannot mint a second intent, so a replayed
-- redirect cannot produce a second set of bindings.
SELECT intent_must_violate($$
  INSERT INTO github_installation_intents
    (organization_id,project_id,environment_id,id,state_hash,classification,
     actor_principal,challenge_id,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
          'env_0000000000000000000000000J','ghi_0000000000000000000000000B',
          'sha256:' || repeat('1',64),'INTERNAL','user:operator@example.com',
          'ach_0000000000000000000000000B',now() + interval '10 minutes');
$$,'23505','one state completes one installation');

-- Must fail: an intent that expires before it exists is not a lifetime.
SELECT intent_must_violate($$
  INSERT INTO github_installation_intents
    (organization_id,project_id,environment_id,id,state_hash,classification,
     actor_principal,challenge_id,created_at,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
          'env_0000000000000000000000000J','ghi_0000000000000000000000000C',
          'sha256:' || repeat('2',64),'INTERNAL','user:operator@example.com',
          'ach_0000000000000000000000000C',now(),now() - interval '1 minute');
$$,'23514','an intent expires after it is created');

-- Must fail: RESTRICTED is not offered for a bulk install, because it is a
-- judgement about one repository rather than about everything an installation
-- happens to reach.
SELECT intent_must_violate($$
  INSERT INTO github_installation_intents
    (organization_id,project_id,environment_id,id,state_hash,classification,
     actor_principal,challenge_id,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
          'env_0000000000000000000000000J','ghi_0000000000000000000000000D',
          'sha256:' || repeat('3',64),'RESTRICTED','user:operator@example.com',
          'ach_0000000000000000000000000D',now() + interval '10 minutes');
$$,'23514','a bulk install is not classified RESTRICTED');

-- Must fail: a consumed intent that names neither the installation it
-- completed nor what it bound is a completion nobody can audit.
SELECT intent_must_violate($$
  INSERT INTO github_installation_intents
    (organization_id,project_id,environment_id,id,state_hash,classification,
     actor_principal,challenge_id,status,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
          'env_0000000000000000000000000J','ghi_0000000000000000000000000E',
          'sha256:' || repeat('4',64),'INTERNAL','user:operator@example.com',
          'ach_0000000000000000000000000E','CONSUMED',now() + interval '10 minutes');
$$,'23514','a consumed intent names what it produced');

-- Must fail: a refused intent with no reason.
SELECT intent_must_violate($$
  INSERT INTO github_installation_intents
    (organization_id,project_id,environment_id,id,state_hash,classification,
     actor_principal,challenge_id,status,expires_at)
  VALUES ('org_0000000000000000000000000J','prj_0000000000000000000000000J',
          'env_0000000000000000000000000J','ghi_0000000000000000000000000F',
          'sha256:' || repeat('5',64),'INTERNAL','user:operator@example.com',
          'ach_0000000000000000000000000F','REFUSED',now() + interval '10 minutes');
$$,'23514','a refused intent names why');

-- Must pass: a completed intent records the installation and the count.
UPDATE github_installation_intents
   SET status='CONSUMED', installation_id=42991, bound_count=3, consumed_at=now()
 WHERE id='ghi_0000000000000000000000000A';

ROLLBACK;
