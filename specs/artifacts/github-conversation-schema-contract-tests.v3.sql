-- Specification 24 §9 oracles for the claim state: an intent is spent when it
-- is presented, a pending intent has no claim time, and a spent one does.
-- These matter in the database because the redirect that presents an intent is
-- an ordinary unauthenticated browser GET, and because the window this state
-- closes is the one between claiming and completing — a window the application
-- spends making two network calls to GitHub.
SET search_path TO solvan_conversation, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION claim_must_violate(
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
VALUES ('org_0000000000000000000000000K','Claim state contract org');
INSERT INTO solvan.projects (organization_id,id,display_name,gcp_project_id)
VALUES ('org_0000000000000000000000000K','prj_0000000000000000000000000K',
        'Claim state contract project','claim-state-contract');
INSERT INTO solvan.environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_0000000000000000000000000K','prj_0000000000000000000000000K',
        'env_0000000000000000000000000K','Claim state contract environment',
        'europe-west1','INTERNAL');

INSERT INTO github_installation_intents
  (organization_id,project_id,environment_id,id,state_hash,classification,
   actor_principal,challenge_id,expires_at)
VALUES ('org_0000000000000000000000000K','prj_0000000000000000000000000K',
        'env_0000000000000000000000000K','ghi_0000000000000000000000000A',
        'sha256:' || repeat('a',64),'INTERNAL','user:operator@example.com',
        'ach_0000000000000000000000000A',now() + interval '10 minutes');

-- Must fail: a pending intent nobody has presented cannot name when it was.
SELECT claim_must_violate($$
  UPDATE github_installation_intents SET claimed_at=now()
   WHERE id='ghi_0000000000000000000000000A';
$$,'23514','a pending intent has no claim time');

-- Must fail: claiming without recording when it was claimed loses the only
-- evidence that the link was presented rather than merely minted.
SELECT claim_must_violate($$
  UPDATE github_installation_intents SET status='CLAIMED'
   WHERE id='ghi_0000000000000000000000000A';
$$,'23514','a claimed intent records when it was claimed');

-- Must pass: the real transition an incoming redirect performs.
UPDATE github_installation_intents SET status='CLAIMED', claimed_at=now()
 WHERE id='ghi_0000000000000000000000000A' AND status='PENDING';

-- Must fail: completing still has to say what it produced (v2's rule, intact).
SELECT claim_must_violate($$
  UPDATE github_installation_intents SET status='CONSUMED'
   WHERE id='ghi_0000000000000000000000000A';
$$,'23514','a consumed intent still names what it produced');

-- Must pass: completion from CLAIMED, carrying its claim time forward.
UPDATE github_installation_intents
   SET status='CONSUMED', installation_id=42991, bound_count=3, consumed_at=now()
 WHERE id='ghi_0000000000000000000000000A' AND status='CLAIMED';

DO $$
BEGIN
  IF (SELECT claimed_at FROM github_installation_intents
       WHERE id='ghi_0000000000000000000000000A') IS NULL THEN
    RAISE EXCEPTION 'a completed intent lost the time it was claimed';
  END IF;
END $$;

-- Must pass: an intent that expired before anybody presented it is refused
-- with no claim time at all, which is why REFUSED is outside the rule above.
INSERT INTO github_installation_intents
  (organization_id,project_id,environment_id,id,state_hash,classification,
   actor_principal,challenge_id,status,error_class,expires_at)
VALUES ('org_0000000000000000000000000K','prj_0000000000000000000000000K',
        'env_0000000000000000000000000K','ghi_0000000000000000000000000B',
        'sha256:' || repeat('b',64),'INTERNAL','user:operator@example.com',
        'ach_0000000000000000000000000B','REFUSED','INTENT_EXPIRED',
        now() + interval '10 minutes');

ROLLBACK;
