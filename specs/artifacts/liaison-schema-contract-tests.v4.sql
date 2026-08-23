-- Oracle: a steer-grant nonce spends exactly once.

BEGIN;

INSERT INTO solvan_liaison.liaison_consumed_steer_grants
  (organization_id, project_id, environment_id, nonce, grant_digest,
   parked_request_id, confirming_principal)
VALUES
  ('org_00000000000000000000000000', 'prj_00000000000000000000000000',
   'env_00000000000000000000000000', 'non_0000000000000000000000000001',
   'sha256:' || repeat('0', 64), 'prk_00000000000000000000000000',
   'user:approver@example.test');

DO $must_fail$
BEGIN
  BEGIN
    INSERT INTO solvan_liaison.liaison_consumed_steer_grants
      (organization_id, project_id, environment_id, nonce, grant_digest,
       parked_request_id, confirming_principal)
    VALUES
      ('org_00000000000000000000000000', 'prj_00000000000000000000000000',
       'env_00000000000000000000000000', 'non_0000000000000000000000000001',
       'sha256:' || repeat('1', 64), 'prk_00000000000000000000000001',
       'user:other@example.test');
    RAISE EXCEPTION 'a consumed steer nonce was accepted a second time';
  EXCEPTION WHEN unique_violation THEN
    RAISE NOTICE 'ok: a second consumption of the same nonce is refused';
  END;

  -- The same nonce in another environment is a different fact and must insert.
  INSERT INTO solvan_liaison.liaison_consumed_steer_grants
    (organization_id, project_id, environment_id, nonce, grant_digest,
     parked_request_id, confirming_principal)
  VALUES
    ('org_00000000000000000000000000', 'prj_00000000000000000000000000',
     'env_00000000000000000000000001', 'non_0000000000000000000000000001',
     'sha256:' || repeat('2', 64), 'prk_00000000000000000000000002',
     'user:approver@example.test');
  RAISE NOTICE 'ok: the same nonce in another environment is a distinct fact';
END
$must_fail$;

ROLLBACK;
