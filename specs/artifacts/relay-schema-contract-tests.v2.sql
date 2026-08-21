-- Post-migration contract checks for the Relay runtime-proof verifier key.
SET search_path TO solvan_relay, solvan, public;
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema='solvan_relay'
       AND table_name='relay_runtime_proof_key_revisions'
       AND column_name='public_key_ref'
       AND is_nullable='YES'
  ) THEN
    RAISE EXCEPTION 'Relay runtime proof verification key reference is absent';
  END IF;
END $$;

COMMIT;
