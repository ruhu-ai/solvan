-- Forward-only: admit GUIDANCE_REFERENCE to the durable turn record.
--
-- The intent registry gained GUIDANCE_REFERENCE (specification 18 §10) and the
-- router resolves it to the ASK route, but the turn table never learned the
-- value: neither the column domain nor the intent/route pairing admitted it.
-- Every `/skill` invocation in a conversation therefore violated a check on
-- insert, which is a 500 at the exact moment an operator reaches for governed
-- guidance. Both constraints change in one transaction, because a value that
-- is storable without its route pairing is a value that can acquire a route by
-- omission.
--
-- Each constraint is re-added under the name it already carried. The schema
-- oracle asserts specific auto-generated names, and a migration that renames a
-- neighbouring constraint by renumbering is a migration that breaks a test
-- about something it never touched.

BEGIN;

DO $intent_domain$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid='solvan_liaison.liaison_turns'::regclass
       AND conname='liaison_turns_conversation_intent_check'
  ) THEN
    RAISE EXCEPTION 'liaison turn conversation_intent domain constraint is missing';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid='solvan_liaison.liaison_turns'::regclass
       AND conname='liaison_turns_check1'
       AND pg_get_constraintdef(oid) LIKE '%LEDGER_QUERY%'
       AND pg_get_constraintdef(oid) LIKE '%ASK%'
  ) THEN
    RAISE EXCEPTION 'liaison turn ASK-route pairing is not where this migration expects it';
  END IF;
END
$intent_domain$;

ALTER TABLE solvan_liaison.liaison_turns
  DROP CONSTRAINT liaison_turns_conversation_intent_check,
  DROP CONSTRAINT liaison_turns_check1,
  ADD CONSTRAINT liaison_turns_conversation_intent_check CHECK (conversation_intent IN
    ('SOCIAL','HELP','LEDGER_QUERY','FOLLOW_UP','STEER_DRAFT',
     'ACTION_REFERENCE','GUIDANCE_REFERENCE','OUT_OF_SCOPE')),
  ADD CONSTRAINT liaison_turns_check1 CHECK
    ((conversation_intent IN ('LEDGER_QUERY','FOLLOW_UP','GUIDANCE_REFERENCE')) =
     (authority_route = 'ASK'));

COMMIT;
