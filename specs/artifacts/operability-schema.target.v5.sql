-- Permit an explicitly zero read window for local-artifact/compute profiles.
-- Zero is a denial ceiling, never an omitted or unlimited source-read window.

BEGIN;
ALTER TABLE solvan_operability.tool_profile_revisions
  DROP CONSTRAINT tool_profile_revisions_maximum_read_window_ms_check;
ALTER TABLE solvan_operability.tool_profile_revisions
  ADD CONSTRAINT tool_profile_revisions_maximum_read_window_ms_check
  CHECK (maximum_read_window_ms >= 0);
COMMIT;
