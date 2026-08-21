-- Target migration: delivery profiles bind exact release targets and observation commands.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM code_delivery_profiles) THEN
    RAISE EXCEPTION 'legacy code delivery profiles cannot be guessed into a release target';
  END IF;
END $$;

ALTER TABLE code_delivery_profiles
  ADD COLUMN release_target_profile_id text NOT NULL,
  ADD COLUMN release_target_profile_hash text NOT NULL
    CHECK (release_target_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT code_delivery_profile_release_target_fk
    FOREIGN KEY (organization_id,project_id,environment_id,release_target_profile_id)
    REFERENCES release_target_profiles(organization_id,project_id,environment_id,id);

ALTER TABLE private_command_dispatches
  DROP CONSTRAINT private_command_dispatches_command_kind_check,
  ADD CONSTRAINT private_command_dispatches_command_kind_check CHECK (
    command_kind IN ('WORKSPACE_TOOL_INVOKE','EXPLORATORY_SANDBOX_RUN','ADJUDICATE_PATCH',
      'QUALIFY_CODE_CHANGE','CREATE_PR','SYNC_PR','MERGE_PR','START_GITHUB_LINK',
      'CONSUME_GITHUB_CALLBACK','REVOKE_GITHUB_LINK','OBSERVE_RELEASE_TARGET',
      'PREPARE_CANARY','PROMOTE_CANARY','ROLLBACK_RELEASE','VERIFY_RELEASE_EFFECT'));

COMMIT;
