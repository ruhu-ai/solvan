-- Target migration: the Deployment Controller, not the Coordinator, creates a rollout.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

ALTER TABLE private_command_dispatches
  DROP CONSTRAINT private_command_dispatches_command_kind_check,
  ADD CONSTRAINT private_command_dispatches_command_kind_check CHECK (
    command_kind IN ('WORKSPACE_TOOL_INVOKE','EXPLORATORY_SANDBOX_RUN','ADJUDICATE_PATCH',
      'QUALIFY_CODE_CHANGE','CREATE_PR','SYNC_PR','MERGE_PR','START_GITHUB_LINK',
      'CONSUME_GITHUB_CALLBACK','REVOKE_GITHUB_LINK','OBSERVE_RELEASE_TARGET',
      'START_ROLLOUT','PREPARE_CANARY','PROMOTE_CANARY','ROLLBACK_RELEASE',
      'VERIFY_RELEASE_EFFECT'));

COMMIT;
