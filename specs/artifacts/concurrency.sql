-- Reference SQL for Solvan claims, leases, CAS, reservations, outbox, and reapers.
-- Bind all :parameters; never interpolate values. Every Agent operation is scoped.

-- Quarantine poison inbox work before claiming. An event that exhausted its
-- bounded claim budget without completing is failed durably and visibly; it can
-- never crash-loop a coordinator again. Recovery is an explicit re-ingest.
UPDATE solvan.inbox_events
SET processing_state = 'FAILED',
    processed_at = now(),
    error_class = 'POISON_EVENT_QUARANTINED',
    claim_owner = NULL,
    claim_token = NULL,
    claim_expires_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND attempts >= :max_attempts
  AND (
    processing_state = 'PENDING'
    OR (processing_state = 'PROCESSING' AND claim_expires_at < now())
  )
RETURNING id;

-- Claim or reclaim inbox work. The token fences completion and the expiry makes a
-- coordinator crash recoverable without relying on process-local state. Each
-- claim consumes one unit of the bounded attempt budget.
WITH candidate AS (
  SELECT id
  FROM solvan.inbox_events
  WHERE organization_id = :organization_id
    AND project_id = :project_id
    AND environment_id = :environment_id
    AND attempts < :max_attempts
    AND (
      processing_state = 'PENDING'
      OR (processing_state = 'PROCESSING' AND claim_expires_at < now())
    )
  ORDER BY received_at
  FOR UPDATE SKIP LOCKED
  LIMIT :batch_size
)
UPDATE solvan.inbox_events i
SET processing_state = 'PROCESSING',
    claimed_at = now(),
    claim_owner = :claim_owner,
    claim_token = :new_claim_token,
    claim_expires_at = now() + (:claim_ttl_ms * interval '1 millisecond'),
    attempts = i.attempts + 1
FROM candidate
WHERE i.organization_id = :organization_id
  AND i.project_id = :project_id
  AND i.environment_id = :environment_id
  AND i.id = candidate.id
RETURNING i.*;

-- Renew only the current inbox claim holder.
UPDATE solvan.inbox_events
SET claim_expires_at = now() + (:claim_ttl_ms * interval '1 millisecond')
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :inbox_event_id
  AND processing_state = 'PROCESSING'
  AND claim_owner = :claim_owner
  AND claim_token = :claim_token
  AND claim_expires_at >= now()
RETURNING claim_expires_at;

-- Complete only the claim holder's inbox work.
UPDATE solvan.inbox_events
SET processing_state = :terminal_processing_state,
    processed_at = now(),
    result_ref = :result_ref,
    error_class = :error_class,
    claim_owner = NULL,
    claim_token = NULL,
    claim_expires_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :inbox_event_id
  AND processing_state = 'PROCESSING'
  AND claim_owner = :claim_owner
  AND claim_token = :claim_token
  AND claim_expires_at >= now()
  AND :terminal_processing_state IN ('COMPLETED','FAILED')
RETURNING processing_state, processed_at;

-- Acquire/reclaim an incident lease. lease_token fences renewal and release only.
UPDATE solvan.incidents
SET lease_owner = :lease_owner,
    lease_token = :new_lease_token,
    lease_expires_at = now() + interval '60 seconds'
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :incident_id
  AND (lease_owner IS NULL OR lease_expires_at < now())
RETURNING workflow_version, lease_token, lease_expires_at;

-- Renew an incident lease. A stale token cannot renew another claimant's lease.
UPDATE solvan.incidents
SET lease_expires_at = now() + interval '60 seconds'
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :incident_id
  AND lease_owner = :lease_owner
  AND lease_token = :lease_token
  AND lease_expires_at >= now()
RETURNING lease_expires_at;

-- Release only the current incident lease holder.
UPDATE solvan.incidents
SET lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :incident_id
  AND lease_owner = :lease_owner
  AND lease_token = :lease_token
RETURNING workflow_version;

-- Reliability Cases use the same fencing protocol as incidents.
UPDATE solvan.reliability_cases
SET lease_owner = :lease_owner,
    lease_token = :new_lease_token,
    lease_expires_at = now() + interval '60 seconds'
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :reliability_case_id
  AND (lease_owner IS NULL OR lease_expires_at < now())
RETURNING workflow_version, lease_token, lease_expires_at;

UPDATE solvan.reliability_cases
SET lease_expires_at = now() + interval '60 seconds'
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :reliability_case_id
  AND lease_owner = :lease_owner
  AND lease_token = :lease_token
  AND lease_expires_at >= now()
RETURNING lease_expires_at;

UPDATE solvan.reliability_cases
SET lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :reliability_case_id
  AND lease_owner = :lease_owner
  AND lease_token = :lease_token
RETURNING workflow_version;

-- Commit incident state with workflow-version CAS regardless of local compute.
UPDATE solvan.incidents
SET state = :to_state,
    workflow_version = workflow_version + 1,
    last_progress_at = now(),
    updated_at = now()
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :incident_id
  AND state = :from_state
  AND workflow_version = :expected_workflow_version
  AND lease_owner = :lease_owner
  AND lease_token = :lease_token
  AND lease_expires_at >= now()
RETURNING workflow_version;

-- Commit Reliability Case state with the same workflow-version CAS.
UPDATE solvan.reliability_cases
SET state = :to_state,
    workflow_version = workflow_version + 1,
    last_progress_at = now(),
    updated_at = now()
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :reliability_case_id
  AND state = :from_state
  AND workflow_version = :expected_workflow_version
  AND lease_owner = :lease_owner
  AND lease_token = :lease_token
  AND lease_expires_at >= now()
RETURNING workflow_version;

-- Park a due case wake-up that exhausted its bounded claim budget. This runs
-- immediately before every claim so a step whose handler dies on the same
-- permanent fault can never be re-served forever.
UPDATE solvan.scheduled_wakeups
SET status = 'QUARANTINED',
    quarantined_at = now(),
    claim_owner = NULL,
    claim_token = NULL,
    claim_expires_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND wake_at <= now()
  AND attempts >= :max_attempts
  AND (status = 'PENDING' OR (status = 'CLAIMED' AND claim_expires_at < now()))
RETURNING id;

-- Claim or reclaim a due case wake-up inside its bounded budget.
WITH candidate AS (
  SELECT id
  FROM solvan.scheduled_wakeups
  WHERE organization_id = :organization_id
    AND project_id = :project_id
    AND environment_id = :environment_id
    AND wake_at <= now()
    AND attempts < :max_attempts
    AND (status = 'PENDING' OR (status = 'CLAIMED' AND claim_expires_at < now()))
  ORDER BY wake_at
  FOR UPDATE SKIP LOCKED
  LIMIT :batch_size
)
UPDATE solvan.scheduled_wakeups w
SET status = 'CLAIMED',
    claimed_at = now(),
    claim_owner = :claim_owner,
    claim_token = :new_claim_token,
    attempts = w.attempts + 1,
    claim_expires_at = now() + (:claim_ttl_ms * interval '1 millisecond')
FROM candidate
WHERE w.organization_id = :organization_id
  AND w.project_id = :project_id
  AND w.environment_id = :environment_id
  AND w.id = candidate.id
RETURNING w.*;

-- Return one live wake-up claim without completing its step. A refund is only
-- for reasons that say nothing about the step itself, so contention never
-- walks a healthy case toward quarantine.
UPDATE solvan.scheduled_wakeups w
SET status = 'PENDING',
    claimed_at = NULL,
    claim_owner = NULL,
    claim_token = NULL,
    claim_expires_at = NULL,
    attempts = CASE WHEN :refund_attempt THEN greatest(w.attempts - 1, 0)
               ELSE w.attempts END
WHERE w.organization_id = :organization_id
  AND w.project_id = :project_id
  AND w.environment_id = :environment_id
  AND w.id = :wakeup_id
  AND w.status = 'CLAIMED'
  AND w.claim_owner = :claim_owner
  AND w.claim_token = :claim_token
  AND w.claim_expires_at >= now()
RETURNING w.id;

UPDATE solvan.scheduled_wakeups
SET claim_expires_at = now() + (:claim_ttl_ms * interval '1 millisecond')
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :wakeup_id
  AND status = 'CLAIMED'
  AND claim_owner = :claim_owner
  AND claim_token = :claim_token
  AND claim_expires_at >= now()
RETURNING claim_expires_at;

UPDATE solvan.scheduled_wakeups
SET status = 'COMPLETED',
    completed_at = now(),
    outbox_event_id = :outbox_event_id,
    claim_owner = NULL,
    claim_token = NULL,
    claim_expires_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :wakeup_id
  AND status = 'CLAIMED'
  AND claim_owner = :claim_owner
  AND claim_token = :claim_token
  AND claim_expires_at >= now()
RETURNING completed_at, outbox_event_id;

-- Reserve a target inside a transaction after locking its epoch row.
SELECT epoch, last_observed_version
FROM solvan.target_epochs
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND target_key = :target_key
FOR UPDATE;

INSERT INTO solvan.target_reservations (
  organization_id, project_id, environment_id, id, target_key,
  reservation_epoch, expected_target_epoch, action_id, owner_identity,
  lease_token, expires_at
) VALUES (
  :organization_id, :project_id, :environment_id, :reservation_id, :target_key,
  :expected_target_epoch + 1, :expected_target_epoch, :action_id,
  :owner_identity, :lease_token,
  now() + (:reservation_ttl_ms * interval '1 millisecond')
);

UPDATE solvan.target_epochs
SET epoch = epoch + 1, updated_at = now()
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND target_key = :target_key
  AND epoch = :expected_target_epoch
  AND last_observed_version = :expected_target_version
RETURNING epoch;

-- Heartbeat only the live reservation token, before and during connector work.
UPDATE solvan.target_reservations
SET expires_at = now() + (:reservation_ttl_ms * interval '1 millisecond')
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :reservation_id
  AND owner_identity = :owner_identity
  AND lease_token = :lease_token
  AND released_at IS NULL
  AND expires_at >= now()
RETURNING expires_at;

-- Release only the reservation holder's token.
UPDATE solvan.target_reservations
SET released_at = now(), release_reason = :release_reason
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :reservation_id
  AND lease_token = :lease_token
  AND released_at IS NULL
RETURNING released_at;

-- Quarantine poison outbox rows before claiming. A row that exhausted its
-- bounded publish budget without publishing is parked durably and visibly and
-- is never claimed again. Recovery is an explicit superseding operator action.
UPDATE solvan.outbox_events
SET quarantined_at = now(),
    claim_owner = NULL,
    claim_token = NULL,
    claim_expires_at = NULL,
    claimed_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND published_at IS NULL
  AND quarantined_at IS NULL
  AND publish_attempts >= :max_attempts
  AND (claim_token IS NULL OR claim_expires_at < now())
RETURNING id;

-- Claim unpublished outbox rows with a renewable token. Each claim consumes one
-- unit of the bounded publish budget; claimed_until prevents hot re-claim.
WITH candidate AS (
  SELECT id
  FROM solvan.outbox_events
  WHERE organization_id = :organization_id
    AND project_id = :project_id
    AND environment_id = :environment_id
    AND published_at IS NULL
    AND quarantined_at IS NULL
    AND publish_attempts < :max_attempts
    AND (claim_token IS NULL OR claim_expires_at < now())
  ORDER BY created_at
  FOR UPDATE SKIP LOCKED
  LIMIT :batch_size
)
UPDATE solvan.outbox_events o
SET claimed_at = now(),
    claim_owner = :claim_owner,
    claim_token = :new_claim_token,
    claim_expires_at = now() + (:claim_ttl_ms * interval '1 millisecond'),
    publish_attempts = publish_attempts + 1
FROM candidate
WHERE o.organization_id = :organization_id
  AND o.project_id = :project_id
  AND o.environment_id = :environment_id
  AND o.id = candidate.id
RETURNING o.*;

-- Mark publication only with the live claim token. A timeout leaves the row for
-- at-least-once republish after expiry; consumers deduplicate the stable event ID.
UPDATE solvan.outbox_events
SET published_at = now(),
    claim_owner = NULL,
    claim_token = NULL,
    claim_expires_at = NULL
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :outbox_event_id
  AND published_at IS NULL
  AND claim_owner = :claim_owner
  AND claim_token = :claim_token
  AND claim_expires_at >= now()
RETURNING published_at;

-- Reaper candidates. Expiry creates reconciliation work but never releases a
-- mutation reservation. Release is legal only after reconciliation proves a
-- conclusive effect or no-effect result; the reaper never authorizes mutation.
SELECT r.*
FROM solvan.target_reservations r
LEFT JOIN solvan.execution_receipts e
  ON e.organization_id = r.organization_id
 AND e.project_id = r.project_id
 AND e.environment_id = r.environment_id
 AND e.action_id = r.action_id
WHERE r.organization_id = :organization_id
  AND r.project_id = :project_id
  AND r.environment_id = :environment_id
  AND r.released_at IS NULL
  AND r.expires_at < now()
  AND (e.id IS NULL OR e.result = 'AMBIGUOUS')
FOR UPDATE OF r SKIP LOCKED;

-- List only deadline-expired prepared Runtime requests after the receipt grace.
-- Provider inspection may race, but it is read-only; the following CAS owns the
-- one durable recovery decision.
-- :agent_keys is derived from the registered agent catalog minus the kinds whose
-- CREATED attempts a different provider-fenced reaper owns, so a newly
-- registered agent kind is swept instead of being silently omitted.
SELECT id, invocation_id, incident_id, action_id, agent_key, agent_resource,
       workflow_version, runtime_operation_name, runtime_input_ref,
       runtime_output_ref, input_hash, deadline
FROM solvan.agent_runs
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND agent_key = ANY(:agent_keys)
  AND status = 'CREATED'
  AND deadline + (:receipt_grace_seconds * interval '1 second') <= now()
ORDER BY deadline, id
LIMIT :batch_size;

-- Preserve each non-null field returned by a partial provider acknowledgement.
-- An existing different value refuses instead of silently rewriting history.
UPDATE solvan.agent_runs
SET runtime_operation_name = COALESCE(runtime_operation_name, :operation_name),
    runtime_input_ref = COALESCE(runtime_input_ref, :runtime_input_ref),
    runtime_output_ref = COALESCE(runtime_output_ref, :runtime_output_ref)
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :run_id
  AND invocation_id = :invocation_id
  AND status = 'CREATED'
  AND workflow_version = :workflow_version
  AND input_hash = :input_hash
  AND (CAST(:operation_name AS text) IS NULL OR runtime_operation_name IS NULL
       OR runtime_operation_name = :operation_name)
  AND (CAST(:runtime_input_ref AS text) IS NULL OR runtime_input_ref IS NULL
       OR runtime_input_ref = :runtime_input_ref)
  AND (CAST(:runtime_output_ref AS text) IS NULL OR runtime_output_ref IS NULL
       OR runtime_output_ref = :runtime_output_ref)
RETURNING id;

-- Adopt only a known provider operation with a concrete output identity. The
-- normal poller then validates/cancels it under the original run fences.
UPDATE solvan.agent_runs
SET status = 'DISPATCHED',
    runtime_output_ref = COALESCE(runtime_output_ref, :runtime_output_ref),
    started_at = COALESCE(started_at, now())
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :run_id
  AND invocation_id = :invocation_id
  AND status = 'CREATED'
  AND workflow_version = :workflow_version
  AND input_hash = :input_hash
  AND runtime_operation_name = :operation_name
  AND :runtime_output_ref IS NOT NULL
  AND (runtime_output_ref IS NULL OR runtime_output_ref = :runtime_output_ref)
RETURNING id;

-- Otherwise terminalize exactly once. TIMED_OUT is Solvan's acceptance fence,
-- not a statement that the provider operation is absent or terminal.
UPDATE solvan.agent_runs
SET status = 'TIMED_OUT',
    error_class = :dispatch_error_class,
    completed_at = now()
WHERE organization_id = :organization_id
  AND project_id = :project_id
  AND environment_id = :environment_id
  AND id = :run_id
  AND invocation_id = :invocation_id
  AND status = 'CREATED'
  AND workflow_version = :workflow_version
  AND input_hash = :input_hash
RETURNING id;
