"""Scoped token-fenced claim statements."""

# Bounded claim budgets. Each claim consumes one unit; an event that exhausts
# its budget without completing is quarantined before the next claim and never
# claimed again. The outbox budget is deliberately larger than the inbox budget
# so a broker outage ends with delayed publication, not mass quarantine.
INBOX_CLAIM_ATTEMPT_BUDGET = 5
OUTBOX_PUBLISH_ATTEMPT_BUDGET = 25

QUARANTINE_INBOX = """
UPDATE solvan.inbox_events
SET processing_state = 'FAILED', processed_at = now(),
    error_class = 'POISON_EVENT_QUARANTINED',
    claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL
WHERE organization_id = %(organization_id)s
  AND project_id = %(project_id)s AND environment_id = %(environment_id)s
  AND attempts >= %(max_attempts)s
  AND (processing_state = 'PENDING'
    OR (processing_state = 'PROCESSING' AND claim_expires_at < now()))
RETURNING id
"""

CLAIM_INBOX = """
WITH candidate AS (
  SELECT id FROM solvan.inbox_events
  WHERE organization_id = %(organization_id)s
    AND project_id = %(project_id)s AND environment_id = %(environment_id)s
    AND attempts < %(max_attempts)s
    AND (processing_state = 'PENDING'
      OR (processing_state = 'PROCESSING' AND claim_expires_at < now()))
  ORDER BY received_at, id FOR UPDATE SKIP LOCKED LIMIT %(batch_size)s
)
UPDATE solvan.inbox_events AS i
SET processing_state = 'PROCESSING', claimed_at = now(),
    claim_owner = %(claim_owner)s, claim_token = %(claim_token)s,
    claim_expires_at = now() + (%(claim_ttl_ms)s * interval '1 millisecond'),
    attempts = i.attempts + 1
FROM candidate
WHERE i.organization_id = %(organization_id)s AND i.project_id = %(project_id)s
  AND i.environment_id = %(environment_id)s AND i.id = candidate.id
RETURNING i.id, i.event_type, i.claim_token, i.claim_expires_at
"""

COMPLETE_INBOX = """
UPDATE solvan.inbox_events
SET processing_state = %(terminal_state)s, processed_at = now(),
    result_ref = %(result_ref)s, error_class = %(error_class)s,
    claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL
WHERE organization_id = %(organization_id)s AND project_id = %(project_id)s
  AND environment_id = %(environment_id)s AND id = %(event_id)s
  AND processing_state = 'PROCESSING' AND claim_owner = %(claim_owner)s
  AND claim_token = %(claim_token)s AND claim_expires_at >= now()
RETURNING id
"""

# Return one live claim without consuming its bounded budget. Contention is not
# poison: an inbox event whose incident is momentarily leased by another
# coordinator must stay claimable forever, so the attempt it just spent is
# refunded. A refund can never raise the budget above its ceiling because it
# only ever undoes the increment made by the claim it is fenced to.
RELEASE_INBOX = """
UPDATE solvan.inbox_events AS i
SET processing_state = 'PENDING', claimed_at = NULL,
    claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL,
    attempts = CASE WHEN %(refund_attempt)s THEN greatest(i.attempts - 1, 0)
               ELSE i.attempts END
WHERE i.organization_id = %(organization_id)s AND i.project_id = %(project_id)s
  AND i.environment_id = %(environment_id)s AND i.id = %(event_id)s
  AND i.processing_state = 'PROCESSING' AND i.claim_owner = %(claim_owner)s
  AND i.claim_token = %(claim_token)s AND i.claim_expires_at >= now()
RETURNING i.id
"""

QUARANTINE_OUTBOX = """
UPDATE solvan.outbox_events
SET quarantined_at = now(), claimed_at = NULL,
    claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL
WHERE organization_id = %(organization_id)s
  AND project_id = %(project_id)s AND environment_id = %(environment_id)s
  AND published_at IS NULL AND quarantined_at IS NULL
  AND publish_attempts >= %(max_attempts)s
  AND (claim_token IS NULL OR claim_expires_at < now())
RETURNING id
"""

CLAIM_OUTBOX = """
WITH candidate AS (
  SELECT id FROM solvan.outbox_events
  WHERE organization_id = %(organization_id)s
    AND project_id = %(project_id)s AND environment_id = %(environment_id)s
    AND published_at IS NULL AND quarantined_at IS NULL
    AND publish_attempts < %(max_attempts)s
    AND (claim_token IS NULL OR claim_expires_at < now())
  ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT %(batch_size)s
)
UPDATE solvan.outbox_events AS o
SET claimed_at = now(), claim_owner = %(claim_owner)s, claim_token = %(claim_token)s,
    claim_expires_at = now() + (%(claim_ttl_ms)s * interval '1 millisecond'),
    publish_attempts = publish_attempts + 1
FROM candidate
WHERE o.organization_id = %(organization_id)s AND o.project_id = %(project_id)s
  AND o.environment_id = %(environment_id)s AND o.id = candidate.id
RETURNING o.id, o.event_type, o.claim_token, o.claim_expires_at
"""

COMPLETE_OUTBOX = """
UPDATE solvan.outbox_events
SET published_at = now(), claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL
WHERE organization_id = %(organization_id)s AND project_id = %(project_id)s
  AND environment_id = %(environment_id)s AND id = %(event_id)s
  AND published_at IS NULL AND claim_owner = %(claim_owner)s
  AND claim_token = %(claim_token)s AND claim_expires_at >= now()
RETURNING id
"""
