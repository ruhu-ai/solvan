---
name: triage-queue-backlog
description: Run the standard triage flow for message backlog growth. Use when alerts mention Pub/Sub oldest-unacked age, subscription backlog, outbox depth, or when downstream consumers fall behind while producers look healthy.
license: Apache-2.0
metadata:
  solvan-owner: reliability
  solvan-provenance: first-party
---

Run these bounded reads **in order** through the registered evidence
profile. Record observations and citations only; do not approve, mutate, or
declare recovery.

## Checks

1. **Backlog and age** — read backlog size and oldest-unacked age for the
   affected subscription or outbox against the healthy baseline. Distinguish
   a plateau (stuck consumer) from steady growth (throughput mismatch).
2. **Publish versus ack rate** — read both rates over the window. Growth with
   flat ack rate implicates the consumer; growth with a publish spike
   implicates the producer.
3. **Consumer health** — read consumer error metrics and the approved
   handler-failure log signature. Repeated failures on the same message
   suggest a poison message rather than capacity.
4. **Quarantine state** — read the registered quarantine/parked-event
   counters; a rising quarantine count with a recovering backlog is the
   system working as designed, and worth citing as such.
5. **Capacity ceiling** — only if 1–4 are inconclusive, read consumer
   instance counts and concurrency against configured maxima.

## Output

- Lead with the mechanism (stuck consumer, poison message, throughput
  mismatch, capacity ceiling) and the rates that establish it, with refs.
- If the backlog is already draining, cite the drain rate and projected
  clearance as an observation, not a recovery verdict.
