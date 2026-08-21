---
name: triage-connection-exhaustion
description: Run the standard triage flow for connection-pool exhaustion. Use when an incident's class is connection_exhaustion, when latency alerts mention database wait time, pool utilization, or connection acquisition timeouts, or when 5xx errors appear while the database itself looks healthy.
license: Apache-2.0
metadata:
  solvan-owner: reliability
  solvan-provenance: first-party
---

Run these bounded reads **in order** through the registered evidence
profile and stop as soon as the cause is established. Record observations and
citations only; do not approve, mutate, deploy, or declare recovery.

## Checks

1. **Pool utilization** — read the registered connection-pool metric for the
   affected service and compare the incident window with the frozen healthy
   baseline. Sustained utilization above 90% for 60+ seconds is the classic
   signature; it usually leads the latency curve by roughly 30 seconds.
2. **Acquisition wait** — read the pool wait-time metric. Rising wait with a
   flat active-connection ceiling means exhaustion; rising wait with rising
   active connections means load growth instead.
3. **Error signature** — collect the approved connection-timeout log signature
   for the same window. Cite counts, not raw log lines.
4. **Service latency** — read the service p95 for the window to establish
   which side of the pool the queueing sits on.
5. **Change correlation** — only if 1–4 are inconclusive, read the registered
   change history for the two hours before onset and note any deploy or
   configuration change touching the service or its database.

## Output

- Lead with which check established the cause, with the metric values and the
  durable evidence references for each observation.
- Separate direct observations from inferences explicitly.
- If no check is conclusive, return INSUFFICIENT_EVIDENCE with what was read.

## Boundary

A tight pool is often intentional backpressure. Never present a pool-size
increase as the fix; if sizing appears relevant, record it as an inference for
the application's proposal machinery to consider under its own policy gates.
