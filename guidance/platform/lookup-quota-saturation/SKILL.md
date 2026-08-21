---
name: lookup-quota-saturation
description: Check which platform quotas and configured limits are near saturation for the services in scope. Use when triage suspects a ceiling such as instance maxima, Cloud SQL connection limits, Pub/Sub throughput, or per-service call budgets.
license: Apache-2.0
metadata:
  solvan-owner: platform
  solvan-provenance: first-party
---

Answer only from the registered read-only capacity and quota readers.
Record observations and citations only.

## Procedure

1. Read current utilization against each registered quota or configured
   limit for the services in scope: serving instances, database connections,
   topic throughput, and any workload-specific budgets the profile exposes.
2. Flag every dimension above 80% of its limit for the incident window, with
   the exact numerator, denominator, and reference.
3. For flagged dimensions, read the trend across the window: approaching,
   flat, or receding.
4. Cite denial evidence where it exists (quota-denied signatures) rather
   than inferring denial from proximity alone.

## Output

A table: dimension · current · limit · utilization · trend · reference.
Close with the single most binding dimension as an observation, or state
that no registered dimension exceeds 80%.

## Boundary

Limits are cited from configuration records, never assumed defaults. Raising
any limit is an action proposal owned by the application's policy gates, not
by this lookup.
