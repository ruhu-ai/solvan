---
name: triage-memory-pressure
description: Run the standard triage flow for container memory pressure. Use when alerts mention out-of-memory kills, container restarts, memory utilization near limits, or when latency degrades in a sawtooth pattern aligned with instance recycling.
license: Apache-2.0
metadata:
  solvan-owner: reliability
  solvan-provenance: first-party
---

Run these bounded reads **in order** through the registered evidence
profile. Record observations and citations only; do not approve, mutate,
resize, or declare recovery.

## Checks

1. **Utilization versus limit** — read per-instance memory utilization
   against the configured limit for the incident window and baseline.
2. **Restart evidence** — read instance restart counts and the approved
   OOM-kill log signature. Restarts without the signature point away from
   memory as the cause.
3. **Shape of growth** — classify the utilization curve: a step after a
   deploy suggests a changed working set; a steady slope across requests
   suggests a leak; spikes under specific traffic suggest request-correlated
   allocation.
4. **Traffic correlation** — read request rate and payload-size metrics for
   the same window to test the request-correlated hypothesis.
5. **Revision comparison** — only if the shape is leak-like, compare memory
   slope across serving revisions to bound when the behavior began.

## Output

- Lead with the classification (changed working set, leak, request-driven,
  or not-memory) and the curve evidence, with refs for every observation.
- A restart cycle that temporarily restores service is an observation about
  symptom relief, never a recovery conclusion.
