---
name: triage-error-rate
description: Run the standard triage flow for a server error-rate spike. Use when an incident's class is service_error_rate, when availability or 5xx-ratio alerts fire, or when synthetic checks fail while infrastructure metrics look nominal.
license: Apache-2.0
metadata:
  solvan-owner: reliability
  solvan-provenance: first-party
---

Run these bounded reads **in order** through the registered evidence
profile and stop when the failing layer is established. Record observations
and citations only; do not approve, mutate, deploy, or declare recovery.

## Checks

1. **Ratio and shape** — read the error-ratio metric for the incident window
   against the healthy baseline. A step change points at a deploy or
   dependency edge; a ramp points at saturation or leak-shaped causes.
2. **Segment by revision** — read the same ratio split by service revision.
   Errors isolated to one revision reclassify the work as a deployment
   regression; note that and continue only if the split is inconclusive.
3. **Top signatures** — collect the approved error-log signature summary for
   the window. Cite the top signatures by count; never paste raw payloads.
4. **Dependency read** — read the registered upstream/downstream health
   signals for the service's declared dependencies. Inherited errors point
   the investigation at the dependency, not the alerting service.
5. **Synthetic agreement** — read the synthetic-check results for the same
   window; disagreement between synthetic and ratio metrics is itself a
   finding worth citing.

## Output

- Lead with the failing layer (service code, revision, dependency, or
  measurement) and the values that establish it, each with evidence refs.
- Mark every conclusion drawn from correlation as an inference.
- If no check is conclusive, return INSUFFICIENT_EVIDENCE with what was read.
