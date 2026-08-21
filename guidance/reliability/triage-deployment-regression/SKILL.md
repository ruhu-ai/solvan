---
name: triage-deployment-regression
description: Run the standard triage flow for a regression that began with a deploy or rollout. Use when an incident's class is deployment_regression, when degradation onset aligns with a release, or when error or latency curves differ by service revision.
license: Apache-2.0
metadata:
  solvan-owner: reliability
  solvan-provenance: first-party
---

Run these bounded reads **in order** through the registered evidence
profile. Record observations and citations only; do not approve, mutate,
deploy, roll back, or declare recovery.

## Checks

1. **Revision inventory** — read the registered deployment state: which
   revisions currently serve traffic, their split, and when the newest one
   began receiving load.
2. **Onset alignment** — compare degradation onset with the rollout
   timestamp. Note the gap explicitly; a lag of minutes is compatible with
   gradual traffic shifting, a lag of hours weakens the hypothesis.
3. **Per-revision comparison** — read error and latency metrics segmented by
   revision over the same window. A clean split is the strongest evidence
   this class offers.
4. **Change contents** — read the registered change-history record for the
   suspect release: configuration deltas, environment changes, and schema
   migrations, cited as references.
5. **Pre-state capture** — record the observed pre-degradation serving state
   (revisions and split) as evidence, so any rollback proposal the
   application later constructs derives its undo plan from observed state.

## Output

- State whether the evidence supports revision-correlated regression, with
  the split metrics and refs; separate observation from inference.
- Name the exact suspect revision and the last known-good revision as
  observations, without recommending an action.
- If serving state cannot be read, return INSUFFICIENT_EVIDENCE.
