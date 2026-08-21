---
name: postmortem-draft
description: Draft the permanent-repair postmortem skeleton for a Reliability Case. Use when a case approaches verified close and needs a structured postmortem draft assembled from durable records for a human owner to complete.
license: Apache-2.0
metadata:
  solvan-owner: reporting
  solvan-provenance: first-party
---

Assemble a draft only from cited durable records. The draft is an input
for a human owner; it is never the published postmortem and never asserts
conclusions beyond its citations.

## Skeleton

1. **Summary** — class, duration, impact metrics; from incident records.
2. **Timeline** — every recorded state transition with timestamps: detection,
   plan, evidence milestones, approval, execution, mitigation, case steps,
   repair, verified close. Each line cites its transition record.
3. **Cause analysis** — established findings first (observations with refs),
   then contributing hypotheses explicitly labelled as inferences with their
   confidence and contradicting evidence where recorded.
4. **What limited the impact** — controls that worked, from records: budgets
   hit, gates refused, quarantines, fallbacks taken.
5. **Repair** — the permanent change as recorded: patch reference, review,
   canary and rollout receipts, verification outcome.
6. **Recurrence guards** — recorded detector, policy, or guidance changes
   attached to the case; proposed-but-not-adopted items listed separately.
7. **Open questions** — evidence gaps the records themselves expose.

## Rules

- Blameless by construction: systems and records, no individual names.
- Every timeline entry and claim carries a reference; unresolvable
  references demote the line to "not established".
- The draft ends with an explicit "drafted from records; human owner
  completes narrative and lessons" marker.

## Boundary

Publishing, editing judgment, and lesson selection belong to the human case
owner. This draft cannot close the case and is not part of any verification.
