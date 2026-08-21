---
name: interpret-slo-burn
description: Interpret an SLO burn-rate signal into severity and time-to-exhaustion. Use when an alert is an error-budget burn alert, when deciding whether degradation is page-worthy or ticket-worthy, or when a triage flow needs budget context.
license: Apache-2.0
metadata:
  solvan-owner: platform
  solvan-provenance: first-party
---

Answer only from the registered SLO and error-budget metrics for the
exact objective named in the invocation. Record observations and citations
only.

## Procedure

1. Read the objective's definition record: target, window, and the metric it
   is computed from. Cite it; never restate an objective from memory.
2. Read the short-window and long-window burn rates supplied by the
   registered reader (typically one hour and six hours).
3. Compute time-to-exhaustion at the current long-window rate and report it
   as an observation with both inputs cited.
4. Classify the combination against the objective's own registered
   thresholds — fast burn (both windows elevated), slow burn (long window
   only), or noise (short window only) — citing the threshold record.
5. Read remaining error budget for the current period.

## Output

- objective · target · window (cited)
- burn: short-window ×N, long-window ×M (cited)
- remaining budget and projected exhaustion (computed, inputs cited)
- classification per the registered thresholds

## Boundary

Thresholds and targets come from registered records; this procedure never
proposes changing an objective and never converts a classification into a
paging decision — escalation is policy owned by the application.
