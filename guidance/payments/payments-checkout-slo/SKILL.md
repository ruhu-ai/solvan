---
name: payments-checkout-slo
description: Workload knowledge for the payments checkout SLO. Use when a payments availability or latency objective fires, when judging whether a checkout breach is real, or when a triage flow needs to know which endpoints compose checkout.
license: Apache-2.0
metadata:
  solvan-owner: payments
  solvan-provenance: first-party
---

Project-specific knowledge for interpreting the checkout objective.
Observations and citations only.

## What the fleet should know

- The checkout objective is computed over the charge and refund request
  paths only; administrative and health-check requests are excluded by the
  objective definition. Cite the registered objective record rather than
  recomputing membership.
- The latency objective tracks p95 over its stated window. Single-request
  outliers do not breach it; sustained elevation does. Read the burn-rate
  interpretation procedure for severity rather than reacting to one sample.
- The synthetic checkout probe exercises the same path with marked traffic.
  Synthetic failure with green ratio metrics usually means a probe-path or
  dependency issue and is a distinct finding, not a contradiction to hide.
- Checkout error budget is consumed fastest during top-of-hour spikes; a
  breach that begins mid-hour is more likely a real regression than traffic
  shape.

## Order of reads for a checkout objective alert

1. The registered objective definition (membership and target).
2. Burn-rate windows via the SLO interpretation procedure.
3. Endpoint-level ratio and p95 for charge and refund separately.
4. Synthetic probe results for the same window.

## Boundary

Objective definitions are records; never widen or narrow endpoint membership
in prose, and never trade the objective against a deploy schedule — that is
a human decision surfaced through the application.
