---
name: incident-summary
description: Produce the standard operator-facing incident summary. Use when a liaison or case surface needs a consistent summary of an incident's cause, impact, actions, and verification, or when an operator asks for a status they can forward.
license: Apache-2.0
metadata:
  solvan-owner: reporting
  solvan-provenance: first-party
---

Instantiate this template only from cited durable records. Every field
names its evidence reference; a field whose citation cannot resolve is
written as "not established", never filled from prose.

## Template

- **What happened** — one sentence from the incident record's class and the
  established cause finding.
- **Impact** — affected service and objective, with the metric values and
  window from cited evidence.
- **Timeline** — detected at, mitigated at, verified at; each from the
  recorded state transitions.
- **What was done** — each executed action by its action record: what, on
  which target, under which approval or preauthorization; receipts cited.
- **Verification** — the independent verification outcome by its record;
  connector success is never written as recovery.
- **Ownership** — the open Reliability Case and its next scheduled step,
  from the case record.

## Rules

- Observations and inferences keep their labels; an inference is written as
  "likely … (inference)".
- No names of individuals; teams and roles only.
- Withheld or failed factual claims are omitted entirely, not paraphrased.
- Length target: the summary reads in under one minute.

## Boundary

This template formats established records for people. It asserts nothing the
ledger does not already assert, and it never announces recovery ahead of the
verification record.
