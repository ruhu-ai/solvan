---
name: triage-scaling-stall
description: Run the standard triage flow for autoscaling stalls and cold-start pileups. Use when alerts mention request queueing at ingress, instance counts pinned at a ceiling, cold-start latency, or concurrency saturation on Cloud Run services.
license: Apache-2.0
metadata:
  solvan-owner: reliability
  solvan-provenance: first-party
---

Run these bounded reads **in order** through the registered evidence
profile. Record observations and citations only; do not approve, mutate,
scale, or declare recovery.

## Checks

1. **Instance count versus ceiling** — read the serving instance count
   against the configured maximum for the window. A pinned count under
   rising load is the primary stall signature.
2. **Concurrency utilization** — read per-instance concurrency against its
   configured target; saturation with spare instance headroom points at
   concurrency limits rather than instance limits.
3. **Startup path** — read cold-start counts and startup latency. A pileup
   of concurrent cold starts after an idle period or deploy is its own
   mechanism, distinct from a ceiling.
4. **Denial signatures** — collect the approved quota-denied and
   scale-denied log signatures for the window; cite counts.
5. **Traffic shape** — read the request-rate curve to separate a legitimate
   surge from a retry storm; retry storms show multiplied request rates with
   flat unique-client counts where that signal is registered.

## Output

- Lead with the binding constraint (instance ceiling, concurrency target,
  startup path, quota, or none) and the values that establish it, with refs.
- If the constraint is a configured ceiling, cite the configured value as an
  observation; proposing a new value is the application's decision, not this
  procedure's.
