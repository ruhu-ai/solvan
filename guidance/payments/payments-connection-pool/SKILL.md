---
name: payments-connection-pool
description: Workload knowledge for the payments-api connection pool. Use when investigating latency or error spikes on the payments service, especially when alerts reference database wait times or checkout endpoints, before reading application logs.
license: Apache-2.0
metadata:
  solvan-owner: payments
  solvan-provenance: first-party
---

Project-specific knowledge for the payments workload; pair it with the
generic connection-exhaustion triage flow. Observations and citations only.

## What the fleet should know

- The payments-api service runs a deliberately tight shared connection pool.
  The sizing is intentional backpressure: it pushes queueing to the service
  edge rather than fanning load into the database.
- Sustained pool utilization above 90% for more than 60 seconds causes
  request queueing and downstream 5xx before the database itself shows any
  distress. Database-side health metrics staying green does not clear the
  pool as a suspect.
- Pool utilization leads the checkout latency curve by roughly 30 seconds;
  when triaging latency, read the pool metric first — it is the earlier
  signal.
- Checkout traffic is spiky at the top of the hour; a pool spike that decays
  within two minutes of the hour boundary matches the known traffic shape
  and should be cited against baseline before being treated as an incident
  signal.

## Order of reads for payments latency

1. Registered pool-utilization metric (leads by ~30s).
2. Checkout endpoint p95 for the same window.
3. Approved connection-timeout log signature counts.
4. Only then the broader error-log signatures.

## Boundary

Do not present a pool-size increase as a fix; the tight pool is a recorded
design decision of the payments owner. If sizing appears causal, record the
inference and leave the proposal to the application's policy gates.
