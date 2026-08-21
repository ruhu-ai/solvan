# Security and governance review checklist

Use this checklist for changes that affect data retrieval, model context,
credentials, policies, mutations, verification, integrations, or telemetry.

- [ ] Identity comes from verified cryptographic claims, never a header, body,
      or model output.
- [ ] Tenant, project, environment, purpose, classification, and region are
      filtered before retrieval and again before prompt construction.
- [ ] Logs, traces, repositories, tickets, tool output, model output, and
      memory are treated as untrusted data.
- [ ] Model Armor is defense in depth, not the sole authority boundary.
- [ ] Every mutation has deterministic authorization, target reservation,
      idempotency, budget, dry-run/effect comparison, and independent
      verification.
- [ ] Verification has separate identity, process, conversation, and mutable
      artifact context from the producer.
- [ ] Credentials are references with explicit posture; secrets never enter
      the console, Cloud SQL, logs, traces, or model context.
- [ ] Audit records are append-only, correlated, redacted, and dual-written
      where the customer contract requires it.
- [ ] Cloud claims are bound to the exact project, region, deployment, commit,
      and receipt set.
- [ ] A failed, stale, missing, or contradictory control fails closed and is
      displayed as blocked or unknown, never healthy.
