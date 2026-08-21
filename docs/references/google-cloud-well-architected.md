# Google Cloud Well-Architected reference

Status: design input  
Retrieved: 2026-08-09  
Primary source: [Google Cloud Well-Architected Framework](https://docs.cloud.google.com/architecture/framework?hl=en)

## Relevant pillars and perspectives

- **Operational excellence:** deploy, operate, monitor, and manage workloads
  with repeatable processes and useful documentation.
- **Reliability:** define realistic objectives, observe failure modes, and
  design recovery paths that can be tested.
- **Security, privacy, and compliance:** make identity, data boundaries, and
  policy enforcement explicit.
- **AI/ML perspective:** apply the cross-pillar controls to model-backed
  systems, including data governance, evaluation, and monitoring.

## Design consequences

1. Keep the architecture map, decision records, source register, and release
   receipts together so a reviewer can connect intent to operating evidence.
2. Prefer simple, decoupled, stateless provider workers with durable state in
   Cloud SQL and bounded external artifacts.
3. Define health and reliability at the service boundary, not only from
   infrastructure availability.
4. Treat region, project, identity, data classification, and network policy as
   release inputs that must be checked together.
5. Design for change: small, reviewable changes with fast deterministic checks
   are safer than a large unverified platform migration.

## Solvan review questions

- Can the service restart without losing workflow authority?
- Is the customer-visible objective measurable and independently verifiable?
- Is every privileged path customer-owned, policy-bound, and auditable?
- Does the design state its data residency and failure behavior?
- Does the documentation explain why the current design exists and what would
  cause it to change?
