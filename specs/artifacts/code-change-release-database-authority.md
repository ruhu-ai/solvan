# Code-change and release database authority

Status: target contract. This is the required grant plan for the
`solvan_delivery` schema. The migration/bootstrap implementation must apply it
before any target delivery service can start.

The schema owner is a migration-only identity. It is never a Cloud Run,
console, job, sandbox, GitHub, deployment, verifier, or human runtime
identity. Every runtime identity has `USAGE` on `solvan_delivery` and only the
table/function permissions listed below. No runtime identity receives schema
ownership, `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `DELETE`, `REFERENCES`, or
default privileges over the schema.

| Runtime identity | Read | Write | Explicitly absent |
|---|---|---|---|
| Authenticated console API | repair-command definitions and code-delivery profiles only | register/supersede an approved repair definition or immutable delivery profile | code-change requests/decisions, private commands, GitHub/OAuth operations, rollouts, verifier receipt, DDL |
| Coordinator | requests, qualification intents/receipts, delivery profiles, decision heads, command dispatches, repair rows, receipts, operations | append qualification intents; create a request only from a qualified receipt; create command rows; append transitions and decision-chain leaves; bind/supersede guidance; create/reconcile operation rows | GitHub OAuth secret, GitHub API, provider qualification receipt, deployment target, verifier receipt, DDL |
| Workspace adapter | exact invocation, artifact/candidate/catalog rows | append candidate generations and exploratory receipts only | requests, decisions, operations, GitHub, rollouts, deployment, DDL |
| GitHub Provider | exact qualification intent/candidate/profile, CCR, live decision leaf, repository binding, command/operation rows | append one qualification receipt; append/reconcile GitHub operations and Provider transitions only | OAuth token/client secret, qualification intent or CCR creation, Workspace model/provider authority, rollouts, verifier receipt, DDL |
| Identity Broker | OAuth profile, active reviewer policy from the delivery profile, and its own link transaction/binding rows | create/consume link transactions; append binding events | GitHub installation capability, code-change operation, rollout, DDL |
| Deployment Controller | release candidate, target/reservation, rollout, live deployment decision, operation rows | reserve/reconcile target; create/reconcile rollout and rollout-operation rows; append deployment transitions | GitHub, OAuth, Workspace, verifier receipt, DDL |
| Release Verifier | exact rollout and frozen verification material | append one verifier receipt and verifier transition only | deployment mutation, rollback, GitHub, approval, DDL |

All mutation grants are relation- and column-specific. The migration applies
`REVOKE ALL ... FROM PUBLIC`, grants no direct `UPDATE` on immutable history,
and gives the owner-only migration role the ability to alter or truncate.
Statement-level `BEFORE TRUNCATE` guards in the target schema are a second
line of defense; they are not a substitute for this least-privilege plan.

The bootstrap qualification must introspect `information_schema.role_table_grants`
and `information_schema.role_routine_grants` for every delivery runtime role.
It fails when an identity has an unlisted relation permission, any `TRUNCATE`/
`DELETE`/schema privilege, another component's write privilege, or access to a
secret-bearing OAuth profile field. `CCR-013`, `CCR-018`, and `CCR-019` require
that evidence.
