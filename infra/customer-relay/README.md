# Customer-owned Solvant Relay deployment

This directory is deliberately not part of Solvan cell Terraform. Apply the
CronJob only from the customer's own GitOps/control plane, with customer-owned
workload identity, policy/key secret, persistent encrypted ledger and egress
policy allowing only Cloud Monitoring, Cloud Storage upload URLs and the exact
Solvan Relay-control audience. It creates no inbound Service or Ingress.

The customer must set a local kill switch by suspending the CronJob or denying
its workload identity. The Relay must have Cloud Monitoring read permission
only; it must not have mutation permissions, broad Cloud Storage access, or
any credential usable by Solvan.

## Profiles and qualification evidence

- `gke-cronjob.yaml` is the Kubernetes profile. The customer must enforce the
  named FQDN/egress allowlist at its gateway: a standard Kubernetes
  `NetworkPolicy` cannot express the one-time upload URL constraint.
- `onprem-compose.yaml` plus `solvant-relay.service` and
  `solvant-relay.timer` are the rootless on-prem profile. The unit is a
  customer template; its three bind mounts must resolve to customer-owned
  policy/keys, kill-switch state, and encrypted ledger storage.
- `cloud-run-job.yaml` is a customer job shape only. It is not production
  eligible until the customer supplies a durable encrypted ledger mount and
  its own secret-delivery/egress controls; Cloud Run's ordinary ephemeral
  filesystem is not sufficient for ambiguous-attempt reconciliation.

The customer records the completed qualification in
`qualification-receipt.template.json`, after replacing all placeholders and
signing it with a customer-controlled identity. The receipt must validate
against `specs/artifacts/relay-qualification-receipt.schema.json`; a template,
local test, or Terraform plan is not a qualification receipt.

## Deployment contract

Before applying `gke-cronjob.yaml`, the customer must replace every placeholder
and retain these boundaries in their own GitOps review:

- Grant the workload identity only `monitoring.timeSeries.list` (or the
  provider's exact equivalent) in the customer project. Do not grant Cloud
  Storage, Cloud SQL, IAM administration, Kubernetes write, or any mutation
  permission.
- Give that exact workload-identity principal `roles/run.invoker` on the
  customer-specific Relay-control service. The central Terraform input is
  `solvant_relay_invoker_members`; it refuses public and broad authenticated
  members.
- Mount a customer-owned, immutable policy and key secret plus a persistent
  encrypted ledger volume. Solvan never writes either mount. Rotate the
  runtime-proof key by re-enrolling the Relay rather than replacing it in
  place.
- Mount a customer-owned `CUSTOMER_MANAGED_RELAY_KILL_SWITCH` ConfigMap whose
  `state` key is exactly `DISENGAGED` or `ENGAGED`. `ENGAGED` is reported to
  the control plane and prevents polling or claiming new work; an unreadable or
  malformed configured state fails closed. Suspending the CronJob remains the
  immediate kill switch for already scheduled invocations.
- Restrict egress at the customer network boundary to Cloud Monitoring, the
  exact Relay-control audience, and the one-time Cloud Storage upload URL. The
  Kubernetes NetworkPolicy API cannot express URL allowlists; use the
  customer's FQDN/egress gateway policy to enforce them.
- Verify the image digest, the customer policy signature, the Relay-control
  public key, and the `RELAY_CONTROL_AUDIENCE` before enabling the CronJob.
  The deployed process refuses if any one differs from its enrollment.

Suspending the CronJob is the local kill switch. It is immediate for new reads;
an already claimed job is reconciled rather than treated as though no provider
call happened.
