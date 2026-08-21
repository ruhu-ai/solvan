# Solvan GCP environment stack

Status: deployable configuration; not cloud evidence until apply and preflight

This root owns the stable regional GCP core and the currently Terraform-backed
Gemini Enterprise Agent Platform resources for normal cloud environments.
`dev` is the mutable engineering environment. `staging` qualifies releases and
may host an explicitly enabled isolated fault drill. `production` serves
declared customer estates and rejects that drill at Terraform validation.

Each environment requires its own existing GCP project, remote GCS state
prefix, service identities, secrets, data stores, and evidence namespace. Do
not point both environments at the same state prefix or project. The stack also
requires immutable image digests and explicit human approvers.

The release is pinned to `europe-west1`. Agent Runtime deployments and their
immutable reasoning-engine names are produced by the versioned platform deploy
script after this root is applied; final Registry, Gateway, Identity, Memory
Bank, Armor, IAM, location, and trace state is proven by preflight rather than
inferred from Terraform state.

Cloud Scheduler has one-minute cron granularity. The detector job therefore
starts an authenticated burst once per minute, and the handler evaluates at
0, 25, and 50 seconds using idempotent window keys. A fault drill may force-run
the same Scheduler job immediately before fault injection.

## Environment files

- `dev.tfvars.example` and `dev.tfbackend.example` are safe starting points for
  active cloud development. Dev receipts never count as release proof.
- `staging.tfvars.example` and `staging.tfbackend.example` are the release
  starting points. The checked-in release tools accept only `staging` for a
  promotable competition release.
- `production.tfvars.example` and `production.tfbackend.example` are the
  starting points for a real product deployment. They keep the synthetic
  payments workload, its Registry endpoint, and its scenario identities off.

Copy examples to untracked operator-owned files and replace every placeholder.
Never commit project credentials, OAuth tokens, secrets, generated release
tfvars, or real backend coordinates.

Initialize one environment at a time:

```bash
terraform -chdir=infra/terraform/environments/gcp init \
  -reconfigure -backend-config=<environment.tfbackend>
terraform -chdir=infra/terraform/environments/gcp plan \
  -var-file=<environment.tfvars>
```

Changing environments always requires `init -reconfigure` with the matching
backend file. Review `terraform workspace show`; the release workflow uses the
default workspace and environment isolation comes from separate projects and
backend prefixes, not Terraform workspaces.

## Fault drill

`fault_drill_enabled` defaults to `false`. It controls the isolated
synthetic payments service, calibration seed, scenario jobs, Registry endpoint,
and the only IAM bindings that can invoke or mutate that fixture. Enable it
only in a dedicated `dev` or `staging` project and run the named
`scripts/seed-fault-drill`, `scripts/run-fault-drill`, and
`scripts/restore-fault-drill` commands. It is rejected for `production`.
