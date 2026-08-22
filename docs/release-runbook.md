# Solvan competition release runbook

Status: required operator procedure; commands are plan-only unless `--apply` is present

This is the command-level path from a reviewed commit to a recoverable GCP
competition deployment. It does not turn a local result into cloud evidence.
Use the dedicated Solvan staging project, one full published Git SHA, one
deployment ID, and one approved calibration receipt for the entire sequence.
Solvan dev is for mutable engineering only and cannot satisfy this runbook.
Never use the Ruhu development project.

## 1. Preconditions

- `scripts/check` and `scripts/check-contracts` pass from the exact candidate.
- The working tree is clean and the full SHA exists on the judging remote.
- `gcloud`, Terraform, Cloud Build trigger access, billing, and the approved
  operator identities are configured for the dedicated Solvan staging project.
  The operator does not submit a local source archive or run Docker locally.
- The regional Cloud Build GitHub App connection
  `solvan-staging-github` exists in `europe-west1`, its
  `installationState.stage` is `COMPLETE`, and the approved human GitHub
  administrator has limited the installation to the public judging repository.
  Create this connection once with Google's browser-mediated flow; never put a
  GitHub token in tfvars, source, logs, or a release receipt:

  ```bash
  gcloud builds connections create github solvan-staging-github \
    --project <solvan-staging-project-id> \
    --region europe-west1
  gcloud builds connections describe solvan-staging-github \
    --project <solvan-staging-project-id> \
    --region europe-west1
  ```

  The first command is incomplete until the approved human follows Google's
  authorization link, installs the Cloud Build GitHub App, and the second
  command reports `COMPLETE`.
- The GCS backend config and reviewed base tfvars are outside Git or contain no
  secrets. Copy `infra/terraform/environments/gcp/staging.tfbackend.example`
  and `staging.tfvars.example`; do not edit generated release tfvars. The
  backend prefix must be `solvan/staging`, never `solvan/dev`.
- The calibration object is in the release evidence bucket and its hash is
  `sha256:<64 lowercase hex>`. Its `release_commit`, project, region, known-good
  revision, fault revision, and Cloud SQL instance must match this release.
- The human S1 approval token comes from the approved Google user OAuth flow,
  has the deployed approval audience, and remains valid for at least two
  minutes. Store it in a mode-0600 temporary file; never commit or log it.

For every command below, first run the plan form shown without `--apply` and
review the resolved project, paths, phases, and acknowledgements.

## 2. Deploy with schedulers paused

```bash
scripts/deploy \
  --project <solvan-staging-project-id> \
  --deployment-id <deployment-id> \
  --release-version <semver> \
  --backend-config <staging.tfbackend> \
  --base-tfvars <staging.tfvars> \
  --remote origin \
  --calibration-receipt-uri gs://<evidence-bucket>/<calibration-object> \
  --calibration-receipt-hash sha256:<digest>
```

After review, repeat with:

```bash
  --ack-dedicated-project <solvan-staging-project-id> --apply
```

This first apply refuses before trigger creation unless the external GitHub
connection is `COMPLETE`. Terraform then links the exact repository as a
regional Cloud Build Repository resource, binds both trigger source fields to
that resource, and provisions and validates the managed-build trigger, its
dedicated identity, exact IAM, and Artifact Registry. It stops at a hash-bound
`AWAITING_MANAGED_BUILD` checkpoint. Run the exact command printed in
`next_required_gate`; its shape is:

```bash
gcloud builds triggers run solvan-staging-release-images \
  --project <solvan-staging-project-id> \
  --region europe-west1 \
  --sha <full-published-sha> \
  --substitutions _RELEASE_COMMIT=<full-published-sha>
```

Approve that exact pending build in Cloud Build. Record its immutable build
UUID, wait for `SUCCESS`, then advance the same deployment checkpoint:

```bash
scripts/deploy \
  <the-identical-arguments-from-the-first-apply> \
  --managed-build-id <cloud-build-uuid> \
  --ack-dedicated-project <solvan-staging-project-id> \
  --resume
```

Resume rejects a changed plan, source commit, trigger, build identity, approval
decision, resolved source SHA, provenance, image set, or prior phase digest. It
does not rebuild. It checkpoints each mutation and each accepted Agent Runtime
resource. If an Agent Runtime create was interrupted before Google exposed its
resource, resume refuses a replacement create until that exact labeled resource
is visible; it never creates a duplicate merely because the client timed out.

The deployment then stops again at
`AWAITING_HUMAN_CATALOG_PUBLICATION_APPROVAL`. Approve only the exact Cloud
Deploy publication rollout named by `next_required_gate`, then run:

```bash
scripts/deploy \
  <the-identical-arguments-from-the-first-apply> \
  --ack-dedicated-project <solvan-staging-project-id> \
  --resume-after-catalog-approval
```

The final continuation revalidates the published source, scheduler pause,
ordered rollout, Terraform output digest, and receipt digest. A successful
result writes `.solvan/releases/<deployment-id>/deployment-receipt.json`,
immutable image digests, Agent Runtime/IAP receipts, generated tfvars, and final
Terraform output, and remains `DEPLOYED_UNVERIFIED_SCHEDULERS_PAUSED`.

## 3. Qualify the optional Antigravity provider

Skip this section only when the reviewed Terraform topology has the optional
provider disabled. A normal repair task must first leave exactly one public,
independently attested synthetic Antigravity workspace hibernated with a
checkpoint. Plan the deliberate provider replacement:

```bash
scripts/qualify-antigravity \
  --terraform-output .solvan/releases/<deployment-id>/terraform-output.json \
  --project <project-id> \
  --release-commit <full-sha> \
  --deployment-id <deployment-id> \
  --output .solvan/releases/<deployment-id>/antigravity-qualification.json
```

After review, repeat with
`--ack-deployment <deployment-id> --apply`. The coordinator replaces no
production workload: the tool creates one fresh revision of the private
experiment-only provider, rehydrates the exact checkpoint, and writes five
qualification proofs. If the final evidence write is interrupted, rerun the
same command; the coordinator reconciles the content-bound receipt without a
second provider call or another revision replacement.

## 4. Collect live platform proofs

```bash
scripts/probe-platform \
  --terraform-output .solvan/releases/<deployment-id>/terraform-output.json \
  --project <project-id> \
  --release-commit <full-sha> \
  --deployment-id <deployment-id> \
  --output .solvan/releases/<deployment-id>/proof-manifest.json
```

After review, repeat with:

```bash
  --ack-deployment <deployment-id> --apply
```

Every proof must have a GCS reference. Evaluate the exact topology and manifest:

```bash
scripts/preflight \
  --terraform-output .solvan/releases/<deployment-id>/terraform-output.json \
  --proof-manifest .solvan/releases/<deployment-id>/proof-manifest.json \
  --project <project-id> \
  --release-commit <full-sha> \
  --deployment-id <deployment-id> \
  --output .solvan/releases/<deployment-id>/preflight-receipt.json \
  --upload-uri gs://<evidence-bucket>/preflight/<deployment-id>/receipt.json
```

Do not promote unless the receipt status is `PASS`, all required proof values
are `true`, and its content hash validates.

## 5. Promote the passing release

Plan, then apply with the same backend, base tfvars, generated tfvars, SHA, and
durable preflight object:

```bash
scripts/promote \
  --project <project-id> \
  --release-commit <full-sha> \
  --deployment-id <deployment-id> \
  --preflight-uri gs://<evidence-bucket>/preflight/<deployment-id>/receipt.json \
  --backend-config <backend-config.hcl> \
  --base-tfvars <release.tfvars> \
  --generated-tfvars .solvan/releases/<deployment-id>/release.auto.tfvars.json \
  --remote origin
```

Apply adds `--ack-unpause <deployment-id> --apply`. The tool restores paused
Terraform state if scheduler promotion fails.

## 6. Run S1–S6 against the same deployment

Plan all six in one invocation:

```bash
scripts/scenarios-cloud \
  --project <project-id> \
  --release-commit <full-sha> \
  --deployment-id <deployment-id> \
  --terraform-output .solvan/releases/<deployment-id>/terraform-output.json \
  --preflight-receipt .solvan/releases/<deployment-id>/preflight-receipt.json \
  --human-identity-token-file <mode-0600-user-token-file> \
  --scenario S1 --scenario S2 --scenario S3 \
  --scenario S4 --scenario S5 --scenario S6 \
  --remote origin
```

After review, repeat with `--ack-scenarios <deployment-id> --apply`. S1 must be
`LIVE_GCP`; S2–S6 must be `SCRIPTED_GCP`. Each independent oracle must return
the exact checked-in assertion set, and every receipt must bind the same full
SHA, project, region, and deployment ID. Any failed assertion blocks MSR.

## 7. Restore and pause after the drill or on failure

Cleanup is deliberately available even if the working tree later becomes
dirty. It resolves only resources in the captured Terraform output, pauses the
exact four release schedulers, executes the isolated non-agent cleanup job,
restores 100% traffic to the calibrated known-good revision, reconciles the
target epoch, and verifies the resulting GCS receipt.

```bash
scripts/restore-fault-drill \
  --project <project-id> \
  --release-commit <full-sha> \
  --deployment-id <deployment-id> \
  --terraform-output .solvan/releases/<deployment-id>/terraform-output.json \
  --output .solvan/releases/<deployment-id>/cleanup-receipt.json
```

After review, repeat with `--ack-cleanup <deployment-id> --apply`. Cleanup
leaves schedulers paused. Before another promotion, set
`scheduler_paused=true` in the generated release variables through the reviewed
Terraform workflow and reconcile state. Do not delete calibration, preflight,
scenario, audit, or cleanup evidence before submission capture.

## 8. Terminal checks

- Store deployment, platform, promotion, S1–S6, and cleanup receipts together.
- Confirm the console release page shows the same immutable bindings and no
  scenario is promoted from local-contract evidence. The API must show the
  exact full commit and deployment ID injected by `scripts/deploy`; a missing
  GCS permission or malformed receipt must remain
  `EVIDENCE_PROJECTION_UNAVAILABLE`/`PENDING_RECEIPTS`, never pass.
- Record the final test URL, public or judge-accessible Git URL, commit SHA,
  architecture image, demo video, limitations, and data-handling statement.
- If the project, commit, topology, calibration, or deployment ID changes,
  restart at deployment; do not splice receipts from different releases.

Complete a copy of
`specs/artifacts/submission-freeze-manifest.template.yaml`, then plan its exact
repository/content bindings:

```bash
scripts/freeze-submission \
  --manifest <completed-freeze-manifest.yaml> \
  --output .solvan/releases/<deployment-id>/submission-freeze.json
```

After representative review, repeat with
`--ack-deployment <deployment-id> --apply`. The command requires the exact
published HEAD, a clean tree, six bound Runtime/Registry/Identity entries, the
exact S1–S6 GCS receipt set, all release attestations, a video no longer than
240 seconds, and content hashes matching the architecture, README, and
third-party disclosure in that commit. An existing different freeze artifact
is never overwritten.
