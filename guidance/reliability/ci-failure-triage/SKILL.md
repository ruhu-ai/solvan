---
name: ci-failure-triage
description: Classify a bounded GitHub CI failure artifact on a successor repair plan and prepare a new candidate or an insufficient-evidence result.
license: Apache-2.0
metadata:
  solvan-owner: reliability
  solvan-provenance: first-party
---

Use this skill only when the Coordinator supplies a successor repair plan with
an exact `CI_FAILURE_EVIDENCE` artifact. Validate the frozen repository, pull
request, base, head, tree, check identity, provider receipt, and approved
annotation excerpts before classifying the failure.

Do not rerun CI, alter a pull request, retarget a branch, override a check,
select a reviewer, merge, deploy, roll back, or reuse the prior workspace.
