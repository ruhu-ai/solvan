# Solvan submission guide

Status: active guidance
Submission deadline: 2026-08-31 17:00 PT
Supporting guide:
[`docs/exec-plans/active/2026-08-14-final-17-day-submission-plan.md`](docs/exec-plans/active/2026-08-14-final-17-day-submission-plan.md)

Use the remaining time in two broad passes:

1. Complete and stabilize the payments-stack Minimum Submittable Release.
2. Qualify the release in staging, assemble exact evidence, document it, and
   freeze the submission with time left for contingency.

The release is ready only when one clean published commit and one dedicated
`europe-west1` staging deployment have passing canonical checks, platform
preflight, S1-S6 receipts, accurate documentation, and a matching video and
freeze manifest. Local tests and screenshots support diagnosis but never replace
cloud-bound evidence.

Keep the payments vertical slice primary. Target work such as Ruhu, SaaS scale,
expanded channels, and optional provider qualification must not delay the
required path.
