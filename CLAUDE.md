@AGENTS.md

# Claude Code

- Treat `AGENTS.md` as the shared, vendor-neutral repository contract.
- Run `scripts/check` before declaring implementation work complete.
- Use the active execution plan for substantial multi-session work; do not
  create plan paperwork for a small, self-contained edit.
- Do not weaken authorization, idempotency, approval, isolation, verification,
  privacy, or release gates to make a test pass.
- Prefer deterministic enforcement in code, tests, hooks, or CI over adding
  more prose to this file.

