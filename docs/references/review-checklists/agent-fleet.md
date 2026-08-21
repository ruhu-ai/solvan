# Agent Fleet review checklist

Use this checklist when changing Agent Fleet, platform health, registry,
runtime, memory, identity, gateway, Armor, or observability surfaces.

- [ ] Lifecycle, health, and evidence scope are separate fields.
- [ ] “Local checks passed” cannot be mistaken for “cloud receipt verified.”
- [ ] Every component shows the last check and a safe next step when incomplete.
- [ ] `planned`, `implemented`, `provisioned`, and `deployed` have distinct
      meanings and do not share one overloaded badge.
- [ ] Health is derived from named checks and cannot be manually marked.
- [ ] Registry discovery and effective permission are shown separately.
- [ ] A permission is derived from the rule the coordinator binds runs with, not
      re-derived on the surface that renders it.
- [ ] An authority no record has observed renders as unevaluated, never as
      allowed and never as denied.
- [ ] A capability offered by no approved profile is distinguishable from one
      that was refused.
- [ ] A cell naming a permission also names the authority that decided it, and
      an unstarted setup step does not read as a fault.
- [ ] Agent identity, Gateway route, Model Armor policy, and observability
      claims name their project, region, revision, and source receipt where
      applicable.
- [ ] Preview or local-only features show their degradation path.
- [ ] No card implies that an agent or model has production mutation authority.
- [ ] The page remains understandable without machine status codes.
