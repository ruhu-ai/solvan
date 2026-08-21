# Solvan reference library

Status: design input and review index  
Maintainer: Solvan engineering  
Last reviewed: 2026-08-09

This directory contains curated links and paraphrased design implications for
the sources we use when reviewing Solvan. It is not a mirror of third-party
books or documentation. The normative authority remains the competition rules,
the specification pack, security requirements, and captured implementation
receipts described in [documentation policy](../documentation-policy.md).

## Authority tiers

| Tier | Use | Examples |
|---|---|---|
| Normative | Governs implementation and release claims | Competition rules; `specs/`; official platform source register |
| Design input | Informs a design review; does not prove implementation | Google SRE; Well-Architected; OpenTelemetry; accessibility systems |
| Study-only | Market or implementation comparison; never a requirement | Competitors; open-source snapshots; blog posts; screenshots |

Every reference entry records a canonical URL, retrieval date, relevant
sections, Solvan design consequences, and the checks or specifications it can
influence. A reference can inform a decision, but it cannot turn roadmap text,
model output, or a screenshot into evidence.

## Review workflow

1. Start with the applicable checklist in `review-checklists/`.
2. Read the linked source and confirm that its launch stage, scope, and date
   still apply.
3. Record the design consequence in the smallest governing specification.
4. Add or update a deterministic acceptance check where the consequence is
   testable.
5. Run `scripts/check` and record the environment and evidence scope.

Review volatile Google platform claims through the [Gemini Enterprise Agent
Platform source register](../sources/gemini-enterprise-agent-platform.md) and
deployment preflight before release. Do not silently replace a source-register
fact with a remembered value.

## Reference groups

- [Google SRE](google-sre.md)
- [Google Cloud Well-Architected](google-cloud-well-architected.md)
- [Observability and OpenTelemetry](observability-and-otel.md)
- [Accessible operational UI](ui-ux-patterns.md)
- [Incident console checklist](review-checklists/incident-console.md)
- [Agent Fleet checklist](review-checklists/agent-fleet.md)
- [Security and governance checklist](review-checklists/security-governance.md)

## Copyright and licensing

Store links, short identifying metadata, and original Solvan paraphrases. Do
not copy an entire book, article, screenshot collection, or proprietary design
document into this repository. Open-source code belongs in the pinned
`.opensrc` snapshot workflow with its nearest license and notices preserved.
