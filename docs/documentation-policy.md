# Documentation authority and status policy

## Authority

1. Official competition rules govern eligibility and submission.
2. Normative specifications under `specs/` define required product behavior.
3. Security, authority, approval, data-integrity, privacy, and sovereignty
   requirements always fail closed and take precedence.
4. `solvan v0.3.md` defines vision and rationale; the smallest detailed
   specification governs implementation mechanics.
5. Code, migrations, tests, cloud resources, and receipts show current behavior.
6. A passing test or screenshot proves only the named path and environment.

## Status vocabulary

| Term | Meaning |
|---|---|
| `required` | normative competition-release behavior |
| `target` | normative product behavior not necessarily in the competition release |
| `implemented` | a production path exists; no test claim implied |
| `verified` | named deterministic checks passed in the cited environment |
| `evaluated` | named model-backed cases were executed and scored |
| `release-qualified` | every required release gate passed with stored evidence |
| `preview-dependent` | relies on a documented Pre-GA feature and has a degradation path |
| `roadmap` | intentionally outside the current release |

Use the narrowest accurate status. Never use roadmap prose, a model-generated
artifact, or a UI mock as evidence that a behavior is implemented.

## Source maintenance

Platform launch stage, location, protocol coverage, and limitations are volatile.
Update `docs/sources/gemini-enterprise-agent-platform.md` and run deployment
preflight before changing a platform claim. Record retrieval date, official URL,
design consequence, and fallback.

