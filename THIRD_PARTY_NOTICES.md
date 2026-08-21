# Third-party notices and competition disclosure

Status: required release inventory
Reviewed: 2026-08-08

Solvan depends on the packages pinned in `uv.lock` and `pnpm-lock.yaml`. This
inventory summarizes direct dependencies used by the product and its required
release harness. Transitive license texts remain available in the installed
package distributions and their linked upstream repositories; the lockfiles are
the authoritative version inventory.

## Product runtime dependencies

| Component | Pinned version | License |
|---|---:|---|
| FastAPI | 0.139.2 | MIT |
| Google Auth | 2.56.3 | Apache-2.0 |
| Google ADK | 2.5.0 | Apache-2.0 |
| Google Cloud AI Platform | 1.163.0 | Apache-2.0 |
| HTTPX | 0.28.1 | BSD-3-Clause |
| OpenTelemetry API/SDK | 1.42.1 | Apache-2.0 |
| OpenTelemetry GCP Logging exporter | 1.14.0a0 | Apache-2.0 |
| OpenTelemetry GCP Trace exporter | 1.14.0 | Apache-2.0 |
| Psycopg, Psycopg Binary, and Psycopg Pool | 3.2.9 / 3.2.9 / 3.2.6 | LGPL-3.0 |
| Pydantic | 2.12.5 | MIT |
| PyYAML | 6.0.2 | MIT |
| Requests | 2.34.2 | Apache-2.0 |
| Uvicorn | 0.35.0 | BSD-3-Clause |
| React and React DOM | 19.1.1 | MIT |
| Lucide React | 1.30.0 | ISC |
| Vite and React plugin | 7.1.1 / 4.7.0 | MIT |

## Evaluation and build dependencies

| Component | Pinned version | License |
|---|---:|---|
| Google Gen AI | 2.17.0 | Apache-2.0 |
| Playwright | 1.54.2 | Apache-2.0 |
| axe-core / axe Playwright adapter | 4.12.1 | MPL-2.0 |
| TypeScript | 5.9.2 | Apache-2.0 |
| pytest / pytest-cov | 8.4.1 / 6.2.1 | MIT |
| Ruff | 0.12.7 | MIT |
| mypy | 1.17.1 | MIT |
| Terraform Google provider | lockfile-selected | MPL-2.0 |

Lucide icons are bundled through `lucide-react`; no remote icon or font assets
are loaded by the console.

## Open-source research snapshots

Solvan's development referenced a number of third-party repositories read-only,
under licences ranging from Apache-2.0 and MIT to source-available terms. None
is a dependency, none is vendored, and no source was copied into Solvan. Every
such reference was study-only, and the snapshot manifest recording each
repository and its exact commit is retained privately rather than published
here.

## Pre-existing work and generated assets

- `solvan v0.3.md` is the project-authored product-vision input from which the
  competition specification pack was derived.
- Ruhu is a separate pre-existing design-partner project. Solvan contains only
  a least-privilege integration profile; no Ruhu source code is vendored.
- The application, release harness, specifications, console, Terraform, tests,
  architecture image, and submission materials in this repository are Solvan
  project work recorded in Git.
- Local and cloud receipts, repository maps, Terraform plans, screenshots, and
  video captures are generated artifacts. They must retain their exact commit
  and deployment binding when used in the submission.

This file is an attribution/disclosure inventory, not legal advice and not a
replacement for the complete license terms shipped by each dependency.
