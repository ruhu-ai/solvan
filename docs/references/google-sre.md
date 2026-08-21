# Google SRE reference

Status: design input  
Retrieved: 2026-08-09  
Primary source: [Google SRE Book](https://sre.google/sre-book/) and [Google SRE Workbook](https://sre.google/workbook/)

## Sections used by Solvan

| Topic | Source | Solvan application |
|---|---|---|
| Service-level objectives | [SLOs](https://sre.google/sre-book/service-level-objectives/) | Define health from a small set of meaningful indicators; show thresholds, windows, and error-budget context rather than a generic green light. |
| Monitoring and alerting | [Practical alerting](https://sre.google/sre-book/practical-alerting/) | A signal must identify a condition and the action or owner it requires. Avoid dashboards that make an operator interpret ambiguous alerts. |
| Incident response | [Managing incidents](https://sre.google/sre-book/managing-incidents/) | Keep incident command, evidence, communication, mitigation, and follow-up responsibilities explicit. |
| Toil and automation | [Eliminating toil](https://sre.google/sre-book/eliminating-toil/) | Automate bounded, repeatable work while retaining policy, budget, and verification controls. |
| Postmortems and learning | [Postmortem culture](https://sre.google/sre-book/postmortem-culture/) | Preserve immutable incident history and use recurrence findings to improve controls, not to rewrite prior facts. |
| Monitoring dashboards | [SRE Workbook monitoring](https://sre.google/workbook/monitoring/) | Put user-impacting indicators first, then provide causal detail and links to evidence. |

## Review rules derived for Solvan

- Every displayed health claim names its indicator, scope, observation window,
  freshness, and evidence authority.
- Health is not manually marked by an operator or model.
- A warning or ticket must explain who needs to act and by when; otherwise it is
  logging, not an attention item.
- The console should show the user-facing consequence before infrastructure
  detail.
- Automation must reduce toil without becoming an unbounded control loop.

These are design inputs, not permission to copy Google-specific operating
procedures into a customer environment. Solvan's deterministic policies,
Cloud SQL state, and customer-authored actuator policy remain authoritative.
