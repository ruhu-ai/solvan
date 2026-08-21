# Observability and OpenTelemetry reference

Status: design input with Google platform constraints in the source register  
Retrieved: 2026-08-09

## Primary sources

- [Google Cloud observability for AI agents](https://docs.cloud.google.com/gemini-enterprise-agent-platform/optimize/observability/overview)
- [Instrument ADK with OpenTelemetry](https://docs.cloud.google.com/stackdriver/docs/instrumentation/ai-agent-adk)
- [Google Cloud SLO and alert dashboards](https://docs.cloud.google.com/stackdriver/docs/solutions/slo-monitoring/ui/svc-dashboard)
- [OpenTelemetry documentation](https://opentelemetry.io/docs/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)

## Design consequences

- Use traces, metrics, and logs together; no single telemetry stream is the
  complete incident record.
- Correlate incident, case, agent run, action, verification, and audit IDs.
- Keep prompts, responses, credentials, raw PII, and private chain-of-thought
  out of span attributes unless an explicit, authorized redaction policy says
  otherwise.
- Display telemetry freshness and source scope. A local trace is not a cloud
  receipt, and an observability trace is not workflow authority.
- Use meaningful SLIs and SLOs for health; do not turn every metric into an
  alert or status badge.

## Review questions

- Can an operator move from user impact to the causal signal and then to the
  exact stored evidence?
- Does the trace survive worker retries without creating duplicate authority?
- Are telemetry gaps visible as unknown or inconclusive rather than healthy?
- Are dashboards actionable without exposing sensitive model content?
