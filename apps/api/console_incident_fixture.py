"""The scripted incident queue: one live incident and its settled history.

Held apart from the rest of the console fixture because an incident carries the
whole evidence chain — index, impact, causal sequence, plan, verification — and
that is a different subject from the shell, the fleet, or the release gate.
"""

# ruff: noqa: E501, RUF001 -- fixture copy retains operational typography.

from __future__ import annotations

from typing import Any

from apps.api.console_incident_history import closed_incident
from solvan.application.patch_diff import diff_view

#: The scripted repair. It is a real unified diff so the review surface
#: exercises the same parser the live path uses.
_SCRIPTED_PATCH = """diff --git a/src/payments.py b/src/payments.py
index 3a1f9c2..7d14b09 100644
--- a/src/payments.py
+++ b/src/payments.py
@@ -79,10 +79,12 @@ class PaymentWriter:
     def charge(self, request: ChargeRequest) -> ChargeResult:
         connection = self._pool.acquire()
-        result = self._write(connection, request)
-        if result.failed:
-            raise PaymentError(result.code)
-        self._pool.release(connection)
-        return result
+        try:
+            result = self._write(connection, request)
+            if result.failed:
+                raise PaymentError(result.code)
+            return result
+        finally:
+            self._pool.release(connection)
"""


def scripted_patch_diff() -> dict[str, Any]:
    """Parse the scripted repair with the same parser the live path uses."""

    return diff_view(_SCRIPTED_PATCH)


def incident_fixtures() -> list[dict[str, Any]]:
    """Return the scripted incident queue used by the local harness."""

    return [
        {
            "id": "INC-1042",
            "machine_id": "inc_01J4QZK8Q4J8Q6B95KQY4M9R2S",
            "title": "Elevated payment errors after revision v2.8.1",
            "severity": "SEV2",
            "service": "payments-api",
            "state": "MITIGATED",
            "owner": "Reliability Case REL-0042",
            "age": "18m",
            "next_action": "Approve permanent rollback",
            "impact_summary": "18.4% of payment writes failed for 8m 10s",
            "waiting_on_human": True,
            "environment": "development · europe-west1",
            "workflow_version": 12,
            "detected_at": "11:50:03 UTC",
            "agent_council": [
                {
                    "name": "Incident Supervisor Agent",
                    "role": "Owns investigation planning and hypothesis ranking",
                    "status": "COMPLETE",
                    "detail": "Accepted the durable plan and confirmed the leak rule.",
                    "identity": "incident-supervisor",
                    "budget": "1/1 model · 1/2 tools",
                },
                {
                    "name": "Evidence Agent",
                    "role": "Reads bounded metrics, logs, and traces",
                    "status": "COMPLETE",
                    "detail": "Measured the 18.4% impact and four checked-out connections.",
                    "identity": "evidence-agent",
                    "budget": "1/1 model · 2/3 tools",
                },
                {
                    "name": "Infrastructure Agent",
                    "role": "Reads revision and resource metadata",
                    "status": "COMPLETE",
                    "detail": "Compared v2.8.1 with the known-good pool behavior.",
                    "identity": "infrastructure-agent",
                    "budget": "1/1 model · 2/3 tools",
                },
                {
                    "name": "Execution Agent",
                    "role": "Runs only an authorized, bounded actuator",
                    "status": "COMPLETE",
                    "detail": "Reconciled one payments pool recycle; no traffic change was made.",
                    "identity": "execution-agent",
                    "budget": "0/0 model · 1/1 action",
                },
                {
                    "name": "Verification Agent",
                    "role": "Independently adjudicates recovery",
                    "status": "COMPLETE",
                    "detail": "Observed a clean window and accepted one fresh synthetic payment.",
                    "identity": "verification-agent",
                    "budget": "0/1 model · 2/4 tools",
                },
                {
                    "name": "Workspace Agent",
                    "role": "Proposes a durable repair; never deploys it",
                    "status": "PROPOSED",
                    "detail": "Produced a tested repair proposal awaiting exact human review.",
                    "identity": "workspace-agent",
                    "budget": "1/1 model · 3/4 tools",
                },
            ],
            "causal_chain": [
                {
                    "label": "Fault",
                    "detail": "Revision v2.8.1 retains checked-out database connections.",
                    "status": "observed",
                    "source": "Payments fixture · redacted",
                },
                {
                    "label": "Mechanism",
                    "detail": "Completed requests did not return their connections to the pool on the v2.8.1 path.",
                    "status": "observed",
                    "source": "Evidence Agent · citation-resolved",
                },
                {
                    "label": "Impact",
                    "detail": "The bounded pool reached four connections; later synthetic payments returned HTTP 503.",
                    "status": "observed",
                    "source": "Cloud Monitoring · fresh 22s",
                },
                {
                    "label": "Bounded recovery",
                    "detail": "The private actuator moved pool generation 1 → 2 once and reconciled its effect.",
                    "status": "action",
                    "source": "ACT-1042 · execution receipt",
                },
                {
                    "label": "Current outcome",
                    "detail": "Payment recovery passed independently; the defective revision still needs approved rollback.",
                    "status": "verified",
                    "source": "VER-1042 · immutable profile",
                },
            ],
            "brief": {
                "situation": "Payment writes are serving again after a bounded pool recycle; the defective revision remains deployed.",
                "impact": "18.4% synthetic payment failures at peak; no duplicate charges observed.",
                "customer_window": "Payment writes failed for 8m 10s, from 11:50:03 to 11:58:13 UTC.",
                "data_loss": "No payment was recorded twice. Every rejected write returned HTTP 503 before the ledger was touched.",
                "impact_lines": [
                    {
                        "metric": "18.4% error ratio",
                        "scope": "POST /v1/payments",
                        "detail": "peak at 11:51:40; baseline 0.0%",
                        "citation": "evd_…8M1A",
                    },
                    {
                        "metric": "2.7 s p95 latency",
                        "scope": "POST /v1/payments",
                        "detail": "33× the 82 ms healthy baseline",
                        "citation": "evd_…F03K",
                    },
                    {
                        "metric": "4 of 4 connections held",
                        "scope": "payments-admin / connection-pool",
                        "detail": "pool ceiling reached; the fifth request had nowhere to go",
                        "citation": "evd_…A12B",
                    },
                    {
                        "metric": "0 downstream services",
                        "scope": "checkout-api, ledger-writer",
                        "detail": "the bounded pool contained the fault to payments-api",
                        "citation": "evd_…C77D",
                    },
                ],
                "last_verified": "Fresh synthetic payment committed once at 12:05:41 UTC.",
                "root_cause": "Confirmed: revision v2.8.1 leaks database connections on the payment path.",
                "attention": "Approval required for an exact traffic rollback to v2.8.0.",
                "next": "Payments owner reviews ACT-1043 before 12:28 UTC.",
                "freshness": "Committed event 47 · refreshed 22s ago",
                "citations": ["evd_…8M1A", "evd_…F03K", "ver_…7Q2C"],
                "memories": ["mem_…2D8P"],
            },
            "feed": {
                "sequence": "42–47",
                "last_event": 47,
                "lease": "Healthy · renewed 41s ago",
            },
            # Every ref cited anywhere on this incident, resolved once. A
            # citation the console cannot resolve to a record here is
            # rendered as unresolved rather than as a confident chip.
            "evidence_index": [
                {
                    "ref": "evd_…8M1A",
                    "kind": "metric",
                    "label": "Payment error ratio rose 0.0% → 18.4%",
                    "source": "Cloud Monitoring · payments-api",
                    "window": "11:49:12 – 11:52:12 UTC",
                    "freshness": "fresh · 22s old",
                    "classification": "INTERNAL",
                    "content_ref": "gs://scripted-demo/evidence/error-ratio.json",
                },
                {
                    "ref": "evd_…F03K",
                    "kind": "metric",
                    "label": "p95 latency rose 82 ms → 2.7 s",
                    "source": "Cloud Monitoring · payments-api",
                    "window": "11:49:12 – 11:52:12 UTC",
                    "freshness": "fresh · 22s old",
                    "classification": "INTERNAL",
                    "content_ref": "gs://scripted-demo/evidence/latency-p95.json",
                },
                {
                    "ref": "evd_…A12B",
                    "kind": "log",
                    "label": "Four payment requests completed without returning a connection",
                    "source": "Payments fixture · redacted",
                    "window": "11:50:41 – 11:51:44 UTC",
                    "freshness": "fresh · 1m old",
                    "classification": "INTERNAL · redacted",
                    "content_ref": "gs://scripted-demo/evidence/pool-checkout.log",
                },
                {
                    "ref": "evd_…C77D",
                    "kind": "trace",
                    "label": "No error propagated past payments-api to checkout or ledger",
                    "source": "Cloud Trace · 1,204 spans",
                    "window": "11:49:00 – 11:59:00 UTC",
                    "freshness": "fresh · 3m old",
                    "classification": "INTERNAL",
                    "content_ref": "gs://scripted-demo/evidence/downstream-spans.json",
                },
                {
                    "ref": "ver_…7Q2C",
                    "kind": "synthetic",
                    "label": "One fresh synthetic payment committed after the recycle",
                    "source": "Verification Agent · payments-recovery-v1",
                    "window": "12:05:41 UTC",
                    "freshness": "fresh · 22s old",
                    "classification": "INTERNAL",
                    "content_ref": "gs://scripted-demo/evidence/synthetic-payment.json",
                },
                {
                    "ref": "rcp_…98F2",
                    "kind": "receipt",
                    "label": "Pool generation moved 1 → 2 exactly once",
                    "source": "Execution receipt · ACT-1042",
                    "window": "11:58:10 – 11:58:13 UTC",
                    "freshness": "immutable",
                    "classification": "INTERNAL",
                    "content_ref": "gs://scripted-demo/receipts/act-1042.json",
                },
            ],
            "plan": {
                "version": 2,
                "progress": "3 completed · 1 running · 1 pending",
                "steps": [
                    {
                        "marker": "✓",
                        "name": "Confirm customer-path impact",
                        "purpose": "Measure bounded service telemetry",
                        "agent": "Evidence Agent · r17",
                        "status": "COMPLETED",
                        "dependencies": "none",
                        "budget": "2/3 tools · 1/1 model",
                        "evidence_delta": "+3",
                        "trace": "trace …a91c",
                    },
                    {
                        "marker": "✓",
                        "name": "Inspect revision and pool state",
                        "purpose": "Read metadata only",
                        "agent": "Infrastructure Agent · r09",
                        "status": "COMPLETED",
                        "dependencies": "impact",
                        "budget": "2/3 tools · 1/1 model",
                        "evidence_delta": "+2",
                        "trace": "trace …bc22",
                    },
                    {
                        "marker": "✓",
                        "name": "Test leak hypothesis",
                        "purpose": "Correlate bounded evidence",
                        "agent": "Supervisor · r21",
                        "status": "COMPLETED",
                        "dependencies": "impact, metadata",
                        "budget": "1/2 tools · 1/1 model",
                        "evidence_delta": "+1",
                        "trace": "trace …d730",
                    },
                    {
                        "marker": "~",
                        "name": "Prepare permanent rollback",
                        "purpose": "Bind known-good revision and policy",
                        "agent": "Coordinator",
                        "status": "AWAITING_APPROVAL",
                        "dependencies": "confirmed hypothesis",
                        "budget": "0/1 tools · 0/0 model",
                        "evidence_delta": "+0",
                        "trace": "audit …4f19",
                    },
                    {
                        "marker": " ",
                        "name": "Verify permanent repair",
                        "purpose": "Independent observation window",
                        "agent": "Verification Agent · planned",
                        "status": "PENDING",
                        "dependencies": "rollback reconciled",
                        "budget": "0/4 tools · 0/1 model",
                        "evidence_delta": "+0",
                        "trace": "not started",
                    },
                ],
            },
            "guidance": {
                "selection_id": "gsl_…D31A",
                "revision": "payments.connection-exhaustion@1",
                "name": "Payment connection exhaustion",
                "role": "PRIMARY",
                "revision_hash": "sha256:8ac4…17e2",
                "profile": "evidence.ruhu-observability.v1@1",
                "steps": [
                    {
                        "key": "observe-errors",
                        "title": "Observe bounded payment errors",
                        "kind": "OBSERVE",
                        "status": "SATISFIED",
                        "predicate": "evidence-kind-present@1",
                        "reason": None,
                        "citations": ["evd_…8M1A", "evd_…F03K"],
                        "tool_receipts": ["tcl_…A91C"],
                    },
                    {
                        "key": "resolve-graph",
                        "title": "Resolve the approved production binding",
                        "kind": "CHECKPOINT",
                        "status": "SATISFIED",
                        "predicate": "production-graph-binding-resolved@1",
                        "reason": None,
                        "citations": ["pgs_…01"],
                        "tool_receipts": [],
                    },
                    {
                        "key": "verify-recovery",
                        "title": "Require independent recovery evidence",
                        "kind": "CHECKPOINT",
                        "status": "SATISFIED",
                        "predicate": "verification-profile-passed@1",
                        "reason": None,
                        "citations": ["ver_…7Q2C"],
                        "tool_receipts": [],
                    },
                ],
            },
            "findings": {
                "validated": [
                    {
                        "title": "Database pool reached its four-connection ceiling",
                        "statement": "Checked-out connections increased from 0 to 4 during the 60-second fault window; the fifth synthetic request returned HTTP 503.",
                        "source": "Cloud Monitoring · fresh 22s",
                        "citations": ["evd_…8M1A", "evd_…F03K"],
                    },
                    {
                        "title": "Revision v2.8.1 retains connections",
                        "statement": "Four completed payment requests remained checked out after response completion; v2.8.0 baseline returned each connection.",
                        "source": "Payments fixture · redacted",
                        "citations": ["evd_…A12B"],
                    },
                ],
                "inferred": [
                    {
                        "title": "Leak may affect other write endpoints",
                        "statement": "The shared pool suggests adjacent write handlers could be exposed; those paths were not exercised.",
                        "source": "Supervisor inference",
                        "citations": [],
                    },
                ],
            },
            "hypotheses": [
                {
                    "state": "CONFIRMED",
                    "label": "Connection leak in v2.8.1",
                    "confidence": "high",
                    "score": "0.94",
                    "rule": "connection-leak-confirmation-v1",
                },
                {
                    "state": "CONTRADICTED",
                    "label": "Cloud SQL capacity exhaustion",
                    "confidence": "low",
                    "score": "0.12",
                    "rule": "fresh capacity evidence",
                },
            ],
            "actions": [
                {
                    "id": "ACT-1042",
                    "name": "Recycle payments DB connection pool",
                    "status": "VERIFIED",
                    "phase": "Verified",
                    "target": "payments-admin / connection-pool",
                    "change": "pool-generation-1 → pool-generation-2",
                    "risk": "MEDIUM · bounded autonomous",
                    "blast_radius": "payments-api only",
                    "policy": "payments-pool-recycle-v1",
                    "receipt": "rcp_…98F2 · effect reconciled",
                    "verification": "VER-1042 · passed",
                },
                {
                    "id": "ACT-1043",
                    "name": "Rollback Cloud Run traffic",
                    "status": "AWAITING_APPROVAL",
                    "phase": "Awaiting approval",
                    "target": "projects/solvan-demo/locations/europe-west1/services/payments-api",
                    "change": "v2.8.1 (100%) → v2.8.0 (100%)",
                    "risk": "HIGH · human approval",
                    "blast_radius": "all new payments requests",
                    "policy": "cloud-run-rollback-v3",
                    "digest": "sha256:7d14…09ac",
                    "expected_version": "v2.8.1 · target epoch 7",
                    "expected_effect": (
                        "Replace 100% of payments-api traffic from v2.8.1 to v2.8.0."
                    ),
                    "expected_effect_hash": "sha256:91ce…7a20",
                    "evidence_version": "incident evidence 8 · policy 3",
                    "expires": "12:28:00 UTC · 19m remaining",
                    "verification": "payments-recovery-v1",
                    "rollback_plan": "Restore v2.8.1 traffic only after a separate exact approval.",
                },
            ],
            "verification": {
                "id": "VER-1042",
                "verdict": "PASSED",
                "profile": "payments-recovery-v1 · version 1",
                "owner": "payments-sre",
                "binding": "production graph pgs_…01 / connection_exhaustion",
                "signals": [],
                "window": "11:40–12:05:13",
                "intervals": [
                    {
                        "name": "Healthy baseline",
                        "window": "11:40–11:45",
                        "error_ratio": "0.0%",
                        "p95": "82 ms",
                        "result": "context only",
                    },
                    {
                        "name": "Fault",
                        "window": "11:49–11:52",
                        "error_ratio": "18.4%",
                        "p95": "2.7 s",
                        "result": "threshold breached",
                    },
                    {
                        "name": "Mutation",
                        "window": "11:58:10–11:58:13",
                        "error_ratio": "—",
                        "p95": "—",
                        "result": "effect reconciled",
                    },
                    {
                        "name": "Warmup",
                        "window": "11:58:13–12:00:13",
                        "error_ratio": "1.2%",
                        "p95": "190 ms",
                        "result": "excluded",
                    },
                    {
                        "name": "Observation",
                        "window": "12:00:13–12:05:13",
                        "error_ratio": "0.0%",
                        "p95": "91 ms",
                        "result": "passed",
                    },
                ],
                "threshold": "error ratio < 2.0% for 5m · immutable profile",
                "synthetic": "payment syn_…3A1 committed once at 12:05:41",
            },
            "series": {
                "signal_kind": "",
                "points": [],
                "markers": [],
                "window_band": None,
                "objective": "",
                "evidence_refs": [],
            },
            "phase_rail": [
                {"name": "Detect", "duration": "3s", "state": "done"},
                {"name": "Investigate", "duration": "1m 47s", "state": "done"},
                {"name": "Diagnose", "duration": "52s", "state": "done"},
                {"name": "Propose", "duration": "11s", "state": "done"},
                {"name": "Await approval", "duration": "4m 02s", "state": "done"},
                {"name": "Mitigate", "duration": "3s", "state": "done"},
                {"name": "Verify", "duration": "5m 12s", "state": "current"},
            ],
            "timeline": [
                {
                    "time": "11:50:03",
                    "actor": "Detection rule",
                    "event": "Sustained HTTP 5xx threshold breached",
                    "state": "DETECTED · v1",
                    "kind": "danger",
                },
                {
                    "time": "11:50:06",
                    "actor": "Coordinator",
                    "event": "Investigation plan v1 committed before dispatch",
                    "state": "INVESTIGATING · v3",
                    # Deterministic dispatch, not model activity.
                    "kind": "info",
                },
                {
                    "time": "11:52:31",
                    "actor": "Supervisor r21",
                    "event": "Root cause confirmed by named rule",
                    "state": "ROOT_CAUSE_CONFIRMED · v7",
                    "kind": "provenance",
                },
                {
                    "time": "11:58:13",
                    "actor": "Private actuator",
                    "event": "Pool recycle effect reconciled; recovery not yet claimed",
                    "state": "VERIFYING_MITIGATION · v10",
                    "kind": "info",
                },
                {
                    "time": "12:05:41",
                    "actor": "Independent verifier",
                    "event": "Observation window and fresh synthetic probe passed",
                    "state": "MITIGATED · v12",
                    "kind": "success",
                },
                {
                    "time": "12:06:04",
                    "actor": "Case scheduler",
                    "event": "REL-0042 opened; next wake-up durably scheduled",
                    "state": "MITIGATED · v12",
                    "kind": "neutral",
                },
            ],
        },
        closed_incident(
            display_id="INC-1039",
            title="Checkout latency regression after cache eviction change",
            service="checkout-api",
            severity="SEV3",
            age="2d",
            impact_summary="p95 latency doubled for 21m; no requests failed",
            mechanism="A narrowed cache key evicted warm entries on every deploy.",
            mitigation="Restored the previous cache key policy",
        ),
        closed_incident(
            display_id="INC-1036",
            title="Ledger writer fell behind after a partition rebalance",
            service="ledger-writer",
            severity="SEV3",
            age="6d",
            impact_summary="Write lag peaked at 4m 30s; nothing was lost",
            mechanism="Consumer lag grew while a rebalance held two partitions unassigned.",
            mitigation="Scaled consumers and let the backlog drain",
        ),
    ]
