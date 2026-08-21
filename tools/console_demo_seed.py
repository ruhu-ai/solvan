"""Demonstration records for the local console, written as durable rows.

The console renders one projection everywhere, so a local harness cannot be
given a story by rendering different code. It is given one by seeding the same
tables a deployment writes, and the projection derives the screens from them
exactly as it would in production. What differs from a deployment is the data
and the authority, never the code path.

This is demonstration data and says so: identifiers are visibly synthetic,
evidence references point at `demo://` rather than a bucket, and nothing here is a
capability probe, an approval receipt, or cloud release evidence. Seeding is
idempotent — every write is keyed and conflict-skipped — so a restart against a
retained volume changes nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

SCOPE_KEYS = ("organization_id", "project_id", "environment_id")

INCIDENT_ID = "inc_11111111111111111111111111"
SERVICE_ID = "svc_00000000000000000000000000"
GRAPH_ID = "pgs_00000000000000000000000000"
PLAN_ID = "ipl_00000000000000000000000001"
#: Six evidence records, one per read the triage flow actually makes.
EVIDENCE = (
    (
        "evd_00000000000000000000000001",
        "CLOUD_MONITORING",
        "payments-api/http_5xx_ratio",
        "Server error ratio over the incident window.",
    ),
    (
        "evd_00000000000000000000000002",
        "CLOUD_MONITORING",
        "payments-api/db_pool_utilization",
        "Connection-pool utilization against the frozen healthy baseline.",
    ),
    (
        "evd_00000000000000000000000003",
        "CLOUD_MONITORING",
        "payments-api/db_pool_acquire_wait_ms",
        "Pool acquisition wait, the signature that leads the latency curve.",
    ),
    (
        "evd_00000000000000000000000004",
        "CLOUD_LOGGING",
        "payments-api/checkout-errors",
        "Registered timeout signature on the checkout path.",
    ),
    (
        "evd_00000000000000000000000005",
        "CLOUD_TRACE",
        "payments-api/POST-v1-payments",
        "One incident-bound trace showing time spent waiting on a connection.",
    ),
    (
        "evd_00000000000000000000000006",
        "CLOUD_RUN",
        "payments-api/revision-v2.8.1",
        "Deployment metadata for the revision the regression begins with.",
    ),
)
STEPS = (
    ("read-error-ratio", 1, "evidence-agent", "Establish the error ratio and its shape."),
    ("read-pool-utilization", 2, "evidence-agent", "Compare pool utilization with baseline."),
    ("read-acquisition-wait", 3, "evidence-agent", "Read acquisition wait and timeout counts."),
    ("read-change-history", 4, "infrastructure-agent", "Correlate onset with the rollout."),
)


def _hash(seed: str) -> str:
    """A visibly synthetic content hash of the right shape."""

    import hashlib

    return f"sha256:{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"


def _scope_values(scope: tuple[str, str, str]) -> dict[str, str]:
    return dict(zip(SCOPE_KEYS, scope, strict=True))


def seed_investigation(
    connection: psycopg.Connection[Any], *, scope: tuple[str, str, str], detected_at: datetime
) -> int:
    """Write the plan, reads, and inferences the incident screens stand on.

    The projection derives the investigation map, the evidence ledger, the
    citations, and the operator brief from these rows. Seeding them is what
    makes those screens show a real derivation rather than an empty state.
    """

    values = _scope_values(scope)
    written = 0
    for index, (step_key, ordinal, agent_key, _purpose) in enumerate(STEPS):
        run_id = _run_id(index)
        started = detected_at + timedelta(minutes=ordinal)
        connection.execute(
            """INSERT INTO solvan.agent_runs
                 (organization_id,project_id,environment_id,id,incident_id,logical_step_key,
                  agent_key,agent_resource,agent_revision,invocation_id,workflow_version,
                  attempt,status,deadline,budget_json,input_ref,input_hash,output_ref,
                  output_hash,started_at,completed_at,trace_id,span_id)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(incident_id)s,%(step_key)s,%(agent_key)s,%(resource)s,
                  'local-development',%(invocation)s,1,1,'SUCCEEDED',%(deadline)s,
                  %(budget)s,%(input_ref)s,%(input_hash)s,%(output_ref)s,%(output_hash)s,
                  %(started)s,%(completed)s,%(trace)s,%(span)s)
               ON CONFLICT DO NOTHING""",
            {
                **values,
                "id": run_id,
                "incident_id": INCIDENT_ID,
                "step_key": step_key,
                "agent_key": agent_key,
                "resource": f"demo://agents/{agent_key}",
                "invocation": f"demo-{step_key}",
                "deadline": started + timedelta(minutes=5),
                "budget": Jsonb({"maximum_tool_requests": 3, "maximum_wall_clock_ms": 300_000}),
                "input_ref": f"demo://runs/{step_key}/input.json",
                "input_hash": _hash(f"demo-input-{step_key}"),
                "output_ref": f"demo://runs/{step_key}/output.json",
                "output_hash": _hash(f"demo-output-{step_key}"),
                "started": started,
                "completed": started + timedelta(seconds=40),
                "trace": f"{index + 1:032x}",
                "span": f"{index + 1:016x}",
            },
        )
        written += 1
    # The plan cites the run that authored it, and a step cites the plan, so the
    # runs are written first. The order is the foreign keys, not a preference.
    connection.execute(
        """INSERT INTO solvan.investigation_plans
             (organization_id,project_id,environment_id,id,incident_id,plan_version,
              objective,completion_condition,uncertainties_json,content_hash,status,
              created_by_agent_run_id,created_at)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(plan_id)s,
              %(incident_id)s,1,
              'Establish whether payment failures are caused by connection-pool exhaustion.',
              'A confirmed mechanism with cited evidence, or an exhausted read budget.',
              %(uncertainties)s,%(hash)s,'ACCEPTED',%(run_id)s,%(created_at)s)
           ON CONFLICT DO NOTHING""",
        {
            **values,
            "plan_id": PLAN_ID,
            "incident_id": INCIDENT_ID,
            "uncertainties": Jsonb(
                ["Whether the pool ceiling or a leaked connection is the proximate cause."]
            ),
            "hash": _hash("demo-plan-1"),
            "run_id": _run_id(0),
            "created_at": detected_at + timedelta(seconds=30),
        },
    )
    for index, (step_key, ordinal, agent_key, purpose) in enumerate(STEPS):
        run_id = _run_id(index)
        started = detected_at + timedelta(minutes=ordinal)
        connection.execute(
            """INSERT INTO solvan.investigation_steps
                 (organization_id,project_id,environment_id,id,plan_id,step_key,ordinal,
                  kind,agent_key,agent_resource,agent_revision,current_agent_run_id,
                  allowed_tool_names_json,scope_ref,purpose,required,depends_on_json,
                  budget_json,status,result_ref,evidence_delta_count,started_at,completed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(plan_id)s,%(step_key)s,%(ordinal)s,'INVOKE_AGENT',%(agent_key)s,%(resource)s,
                  'local-development',%(run_id)s,%(tools)s,%(scope_ref)s,%(purpose)s,true,
                  %(depends)s,%(budget)s,'SUCCEEDED',%(result_ref)s,%(delta)s,
                  %(started)s,%(completed)s)
               ON CONFLICT DO NOTHING""",
            {
                **values,
                "id": f"ist_0000000000000000000000000{ordinal}",
                "plan_id": PLAN_ID,
                "step_key": step_key,
                "ordinal": ordinal,
                "agent_key": agent_key,
                "resource": f"demo://agents/{agent_key}",
                "run_id": run_id,
                "tools": Jsonb(["cloud_monitoring_query", "cloud_logging_query"]),
                "scope_ref": f"service:{SERVICE_ID}",
                "purpose": purpose,
                "depends": Jsonb([STEPS[index - 1][0]] if index else []),
                "budget": Jsonb({"maximum_tool_requests": 3}),
                "result_ref": f"demo://runs/{step_key}/output.json",
                "delta": 2 if index < 3 else 0,
                "started": started,
                "completed": started + timedelta(seconds=40),
            },
        )
        written += 1
    for index, (evidence_id, source_kind, resource, _summary) in enumerate(EVIDENCE):
        window_start = detected_at - timedelta(minutes=10)
        connection.execute(
            """INSERT INTO solvan.evidence_items
                 (organization_id,project_id,environment_id,id,incident_id,source_kind,
                  source_resource,query_spec_json,window_start,window_end,observed_at,
                  content_ref,content_hash,classification,residency,
                  redaction_manifest_ref,provenance_json,freshness_expires_at,
                  created_by_agent_run_id)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(incident_id)s,%(source_kind)s,%(resource)s,%(query)s,%(start)s,
                  %(end)s,%(observed)s,%(content_ref)s,%(content_hash)s,'INTERNAL',
                  'europe-west1',%(redaction)s,%(provenance)s,%(expires)s,%(run_id)s)
               ON CONFLICT DO NOTHING""",
            {
                **values,
                "id": evidence_id,
                "incident_id": INCIDENT_ID,
                "source_kind": source_kind,
                "resource": resource,
                "query": Jsonb({"kind": "bounded_window", "resource": resource}),
                "start": window_start,
                "end": detected_at,
                "observed": detected_at + timedelta(minutes=index + 1),
                "content_ref": f"demo://evidence/{evidence_id}.json",
                "content_hash": _hash(f"demo-evidence-{evidence_id}"),
                "redaction": f"demo://redaction/{evidence_id}.json",
                "provenance": Jsonb(
                    {"tool": "cloud_monitoring_query@1", "connection": "demo-local"}
                ),
                "expires": detected_at + timedelta(days=7),
                "run_id": _run_id(min(index, len(STEPS) - 1)),
            },
        )
        written += 1
    _seed_findings(connection, values=values, detected_at=detected_at)
    return written


def _run_id(index: int) -> str:
    return f"run_0000000000000000000000000{index + 1}"


def _seed_findings(
    connection: psycopg.Connection[Any], *, values: dict[str, str], detected_at: datetime
) -> None:
    """Observations, the inference they support, and the confirmed mechanism."""

    findings = (
        (
            "fnd_00000000000000000000000001",
            "error-ratio-elevated",
            "OBSERVATION",
            "Payment write error ratio rose from 0.0% to 18.4% and stayed there for 8m 10s.",
            ("evd_00000000000000000000000001",),
        ),
        (
            "fnd_00000000000000000000000002",
            "pool-saturated",
            "OBSERVATION",
            "Connection-pool utilization held above 90% for 4m 30s against a 41% baseline.",
            ("evd_00000000000000000000000002", "evd_00000000000000000000000003"),
        ),
        (
            "fnd_00000000000000000000000003",
            "onset-follows-rollout",
            "INFERENCE",
            "Saturation begins 40s after revision v2.8.1 takes traffic, and no other change "
            "landed in the window.",
            ("evd_00000000000000000000000006", "evd_00000000000000000000000004"),
        ),
    )
    for finding_id, key, kind, statement, citations in findings:
        connection.execute(
            """INSERT INTO solvan.findings
                 (organization_id,project_id,environment_id,id,incident_id,agent_run_id,
                  finding_key,revision,kind,statement,confidence_score,content_hash,created_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(incident_id)s,%(run_id)s,%(key)s,1,%(kind)s,%(statement)s,0.9,
                  %(hash)s,%(created_at)s)
               ON CONFLICT DO NOTHING""",
            {
                **values,
                "id": finding_id,
                "incident_id": INCIDENT_ID,
                "run_id": _run_id(0),
                "key": key,
                "kind": kind,
                "statement": statement,
                "hash": _hash(f"demo-finding-{key}"),
                "created_at": detected_at + timedelta(minutes=5),
            },
        )
        for evidence_id in citations:
            connection.execute(
                """INSERT INTO solvan.finding_evidence
                     (organization_id,project_id,environment_id,finding_id,evidence_id,
                      relationship)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(finding_id)s,%(evidence_id)s,'SUPPORTS')
                   ON CONFLICT DO NOTHING""",
                {**values, "finding_id": finding_id, "evidence_id": evidence_id},
            )
    # A hypothesis may only cite a confirmation rule that exists: what counts as
    # confirmation is decided before the evidence, not chosen to fit it.
    connection.execute(
        """INSERT INTO solvan.confirmation_rules
             (organization_id,project_id,environment_id,id,version,incident_class,
              required_observations_json,contradiction_policy,status,approved_by,approved_at)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
              'connection-exhaustion-confirmation',1,'connection_exhaustion',
              %(required)s,'REJECT','APPROVED','local-development-owner',%(approved_at)s)
           ON CONFLICT DO NOTHING""",
        {
            **values,
            "required": Jsonb(
                [
                    "Sustained pool utilization above 90% for 60 seconds or more.",
                    "Rising acquisition wait correlated with the error ratio.",
                ]
            ),
            "approved_at": detected_at,
        },
    )
    hypotheses = (
        (
            "hyp_00000000000000000000000001",
            "connection-leak",
            "The checkout error path does not release its pooled connection, so the bounded "
            "pool is exhausted under normal concurrency.",
            "CONFIRMED",
        ),
        (
            "hyp_00000000000000000000000002",
            "pool-too-small",
            "Normal concurrency exceeds the configured pool size.",
            "CONTRADICTED",
        ),
    )
    for hypothesis_id, cause_key, statement, state in hypotheses:
        connection.execute(
            """INSERT INTO solvan.hypotheses
                 (organization_id,project_id,environment_id,id,incident_id,statement,
                  normalized_cause_key,revision,status,supporting_evidence_refs,
                  contradicting_evidence_refs,confidence_score,confirmation_rule_id,
                  confirmation_rule_version,confirmed_at,created_by_run_id)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(incident_id)s,%(statement)s,%(cause_key)s,1,%(status)s,%(supporting)s,
                  %(contradicting)s,%(confidence)s,'connection-exhaustion-confirmation',1,
                  %(confirmed_at)s,%(run_id)s)
               ON CONFLICT DO NOTHING""",
            {
                **values,
                "id": hypothesis_id,
                "incident_id": INCIDENT_ID,
                "statement": statement,
                "cause_key": cause_key,
                "status": state,
                "supporting": Jsonb(
                    ["evd_00000000000000000000000002", "evd_00000000000000000000000005"]
                    if state == "CONFIRMED"
                    else ["evd_00000000000000000000000001"]
                ),
                "contradicting": Jsonb(
                    [] if state == "CONFIRMED" else ["evd_00000000000000000000000002"]
                ),
                "confidence": 0.92 if state == "CONFIRMED" else 0.15,
                "confirmed_at": (
                    detected_at + timedelta(minutes=6) if state == "CONFIRMED" else None
                ),
                "run_id": _run_id(1),
            },
        )


def seed_console_demo_records(
    connection: psycopg.Connection[Any], *, scope: tuple[str, str, str]
) -> int:
    """Seed every demonstration record the console projection reads."""

    detected = connection.execute(
        """SELECT detected_at FROM solvan.incidents
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s AND id=%s""",
        (*scope, INCIDENT_ID),
    ).fetchone()
    if detected is None:
        return 0
    detected_at = detected[0]
    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=UTC)
    return seed_investigation(connection, scope=scope, detected_at=detected_at)
