"""UTC daily spend counters for conversation turns.

Per-turn ceilings bound one answer; these bound a day of them, so a thread
cannot be walked into unbounded provider spend one small question at a time.
Kept apart from the turn runtime because they answer a different question:
not "may this attempt proceed" but "what has this thread and this person
already spent today". Specification 14 §11.3.
"""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.domain import Scope


def record_daily_usage(
    connection: Connection[Any],
    *,
    scope: Scope,
    thread_id: str,
    principal: str,
    model_calls: int,
    tool_calls: int,
    tokens: int,
) -> None:
    """Add one turn's usage to the UTC daily counters (§11.3).

    Aborted and failed model calls consume budget, so this is called on every
    terminal outcome rather than only on a completed answer. The counters are
    additive under the row lock, so concurrent lanes cannot lose a turn's spend.
    """

    for subject_kind, subject_id in (("THREAD", thread_id), ("PRINCIPAL", principal)):
        connection.execute(
            """INSERT INTO solvan_liaison.liaison_budget_counters (
                  organization_id,project_id,environment_id,subject_kind,subject_id,
                  window_date,model_calls,tool_calls,tokens)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                  %(subject_kind)s,%(subject_id)s,(now() AT TIME ZONE 'utc')::date,
                  %(model_calls)s,%(tool_calls)s,%(tokens)s)
               ON CONFLICT (organization_id,project_id,environment_id,
                            subject_kind,subject_id,window_date)
               DO UPDATE SET
                 model_calls = solvan_liaison.liaison_budget_counters.model_calls
                               + EXCLUDED.model_calls,
                 tool_calls = solvan_liaison.liaison_budget_counters.tool_calls
                              + EXCLUDED.tool_calls,
                 tokens = solvan_liaison.liaison_budget_counters.tokens + EXCLUDED.tokens""",
            {
                **scope.canonical_dict(),
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "model_calls": max(0, model_calls),
                "tool_calls": max(0, tool_calls),
                "tokens": max(0, tokens),
            },
        )


def daily_model_calls(
    connection: Connection[Any], *, scope: Scope, thread_id: str, principal: str
) -> tuple[int, int]:
    """Today's model calls for this thread and this principal, in that order."""

    rows = connection.execute(
        """SELECT subject_kind,model_calls FROM solvan_liaison.liaison_budget_counters
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s
              AND window_date=(now() AT TIME ZONE 'utc')::date
              AND ((subject_kind='THREAD' AND subject_id=%(thread_id)s)
                OR (subject_kind='PRINCIPAL' AND subject_id=%(principal)s))""",
        {**scope.canonical_dict(), "thread_id": thread_id, "principal": principal},
    ).fetchall()
    counted = {str(kind): int(value) for kind, value in rows}
    return counted.get("THREAD", 0), counted.get("PRINCIPAL", 0)
