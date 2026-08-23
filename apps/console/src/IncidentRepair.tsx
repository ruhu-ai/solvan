/** Verification and permanent-repair surfaces for one incident.
 *
 *  Every governance track here is derived from the record. None of these
 *  components may assert a step happened. */
import { useState } from "react";
import { ShieldCheck, X } from "lucide-react";
import type { ConsoleSnapshot, Incident, StatusTone } from "./types";
import { LabelValue, MonoChip, PageHeader, StatusBadge, phaseClass } from "./components";
import { callApi } from "./api";

/** Violet marks a step that is executing. A step that has not started yet is
 *  not activity, and a fall-through default would paint it as one. */
function workspaceStateLabel(state: string): string {
  const labels: Record<string, string> = {
    OPEN: "Open",
    HIBERNATED: "Hibernated",
    BLOCKED: "Blocked",
    CLOSED: "Closed",
  };
  return labels[state] ?? state.replaceAll("_", " ");
}

function workspaceStateTone(state: string): StatusTone {
  if (state === "BLOCKED") return "warning";
  if (state === "CLOSED") return "neutral";
  return "info";
}

const caseStateLabels: Record<string, { label: string; tone: StatusTone }> = {
  OPEN: { label: "Open", tone: "info" },
  ROOT_CAUSE_ANALYSIS: { label: "Root cause analysis", tone: "agent" },
  BLOCKED: { label: "Blocked", tone: "warning" },
  REPAIR_PLANNED: { label: "Repair planned", tone: "info" },
  REPAIR_IN_PROGRESS: { label: "Repair in progress", tone: "agent" },
  AWAITING_REVIEW: { label: "Awaiting human review", tone: "warning" },
  READY_FOR_CANARY: { label: "Ready for canary", tone: "info" },
  CANARY_RUNNING: { label: "Canary running", tone: "info" },
  READY_FOR_ROLLOUT: { label: "Ready for rollout", tone: "info" },
  ROLLOUT_RUNNING: { label: "Rollout running", tone: "info" },
  ROLLED_BACK: { label: "Rolled back", tone: "warning" },
  OBSERVING: { label: "Observing for recurrence", tone: "info" },
  REOPENED: { label: "Reopened", tone: "warning" },
  CLOSED_VERIFIED: { label: "Closed and verified", tone: "success" },
  CANCELLED: { label: "Cancelled", tone: "neutral" },
};

function CaseStateBadge({ state }: { state: string }): React.JSX.Element {
  const mapped = caseStateLabels[state] ?? { label: state.replaceAll("_", " "), tone: "neutral" as StatusTone };
  return <StatusBadge label={mapped.label} tone={mapped.tone} machine={state} />;
}


/** How one verification verdict reads to an operator.
 *
 *  The label and tone are derived, never asserted. A verdict the console does
 *  not recognise reads as unverified rather than inheriting the passing look —
 *  the console must not be the thing that claims recovery happened. */
function verificationPresentation(verdict: string): { label: string; tone: StatusTone; headline: string; detail: string } {
  if (verdict === "VERIFIED" || verdict === "PASSED") {
    return {
      label: "Verification passed",
      tone: "success",
      headline: "Recovery independently verified",
      detail: "The connector receipt did not decide this verdict. Fresh telemetry and a synthetic payment passed the immutable profile.",
    };
  }
  if (verdict === "FAILED") {
    return {
      label: "Verification failed",
      tone: "danger",
      headline: "Recovery was not verified",
      detail: "The independent oracle did not meet the immutable profile. Treat the mitigation as unproven and keep the incident open.",
    };
  }
  if (verdict === "INCONCLUSIVE") {
    return {
      label: "Verification inconclusive",
      tone: "warning",
      headline: "Recovery could not be decided",
      detail: "The oracle returned no decisive result against the immutable profile. Recovery is unproven until it runs again.",
    };
  }
  return {
    label: verdict ? `Verification ${verdict.toLowerCase()}` : "Verification pending",
    tone: "neutral",
    headline: "Recovery is not yet verified",
    detail: "No independent verdict has been recorded against the immutable profile for this mitigation.",
  };
}

export function VerificationPanel({ incident }: { incident: Incident }): React.JSX.Element {
  const verification = incident.verification;
  const presentation = verificationPresentation(verification.verdict);
  return <section><div className="verification-header"><div><p className="eyebrow">Independent recovery oracle</p><h2>{verification.id} · mitigation verification</h2><p>{verification.profile} · owner {verification.owner}</p></div><StatusBadge label={presentation.label} tone={presentation.tone} machine={verification.verdict} /></div><div className="verification-summary"><LabelValue label="Resolved binding" value={verification.binding} /><LabelValue label="Immutable threshold" value={verification.threshold} /><LabelValue label="Fresh synthetic probe" value={verification.synthetic} /></div><div className="interval-rail" aria-hidden="true">{verification.intervals.map((interval, index) => <div className={`interval interval-${index}`} key={interval.name}><span>{interval.name}</span></div>)}</div>{verification.intervals.length > 0 && <div className="responsive-table card"><table><caption>Equivalent table for baseline and verification intervals</caption><thead><tr><th>Interval</th><th>Window</th><th>Error ratio</th><th>p95 latency</th><th>Result</th></tr></thead><tbody>{verification.intervals.map((interval) => <tr key={interval.name}><td data-label="Interval">{interval.name}</td><td data-label="Window">{interval.window}</td><td data-label="Error ratio">{interval.error_ratio}</td><td data-label="p95 latency">{interval.p95}</td><td data-label="Result">{interval.result}</td></tr>)}</tbody></table></div>}{verification.signals.length > 0 && <div className="responsive-table card"><table><caption>Signals observed in the verification window · {verification.window}</caption><thead><tr><th>Signal</th><th>Observed</th><th>Objective</th><th>Observed at</th><th>Evidence</th></tr></thead><tbody>{verification.signals.map((signal) => <tr key={signal.signal}><td data-label="Signal">{signal.signal}<br /><span className="muted">{signal.provider_kind}</span></td><td data-label="Observed">{signal.observed_value === null ? "not observed" : signal.observed_value.toLocaleString()}</td><td data-label="Objective">{signal.objective}</td><td data-label="Observed at">{signal.observed_at || "not recorded"}</td><td data-label="Evidence">{signal.citations.length === 0 ? "none recorded" : signal.citations.map((citation) => <MonoChip key={citation}>{citation}</MonoChip>)}</td></tr>)}</tbody></table></div>}<div className="security-note"><span aria-hidden="true"><ShieldCheck size={18} strokeWidth={1.75} /></span><div><strong>{presentation.headline}</strong><p>{presentation.detail}</p></div></div></section>;
}

const REPAIR_PHASES = ["Proposed by workspace", "Deterministic tests passed", "Review approved", "Deployed", "Verified"] as const;

/** How far one permanent repair actually got.
 *
 *  Every step is evidenced: a proposal needs a patch artifact, a passing test
 *  step needs a passing patch status, and review/deploy/verify come from the
 *  case state. A cancelled, blocked or rolled-back case stops rather than
 *  ticking the remaining steps. */
function repairProgress(record: ConsoleSnapshot["cases"][number]): { reached: number; failed: boolean } {
  const state = record.state;
  const proposed = Boolean(record.patch_artifact) && record.patch_artifact !== "not proposed";
  const testsPassed = record.patch_status === "TESTS_PASSED";
  let reached = 0;
  if (proposed) reached = 1;
  if (proposed && testsPassed) reached = 2;
  if (state === "MERGED" || state === "DEPLOYED" || state === "CLOSED_VERIFIED") reached = 3;
  if (state === "DEPLOYED" || state === "CLOSED_VERIFIED") reached = 4;
  if (state === "CLOSED_VERIFIED") reached = 5;
  return { reached, failed: state === "CANCELLED" || state === "BLOCKED" || state === "ROLLED_BACK" };
}

export function PermanentRepair({ caseRecord, authority, apiUrl, onChanged }: { caseRecord: ConsoleSnapshot["cases"][number]; authority: string; apiUrl: string; onChanged: () => void }): React.JSX.Element {
  return <section><div className="section-heading"><div><p className="eyebrow">Linked Reliability Case</p><h2>{caseRecord.id} · permanent repair</h2><p>{caseRecord.repair}</p></div><CaseStateBadge state={caseRecord.state} /></div><div className="verification-summary"><LabelValue label="Immutable repair plan" value={caseRecord.repair_plan} /><LabelValue label="Workspace provider" value={caseRecord.provider} /><LabelValue label="Pinned repository commit" value={caseRecord.commit} /><LabelValue label="Isolated test receipt" value={caseRecord.patch_status} /></div><WorkspaceCognitionPanel record={caseRecord} /><PatchReviewPanel record={caseRecord} authority={authority} apiUrl={apiUrl} onChanged={onChanged} /><CodeChangeReviewPanel caseId={caseRecord.id} authority={authority} apiUrl={apiUrl} onChanged={onChanged} /><PhaseRail phases={caseRecord.phases} current={1} /><ContinuityLedger checkpoints={caseRecord.checkpoints} /><div className="next-wakeup"><span aria-hidden="true">◷</span><div><strong>No process running</strong><p>Next durable wake-up {caseRecord.next} · owner {caseRecord.owner}</p></div></div></section>;
}

function WorkspaceCognitionPanel({ record }: { record: ConsoleSnapshot["cases"][number] }): React.JSX.Element | null {
  const workspace = record.workspace;
  if (!workspace) return null;
  return <section className="workspace-cognition card" aria-labelledby={`workspace-${workspace.id}`}>
    <div className="section-heading">
      <div><p className="eyebrow">Workspace cognition</p><h3 id={`workspace-${workspace.id}`}>{workspace.id} · logical incident workspace</h3><p>One durable workspace retains mechanism context while task runs remain independently fenced.</p></div>
      <StatusBadge label={workspaceStateLabel(workspace.status)} tone={workspaceStateTone(workspace.status)} machine={workspace.status} />
    </div>
    <div className="verification-summary">
      <LabelValue label="Provider / SDK" value={`${workspace.provider} · ${workspace.implementation_sdk} ${workspace.implementation_sdk_version}`} />
      <LabelValue label="Registry binding" value={workspace.registry_agent_key} />
      <LabelValue label="Data eligibility" value={`${workspace.classification} · ${workspace.synthetic ? "synthetic" : "non-synthetic"} · ${workspace.eligibility_decision}`} />
      <LabelValue label="Provider revision" value={workspace.provider_revision} />
      <LabelValue label="Input manifest" value={workspace.input_manifest_hash} />
      <LabelValue label="Network policy" value={workspace.network_policy_hash} />
    </div>
    <div className="workspace-authority">
      <strong>Proposal authority only</strong>
      <p>The workspace cannot perform {workspace.denied_authorities.join(", ")}.</p>
    </div>
    {workspace.repair_cognition && <div className="cognition-evidence" aria-label="Competing repair hypotheses and deterministic reproduction">
      <div className="cognition-heading"><div><p className="eyebrow">Proposed mechanism</p><h4>{workspace.repair_cognition.mechanism}</h4></div><StatusBadge label={`${workspace.repair_cognition.trust_class} · ${workspace.repair_cognition.status}`} tone="warning" /></div>
      <div className="hypothesis-grid">{workspace.repair_cognition.hypotheses.map((hypothesis) => <article className={hypothesis.leading ? "hypothesis leading" : "hypothesis"} key={hypothesis.hypothesis_key}>
        <div><MonoChip>{hypothesis.hypothesis_key}</MonoChip>{hypothesis.leading && <span className="leading-label">Leading</span>}</div>
        <p>{hypothesis.statement}</p>
        <dl><dt>Supports</dt><dd>{hypothesis.supporting_citations.join(" · ")}</dd><dt>Contradicts</dt><dd>{hypothesis.contradicting_citations.length > 0 ? hypothesis.contradicting_citations.join(" · ") : "No cited contradiction"}</dd></dl>
      </article>)}</div>
      <div className="reproduction-grid">
        <div><strong>Baseline reproduction</strong><StatusBadge label={workspace.repair_cognition.reproduction.exit_code !== 0 ? "Failure reproduced" : "Not reproduced"} tone={workspace.repair_cognition.reproduction.exit_code !== 0 ? "success" : "danger"} /><code>{workspace.repair_cognition.reproduction.command}</code><small>exit {workspace.repair_cognition.reproduction.exit_code} · {workspace.repair_cognition.reproduction.output_ref}</small></div>
        <div><strong>Patched regression</strong><StatusBadge label={workspace.repair_cognition.regression.exit_code === 0 ? "Passed" : "Failed"} tone={workspace.repair_cognition.regression.exit_code === 0 ? "success" : "danger"} /><code>{workspace.repair_cognition.regression.command}</code><small>exit {workspace.repair_cognition.regression.exit_code} · {workspace.repair_cognition.regression.output_ref}</small></div>
      </div>
      <small className="artifact-binding">Typed cognition artifact {workspace.repair_cognition.artifact_ref} · {workspace.repair_cognition.artifact_hash}</small>
    </div>}
    <div className="phase-track workspace-phase" aria-label="Workspace proposal governance">
      {REPAIR_PHASES.map((phase, index) => <span key={phase} className={phaseClass(index, repairProgress(record), { verifiedAt: REPAIR_PHASES.length - 1 })}>{phase}</span>)}
    </div>
    <div className="responsive-table">
      <table><caption>Workspace task-run integrity receipts</caption><thead><tr><th>Task run</th><th>Task / attempt</th><th>Status</th><th>Request hash</th><th>Output / provider boot</th></tr></thead><tbody>{workspace.task_runs.map((run) => <tr key={run.id}><td>{run.id}</td><td>{run.task} · {run.attempt}</td><td>{run.status}</td><td>{run.request_hash}</td><td>{run.output_hash}<br /><span className="muted">{run.provider_boot_hash} · {run.provider_service_revision}</span></td></tr>)}</tbody></table>
    </div>
    {workspace.checkpoints.length > 0 && <div className="workspace-checkpoints"><strong>Checkpoint and rehydration lineage</strong><ul>{workspace.checkpoints.map((checkpoint) => <li key={checkpoint.id}>{checkpoint.event} #{checkpoint.sequence} · {checkpoint.id} · manifest {checkpoint.artifact_manifest_hash} · boot {checkpoint.provider_boot_hash}</li>)}</ul></div>}
  </section>;
}

function PatchReviewPanel({ record, authority, apiUrl, onChanged }: { record: ConsoleSnapshot["cases"][number]; authority: string; apiUrl: string; onChanged: () => void }): React.JSX.Element | null {
  const [identityToken, setIdentityToken] = useState("");
  const [reviewReason, setReviewReason] = useState("Reviewed the exact diff and passing isolated test receipt in Solvan.");
  const [message, setMessage] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  if (record.state !== "AWAITING_REVIEW" || !record.patch_digest) return null;
  const live = authority === "GOOGLE_CLOUD_IAM";
  async function submitReview(decision: "APPROVE" | "CHANGES_REQUESTED"): Promise<void> {
    if (!reviewReason.trim()) { setMessage("A review reason is required."); return; }
    if (!live) { setMessage(`Local development only; ${decision.toLowerCase().replace("_", " ")} created no durable review authority.`); return; }
    setSubmitting(true); setMessage(null);
    try {
      const result = await callApi(`${apiUrl}/api/v1/patches/${record.patch_artifact}:review`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "x-solvan-approval-token": identityToken }, body: JSON.stringify({ schema_version: 1, patch_digest: record.patch_digest, decision, reason: reviewReason.trim() }) });
      if (!result.ok) { setMessage(`Review refused · ${result.detail}`); return; }
      setIdentityToken(""); setMessage("Exact patch review recorded; coordinator application is pending."); onChanged();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Review failed"); } finally { setSubmitting(false); }
  }
  return <section className="card"><div className="section-heading"><div><p className="eyebrow">Exact patch review</p><h3>{record.patch_artifact}</h3></div><StatusBadge label="Human review required" tone="warning" /></div><div className="approval-digest"><LabelValue label="Patch digest" value={record.patch_digest} /><LabelValue label="Unified diff" value={record.patch_ref} /><LabelValue label="Test receipt" value={record.test_ref} /><LabelValue label="Residual risks" value={record.residual_risks.join("; ") || "none declared"} /></div><PatchDiffView diff={record.patch_diff} /><label className="token-field">Review reason<textarea value={reviewReason} onChange={(event) => setReviewReason(event.target.value)} required /></label>{live && <label className="token-field">One-time Google identity token<input type="password" autoComplete="off" value={identityToken} onChange={(event) => setIdentityToken(event.target.value)} required /><small>Held only in this view and sent over TLS for Google signature and audience verification.</small></label>}<div className="dialog-actions"><button className="reject-button" disabled={submitting || (live && !identityToken)} onClick={() => void submitReview("CHANGES_REQUESTED")}>Request changes</button><button className="primary-button" disabled={submitting || (live && !identityToken)} onClick={() => void submitReview("APPROVE")}>{submitting ? "Revalidating…" : live ? "Approve exact patch" : "Approve patch in local development"}</button></div>{message && <p className="inline-notice" role="status">{message}</p>}</section>;
}

type CodeChangeProjection = {
  request: Record<string, string | number>;
  transitions: Array<Record<string, string | number | null>>;
  decisions: Array<Record<string, string | number | null>>;
  operations: Array<Record<string, string | number | null>>;
  github_observations: Array<Record<string, string | number | null | string[]>>;
  release_candidates: Array<Record<string, string | number | null>>;
  target_observations: Array<Record<string, string | number | null>>;
  release_baselines: Array<Record<string, string | number | null>>;
  rollouts: Array<Record<string, string | number | null>>;
  rollout_operations: Array<Record<string, string | number | null>>;
  release_verifications: Array<Record<string, string | number | null>>;
  rollback_verifications: Array<Record<string, string | number | null>>;
};

function ReleaseDeliveryEvidence({ projection }: { projection: CodeChangeProjection }): React.JSX.Element | null {
  if (
    projection.release_candidates.length === 0
    && projection.rollouts.length === 0
    && projection.release_verifications.length === 0
    && projection.rollback_verifications.length === 0
  ) return null;
  return <div className="release-evidence">
    <div className="section-heading integration-subheading"><div><p className="eyebrow">Independent release evidence</p><h4>Deployment and verification ledger</h4></div></div>
    {projection.release_candidates.map((candidate) => <div className="verification-summary" key={String(candidate.id)}><LabelValue label="Release candidate" value={String(candidate.id)} /><LabelValue label="Merged commit" value={String(candidate.merged_commit_sha)} /><LabelValue label="Artifact" value={String(candidate.build_artifact_ref)} /><LabelValue label="Provenance" value={String(candidate.provenance_hash)} /></div>)}
    {projection.rollouts.length > 0 && <div className="responsive-table"><table><caption>Governed rollout state</caption><thead><tr><th>Rollout</th><th>Target</th><th>State</th><th>Reservation</th><th>Lease</th></tr></thead><tbody>{projection.rollouts.map((rollout) => <tr key={String(rollout.id)}><td><MonoChip>{String(rollout.id)}</MonoChip></td><td>{String(rollout.target_key)}</td><td><StatusBadge label={String(rollout.status).replaceAll("_", " ")} tone={rollout.status === "PROMOTED" ? "success" : rollout.status === "VERIFICATION_FAILED" ? "danger" : "warning"} /></td><td>{String(rollout.reservation_status)}</td><td>{String(rollout.lease_expires_at)}</td></tr>)}</tbody></table></div>}
    {projection.rollout_operations.length > 0 && <div className="responsive-table"><table><caption>Controller effect fences</caption><thead><tr><th>Stage</th><th>Operation</th><th>Status</th><th>Provider receipt</th></tr></thead><tbody>{projection.rollout_operations.map((operation) => <tr key={String(operation.id)}><td>{String(operation.stage_ordinal)}</td><td>{String(operation.operation_kind).replaceAll("_", " ")}</td><td>{String(operation.status)}</td><td>{operation.response_hash ? <MonoChip>{String(operation.response_hash)}</MonoChip> : "Pending"}</td></tr>)}</tbody></table></div>}
    {projection.release_verifications.length > 0 && <div className="responsive-table"><table><caption>Signed independent health receipts</caption><thead><tr><th>Stage</th><th>Result</th><th>Window</th><th>Verifier</th><th>Receipt</th></tr></thead><tbody>{projection.release_verifications.map((receipt) => <tr key={String(receipt.id)}><td>{String(receipt.stage_ordinal)}</td><td><StatusBadge label={String(receipt.result)} tone={receipt.result === "VERIFIED" ? "success" : receipt.result === "FAILED" ? "danger" : "warning"} /></td><td>{String(receipt.window_start)} → {String(receipt.window_end)}</td><td>{String(receipt.verifier_identity)}</td><td><MonoChip>{String(receipt.receipt_envelope_hash)}</MonoChip></td></tr>)}</tbody></table></div>}
    {projection.rollback_verifications.length > 0 && <div className="responsive-table"><table><caption>Signed rollback verification</caption><thead><tr><th>Expected revision</th><th>Result</th><th>Verifier</th><th>Receipt</th></tr></thead><tbody>{projection.rollback_verifications.map((receipt) => <tr key={String(receipt.id)}><td>{String(receipt.expected_revision)}</td><td><StatusBadge label={String(receipt.result)} tone={receipt.result === "VERIFIED" ? "success" : "danger"} /></td><td>{String(receipt.verifier_identity)}</td><td><MonoChip>{String(receipt.receipt_envelope_hash)}</MonoChip></td></tr>)}</tbody></table></div>}
  </div>;
}

type DecisionChallenge = {
  challenge_id: string;
  stage: string;
  required_role: string;
  decision_digest: string;
  material: Record<string, unknown>;
  expires_at: string;
};

const decisionStageByState: Record<string, string> = {
  PR_CREATION_APPROVAL_PENDING: "PR_CREATION",
  MERGE_APPROVAL_PENDING: "MERGE",
  DEPLOYMENT_APPROVAL_PENDING: "DEPLOYMENT",
  ROLLBACK_APPROVAL_PENDING: "ROLLBACK",
};

function CodeChangeReviewPanel({ caseId, authority, apiUrl, onChanged }: { caseId: string; authority: string; apiUrl: string; onChanged: () => void }): React.JSX.Element | null {
  const [token, setToken] = useState("");
  const [projection, setProjection] = useState<CodeChangeProjection | null>(null);
  const [challenge, setChallenge] = useState<DecisionChallenge | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [reason, setReason] = useState("Reviewed the exact current material and its immutable evidence bindings.");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (authority !== "GOOGLE_CLOUD_IAM") return null;

  async function load(): Promise<void> {
    if (!token.trim()) { setMessage("A fresh Google identity token is required."); return; }
    setBusy(true); setMessage(null); setChallenge(null); setConfirmed(false);
    try {
      const response = await fetch(`${apiUrl}/api/v1/code-change-requests/by-case/${caseId}/current`, { headers: { "X-Solvan-Approval-Token": token.trim() } });
      if (!response.ok) { setMessage(`Request review unavailable · ${await response.text()}`); return; }
      const value = (await response.json()) as CodeChangeProjection | null;
      setProjection(value);
      setMessage(value ? null : "No governed Code Change Request exists for this case yet.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Request review failed"); } finally { setBusy(false); }
  }

  async function reviewCurrentStage(): Promise<void> {
    const requestId = String(projection?.request.id ?? "");
    const stage = decisionStageByState[String(projection?.request.state ?? "")];
    if (!requestId || !stage) return;
    setBusy(true); setMessage(null); setChallenge(null); setConfirmed(false);
    try {
      const response = await fetch(`${apiUrl}/api/v1/code-change-requests/${requestId}/decision-challenges/${stage}`, { method: "POST", headers: { "X-Solvan-Approval-Token": token.trim() } });
      if (!response.ok) { setMessage(`Decision material unavailable · ${await response.text()}`); return; }
      setChallenge((await response.json()) as DecisionChallenge);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Decision material failed"); } finally { setBusy(false); }
  }

  async function decide(decision: "APPROVED" | "REJECTED"): Promise<void> {
    if (!challenge || !projection || !confirmed || reason.trim().length < 8) return;
    setBusy(true); setMessage(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/code-change-requests/${projection.request.id}/decisions`, { method: "POST", headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": token.trim(), "Idempotency-Key": crypto.randomUUID() }, body: JSON.stringify({ schema_version: 1, challenge_id: challenge.challenge_id, decision_digest: challenge.decision_digest, decision, reason: reason.trim() }) });
      if (!response.ok) { setMessage(`Decision refused · ${await response.text()}`); return; }
      setChallenge(null); setConfirmed(false); setToken("");
      setMessage(`${challenge.stage.replaceAll("_", " ")} decision recorded. The coordinator will revalidate it before any effect.`);
      setProjection(null); onChanged();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Decision failed"); } finally { setBusy(false); }
  }

  const stage = projection ? decisionStageByState[String(projection.request.state)] : undefined;
  return <section className="card code-change-review"><div className="section-heading"><div><p className="eyebrow">Governed code delivery</p><h3>Code Change Request</h3><p>Load the scope-checked immutable record before making a stage-specific decision.</p></div>{projection && <StatusBadge label={String(projection.request.state).replaceAll("_", " ")} tone={stage ? "warning" : "info"} machine={String(projection.request.state)} />}</div><label className="token-field">Fresh Google identity token<input type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} /><small>Verified server-side for this read and again for each decision; never stored by this view.</small></label><button className="secondary-button" disabled={busy || !token.trim()} onClick={() => void load()}>{busy ? "Revalidating…" : "Load exact request"}</button>{projection && <><div className="verification-summary"><LabelValue label="Request" value={String(projection.request.id)} /><LabelValue label="Repository" value={`${projection.request.owner}/${projection.request.name}`} /><LabelValue label="Frozen base" value={String(projection.request.base_commit_sha)} /><LabelValue label="Proposed tree" value={String(projection.request.proposed_tree_hash)} /><LabelValue label="Patch digest" value={String(projection.request.patch_digest)} /><LabelValue label="Expires" value={String(projection.request.expires_at)} /></div><div className="responsive-table"><table><caption>Immutable Code Change Request transitions</caption><thead><tr><th>Sequence</th><th>Transition</th><th>Actor</th><th>Receipt</th></tr></thead><tbody>{projection.transitions.map((item) => <tr key={String(item.sequence_no)}><td>{item.sequence_no}</td><td>{item.from_state} → {item.to_state}</td><td>{item.actor_kind} · {item.actor_identity}</td><td>{item.receipt_hash ?? "No external receipt"}</td></tr>)}</tbody></table></div>{projection.github_observations.length > 0 && <div className="responsive-table"><table><caption>Authoritative GitHub observations</caption><thead><tr><th>Sequence</th><th>Kind</th><th>Head / merge</th><th>Checks</th><th>Review</th></tr></thead><tbody>{projection.github_observations.map((item) => <tr key={String(item.sequence_no)}><td>{String(item.sequence_no)}</td><td>{String(item.observation_kind)}</td><td>{String(item.merge_commit_sha ?? item.head_commit_sha)}</td><td>{String(item.required_check_state)}</td><td>{String(item.review_state)}</td></tr>)}</tbody></table></div>}<ReleaseDeliveryEvidence projection={projection} />{stage && <button className="primary-button" disabled={busy} onClick={() => void reviewCurrentStage()}>Review exact {stage.replaceAll("_", " ")} material</button>}</>}{challenge && <div className="decision-confirmation"><h4>{challenge.stage.replaceAll("_", " ")} · {challenge.required_role}</h4><p>This challenge expires {challenge.expires_at}. Any material change invalidates it.</p><LabelValue label="Decision digest" value={challenge.decision_digest} /><pre>{JSON.stringify(challenge.material, null, 2)}</pre><label className="token-field">Decision reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} /></label><label className="confirmation-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> I reviewed this exact digest and understand this decision authorizes only this stage.</label><div className="dialog-actions"><button className="reject-button" disabled={busy || !confirmed || reason.trim().length < 8} onClick={() => void decide("REJECTED")}>Reject this stage</button><button className="primary-button" disabled={busy || !confirmed || reason.trim().length < 8} onClick={() => void decide("APPROVED")}>Approve this exact stage</button></div></div>}{message && <p className="inline-notice" role="status">{message}</p>}</section>;
}

export function Cases({ cases, authority, apiUrl, onChanged }: { cases: ConsoleSnapshot["cases"]; authority: string; apiUrl: string; onChanged: () => void }): React.JSX.Element {
  const record = cases[0];
  if (!record) return <><PageHeader eyebrow="Long-horizon ownership" title="Reliability Cases" description="Permanent repair continues across processes, deployments, and calendar days." /><section className="card"><h2>No Reliability Case yet</h2><p>A case opens after mitigation is independently verified.</p></section></>;
  return <><PageHeader eyebrow="Long-horizon ownership" title="Reliability Cases" description="Permanent repair continues across processes, deployments, and calendar days." /><section className="case-hero card"><div><MonoChip>{record.id}</MonoChip><h2>{record.service} permanent repair</h2><p>Originating incident {record.incident} · {record.repair}</p></div><CaseStateBadge state={record.state} /></section><div className="verification-summary"><LabelValue label="Immutable repair plan" value={record.repair_plan} /><LabelValue label="Workspace provider" value={record.provider} /><LabelValue label="Pinned commit" value={record.commit} /><LabelValue label="Patch/test state" value={record.patch_status} /></div><WorkspaceCognitionPanel record={record} /><PatchReviewPanel record={record} authority={authority} apiUrl={apiUrl} onChanged={onChanged} /><CodeChangeReviewPanel caseId={record.id} authority={authority} apiUrl={apiUrl} onChanged={onChanged} /><PhaseRail phases={record.phases} current={1} /><ContinuityLedger checkpoints={record.checkpoints} /><div className="next-wakeup"><span aria-hidden="true">◷</span><div><strong>No process running · this is healthy</strong><p>Next durable wake-up {record.next}. Cloud SQL retains the next action and fencing authority.</p></div></div></>;
}

/** The change itself. A digest names which change is meant; only the diff lets
 *  a reviewer judge it, so approval is never offered over a hash alone. */
function PatchDiffView({ diff }: { diff: ConsoleSnapshot["cases"][number]["patch_diff"] }): React.JSX.Element {
  if (diff.files.length === 0) {
    return <p className="diff-unavailable">{diff.note || "No reviewable change is attached to this artifact."}</p>;
  }
  return (
    <div className="patch-diff">
      <div className="diff-summary">
        <span>{diff.files.length} {diff.files.length === 1 ? "file" : "files"} changed</span>
        <span className="diff-added">+{diff.added}</span>
        <span className="diff-removed">−{diff.removed}</span>
      </div>
      {diff.note && <p className="diff-note">{diff.note}</p>}
      {diff.files.map((file) => (
        <article key={file.path}>
          <header><code>{file.path}</code><span><span className="diff-added">+{file.added}</span> <span className="diff-removed">−{file.removed}</span></span></header>
          <table>
            <caption className="visually-hidden">Unified diff for {file.path}</caption>
            <tbody>
              {file.lines.map((line, index) => (
                <tr key={`${file.path}-${index}`} className={`diff-${line.kind}`}>
                  <td className="diff-gutter" aria-hidden="true">{line.old_line ?? ""}</td>
                  <td className="diff-gutter" aria-hidden="true">{line.new_line ?? ""}</td>
                  <td className="diff-sign" aria-hidden="true">{line.kind === "add" ? "+" : line.kind === "remove" ? "−" : ""}</td>
                  <td className="diff-text">{line.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </article>
      ))}
    </div>
  );
}

function PhaseRail({ phases, current }: { phases: string[]; current: number }): React.JSX.Element {
  return <ol className="phase-rail" aria-label="Permanent repair phases">{phases.map((phase, index) => <li key={phase} className={index < current ? "complete" : index === current ? "current" : "future"}><span aria-hidden="true">{index < current ? "✓" : index + 1}</span><strong>{phase}</strong></li>)}</ol>;
}

function ContinuityLedger({ checkpoints }: { checkpoints: Array<{ day: string; events: string[] }> }): React.JSX.Element {
  return <section className="continuity-ledger"><div className="section-heading"><div><p className="eyebrow">Durable continuity</p><h2>Calendar-day ledger</h2></div><span className="muted">scripted receipt replay</span></div>{checkpoints.map((checkpoint) => <article key={checkpoint.day}><h3>{checkpoint.day}</h3><ol>{checkpoint.events.map((event) => <li key={event}>{event}</li>)}</ol></article>)}</section>;
}
