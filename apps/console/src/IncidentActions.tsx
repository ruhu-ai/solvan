import { useRef, useState } from "react";
import { X } from "lucide-react";
import type { Action, StatusTone } from "./types";
import { LabelValue, MonoChip, StatusBadge, phaseClass } from "./components";
import { callApi } from "./api";

const ACTION_PHASES = ["Proposed", "Authorized", "Reconciled", "Verified"] as const;

/** How far one action actually got, and whether it stopped there.
 *
 *  `reached` counts completed phases. A terminal failure stops the track at the
 *  phase it died in rather than ticking the rest: an EXPIRED or REJECTED action
 *  must never read the same as a healthy one. */
function actionProgress(status: string): { reached: number; failed: boolean; tone: StatusTone } {
  if (status === "VERIFIED") return { reached: 4, failed: false, tone: "success" };
  if (status === "EXECUTED" || status === "RECONCILING") return { reached: 3, failed: false, tone: "info" };
  if (status === "APPROVED" || status === "EXECUTING") return { reached: 2, failed: false, tone: "info" };
  if (status === "FAILED") return { reached: 2, failed: true, tone: "danger" };
  if (status === "REJECTED" || status === "EXPIRED") return { reached: 1, failed: true, tone: "danger" };
  if (status === "AWAITING_APPROVAL") return { reached: 1, failed: false, tone: "warning" };
  return { reached: 1, failed: false, tone: "neutral" };
}


export function Actions({ actions, authority, apiUrl, environment, onChanged }: { actions: Action[]; authority: string; apiUrl: string; environment: string; onChanged: () => void }): React.JSX.Element {
  return <section><div className="section-heading"><div><p className="eyebrow">Governed changes</p><h2>Action sequence</h2><p>Connector success and independent recovery remain separate states.</p></div><div className="budget-pill"><strong>{actions.length}</strong><span>durable actions</span></div></div><div className="action-list">{actions.map((action) => <ActionCard key={action.id} action={action} authority={authority} apiUrl={apiUrl} environment={environment} onChanged={onChanged} />)}</div></section>;
}

export function ActionCard({ action, authority, apiUrl, environment, onChanged }: { action: Action; authority: string; apiUrl: string; environment: string; onChanged: () => void }): React.JSX.Element {
  const progress = actionProgress(action.status);
  const [localOnly, setLocalOnly] = useState(false);
  const [identityToken, setIdentityToken] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [approvalStatus, setApprovalStatus] = useState<string | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const awaiting = action.status === "AWAITING_APPROVAL";
  const live = authority === "GOOGLE_CLOUD_IAM";
  async function approve(): Promise<void> {
    if (!live) { setLocalOnly(true); dialog.current?.close(); return; }
    if (!identityToken || !action.digest) { setApprovalStatus("A one-time Google identity token and immutable digest are required."); return; }
    setSubmitting(true); setApprovalStatus(null);
    try {
      const result = await callApi(`${apiUrl}/api/v1/actions/${action.id}:approve`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "x-solvan-approval-token": identityToken }, body: JSON.stringify({ schema_version: 1, action_digest: action.digest, reason: "Operator approved the exact rollback material shown in the Solvan console." }) });
      if (!result.ok) { setApprovalStatus(`Approval refused · ${result.detail}`); return; }
      setIdentityToken(""); setApprovalStatus("Exact approval committed. The coordinator may now dispatch execution."); dialog.current?.close(); onChanged();
    } catch (reason: unknown) { setApprovalStatus(reason instanceof Error ? reason.message : "Approval failed safely."); }
    finally { setSubmitting(false); }
  }
  return <article className="action-card"><div className="action-header"><div><div className="action-id"><MonoChip>{action.id}</MonoChip><StatusBadge label={action.phase} tone={progress.tone} machine={action.status} /></div><h3>{action.name}</h3><p>{action.change}</p></div><span className="risk-label">{action.risk}</span></div><div className="phase-track" aria-label={`Action phase: ${action.phase}`}>{ACTION_PHASES.map((phase, index) => <span key={phase} className={phaseClass(index, progress, { verifiedAt: ACTION_PHASES.length - 1 })}>{phase}</span>)}</div><div className="action-facts"><LabelValue label="Exact target" value={action.target} /><LabelValue label="Blast radius" value={action.blast_radius} /><LabelValue label="Policy" value={action.policy} /><LabelValue label="Verification" value={action.verification} />{action.receipt && <LabelValue label="Execution receipt" value={action.receipt} />}{action.expected_version && <LabelValue label="Expected version / epoch" value={action.expected_version} />}{action.expected_effect_hash && <LabelValue label="Expected-effect hash" value={action.expected_effect_hash} />}{action.evidence_version && <LabelValue label="Bound evidence / policy" value={action.evidence_version} />}{action.digest && <LabelValue label="Immutable digest" value={action.digest} />}{action.expires && <LabelValue label="Approval expiry" value={action.expires} />}</div>{awaiting && <div className="approval-footer"><div><strong>Human decision required</strong><span>{live ? "Google identity, RBAC, target, evidence, and digest are rechecked server-side." : "Local development cannot authorize or execute the action."}</span></div><div><button className="primary-button" onClick={() => dialog.current?.showModal()}>Review exact approval</button></div></div>}{localOnly && <p className="inline-notice" role="status">Recorded in local development only. No durable approval or action authority was created.</p>}{approvalStatus && <p className="inline-notice" role="status">{approvalStatus}</p>}<dialog ref={dialog} className="approval-dialog" onClose={() => undefined}><form method="dialog" onSubmit={(event) => { event.preventDefault(); void approve(); }}><div className="dialog-header"><div><p className="eyebrow">{live ? "Exact production approval" : "Exact approval · local development"}</p><h2>Approve the exact rollback?</h2></div><button className="icon-button" value="cancel" aria-label="Close approval dialog"><X size={18} strokeWidth={1.75} aria-hidden="true" /></button></div><p>{live ? "The server will independently revalidate every field before recording authority." : "This decision binds only the exact target and digest shown below. The local fixture cannot execute it."}</p><div className="approval-digest"><LabelValue label="Environment" value={environment} /><LabelValue label="Exact target" value={action.target} /><LabelValue label="Change" value={action.change} /><LabelValue label="Risk" value={action.risk} /><LabelValue label="Digest" value={action.digest ?? "missing"} /><LabelValue label="Expected version" value={action.expected_version ?? "missing"} /><LabelValue label="Verification profile" value={action.verification} /><LabelValue label="Expires" value={action.expires ?? "missing"} /><LabelValue label="Expected effect" value={action.expected_effect ?? "missing"} /><LabelValue label="Expected-effect hash" value={action.expected_effect_hash ?? "missing"} /><LabelValue label="Rollback plan" value={action.rollback_plan ?? "missing"} /></div>{live && <label className="token-field">One-time Google identity token<input type="password" autoComplete="off" value={identityToken} onChange={(event) => setIdentityToken(event.target.value)} required /><small>Held only in this dialog and sent over TLS for Google signature and audience verification.</small></label>}<div className="dialog-actions"><button className="reject-button" value="cancel" type="button" onClick={() => dialog.current?.close()}>Cancel</button><button className="primary-button" type="submit" disabled={submitting}>{submitting ? "Revalidating…" : live ? "Approve exact action" : "Approve in local development"}</button></div></form></dialog></article>;
}
