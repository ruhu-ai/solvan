import { useEffect, useState } from "react";
import { MonoChip, StatusBadge } from "./components";
import type { ProductionGraphReview, ProductionGraphStatus } from "./types";
import "./styles/production-graph.css";

async function responseDetail(response: Response, fallback: string): Promise<string> {
  const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
  return payload?.detail ?? `${fallback} (${response.status})`;
}

/** Nobody has told this deployment which estate it serves.
 *
 * A precondition nobody has met yet is not a failure, and rendering it as one
 * told an operator the service was broken when it was waiting to be told where
 * to look. The API answers with a closed code so this can be recognised rather
 * than matched against a sentence.
 */
const _SCOPE_NOT_CONFIGURED = "PRODUCTION_SCOPE_NOT_CONFIGURED";

export function ProductionGraphPanel({ apiUrl }: { apiUrl: string }): React.JSX.Element {
  const [status, setStatus] = useState<ProductionGraphStatus | null>(null);
  const [review, setReview] = useState<ProductionGraphReview | null>(null);
  const [identityToken, setIdentityToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<"DISCOVER" | "REVIEW" | "APPROVE" | null>(null);

  async function loadStatus(signal?: AbortSignal): Promise<void> {
    const response = await fetch(`${apiUrl}/api/v1/production-graph/status`, { credentials: "include", signal });
    if (!response.ok) {
      throw new Error(await responseDetail(response, "Production Graph status unavailable"));
    }
    setStatus((await response.json()) as ProductionGraphStatus);
    setError(null);
  }

  useEffect(() => {
    const controller = new AbortController();
    void loadStatus(controller.signal).catch((reason: unknown) => {
      if (reason instanceof DOMException && reason.name === "AbortError") return;
      setError(reason instanceof Error ? reason.message : "Production Graph status unavailable");
    });
    return () => controller.abort();
  }, [apiUrl]);

  const unconfigured = error === _SCOPE_NOT_CONFIGURED;
  const latestRun = status?.runs[0];
  const current = status?.snapshots.find((item) => item.status === "APPROVED");
  const candidate = status?.snapshots.find(
    (item) => item.status === "DRAFT" && item.content_hash !== null,
  );
  const hasToken = identityToken.trim().length > 0;

  useEffect(() => {
    if (latestRun?.state !== "PENDING" && latestRun?.state !== "RUNNING") return;
    const timer = window.setTimeout(() => {
      void loadStatus().catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : "Production Graph status unavailable");
      });
    }, 3000);
    return () => window.clearTimeout(timer);
  }, [latestRun?.run_id, latestRun?.state]);

  async function startDiscovery(): Promise<void> {
    const token = identityToken.trim();
    if (!token) return;
    const requestId = crypto.randomUUID();
    setBusy("DISCOVER");
    setError(null);
    setNotice(null);
    setReview(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/production-graph/reconciliations`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "Idempotency-Key": requestId,
        },
        body: JSON.stringify({ schema_version: 1, request_id: requestId }),
      });
      if (!response.ok) {
        throw new Error(await responseDetail(response, "Discovery could not start"));
      }
      const receipt = (await response.json()) as { run_id: string; created: boolean };
      setNotice(
        `${receipt.created ? "Discovery queued" : "Existing discovery recovered"}: ${receipt.run_id}`,
      );
      await loadStatus();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Discovery could not start");
    } finally {
      setIdentityToken("");
      setBusy(null);
    }
  }

  async function loadReview(): Promise<void> {
    const token = identityToken.trim();
    if (!token || !candidate) return;
    setBusy("REVIEW");
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/production-graph/${encodeURIComponent(candidate.snapshot_id)}/review-material`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "X-Solvan-Approval-Token": token,
          },
        },
      );
      if (!response.ok) {
        throw new Error(await responseDetail(response, "Exact review material unavailable"));
      }
      setReview((await response.json()) as ProductionGraphReview);
      setNotice(
        "Exact candidate material loaded. Re-enter your identity token only if you approve this digest.",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Exact review material unavailable");
    } finally {
      setIdentityToken("");
      setBusy(null);
    }
  }

  async function approveReview(): Promise<void> {
    const token = identityToken.trim();
    if (!token || !review?.content_hash) return;
    const decisionId = crypto.randomUUID();
    setBusy("APPROVE");
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/production-graph/${encodeURIComponent(review.snapshot_id)}:promote`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "X-Solvan-Approval-Token": token,
            "Content-Type": "application/json",
            "Idempotency-Key": decisionId,
          },
          body: JSON.stringify({
            schema_version: 1,
            decision_id: decisionId,
            mode: "HUMAN_APPROVED",
            expected_content_hash: review.content_hash,
          }),
        },
      );
      if (!response.ok) {
        throw new Error(await responseDetail(response, "Candidate approval refused"));
      }
      const receipt = (await response.json()) as { decision_id: string; created: boolean };
      setReview(null);
      setNotice(
        `${receipt.created ? "Candidate approved" : "Existing approval recovered"}: ${receipt.decision_id}`,
      );
      await loadStatus();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Candidate approval refused");
    } finally {
      setIdentityToken("");
      setBusy(null);
    }
  }

  return (
    <section className="card production-graph-panel" aria-labelledby="production-graph-heading">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Estate discovery</p>
          <h2 id="production-graph-heading">Production Graph</h2>
        </div>
        <StatusBadge
          label={
            unconfigured
              ? "Not configured"
              : error
                ? "Unavailable"
                : current
                  ? "Approved snapshot"
                  : latestRun
                    ? latestRun.state
                    : "Not discovered"
          }
          tone={
            unconfigured
              ? "neutral"
              : error
                ? "warning"
                : current
                  ? "success"
                  : latestRun?.state === "FAILED" || latestRun?.state === "DEGRADED"
                    ? "warning"
                    : "neutral"
          }
        />
      </div>
      <p className="section-note">
        Solvan discovers services and dependencies through registered read-only sources, saves a
        draft, and keeps it out of incident authority until an operator approves the exact diff.
      </p>
      {/* Asking for an identity to run a command that cannot resolve a scope
          invites an operator to paste a credential for nothing. */}
      {!unconfigured && <div className="graph-operator-controls">
        <label className="token-field">
          One-time operator identity token
          <input
            type="password"
            value={identityToken}
            onChange={(event) => setIdentityToken(event.target.value)}
            placeholder="Required only for the next command"
            autoComplete="off"
            spellCheck={false}
          />
          <small>
            Held in this page's memory and cleared after every command. It is never saved by the
            browser.
          </small>
        </label>
        <div className="graph-command-row">
          <button
            className="secondary-button"
            disabled={!hasToken || busy !== null || !status?.execution_configured}
            onClick={() => void startDiscovery()}
          >
            {busy === "DISCOVER" ? "Queuing…" : "Start discovery"}
          </button>
          <button
            className="secondary-button"
            disabled={!hasToken || busy !== null || !candidate}
            onClick={() => void loadReview()}
          >
            {busy === "REVIEW" ? "Loading exact material…" : "Review newest draft"}
          </button>
        </div>
      </div>}
      {unconfigured ? (
        <p className="inline-notice" role="status">
          This deployment has not been told which estate it serves, so there is no graph to
          discover yet. Set the organization, project, and environment it operates on. Nothing has
          failed, and no fixture graph is substituted in the meantime.
        </p>
      ) : error ? (
        <p className="inline-notice graph-error" role="alert">
          {error}. No fixture graph is substituted.
        </p>
      ) : status ? (
        <GraphStatus status={status} current={current} latestRun={latestRun} />
      ) : (
        <p className="inline-notice" role="status">Loading Production Graph status…</p>
      )}
      {notice && <p className="inline-notice" role="status">{notice}</p>}
      {review && (
        <GraphReview
          review={review}
          busy={busy}
          hasToken={hasToken}
          onClose={() => setReview(null)}
          onApprove={() => void approveReview()}
        />
      )}
    </section>
  );
}

function GraphStatus({
  status,
  current,
  latestRun,
}: {
  status: ProductionGraphStatus;
  current: ProductionGraphStatus["snapshots"][number] | undefined;
  latestRun: ProductionGraphStatus["runs"][number] | undefined;
}): React.JSX.Element {
  return <>
    <dl className="platform-health-facts">
      <div><dt>Placement</dt><dd>{status.placement ? `${status.placement.region} · epoch ${status.placement.placement_epoch}` : "No active placement"}</dd></div>
      <div><dt>Read sources</dt><dd>{status.sources.length} policy-bound</dd></div>
      <div><dt>Coordinator</dt><dd>{status.execution_configured ? "Source registry configured" : "Source registry not configured"}</dd></div>
      <div><dt>Current graph</dt><dd>{current ? `v${current.snapshot_version} · ${current.completeness}` : "No approved snapshot"}</dd></div>
    </dl>
    <div className="responsive-table integration-subheading">
      <table>
        <caption className="visually-hidden">Production Graph source policies</caption>
        <thead><tr><th>Source</th><th>Tier</th><th>Required</th><th>Policy revision</th></tr></thead>
        <tbody>{status.sources.map((source) => <tr key={`${source.source_key}:${source.source_revision}`}>
          <td data-label="Source"><MonoChip>{source.source_key}</MonoChip></td>
          <td data-label="Tier">Tier {source.tier}</td>
          <td data-label="Required"><StatusBadge label={source.required_for_complete ? "Required" : "Optional"} tone={source.required_for_complete ? "info" : "neutral"} /></td>
          <td data-label="Policy revision">r{source.source_revision}</td>
        </tr>)}</tbody>
      </table>
    </div>
    <p className="inline-notice" role="status">
      {latestRun ? <>Latest discovery <MonoChip>{latestRun.run_id}</MonoChip> · {latestRun.state.toLowerCase()} · requested {new Date(latestRun.requested_at).toLocaleString()}.</> : "No discovery has run. Enter a one-time operator token to queue the first read-only reconciliation."}
    </p>
  </>;
}

function GraphReview({ review, busy, hasToken, onClose, onApprove }: {
  review: ProductionGraphReview;
  busy: "DISCOVER" | "REVIEW" | "APPROVE" | null;
  hasToken: boolean;
  onClose: () => void;
  onApprove: () => void;
}): React.JSX.Element {
  return <section className="graph-review" aria-labelledby="graph-review-heading">
    <div className="section-heading">
      <div><p className="eyebrow">Exact approval material</p><h3 id="graph-review-heading">Snapshot v{review.snapshot_version}</h3></div>
      <StatusBadge label={review.completeness ?? "Not finalized"} tone={review.completeness === "COMPLETE" ? "success" : "warning"} machine={review.status} />
    </div>
    <dl className="graph-review-facts">
      <div><dt>Content digest</dt><dd><MonoChip>{review.content_hash ?? "not finalized"}</MonoChip></dd></div>
      <div><dt>Material digest</dt><dd><MonoChip>{review.material_hash ?? "not finalized"}</MonoChip></dd></div>
      <div><dt>Diff digest</dt><dd><MonoChip>{review.diff_hash ?? "first snapshot"}</MonoChip></dd></div>
      <div><dt>Governed changes</dt><dd>{review.governed_change_count ?? "First snapshot"}</dd></div>
      <div><dt>Predecessor</dt><dd>{review.predecessor_snapshot_id ? <MonoChip>{review.predecessor_snapshot_id}</MonoChip> : "None"}</dd></div>
      <div><dt>Autonomy after approval</dt><dd>{review.autonomy_eligible ? "Eligible" : "Assisted use only"}</dd></div>
    </dl>
    <div className="graph-review-columns">
      <div><h3>Governed diff</h3>{Object.keys(review.diff_counts).length ? <ul>{Object.entries(review.diff_counts).map(([name, count]) => <li key={name}><span>{name.replaceAll("_", " ")}</span><strong>{count}</strong></li>)}</ul> : <p>No predecessor diff exists for this first snapshot.</p>}</div>
      <div><h3>Source tiers</h3><ul>{review.tier_status.map((tier) => <li key={tier.tier}><span>Tier {tier.tier} · {tier.outcome.toLowerCase()}</span><strong>{tier.observation_count}</strong></li>)}</ul></div>
    </div>
    {review.findings.length > 0 && <div className="graph-findings"><h3>Findings that remain visible after approval</h3><ul>{review.findings.map((finding) => <li key={finding.finding_id}><strong>{finding.finding_kind.replaceAll("_", " ")}</strong><span>{finding.detail_ref}</span></li>)}</ul></div>}
    <div className="approval-footer">
      <div><strong>Human approval binds this exact content digest</strong><span>A changed or stale candidate is refused; approval never starts provider reads.</span></div>
      <div>
        <button className="secondary-button" disabled={busy !== null} onClick={onClose}>Close review</button>
        <button className="primary-button" disabled={!hasToken || busy !== null || review.status !== "DRAFT" || !review.content_hash} onClick={onApprove}>{busy === "APPROVE" ? "Approving exact digest…" : "Approve exact snapshot"}</button>
      </div>
    </div>
  </section>;
}
