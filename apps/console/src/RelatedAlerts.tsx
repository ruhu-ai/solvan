import { useEffect, useState } from "react";
import type { Incident } from "./types";
import { StatusBadge } from "./components";

type RelatedAlertRow = {
  alert_episode_id: string;
  safe_title: string;
  severity: string;
  target_label: string;
  provider_status_label: string;
  disposition_label: string;
  relation: "CREATED" | "ATTACHED";
  source_freshness_at: string;
  recovery_status: string;
  verification_ref: string | null;
};

export function RelatedAlertsPanel({ incident, apiUrl, onOpenAlert }: { incident: Incident; apiUrl: string; onOpenAlert: (alertId: string) => void }): React.JSX.Element | null {
  const [rows, setRows] = useState<RelatedAlertRow[] | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiUrl}/api/incidents/${encodeURIComponent(incident.machine_id)}/related-alerts`, { credentials: "include", signal: controller.signal })
      .then(async (response) => {
        if (response.status === 404) return { rows: [] as RelatedAlertRow[] };
        if (!response.ok) throw new Error(`Related Alerts API returned ${response.status}`);
        return await response.json() as { rows: RelatedAlertRow[] };
      })
      .then((projection) => setRows(projection.rows))
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError")) setRows([]);
      });
    return () => controller.abort();
  }, [apiUrl, incident.machine_id]);
  if (rows === null) return <section className="card related-alerts-panel" aria-busy="true"><p className="eyebrow">Related Alerts</p><p>Loading reader-visible Alert links…</p></section>;
  if (rows.length === 0) return null;
  return <section className="card related-alerts-panel" aria-labelledby="related-alerts-title"><div className="section-heading"><div><p className="eyebrow">Source observations linked by durable disposition</p><h2 id="related-alerts-title">Related Alerts</h2><p>Source clearance and independently verified recovery remain separate.</p></div><StatusBadge label={`${rows.length} visible`} tone="neutral" /></div><div className="related-alert-list">{rows.map((row) => <button type="button" key={row.alert_episode_id} className="related-alert-row" onClick={() => onOpenAlert(row.alert_episode_id)}><div><span className="related-alert-relation">{row.relation === "CREATED" ? "Opened this Incident" : "Attached by deduplication"}</span><strong>{row.safe_title}</strong><small>{row.target_label} · source updated {new Date(row.source_freshness_at).toLocaleString()}</small></div><div className="related-alert-statuses"><StatusBadge label={row.severity} tone={row.severity === "SEV1" ? "danger" : "warning"} /><StatusBadge label={row.provider_status_label === "PROVIDER_REPORTED_CLEARED" ? "Provider reports cleared" : "Active at source"} tone="info" /><StatusBadge label={row.recovery_status === "INDEPENDENTLY_VERIFIED" ? "Recovery independently verified" : "Recovery not adjudicated"} tone={row.recovery_status === "INDEPENDENTLY_VERIFIED" ? "success" : "neutral"} /></div></button>)}</div></section>;
}
