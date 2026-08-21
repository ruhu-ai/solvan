/** The Agent Skills interchange surface: import to quarantine, compile, evaluate,
 *  approve, export, and the scope-bound governance registry it all reads from.
 */
import { useState } from "react";
import { X } from "lucide-react";
import { LabelValue, StatusBadge } from "./components";
import { callApi } from "./api";

export function SkillsInterchangePanel({ apiUrl, region }: { apiUrl: string; region: string }): React.JSX.Element {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [status, setStatus] = useState("No package selected");
  const [projection, setProjection] = useState<SkillImportProjection | null>(null);
  const [identityToken, setIdentityToken] = useState("");
  const [guidanceKey, setGuidanceKey] = useState("payments-connection-leak");
  const [guidanceVersion, setGuidanceVersion] = useState("1.0.0");
  const [ownerDepartment, setOwnerDepartment] = useState("Reliability Platform");
  const [guidanceDescription, setGuidanceDescription] = useState("Bounded response to a payment connection leak.");
  const [destinationId, setDestinationId] = useState("tenant-guidance-default");
  const [evaluationReceiptRef, setEvaluationReceiptRef] = useState("");
  const [expectedHeadEpoch, setExpectedHeadEpoch] = useState("1");
  // These used to be invisible literals baked into the compile request — one of
  // them an agent key that exists nowhere (`incident-supervisor-agent`), so a
  // compile from this form bound a non-existent agent. The bound metadata is
  // operator input, so it is a field like every other.
  const [allowedAgentKeys, setAllowedAgentKeys] = useState("incident-supervisor");
  const [serviceKinds, setServiceKinds] = useState("payments-api");
  const [incidentClasses, setIncidentClasses] = useState("CONNECTION_EXHAUSTION");
  const [symptomTags, setSymptomTags] = useState("connection-leak");
  const [profileRevisions, setProfileRevisions] = useState("supervisor.plan.v1@1");
  const commaList = (value: string): string[] => value.split(",").map((entry) => entry.trim()).filter(Boolean);
  const [commandState, setCommandState] = useState<string | null>(null);
  const [compiled, setCompiled] = useState<{ key: string; version: string; digest: string } | null>(null);
  const [evaluationId, setEvaluationId] = useState<string | null>(null);
  const authHeaders = (): Record<string, string> => identityToken.trim() ? { "Authorization": identityToken.trim(), "X-Solvan-Approval-Token": identityToken.trim() } : {};
  const selectFile = (event: React.ChangeEvent<HTMLInputElement>): void => {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
    setStatus(file ? `Ready · ${file.name} · ${file.size.toLocaleString()} bytes` : "No package selected");
  };
  const importPackage = async (): Promise<void> => {
    if (!selectedFile) return;
    setStatus("Uploading to authenticated quarantine…");
    try {
      const bytes = new Uint8Array(await selectedFile.arrayBuffer());
      let binary = "";
      bytes.forEach((value) => { binary += String.fromCharCode(value); });
      const result = await callApi<{ attempt_id?: string; decision?: string }>(`${apiUrl}/api/v1/skills/import`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID(), ...authHeaders() },
        body: JSON.stringify({
          schema_version: 1,
          command_id: crypto.randomUUID(),
          purpose: "GUIDANCE_IMPORT",
          classification: "INTERNAL",
          region,
          source_kind: "ARCHIVE",
          source_ref: `console://${selectedFile.name}`,
          archive_base64: btoa(binary),
        }),
      });
      if (!result.ok) { setStatus(`REFUSED · ${result.detail}`); return; }
      if (result.body.attempt_id) {
        const detail = await callApi<SkillImportProjection>(`${apiUrl}/api/v1/skills/import-attempts/${encodeURIComponent(result.body.attempt_id)}`);
        if (detail.ok) setProjection(detail.body);
      }
      setStatus(`${result.body.decision ?? "ACCEPTED"} · quarantine receipt committed`);
    } catch {
      setStatus("REFUSED · authenticated target provider is unavailable");
    }
  };
  const compile = async (): Promise<void> => {
    if (!projection?.quarantine || !identityToken.trim()) { setCommandState("A one-time Google identity token and a quarantine receipt are required."); return; }
    setCommandState("Compiling a typed draft…");
    const result = await callApi<{ guidance_key?: string; version?: string; approval_digest?: string }>(`${apiUrl}/api/v1/skills/${encodeURIComponent(projection.attempt_id)}/compile`, {
      method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), ...authHeaders() },
      body: JSON.stringify({ guidance_key: guidanceKey, version: guidanceVersion, display_name: guidanceKey, description: guidanceDescription, owner_department: ownerDepartment, discoverable_departments: [ownerDepartment], applicable_service_kinds: commaList(serviceKinds), applicable_incident_classes: commaList(incidentClasses), symptom_tags: commaList(symptomTags), purpose: "INCIDENT_INVESTIGATION", classification: "INTERNAL", eligible_regions: [region], allowed_agent_keys: commaList(allowedAgentKeys), required_profile_revisions: commaList(profileRevisions), normalized_license_identifier: "Apache-2.0", source_classification: "IMPORTED", contains_third_party_material: false, incompatibilities: [] }),
    });
    if (!result.ok) { setCommandState(`Compile refused · ${result.detail}`); return; }
    setCommandState(`Draft ${result.body.guidance_key}@${result.body.version} committed.`);
    if (result.body.guidance_key && result.body.version && result.body.approval_digest) setCompiled({ key: result.body.guidance_key, version: result.body.version, digest: result.body.approval_digest });
  };
  const submit = async (): Promise<void> => {
    if (!compiled || !identityToken.trim()) { setCommandState("Compile a draft and provide a one-time identity token first."); return; }
    const result = await callApi(`${apiUrl}/api/admin/guidance/${encodeURIComponent(compiled.key)}/revisions/${encodeURIComponent(compiled.version)}/submit`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), ...authHeaders() }, body: JSON.stringify({ schema_version: 1, expected_digest: compiled.digest }) });
    setCommandState(result.ok ? "Draft submitted for independent review." : `Submit refused · ${result.detail}`);
  };
  const evaluate = async (): Promise<void> => {
    if (!compiled || !identityToken.trim() || !/^gs:\/\/[^#]+#generation=[0-9]+$/.test(evaluationReceiptRef.trim())) { setCommandState("Evaluation requires a generation-pinned receipt URI and a one-time evaluator token."); return; }
    const result = await callApi<{ evaluation_id?: string }>(`${apiUrl}/api/admin/guidance/${encodeURIComponent(compiled.key)}/revisions/${encodeURIComponent(compiled.version)}/evaluations`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), ...authHeaders() }, body: JSON.stringify({ schema_version: 1, expected_digest: compiled.digest, receipt_ref: evaluationReceiptRef.trim() }) });
    if (!result.ok) { setCommandState(`Evaluation refused · ${result.detail}`); return; }
    if (result.body.evaluation_id) setEvaluationId(result.body.evaluation_id);
    setCommandState("Independent evaluation receipt recorded.");
  };
  const approve = async (): Promise<void> => {
    if (!compiled || !evaluationId || !identityToken.trim()) { setCommandState("Approval requires the exact compiled digest, verified evaluation ID, and a one-time approver token."); return; }
    const result = await callApi(`${apiUrl}/api/admin/guidance/${encodeURIComponent(compiled.key)}/revisions/${encodeURIComponent(compiled.version)}/approve`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), ...authHeaders() }, body: JSON.stringify({ schema_version: 1, expected_digest: compiled.digest, evaluation_ref: evaluationId, reason: "Reviewed the exact compiled revision and its independent evaluation receipt." }) });
    setCommandState(result.ok ? "Approval decision recorded; current-head and lineage checks were applied." : `Approval refused · ${result.detail}`);
  };
  const exportSkill = async (): Promise<void> => {
    if (!compiled || !identityToken.trim()) { setCommandState("Export requires an approved revision and a one-time exporter token."); return; }
    const result = await callApi(`${apiUrl}/api/v1/skills/${encodeURIComponent(compiled.key)}/export`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), ...authHeaders() }, body: JSON.stringify({ version: compiled.version, destination_id: destinationId, purpose: "GUIDANCE_DISTRIBUTION", stale_acknowledged: false }) });
    setCommandState(result.ok ? "Export receipt committed after destination and byte rescans." : `Export refused · ${result.detail}`);
  };
  const refresh = async (): Promise<void> => {
    const epoch = Number(expectedHeadEpoch);
    if (!compiled || !identityToken.trim() || !Number.isSafeInteger(epoch) || epoch < 1) { setCommandState("Refresh requires the displayed current-head epoch and a one-time author token."); return; }
    const result = await callApi(`${apiUrl}/api/v1/skills/${encodeURIComponent(compiled.key)}/refresh`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), ...authHeaders() }, body: JSON.stringify({ schema_version: 1, command_id: crypto.randomUUID(), purpose: "GUIDANCE_REFRESH", expected_head_epoch: epoch }) });
    setCommandState(result.ok ? "Metadata-only refresh completed; approved content was not fetched or changed." : `Refresh refused · ${result.detail}`);
  };
  return <section className="card skills-interchange-panel" aria-labelledby="skills-interchange-title">
    <div className="section-heading"><div><p className="eyebrow">Agent Skills interchange · target surface</p><h2 id="skills-interchange-title">Import governed guidance</h2><p>Packages are scanned and quarantined before compile, evaluation, approval, selection, or export.</p></div><StatusBadge label="Target · not MSR" tone="neutral" /></div>
    <div className="tool-status-legend"><div><strong>Lifecycle</strong><span>QUARANTINED → DRAFT → IN_REVIEW → APPROVED → DEPRECATED. REJECTED and REFUSED never enter runtime selection.</span></div><div><strong>Evidence</strong><span>License evidence, scanner receipts, content digest, lineage, and destination receipts remain separate records.</span></div><div><strong>Authority</strong><span>This console submits only an authenticated import request; the coordinator and Cloud SQL decide every transition.</span></div></div>
    <div className="platform-next-step"><label htmlFor="skill-package-upload"><strong>Upload package</strong></label><input id="skill-package-upload" type="file" accept=".zip,.tar,.gz" onChange={selectFile} /><button className="button primary" type="button" disabled={!selectedFile} onClick={() => void importPackage()}>Import to quarantine</button><span role="status">{status}</span></div>
    <div className="skills-command-panel" aria-label="Authenticated skill lifecycle commands">
      <div className="section-heading"><div><p className="eyebrow">Operator commands</p><h3>Advance the exact revision</h3></div><StatusBadge label="Server-authorized" tone="neutral" /></div>
      <p className="muted-copy">The token is held only in this page. Every command is rechecked against Cloud SQL role bindings, scope, digest, lineage, and idempotency.</p>
      <label className="token-field"><span>One-time Google identity token</span><input type="password" autoComplete="off" value={identityToken} onChange={(event) => setIdentityToken(event.target.value)} placeholder="Paste a short-lived token" /></label>
      <div className="skills-command-fields"><label><span>Guidance key</span><input value={guidanceKey} onChange={(event) => setGuidanceKey(event.target.value)} /></label><label><span>Version</span><input value={guidanceVersion} onChange={(event) => setGuidanceVersion(event.target.value)} /></label><label><span>Owner department</span><input value={ownerDepartment} onChange={(event) => setOwnerDepartment(event.target.value)} /></label><label className="skills-command-wide"><span>Description</span><input value={guidanceDescription} onChange={(event) => setGuidanceDescription(event.target.value)} /></label></div>
      <div className="skills-command-fields"><label><span>Allowed agent keys</span><input value={allowedAgentKeys} onChange={(event) => setAllowedAgentKeys(event.target.value)} placeholder="incident-supervisor" /></label><label><span>Applicable service kinds</span><input value={serviceKinds} onChange={(event) => setServiceKinds(event.target.value)} /></label><label><span>Applicable incident classes</span><input value={incidentClasses} onChange={(event) => setIncidentClasses(event.target.value)} /></label><label><span>Symptom tags</span><input value={symptomTags} onChange={(event) => setSymptomTags(event.target.value)} /></label><label className="skills-command-wide"><span>Required profile revisions</span><input value={profileRevisions} onChange={(event) => setProfileRevisions(event.target.value)} placeholder="supervisor.plan.v1@1" /></label></div>
      <div className="dialog-actions"><button className="secondary-button" type="button" onClick={() => void compile()} disabled={!projection?.quarantine}>Compile draft</button><button className="secondary-button" type="button" onClick={() => void submit()} disabled={!compiled}>Submit review</button><button className="secondary-button" type="button" onClick={() => void approve()} disabled={!compiled}>Approve</button></div>
      <div className="skills-command-fields"><label className="skills-command-wide"><span>Generation-pinned evaluation receipt</span><input value={evaluationReceiptRef} onChange={(event) => setEvaluationReceiptRef(event.target.value)} placeholder="gs://approved-bucket/receipt.json#generation=123" /></label><label><span>Export destination</span><input value={destinationId} onChange={(event) => setDestinationId(event.target.value)} /></label></div>
      <div className="dialog-actions"><button className="secondary-button" type="button" onClick={() => void evaluate()} disabled={!compiled}>Record evaluation</button><button className="secondary-button" type="button" onClick={() => void exportSkill()} disabled={!compiled}>Export approved revision</button></div>
      <div className="skills-command-fields"><label><span>Expected current-head epoch</span><input inputMode="numeric" value={expectedHeadEpoch} onChange={(event) => setExpectedHeadEpoch(event.target.value)} /></label><p className="muted-copy skills-command-wide">Repository, upstream ref, pinned import commit, subdirectory, and recorded tree hash are loaded from the immutable lineage; this form cannot override them.</p></div>
      <div className="dialog-actions"><button className="secondary-button" type="button" onClick={() => void refresh()} disabled={!compiled}>Run metadata-only refresh</button></div>
      {compiled && <p className="inline-notice">Exact revision: <code>{compiled.key}@{compiled.version}</code> · digest <code>{compiled.digest}</code></p>}
      {commandState && <p className="inline-notice" role="status">{commandState}</p>}
    </div>
    <SkillsGovernancePanel apiUrl={apiUrl} identityToken={identityToken} region={region} />
    <div className="skills-lifecycle-ledger" aria-label="Agent Skill lifecycle definitions">
      <h3>How an imported skill becomes usable</h3>
      <p className="muted-copy">The ledger is evidence-first. A status never implies that a model or browser action has authority.</p>
      <div className="skills-lifecycle-grid">
        {[
          ["QUARANTINED", "Imported and isolated; scanners and license evidence are being recorded."],
          ["DRAFT", "Compiled metadata exists, but no independent evaluation or approval exists."],
          ["IN_REVIEW", "Evaluation and independent approval are in progress."],
          ["APPROVED", "Eligible for coordinator selection when scope, region, and policy match."],
          ["DEPRECATED", "Previously approved, but requires explicit acknowledgement for export."],
          ["REJECTED", "The package or revision failed a governed validation or review."],
          ["REFUSED", "The request was blocked before it could create an eligible record."],
        ].map(([label, meaning]) => <div className="skills-lifecycle-item" key={label}><StatusBadge label={label} tone={label === "APPROVED" ? "success" : label === "REJECTED" || label === "REFUSED" ? "danger" : "neutral"} /><span>{meaning}</span></div>)}
      </div>
      {projection ? <SkillImportEvidence projection={projection} /> : <div className="skills-evidence-empty-state"><strong>Evidence panels</strong><span>Scanner receipts, license evidence, compile metadata, lineage, refresh notices, evaluation, approval, and export receipts appear after an authenticated attempt is selected.</span></div>}
    </div>
  </section>;
}

type SkillsGovernanceProjection = {
  owners: Array<{ owner_slug: string; owner_department: string; retired_at: string | null }>;
  licenses: Array<{ normalized_identifier: string; policy_version: string; import_allowed: boolean; redistribution_allowed: boolean; enabled: boolean }>;
  readers: Array<{ principal: string; owner_department: string; purpose: string; region: string; classification_ceiling: string; expires_at: string | null }>;
  destinations: Array<{ destination_id: string; destination_kind: string; binding_ref: string; region: string; classification_ceiling: string; enabled: boolean }>;
};

function SkillsGovernancePanel({ apiUrl, identityToken, region }: { apiUrl: string; identityToken: string; region: string }): React.JSX.Element {
  const [projection, setProjection] = useState<SkillsGovernanceProjection | null>(null);
  const [message, setMessage] = useState("Load governance to inspect registered policy inputs.");
  const [ownerSlug, setOwnerSlug] = useState("reliability-platform");
  const [ownerDepartment, setOwnerDepartment] = useState("Reliability Platform");
  const [license, setLicense] = useState("Apache-2.0");
  const [licenseVersion, setLicenseVersion] = useState("2026-08-14");
  const [reader, setReader] = useState("");
  const [destinationId, setDestinationId] = useState("tenant-guidance-default");
  const [destinationBinding, setDestinationBinding] = useState("gs://replace-with-regional-bucket/skills-exports");
  const headers = (): Record<string, string> => identityToken.trim()
    ? { "content-type": "application/json", "Authorization": identityToken.trim() }
    : { "content-type": "application/json" };
  const load = async (): Promise<void> => {
    const result = await callApi<SkillsGovernanceProjection>(`${apiUrl}/api/v1/skills/governance`, { headers: headers() });
    if (!result.ok) { setMessage(`Governance read refused · ${result.detail}`); return; }
    setProjection(result.body);
    setMessage("Current scope-bound governance loaded.");
  };
  const post = async (path: string, body: Record<string, unknown>): Promise<void> => {
    const result = await callApi(`${apiUrl}${path}`, { method: "POST", headers: headers(), body: JSON.stringify(body) });
    setMessage(result.ok ? "Governance record registered; refreshing projection." : `Registration refused · ${result.detail}`);
    if (result.ok) await load();
  };
  return <details className="skills-governance-panel">
    <summary>Configure Skills governance</summary>
    <p>Only an authenticated Operability Admin can register these exact inputs. They grant no Agent or mutation authority.</p>
    <div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => void load()}>Load registered governance</button></div>
    <div className="skills-command-fields">
      <label><span>Owner slug</span><input value={ownerSlug} onChange={(event) => setOwnerSlug(event.target.value)} /></label>
      <label><span>Owner department</span><input value={ownerDepartment} onChange={(event) => setOwnerDepartment(event.target.value)} /></label>
      <button type="button" className="secondary-button" onClick={() => void post("/api/v1/skills/governance/owners", { owner_slug: ownerSlug, owner_department: ownerDepartment, purpose: "SKILL_GOVERNANCE" })}>Register owner</button>
      <label><span>License identifier</span><input value={license} onChange={(event) => setLicense(event.target.value)} /></label>
      <label><span>Policy version</span><input value={licenseVersion} onChange={(event) => setLicenseVersion(event.target.value)} /></label>
      <button type="button" className="secondary-button" onClick={() => void post("/api/v1/skills/governance/licenses", { normalized_identifier: license, policy_version: licenseVersion, import_allowed: true, redistribution_allowed: true, enabled: true, purpose: "SKILL_GOVERNANCE" })}>Register license policy</button>
      <label className="skills-command-wide"><span>Reader principal</span><input value={reader} onChange={(event) => setReader(event.target.value)} placeholder="user:operator@example.com" /></label>
      <button type="button" className="secondary-button" disabled={!reader.trim()} onClick={() => void post("/api/v1/skills/governance/readers", { reader_principal: reader, owner_department: ownerDepartment, reader_purpose: "INCIDENT_INVESTIGATION", region, classification_ceiling: "INTERNAL", expires_at: null, purpose: "SKILL_GOVERNANCE" })}>Grant reader discovery</button>
      <label><span>Destination ID</span><input value={destinationId} onChange={(event) => setDestinationId(event.target.value)} /></label>
      <label className="skills-command-wide"><span>Regional GCS binding</span><input value={destinationBinding} onChange={(event) => setDestinationBinding(event.target.value)} /></label>
      <button type="button" className="secondary-button" onClick={() => void post("/api/v1/skills/governance/destinations", { destination_id: destinationId, destination_kind: "GCS", binding_ref: destinationBinding, region, classification_ceiling: "INTERNAL", enabled: true, purpose: "SKILL_GOVERNANCE" })}>Register destination</button>
    </div>
    <p className="inline-notice" role="status">{message}</p>
    {projection && <div className="skills-evidence-grid">
      <article className="skills-evidence-card"><h3>Owners · {projection.owners.length}</h3>{projection.owners.map((item) => <p key={item.owner_slug}><code>{item.owner_slug}</code> · {item.owner_department}{item.retired_at ? " · retired" : ""}</p>)}</article>
      <article className="skills-evidence-card"><h3>License policies · {projection.licenses.length}</h3>{projection.licenses.map((item) => <p key={item.normalized_identifier}><code>{item.normalized_identifier}</code> · {item.policy_version} · {item.redistribution_allowed ? "redistributable" : "no redistribution"}</p>)}</article>
      <article className="skills-evidence-card"><h3>Reader grants · {projection.readers.length}</h3>{projection.readers.map((item) => <p key={`${item.principal}:${item.owner_department}:${item.purpose}:${item.region}`}>{item.principal} · {item.owner_department} · {item.classification_ceiling}</p>)}</article>
      <article className="skills-evidence-card"><h3>Export destinations · {projection.destinations.length}</h3>{projection.destinations.map((item) => <p key={item.destination_id}><code>{item.destination_id}</code> · {item.binding_ref} · {item.enabled ? "enabled" : "disabled"}</p>)}</article>
    </div>}
  </details>;
}

type SkillImportProjection = {
  attempt_id: string;
  status: string;
  reason_codes: string[];
  scanner_receipts: Array<{ scanner: string; version: string; verdict: string; content_hash: string }>;
  quarantine: {
    source_skill_name: string;
    normalized_package_hash: string;
    guidance_content_hash: string;
    license_state: string;
    license_evidence_hash: string | null;
    files: Array<{ path: string; disposition: string; content_hash: string }>;
    validation_receipts: Array<{ sequence: number; reason_code: string; detail: Record<string, unknown> }>;
    retention: Array<{ object_kind: string; deletion_state: string; retention_until: string; storage_region: string }>;
  } | null;
};

function SkillImportEvidence({ projection }: { projection: SkillImportProjection }): React.JSX.Element {
  const quarantine = projection.quarantine;
  return <div className="skills-evidence-grid" aria-label="Skill import evidence">
    <article className="skills-evidence-card"><div className="section-heading"><div><p className="eyebrow">Quarantine diagnostics</p><h3>{projection.attempt_id}</h3></div><StatusBadge label={projection.status} tone={projection.status === "QUARANTINED" ? "warning" : projection.status === "REJECTED" ? "danger" : "neutral"} /></div><p>{projection.reason_codes.length ? projection.reason_codes.join(", ") : "No refusal codes; the package remains isolated until compile and independent approval."}</p>{quarantine && <dl className="tool-facts"><LabelValue label="Package" value={quarantine.source_skill_name} /><LabelValue label="Content digest" value={quarantine.guidance_content_hash} /><LabelValue label="Normalized digest" value={quarantine.normalized_package_hash} /></dl>}</article>
    <article className="skills-evidence-card"><p className="eyebrow">License and scanners</p><h3>{quarantine?.license_state ?? "No quarantine record"}</h3><p>{quarantine?.license_evidence_hash ? `License evidence · ${quarantine.license_evidence_hash}` : "License evidence is absent or not yet recorded."}</p><ul>{projection.scanner_receipts.map((receipt) => <li key={`${receipt.scanner}-${receipt.version}`}><StatusBadge label={receipt.verdict} tone={receipt.verdict === "ALLOWED" ? "success" : "danger"} /> {receipt.scanner} · {receipt.version}</li>)}</ul></article>
    <article className="skills-evidence-card"><p className="eyebrow">Stored files and receipts</p><h3>{quarantine?.files.length ?? 0} files · {quarantine?.validation_receipts.length ?? 0} validation receipts</h3><ul>{quarantine?.files.map((file) => <li key={file.path}><code>{file.path}</code> · {file.disposition}</li>)}</ul></article>
    <article className="skills-evidence-card"><p className="eyebrow">Retention and deletion</p><h3>{quarantine?.retention.length ?? 0} registered objects</h3><ul>{quarantine?.retention.map((item) => <li key={`${item.object_kind}-${item.retention_until}`}><StatusBadge label={item.deletion_state} tone={item.deletion_state === "RETAINED" ? "info" : "warning"} /> {item.object_kind} · {item.storage_region} · until {new Date(item.retention_until).toLocaleDateString()}</li>)}</ul></article>
  </div>;
}
