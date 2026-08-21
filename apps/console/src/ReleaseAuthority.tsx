import { useState } from "react";
import { LabelValue, MonoChip, StatusBadge } from "./components";

/* Release authority: which principals may roll a revision, which targets are
   registered, and which signing key version verifies a release. Its own module
   because it authorizes deployments rather than connecting an estate, and it
   shares no state with the integrations page beyond the API URL. */

type ReleaseAuthorityPosture = {
  api_service_account: string;
  deployment_controller_service_account: string;
  release_verifier_service_account: string;
  release_verifier_key_version: string;
};

type ReleaseTarget = {
  id: string;
  target_key: string;
  service_resource_name: string;
  expected_target_epoch: number;
  runtime_service_account: string;
  canary_percentages: number[];
  verification_profile_id: string;
  verification_profile_version: string;
  profile_hash: string;
  status: string;
};

type ReleaseKey = {
  id: string;
  signer_identity?: string;
  verifier_identity?: string;
  key_version: string;
  status: string;
};

export function ReleaseAuthoritySetup({ apiUrl }: { apiUrl: string }): React.JSX.Element {
  const [token, setToken] = useState("");
  const [posture, setPosture] = useState<ReleaseAuthorityPosture | null>(null);
  const [targets, setTargets] = useState<ReleaseTarget[] | null>(null);
  const [signers, setSigners] = useState<ReleaseKey[] | null>(null);
  const [verifiers, setVerifiers] = useState<ReleaseKey[] | null>(null);
  const [signerIdentity, setSignerIdentity] = useState("");
  const [signerKey, setSignerKey] = useState("");
  const [project, setProject] = useState("");
  const [location, setLocation] = useState("europe-west1");
  const [service, setService] = useState("");
  const [runtimeIdentity, setRuntimeIdentity] = useState("");
  const [container, setContainer] = useState("app");
  const [epoch, setEpoch] = useState("1");
  const [percentages, setPercentages] = useState("10,50,100");
  const [windows, setWindows] = useState("300,600,900");
  const [deadline, setDeadline] = useState("3600");
  const [profileId, setProfileId] = useState("cloud-run-service-health");
  const [profileVersion, setProfileVersion] = useState("1");
  const [maximum5xx, setMaximum5xx] = useState("0.02");
  const [maximum5xxRegression, setMaximum5xxRegression] = useState("0.01");
  const [maximumLatency, setMaximumLatency] = useState("1000");
  const [maximumLatencyRegression, setMaximumLatencyRegression] = useState("250");
  const [minimumPoints, setMinimumPoints] = useState("3");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function request<T>(path: string, options?: RequestInit): Promise<T> {
    if (!token.trim()) throw new Error("Enter a fresh administrator identity token.");
    const response = await fetch(`${apiUrl}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-Solvan-Approval-Token": token.trim(),
        ...(options?.method === "POST" ? { "Idempotency-Key": crypto.randomUUID() } : {}),
      },
    });
    if (!response.ok) throw new Error(`Release authority refused (${response.status}) · ${await response.text()}`);
    return (await response.json()) as T;
  }

  async function load(): Promise<void> {
    setBusy(true); setNotice(null);
    try {
      const [nextPosture, nextTargets, nextSigners, nextVerifiers] = await Promise.all([
        request<ReleaseAuthorityPosture>("/api/v1/release-authority/posture"),
        request<ReleaseTarget[]>("/api/v1/release-authority/targets"),
        request<ReleaseKey[]>("/api/v1/release-authority/signer-keys"),
        request<ReleaseKey[]>("/api/v1/release-authority/verifier-keys"),
      ]);
      setPosture(nextPosture); setTargets(nextTargets);
      setSigners(nextSigners); setVerifiers(nextVerifiers);
      setNotice("Release identities and registered targets were read from current authority.");
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Release authority is unavailable."); }
    finally { setBusy(false); }
  }

  async function registerKey(kind: "signer" | "verifier"): Promise<void> {
    setBusy(true); setNotice(null);
    try {
      const identity = kind === "verifier" && posture
        ? `serviceAccount:${posture.release_verifier_service_account}`
        : signerIdentity.trim();
      const keyVersion = kind === "verifier" && posture
        ? posture.release_verifier_key_version
        : signerKey.trim();
      if (!identity || !keyVersion) throw new Error(`Enter the ${kind} identity and exact KMS key version.`);
      const result = await request<Record<string, string>>(`/api/v1/release-authority/${kind}-keys`, {
        method: "POST",
        body: JSON.stringify({ signer_identity: identity, key_version: keyVersion }),
      });
      if (kind === "signer") setSigners(await request<ReleaseKey[]>("/api/v1/release-authority/signer-keys"));
      else setVerifiers(await request<ReleaseKey[]>("/api/v1/release-authority/verifier-keys"));
      setNotice(`${kind === "signer" ? "Build signer" : "Independent verifier"} registered · ${Object.values(result).join(" · ")}`);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Key registration failed."); }
    finally { setBusy(false); }
  }

  function integerList(value: string, label: string): number[] {
    const result = value.split(",").map((item) => Number(item.trim()));
    if (!result.length || result.some((item) => !Number.isInteger(item))) throw new Error(`${label} must be comma-separated integers.`);
    return result;
  }

  async function registerTarget(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setNotice(null);
    try {
      if (!posture) throw new Error("Load the deployed release identities first.");
      const result = await request<Record<string, string>>("/api/v1/release-authority/targets", {
        method: "POST",
        body: JSON.stringify({
          target_key: `${project.trim()}/${location.trim()}/${service.trim()}`,
          external_project_id: project.trim(), location: location.trim(), service_name: service.trim(),
          expected_target_epoch: Number(epoch), runtime_service_account: runtimeIdentity.trim(),
          allowed_container_name: container.trim(), canary_percentages: integerList(percentages, "Canary percentages"),
          observation_windows_seconds: integerList(windows, "Observation windows"),
          rollout_deadline_seconds: Number(deadline), verification_profile_id: profileId.trim(),
          verification_profile_version: profileVersion.trim(),
          verifier_identity: `serviceAccount:${posture.release_verifier_service_account}`,
          verifier_key_version: posture.release_verifier_key_version,
          health_signals: [
            { signal_kind: "CLOUD_RUN_HTTP_5XX_RATIO", maximum_value: Number(maximum5xx), maximum_regression: Number(maximum5xxRegression), minimum_points: Number(minimumPoints) },
            { signal_kind: "CLOUD_RUN_HTTP_P95_LATENCY_MS", maximum_value: Number(maximumLatency), maximum_regression: Number(maximumLatencyRegression), minimum_points: Number(minimumPoints) },
          ],
        }),
      });
      setNotice(`Cloud Run target probed and registered · ${result.release_target_profile_id} · ${result.profile_hash}`);
      setTargets(await request<ReleaseTarget[]>("/api/v1/release-authority/targets"));
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Target registration failed."); }
    finally { setBusy(false); }
  }

  return <details className="card connection-card" aria-label="Release authority setup">
    <summary><strong>Set up governed Cloud Run releases</strong><span className="cell-detail">Keys, external-project IAM, canary policy, and independent health verification</span></summary>
    <p className="section-note">This setup records public verification authority and a probed Cloud Run target. Solvan never asks for a private key, GitHub password, runtime credential, or service-account key file.</p>
    <label className="field-label">Administrator identity token<input type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} /></label>
    <div className="settings-actions"><button className="secondary-button" type="button" disabled={busy || !token.trim()} onClick={() => void load()}>{busy ? "Checking…" : "Load release posture"}</button></div>
    {posture && <div className="verification-summary"><LabelValue label="Setup/probe identity" value={posture.api_service_account} /><LabelValue label="Deployment Controller" value={posture.deployment_controller_service_account} /><LabelValue label="Independent verifier" value={posture.release_verifier_service_account} /><LabelValue label="Verifier key" value={posture.release_verifier_key_version} /></div>}
    {posture && <div className="inline-notice"><strong>Grant in the customer project before registration:</strong><ul><li><MonoChip>{posture.api_service_account}</MonoChip>: Cloud Run Viewer on the exact target for setup probing, plus Cloud KMS Public Key Viewer on the exact external CI signer key.</li><li><MonoChip>{posture.deployment_controller_service_account}</MonoChip>: Cloud Run Developer on the exact target and Service Account User on the selected runtime identity.</li><li><MonoChip>{posture.release_verifier_service_account}</MonoChip>: Cloud Run Viewer and Monitoring Viewer. It receives no deploy or impersonation role.</li></ul></div>}
    <div className="form-grid"><label className="field-label">CI release signer identity<input value={signerIdentity} onChange={(event) => setSignerIdentity(event.target.value)} placeholder="serviceAccount:builder@project.iam.gserviceaccount.com" /></label><label className="field-label">Exact asymmetric KMS key version<input value={signerKey} onChange={(event) => setSignerKey(event.target.value)} placeholder="projects/…/cryptoKeyVersions/1" /></label></div>
    <div className="settings-actions"><button className="secondary-button" type="button" disabled={busy} onClick={() => void registerKey("signer")}>Register build signer</button><button className="secondary-button" type="button" disabled={busy || !posture} onClick={() => void registerKey("verifier")}>Register deployed verifier</button></div>
    {(signers?.length || verifiers?.length) ? <div className="responsive-table"><table><caption>Release verification keys</caption><thead><tr><th>Authority</th><th>Identity</th><th>Key version</th><th>Status</th></tr></thead><tbody>{signers?.map((key) => <tr key={key.id}><td>Build signer</td><td>{key.signer_identity}</td><td><MonoChip>{key.key_version}</MonoChip></td><td><StatusBadge label={key.status} tone={key.status === "ACTIVE" ? "success" : "neutral"} /></td></tr>)}{verifiers?.map((key) => <tr key={key.id}><td>Independent verifier</td><td>{key.verifier_identity}</td><td><MonoChip>{key.key_version}</MonoChip></td><td><StatusBadge label={key.status} tone={key.status === "ACTIVE" ? "success" : "neutral"} /></td></tr>)}</tbody></table></div> : null}
    <form className="connect-form" onSubmit={(event) => void registerTarget(event)}>
      <h3>Cloud Run release target</h3>
      <div className="form-grid"><label className="field-label">Customer GCP project<input required value={project} onChange={(event) => setProject(event.target.value)} /></label><label className="field-label">Target region<input required value={location} onChange={(event) => setLocation(event.target.value)} /></label><label className="field-label">Cloud Run service<input required value={service} onChange={(event) => setService(event.target.value)} /></label><label className="field-label">Runtime service account<input required value={runtimeIdentity} onChange={(event) => setRuntimeIdentity(event.target.value)} /></label><label className="field-label">Container name<input required value={container} onChange={(event) => setContainer(event.target.value)} /></label><label className="field-label">Target authority epoch<input required type="number" min="1" value={epoch} onChange={(event) => setEpoch(event.target.value)} /></label></div>
      <h3>Progressive rollout</h3>
      <div className="form-grid"><label className="field-label">Traffic stages (%)<input required value={percentages} onChange={(event) => setPercentages(event.target.value)} /></label><label className="field-label">Observation windows (seconds)<input required value={windows} onChange={(event) => setWindows(event.target.value)} /></label><label className="field-label">Overall deadline (seconds)<input required type="number" min="60" value={deadline} onChange={(event) => setDeadline(event.target.value)} /></label><label className="field-label">Verification profile ID<input required value={profileId} onChange={(event) => setProfileId(event.target.value)} /></label><label className="field-label">Profile version<input required value={profileVersion} onChange={(event) => setProfileVersion(event.target.value)} /></label><label className="field-label">Minimum metric points<input required type="number" min="1" value={minimumPoints} onChange={(event) => setMinimumPoints(event.target.value)} /></label></div>
      <h3>Health ceilings</h3>
      <div className="form-grid"><label className="field-label">Maximum 5xx ratio<input required type="number" step="any" min="0" value={maximum5xx} onChange={(event) => setMaximum5xx(event.target.value)} /></label><label className="field-label">Maximum 5xx regression<input required type="number" step="any" min="0" value={maximum5xxRegression} onChange={(event) => setMaximum5xxRegression(event.target.value)} /></label><label className="field-label">Maximum p95 latency (ms)<input required type="number" step="any" min="0" value={maximumLatency} onChange={(event) => setMaximumLatency(event.target.value)} /></label><label className="field-label">Maximum latency regression (ms)<input required type="number" step="any" min="0" value={maximumLatencyRegression} onChange={(event) => setMaximumLatencyRegression(event.target.value)} /></label></div>
      <button className="primary-button" type="submit" disabled={busy || !posture}>{busy ? "Probing…" : "Probe and register exact target"}</button>
    </form>
    {targets && targets.length > 0 && <div className="responsive-table"><table><caption>Registered Cloud Run release targets</caption><thead><tr><th>Target</th><th>Service</th><th>Canary</th><th>Verifier profile</th><th>Status</th></tr></thead><tbody>{targets.map((target) => <tr key={target.id}><td><MonoChip>{target.target_key}</MonoChip><span className="cell-detail">epoch {target.expected_target_epoch}</span></td><td>{target.service_resource_name}</td><td>{target.canary_percentages.join(" → ")}%</td><td>{target.verification_profile_id} · {target.verification_profile_version}</td><td><StatusBadge label={target.status} tone={target.status === "ACTIVE" ? "success" : "neutral"} /></td></tr>)}</tbody></table></div>}
    {targets?.length === 0 && <p className="inline-notice">No release target is registered, so deployment approval cannot create a rollout.</p>}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </details>;
}

