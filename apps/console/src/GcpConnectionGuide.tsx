import { ArrowLeft, ExternalLink, ShieldCheck } from "lucide-react";
import { MonoChip, PageHeader } from "./components";

export function GcpConnectionGuide({ onBack }: { onBack: () => void }): React.JSX.Element {
  return <>
    <button className="back-button" type="button" onClick={onBack}><ArrowLeft size={15} aria-hidden="true" /> Integrations</button>
    <PageHeader
      eyebrow="Google Cloud setup guide"
      title="Connect a GCP project safely"
      description="Create one customer-owned read-only identity, let the wizard generate the exact grants, and verify what Solvan can actually read. No service-account key is created or uploaded."
    />

    <section className="card connection-guide-callout">
      <ShieldCheck size={22} strokeWidth={1.75} aria-hidden="true" />
      <div><h2>The trust boundary</h2><p>Solvan receives permission to mint a short-lived token for one customer reader. The reader has only the source-specific read roles you approve. Solvan never asks for its private key, password, or JSON credential.</p></div>
    </section>

    <div className="connection-guide-grid">
      <section className="card connection-guide-card">
        <p className="eyebrow">Before you begin</p>
        <h2>What you need</h2>
        <ul>
          <li>A Solvan administrator session for this environment.</li>
          <li>The Google Cloud <strong>project ID</strong>, not its display name or numeric project number.</li>
          <li>Permission in that project to create a service account and grant the selected read roles.</li>
          <li>Permission to edit IAM policy on the new service account so the exact Solvan reader may impersonate it.</li>
        </ul>
        <div className="guide-links">
          <a className="secondary-button" href="https://console.cloud.google.com/projectselector2/home/dashboard" target="_blank" rel="noreferrer">Open Google Cloud project selector <ExternalLink size={14} aria-hidden="true" /></a>
          <a className="secondary-button" href="https://console.cloud.google.com/iam-admin/serviceaccounts" target="_blank" rel="noreferrer">Open Service Accounts <ExternalLink size={14} aria-hidden="true" /></a>
        </div>
      </section>

      <section className="card connection-guide-card">
        <p className="eyebrow">Field reference</p>
        <h2>Where each value comes from</h2>
        <dl className="guide-facts">
          <div><dt>Administrator identity token</dt><dd>A short-lived Google ID token from the currently authorized Solvan operator sign-in. It is not a Google API access token, service-account token, or customer credential. Solvan keeps it only in this browser view and verifies its signature, audience, email, and role.</dd></div>
          <div><dt>Customer read-only service account</dt><dd>The email of the service account created in the customer project, normally <MonoChip>solvan-reader@PROJECT_ID.iam.gserviceaccount.com</MonoChip>. Do not create or download a key.</dd></div>
          <div><dt>Your Google Cloud project</dt><dd>The immutable project ID shown in the Google Cloud project selector and dashboard, for example <MonoChip>ruhu-dev</MonoChip>.</dd></div>
          <div><dt>Workload region</dt><dd>The region containing the workload being observed, for example <MonoChip>europe-west2</MonoChip>. It may differ from Solvan’s control-data region.</dd></div>
        </dl>
      </section>
    </div>

    <section className="card connection-guide-card">
      <p className="eyebrow">Connection procedure</p>
      <h2>Set up and verify</h2>
      <ol className="guide-steps">
        <li><div><strong>Select the target project.</strong><p>Open Google Cloud and confirm the project ID and workload region. Enable the APIs required for the sources you plan to connect.</p></div></li>
        <li><div><strong>Create the customer reader identity.</strong><p>In IAM &amp; Admin → Service Accounts, create <MonoChip>solvan-reader</MonoChip>. Leave the key section empty. Creating a key is neither required nor accepted by this flow.</p></div></li>
        <li><div><strong>Enter the four values in Solvan.</strong><p>Select only the telemetry sources this estate should expose, then choose <strong>Show me the grants</strong>.</p></div></li>
        <li><div><strong>Run Solvan’s generated commands in the customer project.</strong><p>The commands grant source-specific read roles to the customer reader and Token Creator only on that exact service account to Solvan’s reader identity. Review them before running them.</p></div></li>
        <li><div><strong>Register and verify.</strong><p>Solvan performs a minimal read-only probe. The connection becomes Ready only when the provider proves the selected capability; a failed probe records the missing grant or next safe step.</p></div></li>
        <li><div><strong>Create monitoring rules.</strong><p>For a Ready Cloud Monitoring connection, bind an exact resource and threshold. Detector results then enter the durable alert and incident pipeline.</p></div></li>
      </ol>
    </section>

    <section className="card connection-guide-card">
      <p className="eyebrow">What never to provide</p>
      <h2>No customer secrets</h2>
      <p>Do not paste or upload a service-account JSON key, private key, refresh token, API key, password, raw IAM policy, or unrestricted credential. If a screen or instruction asks for one, stop: it is not this connection path.</p>
      <button className="primary-button" type="button" onClick={onBack}>Return to Integrations</button>
    </section>
  </>;
}
