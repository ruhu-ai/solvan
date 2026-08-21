import { useState } from "react";
import { Loader2, ShieldCheck } from "lucide-react";
import type { StepUpStart } from "./session";
import { verifyStepUp } from "./session";

export function StepUpDialog({
  apiUrl,
  request,
  onVerified,
  onCancel,
}: {
  apiUrl: string;
  request: StepUpStart;
  onVerified: (challenge: string) => Promise<void>;
  onCancel: () => void;
}): React.JSX.Element {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const challenge = await verifyStepUp(apiUrl, request.step_up_handle, code);
      await onVerified(challenge);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "That verification code was refused.");
      setBusy(false);
    }
  }

  return <div className="step-up-shade" role="presentation">
    <section className="card step-up-dialog" role="dialog" aria-modal="true" aria-labelledby="step-up-title">
      <p className="eyebrow">Confirm it is you</p>
      <h2 id="step-up-title">Enter the code we emailed</h2>
      <p>We sent an eight-digit, one-use code to <strong>{request.destination}</strong>. It authorizes only the exact action you just reviewed and expires in {Math.ceil(request.expires_in_seconds / 60)} minutes.</p>
      <form onSubmit={(event) => void submit(event)}>
        <label htmlFor="operator-step-up-code">Verification code</label>
        <input id="operator-step-up-code" inputMode="numeric" autoComplete="one-time-code"
          pattern="[0-9]{8}" maxLength={8} required autoFocus value={code}
          onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 8))} />
        {error && <p className="inline-notice" role="alert">{error}</p>}
        <div className="settings-actions">
          <button className="secondary-button" type="button" disabled={busy} onClick={onCancel}>Cancel</button>
          <button className="primary-button" type="submit" disabled={busy || code.length !== 8}>
            {busy ? <Loader2 size={16} className="spin" aria-hidden="true" /> : <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
            {busy ? "Verifying…" : "Verify and continue"}
          </button>
        </div>
      </form>
      <p className="muted-copy">Solvan support will never ask you to share this code.</p>
    </section>
  </div>;
}
