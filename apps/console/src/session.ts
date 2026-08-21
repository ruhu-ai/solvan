/** Who the browser is signed in as, and how it asks for a one-use grant.
 *
 *  The session is a cookie the browser never reads: it is `HttpOnly`, so this
 *  module can only ask the API who it belongs to. Roles come back per request
 *  rather than being cached here, because a revocation must take effect at once
 *  rather than when a tab is next reloaded.
 *
 *  The console and the API are one origin. Development used to call the API's
 *  own origin directly while deployment proxied through this one, so the
 *  session transport under test was not the transport that shipped.
 */
import { useCallback, useEffect, useState } from "react";

export type OperatorSession = {
  actor_id: string;
  email: string | null;
  roles: string[];
  absolute_expires_at: string;
};

export type SessionState =
  | { status: "loading" }
  | { status: "signed-out"; reason?: string; provider: string; providerIsProduction: boolean }
  /** The console and the API disagree, or the API cannot be reached. Distinct
   *  from being signed out: the reader is not signed out, the deployment is
   *  inconsistent, and offering them a login they cannot complete states
   *  something false about why they are stuck. */
  | { status: "unavailable"; reason: string }
  | { status: "signed-in"; session: OperatorSession };

export function useOperatorSession(
  apiUrl: string,
): { state: SessionState; refresh: () => void } {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    // One question, asked unconditionally: who is this? There is no preceding
    // question about whether sign-in is required. Asking that first is what
    // made a 404, a mistyped API URL, or a proxy in front of the wrong service
    // render the console as a signed-in reader with no session at all — the
    // absence of an answer became the answer.
    fetch(`${apiUrl}/api/auth/session`, { credentials: "include", signal: controller.signal })
      .then(async (response) => {
        if (response.status === 401) {
          // The refusal names the provider, so the page can say where the
          // button goes without a second round trip that could disagree.
          const detail = await response.json().catch(() => null) as
            { detail?: { provider?: string; provider_is_production?: boolean } } | null;
          setState({
            status: "signed-out",
            provider: detail?.detail?.provider ?? "Google",
            // Absent means production: a console never presents a test sign-in
            // as the real one because a field went missing.
            providerIsProduction: detail?.detail?.provider_is_production !== false,
          });
          return;
        }
        if (response.status === 404) {
          // This API mounts no sign-in. That is a broken deployment, not a
          // deployment that needs none, and it is never a reason to render.
          setState({
            status: "unavailable",
            reason: "This API serves no sign-in, so who you are cannot be established. Either it is running a version that predates operator authentication, or it is deployed without an identity provider configured.",
          });
          return;
        }
        if (!response.ok) throw new Error(`Session check returned ${response.status}`);
        setState({ status: "signed-in", session: await response.json() as OperatorSession });
      })
      .catch((cause: unknown) => {
        if (cause instanceof DOMException && cause.name === "AbortError") return;
        setState({
          status: "unavailable",
          reason: "The API could not be reached, so who you are could not be established. Nothing is shown rather than guessing.",
        });
      });
    return () => controller.abort();
  }, [apiUrl, attempt]);
  return { state, refresh: useCallback(() => setAttempt((value) => value + 1), []) };
}

/** End this browser's session, server-side.
 *
 *  The cookie is `HttpOnly`, so clearing it is the server's to do: a console
 *  that only dropped its own copy would leave a session live for anyone holding
 *  it. The call carries the double-submit token because ending a session is a
 *  state change a cross-site page must not be able to make.
 */
export async function signOut(apiUrl: string): Promise<void> {
  const response = await fetch(`${apiUrl}/api/auth/logout`, {
    method: "POST",
    credentials: "include",
    headers: csrfHeaders(),
  });
  if (!response.ok) throw new Error(`Sign-out failed (${response.status}).`);
}

/** Freeze one action, then request its transaction-bound presence code.
 *
 *  This is what replaces the identity-token field. The operator meets the
 *  The destination comes from the server's verified Google identity binding,
 *  never from this page. What verifies authorizes the operation frozen before
 *  delivery — not whatever the page holds afterwards.
 *
 *  The freeze is a POST carrying the material digest in its body, because a
 *  query parameter travels into history, referrer headers and logs. The
 *  The raw code never enters storage or a URL; the API returns only an opaque
 *  handle and masked destination.
 */
export type StepUpStart = {
  step_up_handle: string;
  destination: string;
  expires_in_seconds: number;
};

export async function requestStepUp(
  apiUrl: string,
  operation: string,
  materialDigest: string,
): Promise<StepUpStart> {
  const response = await fetch(`${apiUrl}/api/auth/step-up`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json", ...csrfHeaders() },
    body: JSON.stringify({ operation, material_digest: materialDigest }),
  });
  if (!response.ok) throw new Error(`This action could not be prepared (${response.status}).`);
  return await response.json() as StepUpStart;
}

/** Spend the emailed presence code and receive its exact one-use action handle. */
export async function verifyStepUp(
  apiUrl: string,
  stepUpHandle: string,
  code: string,
): Promise<string> {
  const response = await fetch(`${apiUrl}/api/auth/step-up/verify`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json", ...csrfHeaders() },
    body: JSON.stringify({ step_up_handle: stepUpHandle, code }),
  });
  if (!response.ok) {
    const value = await response.json().catch(() => null) as { detail?: string } | null;
    throw new Error(value?.detail ?? "That verification code was refused.");
  }
  const { challenge } = await response.json() as { challenge: string };
  return challenge;
}

/** The digest of what a challenge authorizes, as the API rebuilds it.
 *
 *  Here rather than in a surface module because more than one surface now
 *  requests a challenge, and the material digest has to be computed the one way
 *  the API rebuilds it. A second copy that drifted would not fail loudly — it
 *  would ask for a challenge that authorizes something other than what the
 *  operator is about to do.
 */
export async function digest(material: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
  return `sha256:${Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/** Headers that spend a challenge on one exact action. */
export function challengeHeaders(challenge: string): Record<string, string> {
  return { ...csrfHeaders(), "X-Solvan-Challenge": challenge };
}

/** The double-submit token the API compares against its cookie. */
export function csrfHeaders(): Record<string, string> {
  const match = document.cookie.match(/(?:^|;\s*)__Host-solvan_csrf=([^;]+)/);
  return match ? { "X-Solvan-CSRF": decodeURIComponent(match[1]) } : {};
}
