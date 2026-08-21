import { useCallback, useEffect, useState } from "react";
import type { Subscription } from "./AskSupport";

export function useLiaisonSubscription({
  apiUrl,
  recordType,
  recordId,
  identityHeaders,
  enabled,
}: {
  apiUrl: string;
  recordType: string;
  recordId: string;
  identityHeaders: () => Record<string, string>;
  enabled: boolean;
}): {
  following: boolean;
  pending: boolean;
  error: string | null;
  toggle: () => Promise<void>;
} {
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const refresh = useCallback(async () => {
    if (!enabled) {
      setSubscriptions([]);
      return;
    }
    try {
      const response = await fetch(`${apiUrl}/api/v1/subscriptions`, { headers: identityHeaders() });
      if (!response.ok) throw new Error(`Subscription service returned ${response.status}`);
      const body = await response.json() as { subscriptions?: Subscription[] };
      setSubscriptions(body.subscriptions ?? []);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Subscriptions are unavailable");
    }
  }, [apiUrl, enabled, identityHeaders]);

  useEffect(() => { void refresh(); }, [refresh]);

  const active = subscriptions.find((item) => item.status === "ACTIVE" && item.anchor_record_type === recordType && item.anchor_record_id === recordId) ?? null;

  const toggle = useCallback(async (): Promise<void> => {
    if (!enabled || pending) return;
    setPending(true);
    setError(null);
    try {
      const response = active
        ? await fetch(`${apiUrl}/api/v1/subscriptions/${active.id}`, {
          method: "DELETE",
          headers: { "Idempotency-Key": crypto.randomUUID(), ...identityHeaders() },
        })
        : await fetch(`${apiUrl}/api/v1/subscriptions`, {
          method: "POST",
          headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID(), ...identityHeaders() },
          body: JSON.stringify({ schema_version: 1, anchor_record_type: recordType, anchor_record_id: recordId, cadence: "ON_EVENT" }),
        });
      if (!response.ok) throw new Error(`Subscription change was refused (${response.status})`);
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Subscription change failed");
    } finally {
      setPending(false);
    }
  }, [active, apiUrl, enabled, identityHeaders, pending, recordId, recordType, refresh]);

  return { following: Boolean(active), pending, error, toggle };
}
