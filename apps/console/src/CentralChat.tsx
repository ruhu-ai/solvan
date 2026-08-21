import { useCallback, useEffect, useState } from "react";
import { Search, X } from "lucide-react";
import { AskRail } from "./Ask";
import { PageHeader } from "./components";

type DirectoryRecord = {
  record_type: string;
  record_id: string;
  title: string;
  service: string;
  state: string;
  severity: string;
  revision: string;
};

type ServiceRecord = { service_key: string; visible_record_count: number };
type AttachedRecord = DirectoryRecord & { kind: "RECORD"; thread_id: string };
type AttachedService = ServiceRecord & {
  kind: "SERVICE_WINDOW";
  thread_id: string;
  window_start: string;
  window_end: string;
};
type Attachment = AttachedRecord | AttachedService;

/** Workspace Chat plus an explicit, reader-filtered record attachment flow. */
export function CentralChat({
  apiUrl,
  authority,
}: {
  apiUrl: string;
  authority: string;
}): React.JSX.Element {
  const [query, setQuery] = useState("");
  const [directoryMode, setDirectoryMode] = useState<"INCIDENTS" | "SERVICES">("INCIDENTS");
  const [windowHours, setWindowHours] = useState<1 | 6 | 24>(24);
  const [records, setRecords] = useState<DirectoryRecord[]>([]);
  const [services, setServices] = useState<ServiceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectionPending, setSelectionPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attached, setAttached] = useState<Attachment | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      const params = new URLSearchParams({ search: query });
      if (directoryMode === "INCIDENTS") {
        params.set("record_type", "incident");
        params.set("limit", "20");
      }
      const endpoint = `${apiUrl}/api/v1/liaison/${directoryMode === "INCIDENTS" ? "directory" : "services"}?${params}`;
      setLoading(true);
      fetch(endpoint, { signal: controller.signal })
        .then(async (response) => {
          if (!response.ok) throw new Error(`Conversation directory returned ${response.status}`);
          return await response.json() as { items: DirectoryRecord[] | ServiceRecord[] };
        })
        .then((body) => {
          if (directoryMode === "INCIDENTS") setRecords(body.items as DirectoryRecord[]);
          else setServices(body.items as ServiceRecord[]);
          setError(null);
        })
        .catch((reason: unknown) => {
          if (reason instanceof DOMException && reason.name === "AbortError") return;
          setError(reason instanceof Error ? reason.message : "Record directory is unavailable");
        })
        .finally(() => setLoading(false));
    }, 180);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [apiUrl, directoryMode, query]);

  const attach = useCallback(async (record: DirectoryRecord): Promise<void> => {
    setSelectionPending(record.record_id);
    setError(null);
    try {
      const issued = await fetch(`${apiUrl}/api/v1/liaison/selections`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          schema_version: 1,
          record_type: record.record_type,
          record_id: record.record_id,
        }),
      });
      if (!issued.ok) throw new Error(`Record selection was refused (${issued.status})`);
      const receipt = await issued.json() as { selection_receipt_id: string };
      const opened = await fetch(
        `${apiUrl}/api/v1/liaison/selections/${receipt.selection_receipt_id}:open`,
        {
          method: "POST",
          headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID() },
          body: JSON.stringify({ schema_version: 1 }),
        },
      );
      if (!opened.ok) throw new Error(`Record attachment was refused (${opened.status})`);
      const result = await opened.json() as { thread_id: string };
      setAttached({ ...record, kind: "RECORD", thread_id: result.thread_id });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The record could not be attached");
    } finally {
      setSelectionPending(null);
    }
  }, [apiUrl]);

  const attachService = useCallback(async (service: ServiceRecord): Promise<void> => {
    setSelectionPending(service.service_key);
    setError(null);
    const windowEnd = new Date();
    const windowStart = new Date(windowEnd.getTime() - windowHours * 60 * 60 * 1000);
    try {
      const issued = await fetch(`${apiUrl}/api/v1/liaison/service-selections`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          schema_version: 1,
          service_key: service.service_key,
          window_start: windowStart.toISOString(),
          window_end: windowEnd.toISOString(),
        }),
      });
      if (!issued.ok) throw new Error(`Service selection was refused (${issued.status})`);
      const receipt = await issued.json() as { selection_receipt_id: string };
      const opened = await fetch(
        `${apiUrl}/api/v1/liaison/service-selections/${receipt.selection_receipt_id}:open`,
        {
          method: "POST",
          headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID() },
          body: JSON.stringify({ schema_version: 1 }),
        },
      );
      if (!opened.ok) throw new Error(`Service attachment was refused (${opened.status})`);
      const result = await opened.json() as {
        thread_id: string;
        window_start: string;
        window_end: string;
      };
      setAttached({
        ...service,
        kind: "SERVICE_WINDOW",
        thread_id: result.thread_id,
        window_start: result.window_start,
        window_end: result.window_end,
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The service could not be attached");
    } finally {
      setSelectionPending(null);
    }
  }, [apiUrl, windowHours]);

  return <>
    <PageHeader
      eyebrow="Conversation"
      title="Chat with Solvan"
      description="Ask normally about the workspace, attach one visible incident, or bind a service and recent time window. Every focused conversation starts from a short-lived reader receipt."
    />
    <div className="central-chat-layout">
      <section className="central-chat-directory card" aria-labelledby="chat-directory-title">
        <div className="section-heading">
          <div>
            <h2 id="chat-directory-title">Focus the conversation</h2>
            <p>Selecting a result creates a short-lived, server-verified receipt. Typed or pasted names never attach by themselves.</p>
          </div>
        </div>
        <div className="central-chat-directory-tabs" role="tablist" aria-label="Conversation focus">
          <button type="button" role="tab" aria-selected={directoryMode === "INCIDENTS"} onClick={() => setDirectoryMode("INCIDENTS")}>Incidents</button>
          <button type="button" role="tab" aria-selected={directoryMode === "SERVICES"} onClick={() => setDirectoryMode("SERVICES")}>Services</button>
        </div>
        {directoryMode === "SERVICES" && <div className="central-chat-window" aria-label="Service time window">
          <span>Time window</span>
          {([1, 6, 24] as const).map((hours) => <button
            key={hours}
            type="button"
            aria-pressed={windowHours === hours}
            onClick={() => setWindowHours(hours)}
          >Last {hours}h</button>)}
        </div>}
        <label className="central-chat-search">
          <Search size={16} aria-hidden="true" />
          <span className="sr-only">Search visible {directoryMode === "INCIDENTS" ? "incidents" : "services"}</span>
          <input
            type="search"
            value={query}
            placeholder={directoryMode === "INCIDENTS" ? "Search incident, service, or state" : "Search service"}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        {error && <p className="state-inline state-warning" role="alert">{error}</p>}
        {loading ? <p className="muted">Loading visible {directoryMode === "INCIDENTS" ? "incidents" : "services"}…</p>
          : directoryMode === "INCIDENTS" && records.length === 0
          ? <p className="muted">No visible incidents match this search.</p>
          : directoryMode === "SERVICES" && services.length === 0
          ? <p className="muted">No visible services match this search.</p>
          : directoryMode === "INCIDENTS"
          ? <ul className="central-chat-records">
            {records.map((record) => <li key={`${record.record_type}:${record.record_id}`}>
              <button
                type="button"
                onClick={() => void attach(record)}
                disabled={selectionPending !== null}
                aria-label={`Attach ${record.record_id}: ${record.title}`}
              >
                <span><strong>{record.record_id}</strong><small>{record.service || "No service"}</small></span>
                <span><strong>{record.title}</strong><small>{[record.severity, record.state].filter(Boolean).join(" · ")}</small></span>
                <span>{selectionPending === record.record_id ? "Attaching…" : "Attach"}</span>
              </button>
            </li>)}
          </ul>
          : <ul className="central-chat-records central-chat-services">
            {services.map((service) => <li key={service.service_key}>
              <button
                type="button"
                onClick={() => void attachService(service)}
                disabled={selectionPending !== null}
                aria-label={`Attach ${service.service_key} for the last ${windowHours} hours`}
              >
                <span><strong>{service.service_key}</strong><small>{service.visible_record_count} visible record{service.visible_record_count === 1 ? "" : "s"}</small></span>
                <span>{selectionPending === service.service_key ? "Attaching…" : `Attach last ${windowHours}h`}</span>
              </button>
            </li>)}
          </ul>}
      </section>

      <div className="central-chat-conversation">
        {attached && <div className="central-chat-attached" role="status">
          <div>
            <span className="eyebrow">{attached.kind === "RECORD" ? "Attached incident" : "Attached service window"}</span>
            <strong>{attached.kind === "RECORD" ? `${attached.record_id} · ${attached.title}` : `${attached.service_key} · ${new Date(attached.window_start).toLocaleString()}–${new Date(attached.window_end).toLocaleTimeString()}`}</strong>
          </div>
          <button className="secondary-button" type="button" onClick={() => setAttached(null)}>
            <X size={15} aria-hidden="true" /> Return to workspace
          </button>
        </div>}
        <AskRail
          key={attached ? `${attached.kind}:${attached.thread_id}` : "scope"}
          recordType={attached?.kind === "RECORD" ? attached.record_type : "service"}
          recordId={attached?.kind === "RECORD" ? attached.record_id : attached?.service_key ?? "current"}
          anchorKind={attached?.kind ?? "SCOPE"}
          serviceKey={attached?.kind === "SERVICE_WINDOW" ? attached.service_key : undefined}
          windowStart={attached?.kind === "SERVICE_WINDOW" ? attached.window_start : undefined}
          windowEnd={attached?.kind === "SERVICE_WINDOW" ? attached.window_end : undefined}
          initialThreadId={attached?.thread_id ?? null}
          surface="page"
          title={attached ? `About ${attached.kind === "RECORD" ? attached.record_id : attached.service_key}` : "Chat"}
          showClose={false}
          apiUrl={apiUrl}
          authority={authority}
          renderApprovalPart={() => <p className="ask-withheld">Open the incident action panel to review an exact approval.</p>}
          onClose={() => undefined}
        />
      </div>
    </div>
  </>;
}
