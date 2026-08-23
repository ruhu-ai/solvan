import type { EvidenceItem, Incident } from "./types";

/** Resolve every record kind a conversational claim may cite through the
 * incident page's already-authorized evidence drawer. */
export function conversationEvidence(incident: Incident): EvidenceItem[] {
  return [
    ...incident.evidence_index,
    {
      ref: incident.id,
      kind: "record",
      label: incident.title,
      source: "Incident ledger",
      window: `Detected ${incident.detected_at}`,
      freshness: incident.brief.freshness,
      classification: "INTERNAL",
      content_ref: `record://incident/${incident.id}`,
    },
    ...incident.actions.map((action) => ({
      ref: action.id,
      kind: "record" as const,
      label: action.name,
      source: "Governed action ledger",
      window: action.phase,
      freshness: action.status,
      classification: "INTERNAL",
      content_ref: `record://action/${action.id}`,
    })),
    {
      ref: incident.verification.id,
      kind: "record",
      label: `${incident.verification.id} · ${incident.verification.verdict}`,
      source: `Verification Agent · ${incident.verification.profile}`,
      window: incident.verification.window || "Recorded verification window",
      freshness: incident.verification.verdict,
      classification: "INTERNAL",
      content_ref: `record://verification/${incident.verification.id}`,
    },
  ];
}
