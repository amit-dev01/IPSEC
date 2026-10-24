import type { AnalysisDetail, EvidenceResponse } from "@/api/client";

export type Evidence = EvidenceResponse;

/** All evidence sections, kept labelled by their own `source` field. */
export function allEvidence(detail: AnalysisDetail): Evidence[] {
  return [
    ...detail.packet_observed_facts,
    ...detail.supplied_facts,
    ...detail.model_inferred_facts,
    ...detail.unknown_facts,
  ];
}

export function isUnknown(item: Evidence): boolean {
  return item.source === "unknown" || item.fact_value === null;
}

export function factMap(detail: AnalysisDetail): Map<string, Evidence> {
  const map = new Map<string, Evidence>();
  for (const item of allEvidence(detail)) {
    if (!map.has(item.fact_name)) map.set(item.fact_name, item);
  }
  return map;
}

export function asSource(
  source: string,
): "packet_observed" | "lab_manifest" | "analyst_supplied" | "model_inferred" | "unknown" {
  if (
    source === "packet_observed" ||
    source === "lab_manifest" ||
    source === "analyst_supplied" ||
    source === "model_inferred"
  ) {
    return source;
  }
  return "unknown";
}
