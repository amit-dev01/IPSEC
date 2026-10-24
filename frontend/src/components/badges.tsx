import type { ReactNode } from "react";

/**
 * Provenance + severity badges. Color is ALWAYS paired with an icon and a
 * visible text label (never color-only). See docs/ux-epistemics.md.
 */

export type EvidenceSource =
  "packet_observed" | "lab_manifest" | "analyst_supplied" | "model_inferred" | "unknown";

const SOURCE_META: Record<EvidenceSource, { label: string; icon: string; className: string }> = {
  packet_observed: {
    label: "Packet-observed",
    icon: "◎",
    className: "text-prov-observed border-prov-observed",
  },
  lab_manifest: {
    label: "Lab manifest",
    icon: "▣",
    className: "text-prov-manifest border-prov-manifest border-dashed",
  },
  analyst_supplied: {
    label: "Analyst-supplied",
    icon: "✎",
    className: "text-prov-supplied border-prov-supplied border-dashed",
  },
  model_inferred: {
    label: "Model-inferred",
    icon: "◈",
    className: "text-prov-inferred border-prov-inferred",
  },
  unknown: { label: "Unknown", icon: "?", className: "text-prov-unknown border-prov-unknown" },
};

export function SourceBadge({ source }: { source: EvidenceSource }): ReactNode {
  const meta = SOURCE_META[source];
  return (
    <span
      role="img"
      aria-label={`Source: ${meta.label}`}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium ${meta.className}`}
    >
      <span aria-hidden="true">{meta.icon}</span>
      {meta.label}
    </span>
  );
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const SEVERITY_META: Record<Severity, { label: string; icon: string; className: string }> = {
  critical: { label: "Critical", icon: "⬟", className: "text-sev-critical border-sev-critical" },
  high: { label: "High", icon: "◆", className: "text-sev-high border-sev-high" },
  medium: { label: "Medium", icon: "■", className: "text-sev-medium border-sev-medium" },
  low: { label: "Low", icon: "▲", className: "text-sev-low border-sev-low" },
  info: { label: "Info", icon: "●", className: "text-sev-info border-sev-info" },
};

export function SeverityBadge({ severity }: { severity: Severity }): ReactNode {
  const meta = SEVERITY_META[severity];
  return (
    <span
      role="img"
      aria-label={`Severity: ${meta.label}`}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium ${meta.className}`}
    >
      <span aria-hidden="true">{meta.icon}</span>
      {meta.label}
    </span>
  );
}
