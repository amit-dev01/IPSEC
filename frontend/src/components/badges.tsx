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
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium tracking-tight bg-white ${meta.className}`}
    >
      <span aria-hidden="true">{meta.icon}</span>
      {meta.label}
    </span>
  );
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const SEVERITY_META: Record<Severity, { label: string; icon: string; className: string }> = {
  critical: {
    label: "Critical",
    icon: "⬟",
    className: "text-[#d70015] border-[#d70015]/30 bg-[#d70015]/5",
  },
  high: {
    label: "High",
    icon: "◆",
    className: "text-[#ff9500] border-[#ff9500]/30 bg-[#ff9500]/5",
  },
  medium: {
    label: "Medium",
    icon: "■",
    className: "text-[#b64400] border-[#b64400]/30 bg-[#b64400]/5",
  },
  low: { label: "Low", icon: "▲", className: "text-[#0071e3] border-[#0071e3]/30 bg-[#0071e3]/5" },
  info: { label: "Info", icon: "●", className: "text-[#86868b] border-[#e6e6e8] bg-[#ffffff]" },
};

export function SeverityBadge({ severity }: { severity: Severity }): ReactNode {
  const meta = SEVERITY_META[severity];
  return (
    <span
      role="img"
      aria-label={`Severity: ${meta.label}`}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-tight ${meta.className}`}
    >
      <span aria-hidden="true">{meta.icon}</span>
      {meta.label}
    </span>
  );
}

export function ScoreBar({
  label,
  value,
  max,
}: {
  label: string;
  value: number | null;
  max: number;
}): ReactNode {
  if (value === null) {
    return (
      <div>
        <p className="text-sm font-semibold text-[#1d1d1f] tracking-tight">{label}</p>
        <p className="text-sm text-[#707070]">Unknown — insufficient evidence to score.</p>
      </div>
    );
  }
  const pct = Math.round((Math.min(max, Math.max(0, value)) / max) * 100);
  return (
    <div>
      <p className="text-sm font-semibold text-[#1d1d1f] tracking-tight">
        {label}: <span className="tnum font-bold">{value}</span> / {max}
      </p>
      <div
        role="meter"
        aria-label={label}
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={max}
        className="mt-1.5 h-2 w-48 overflow-hidden rounded-full bg-[#e6e6e8]"
      >
        <div className="h-full rounded-full bg-[#0071e3]" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function RiskGauge({ value }: { value: number | null }): ReactNode {
  return <ScoreBar label="Risk score" value={value} max={100} />;
}
