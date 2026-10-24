import type { ReactNode } from "react";

import { SourceBadge } from "@/components/badges";
import type { EvidenceSource } from "@/components/badges";

/**
 * Shared epistemic primitives (docs/ux-epistemics.md). Unknown is neutral,
 * explained, and never a green pass. Confidence kinds are never merged.
 */

export type EvidenceVisibility =
  "visible" | "encrypted_or_unavailable" | "derived" | "not_in_capture" | "unknown";

const VISIBILITY_META: Record<EvidenceVisibility, { label: string; icon: string }> = {
  visible: { label: "Visible", icon: "◉" },
  encrypted_or_unavailable: { label: "Encrypted / not observable", icon: "▦" },
  derived: { label: "Derived from metadata", icon: "ƒ" },
  not_in_capture: { label: "Not in capture", icon: "⊘" },
  unknown: { label: "Visibility unknown", icon: "?" },
};

export function ProvenanceBadge({
  source,
  visibility,
}: {
  source: EvidenceSource;
  visibility?: EvidenceVisibility | undefined;
}): ReactNode {
  const vis = visibility !== undefined ? VISIBILITY_META[visibility] : undefined;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <SourceBadge source={source} />
      {vis !== undefined && visibility !== "visible" && (
        <span
          role="img"
          aria-label={`Visibility: ${vis.label}`}
          className="inline-flex items-center gap-1 rounded border border-line px-1.5 py-0.5 text-xs text-ink-muted"
        >
          <span aria-hidden="true">{vis.icon}</span>
          {vis.label}
        </span>
      )}
    </span>
  );
}

export function ConfidenceMeter({
  value,
  kind,
}: {
  value: number | null;
  kind: "protocol" | "ml_traffic";
}): ReactNode {
  const isProtocol = kind === "protocol";
  const label = isProtocol
    ? "Protocol-evidence confidence (deterministic)"
    : "Model confidence (calibrated probability)";
  const description = isProtocol
    ? "Mean confidence of packet-observed facts. Deterministic evidence quality — not a probability of correctness about hidden settings."
    : "Calibrated classifier probability for a metadata-inferred category. Probabilistic — not payload inspection and not application identification.";
  if (value === null || !Number.isFinite(value)) {
    return (
      <div>
        <p className="text-sm font-medium">{label}</p>
        <UnknownValue reason="No confidence value was reported." />
        <p className="mt-1 text-xs text-ink-muted">{description}</p>
      </div>
    );
  }
  const pct = Math.round(Math.min(1, Math.max(0, value)) * 100);
  return (
    <div>
      <p className="text-sm font-medium">
        {label}: <span className="tnum">{pct}%</span>
      </p>
      <div
        role="meter"
        aria-label={label}
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        className="mt-1 h-2 w-48 overflow-hidden rounded bg-surface-sunken"
      >
        <div
          className={isProtocol ? "h-full bg-accent" : "h-full bg-prov-inferred"}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="mt-1 text-xs text-ink-muted">{description}</p>
    </div>
  );
}

export interface FrameRef {
  frame?: number | string;
  [key: string]: unknown;
}

export function FrameReferenceList({ frames }: { frames: readonly FrameRef[] }): ReactNode {
  if (frames.length === 0) {
    return <span className="text-xs text-ink-muted">No frame references</span>;
  }
  return (
    <ul aria-label="Packet frame references" className="flex flex-wrap gap-1">
      {frames.map((ref, index) => {
        const frame = ref.frame ?? "?";
        return (
          <li
            key={`${String(frame)}-${index}`}
            className="mono rounded border border-line bg-surface-sunken px-1.5 py-0.5 text-xs"
          >
            #{String(frame)}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * Explicit unknown: neutral/amber explanation. Never renders "N/A",
 * "None", or a pass state.
 */
export function UnknownValue({ reason }: { reason: string }): ReactNode {
  return (
    <span className="inline-flex items-start gap-1 rounded border border-sev-medium bg-surface-sunken px-2 py-1 text-xs text-ink">
      <span aria-hidden="true">?</span>
      <span>
        <strong>Unknown.</strong> {reason}
      </span>
    </span>
  );
}
