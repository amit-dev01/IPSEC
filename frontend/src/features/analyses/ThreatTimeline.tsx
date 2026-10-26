/**
 * ThreatTimeline.tsx — Feature 6
 *
 * Animated IKEv2 packet-flow swimlane diagram.
 * Initiator | Network/ESP | Responder swimlanes.
 * Each event animates in sequentially using CSS keyframes + staggered delays.
 *
 * Color semantics (always text-labeled — never color-only):
 *   ike_sa_init  → violet (#af50ff)
 *   ike_auth     → blue   (#60a5fa)
 *   esp_data     → green  (#4ade80)
 *   create_child → teal   (#2dd4bf)
 *   nat_t        → amber  (#fbbf24)
 *   informational→ steel  (#828384)
 *   anomaly      → red    (#f87171)
 */
import type { ReactNode } from "react";
import { useMemo, useState } from "react";

import type { AnalysisDetail } from "@/api/client";
import { buildTimeline } from "./timelineUtils";
import type { EventKind, TimelineEvent } from "./timelineUtils";

const KIND_COLOR: Record<EventKind, string> = {
  ike_sa_init: "#0071e3",
  ike_auth: "#0066cc",
  esp_data: "#34c759",
  create_child_sa: "#30b0c7",
  nat_t: "#ff9500",
  informational: "#86868b",
  rekey: "#b64400",
  anomaly: "#d70015",
};

const KIND_ICON: Record<EventKind, string> = {
  ike_sa_init: "⬡",
  ike_auth: "🔑",
  esp_data: "🔒",
  create_child_sa: "⎇",
  nat_t: "⇄",
  informational: "ℹ",
  rekey: "↺",
  anomaly: "⚠",
};

function arrowX(dir: TimelineEvent["direction"]): { from: number; to: number } {
  if (dir === "init_to_resp") return { from: 80, to: 720 };
  if (dir === "resp_to_init") return { from: 720, to: 80 };
  return { from: 80, to: 720 }; // bidirectional drawn as double
}

function TimelineRow({
  event,
  rowIndex,
  selected,
  onSelect,
}: {
  event: TimelineEvent;
  rowIndex: number;
  selected: boolean;
  onSelect: () => void;
}): ReactNode {
  const color = KIND_COLOR[event.kind];
  const icon = KIND_ICON[event.kind];
  const { from, to } = arrowX(event.direction);
  const isBidi = event.direction === "bidirectional";
  const midX = (from + to) / 2;
  const yOffset = 0;
  const delay = `${rowIndex * 120}ms`;

  const arrowStyle: React.CSSProperties = {
    opacity: 0,
    animation: `tlFadeIn 400ms ease-out ${delay} forwards`,
  };

  return (
    <g
      role="button"
      tabIndex={0}
      aria-label={`${event.label}: ${event.sublabel ?? ""}`}
      aria-pressed={selected}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") onSelect();
      }}
      style={{ cursor: "pointer" }}
    >
      {/* Main arrow line */}
      <line
        x1={from}
        y1={yOffset}
        x2={isBidi ? to : to - 12}
        y2={yOffset}
        stroke={color}
        strokeWidth={selected ? 2.5 : 1.5}
        strokeDasharray={event.inferred ? "5,3" : undefined}
        opacity={0}
        style={{ ...arrowStyle, filter: selected ? `drop-shadow(0 0 4px ${color})` : undefined }}
      />

      {/* Arrowhead(s) */}
      {!isBidi && (
        <polygon
          points={`${to},${yOffset} ${to - 12},${yOffset - 5} ${to - 12},${yOffset + 5}`}
          fill={color}
          style={arrowStyle}
        />
      )}
      {isBidi && (
        <>
          <polygon
            points={`${to},${yOffset} ${to - 12},${yOffset - 5} ${to - 12},${yOffset + 5}`}
            fill={color}
            style={arrowStyle}
          />
          <polygon
            points={`${from},${yOffset} ${from + 12},${yOffset - 5} ${from + 12},${yOffset + 5}`}
            fill={color}
            style={arrowStyle}
          />
        </>
      )}

      {/* Label pill */}
      <rect
        x={midX - 74}
        y={yOffset - 13}
        width={148}
        height={26}
        rx={13}
        fill={selected ? color : "#ffffff"}
        stroke={selected ? color : "#d6d6d6"}
        strokeWidth={selected ? 1.5 : 1}
        style={arrowStyle}
      />
      <text
        x={midX}
        y={yOffset + 4}
        textAnchor="middle"
        fill={selected ? "#ffffff" : "#1d1d1f"}
        fontSize="10"
        fontFamily="var(--font-sf-pro-text), ui-sans-serif, system-ui, sans-serif"
        fontWeight={selected ? "600" : "500"}
        style={arrowStyle}
      >
        {icon} {event.label}
      </text>

      {/* Warning dot */}
      {event.warning !== undefined && (
        <circle cx={midX + 76} cy={yOffset - 6} r={4} fill="#d70015" style={arrowStyle} />
      )}
    </g>
  );
}

export default function ThreatTimeline({ detail }: { detail: AnalysisDetail }): ReactNode {
  const events = useMemo(() => buildTimeline(detail), [detail]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedEvent = events.find((e) => e.id === selectedId) ?? null;

  const ROW_HEIGHT = 56;
  const TOP_PAD = 50;
  const svgHeight = TOP_PAD + events.length * ROW_HEIGHT + 40;

  return (
    <div role="region" aria-label="IKEv2 packet flow threat timeline" className="apple-card p-6">
      {/* Keyframe injection */}
      <style>{`
        @keyframes tlFadeIn {
          from { opacity: 0; transform: translateX(-8px); }
          to   { opacity: 1; transform: translateX(0); }
        }
      `}</style>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
            IKEv2 Exchange Timeline
          </h3>
          <p className="mt-0.5 text-xs text-[#707070]">
            Reconstructed from packet-observed evidence · Dashed = inferred state
          </p>
        </div>
        <span className="rounded-full border border-[#e6e6e8] bg-[#fafafc] px-3 py-1 text-xs text-[#707070]">
          {events.length} chronological events
        </span>
      </div>

      {/* Legend row */}
      <div className="mb-4 flex flex-wrap gap-2" aria-label="Timeline legend">
        {(Object.entries(KIND_COLOR) as [EventKind, string][])
          .filter(([k]) => events.some((e) => e.kind === k))
          .map(([kind, color]) => (
            <span
              key={kind}
              className="inline-flex items-center gap-1.5 rounded-full border border-[#e6e6e8] bg-[#fafafc] px-2.5 py-0.5 text-xs text-[#1d1d1f]"
            >
              <span
                aria-hidden="true"
                className="inline-block h-2 w-2 rounded-full"
                style={{ background: color }}
              />
              <span className="font-mono text-[11px]">
                {KIND_ICON[kind]} {kind.replace(/_/g, " ")}
              </span>
            </span>
          ))}
      </div>

      {/* Main SVG diagram */}
      <div className="overflow-x-auto rounded-[20px] border border-[#e6e6e8] bg-[#fafafc]">
        <svg
          width="800"
          height={svgHeight}
          viewBox={`0 0 800 ${svgHeight}`}
          aria-hidden="true"
          className="min-w-[800px]"
        >
          {/* Swimlane headers */}
          <rect x={0} y={0} width={800} height={TOP_PAD} fill="#f5f5f7" />
          {/* Initiator */}
          <text
            x={80}
            y={32}
            textAnchor="middle"
            fill="#707070"
            fontSize="11"
            fontFamily="var(--font-sf-pro-text), ui-sans-serif, system-ui, sans-serif"
            fontWeight="600"
            letterSpacing="0.05em"
          >
            INITIATOR
          </text>
          <line x1={80} y1={TOP_PAD} x2={80} y2={svgHeight} stroke="#e6e6e8" strokeWidth={1} />
          {/* Network */}
          <text
            x={400}
            y={32}
            textAnchor="middle"
            fill="#707070"
            fontSize="11"
            fontFamily="var(--font-sf-pro-text), ui-sans-serif, system-ui, sans-serif"
            fontWeight="600"
            letterSpacing="0.05em"
          >
            NETWORK / ESP TUNNEL
          </text>
          {/* Responder */}
          <text
            x={720}
            y={32}
            textAnchor="middle"
            fill="#707070"
            fontSize="11"
            fontFamily="var(--font-sf-pro-text), ui-sans-serif, system-ui, sans-serif"
            fontWeight="600"
            letterSpacing="0.05em"
          >
            RESPONDER
          </text>
          <line x1={720} y1={TOP_PAD} x2={720} y2={svgHeight} stroke="#e6e6e8" strokeWidth={1} />

          {/* Row separator lines */}
          {events.map((_, i) => (
            <line
              key={`sep-${i}`}
              x1={0}
              y1={TOP_PAD + (i + 1) * ROW_HEIGHT}
              x2={800}
              y2={TOP_PAD + (i + 1) * ROW_HEIGHT}
              stroke="#f0f0f2"
              strokeWidth={1}
            />
          ))}

          {/* Timeline event rows */}
          {events.map((event, i) => (
            <g
              key={event.id}
              transform={`translate(0, ${TOP_PAD + i * ROW_HEIGHT + ROW_HEIGHT / 2})`}
            >
              {/* Row index label */}
              <text
                x={16}
                y={4}
                fill="#86868b"
                fontSize="9"
                fontFamily="var(--font-sf-pro-text), ui-sans-serif, system-ui, sans-serif"
                fontWeight="500"
              >
                {String(i + 1).padStart(2, "0")}
              </text>

              <TimelineRow
                event={event}
                rowIndex={i}
                selected={selectedId === event.id}
                onSelect={() => setSelectedId(selectedId === event.id ? null : event.id)}
              />
            </g>
          ))}
        </svg>
      </div>

      {/* Detail panel — appears on row click */}
      {selectedEvent !== null && (
        <div
          className="mt-4 rounded-[20px] border border-[#e6e6e8] bg-[#ffffff] p-4"
          role="region"
          aria-label={`Details: ${selectedEvent.label}`}
        >
          <div className="flex items-start gap-3">
            <span
              className="font-mono text-2xl"
              style={{ color: KIND_COLOR[selectedEvent.kind] }}
              aria-hidden="true"
            >
              {KIND_ICON[selectedEvent.kind]}
            </span>
            <div className="flex-1">
              <p
                className="font-semibold text-[#1d1d1f]"
                style={{ color: KIND_COLOR[selectedEvent.kind] }}
              >
                {selectedEvent.label}
              </p>
              {selectedEvent.sublabel !== undefined && (
                <p className="mt-0.5 text-xs text-[#707070]">{selectedEvent.sublabel}</p>
              )}
              <div className="mt-2 flex flex-wrap gap-2 text-xs">
                <span className="rounded-full border border-[#e6e6e8] bg-[#fafafc] px-2.5 py-0.5 text-[#1d1d1f]">
                  Direction: {selectedEvent.direction.replace(/_/g, " ")}
                </span>
                <span className="rounded-full border border-[#e6e6e8] bg-[#fafafc] px-2.5 py-0.5 text-[#1d1d1f]">
                  Source: {selectedEvent.inferred ? "inferred from evidence" : "packet-observed"}
                </span>
              </div>
              {selectedEvent.warning !== undefined && (
                <p className="mt-2 text-xs font-medium text-[#d70015]">⚠ {selectedEvent.warning}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {events.length === 0 && (
        <p className="mt-3 text-sm text-[#707070]">
          No timeline events could be reconstructed from the available evidence.
        </p>
      )}
    </div>
  );
}
