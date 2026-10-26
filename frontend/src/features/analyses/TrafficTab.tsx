import type { ReactNode } from "react";

import type { AnalysisDetail } from "@/api/client";
import { ConfidenceMeter, ProvenanceBadge, UnknownValue } from "@/components/epistemic";

import { factMap } from "./evidence-lib";

interface ModelPrediction {
  status?: string;
  predicted_category?: string | null;
  confidence?: number | null;
  model_version?: string | null;
  limitations?: string[];
}

function hexSpi(value: unknown): string {
  if (value !== null && typeof value === "object" && "spi" in value) {
    const spi = (value as { spi: unknown }).spi;
    if (typeof spi === "number") return `0x${spi.toString(16).padStart(8, "0")}`;
    if (typeof spi === "string") {
      const n = Number(spi);
      return Number.isFinite(n) ? `0x${n.toString(16).padStart(8, "0")}` : spi;
    }
  }
  if (Array.isArray(value) && value.length > 0) return hexSpi(value[0]);
  return "unknown";
}

export default function TrafficTab({ detail }: { detail: AnalysisDetail }): ReactNode {
  const facts = factMap(detail);
  const mlItem = detail.model_inferred_facts.find((e) => e.fact_name === "ml.traffic_category");
  const prediction: ModelPrediction | null =
    mlItem !== undefined && mlItem.fact_value !== null && typeof mlItem.fact_value === "object"
      ? (mlItem.fact_value as ModelPrediction)
      : mlItem !== undefined && typeof mlItem.fact_value === "string"
        ? { status: "available", predicted_category: mlItem.fact_value }
        : null;
  const category = prediction?.predicted_category ?? null;
  const confidence = prediction?.confidence ?? mlItem?.confidence ?? null;
  const status = prediction?.status ?? (mlItem === undefined ? "unavailable" : "available");
  const abstained = status === "unknown" || (status === "available" && category === null);

  const endpoints = facts.get("network.outer_endpoints");
  const espSpi = facts.get("esp.spi_observed");
  const packetCount = facts.get("capture.packet_count_observed");
  const natT = facts.get("ike.nat_traversal_observed");

  return (
    <div className="space-y-6">
      {/* AI traffic inference */}
      <div className="apple-card p-6 space-y-4">
        <div>
          <h2 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
            AI Traffic Inference (Flow-Metadata Features Only)
          </h2>
          <p className="mt-0.5 text-xs text-[#707070]">
            Probabilistic classification derived from timing, packet lengths, burstiness, and flow
            direction
          </p>
        </div>

        <div
          role="note"
          className="rounded-[20px] border border-[#0071e3]/20 bg-[#0071e3]/5 p-4 text-xs text-[#1d1d1f] leading-relaxed"
        >
          <strong className="text-[#0071e3]">Methodological notice:</strong> this classifier uses
          flow metadata only — packet lengths, timing, burstiness, and direction. It does{" "}
          <strong>not</strong> decrypt payloads and does not inspect application content. Predicted
          categories are probabilistic; real application/vendor identity is knowable only from lab
          ground truth (a manifest), never from this model. The backend abstains below its
          configured confidence threshold.
        </div>

        <div className="space-y-3 pt-2">
          {mlItem !== undefined && <ProvenanceBadge source="model_inferred" />}
          {abstained && mlItem !== undefined && (
            <p>
              <UnknownValue reason="The model abstained (confidence below the abstention threshold or unsupported category). No category is claimed." />
            </p>
          )}
          {mlItem === undefined && (
            <p>
              <UnknownValue reason="No traffic model result is available for this analysis (model not installed or insufficient flow features). This is reported as unavailable, not as a zero-confidence guess." />
            </p>
          )}
          {category !== null && (
            <p className="text-sm text-[#1d1d1f]">
              Predicted traffic category: <strong className="text-[#0071e3]">{category}</strong>
              {(prediction?.model_version ?? detail.model_version) != null && (
                <>
                  {" "}
                  · model{" "}
                  <span className="font-mono text-xs text-[#707070]">
                    {prediction?.model_version ?? detail.model_version}
                  </span>
                </>
              )}
            </p>
          )}
          <ConfidenceMeter
            value={abstained || mlItem === undefined ? null : confidence}
            kind="ml_traffic"
          />
          {prediction?.limitations !== undefined && prediction.limitations.length > 0 && (
            <ul className="list-disc pl-5 text-xs text-[#707070] space-y-1">
              {prediction.limitations.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Flow-feature summary */}
      <div className="apple-card p-6 space-y-4">
        <div>
          <h3 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
            Flow-Feature Summary (Sanitized Telemetry)
          </h3>
          <p className="mt-0.5 text-xs text-[#707070]">
            Per-flow length and timing distributions computed inside worker from capture metadata
          </p>
        </div>

        <dl className="grid gap-3 text-xs md:grid-cols-3">
          <div className="rounded-[20px] border border-[#e6e6e8] bg-[#fafafc] p-4">
            <dt className="text-[#707070]">Packets observed</dt>
            <dd className="font-display text-2xl font-semibold text-[#1d1d1f] mt-1">
              {packetCount !== undefined ? String(packetCount.fact_value) : "Unknown"}
            </dd>
          </div>
          <div className="rounded-[20px] border border-[#e6e6e8] bg-[#fafafc] p-4">
            <dt className="text-[#707070]">Predicted category</dt>
            <dd className="font-display text-xl font-semibold text-[#1d1d1f] mt-1">
              {category ?? "Unknown (abstained)"}
            </dd>
          </div>
          <div className="rounded-[20px] border border-[#e6e6e8] bg-[#fafafc] p-4">
            <dt className="text-[#707070]">ESP SPI observed</dt>
            <dd className="font-mono text-xl font-semibold text-[#1d1d1f] mt-1">
              {espSpi !== undefined ? hexSpi(espSpi.fact_value) : "Unknown"}
            </dd>
          </div>
        </dl>
      </div>

      {/* Outer metadata exposure */}
      <div className="apple-card p-6 space-y-4">
        <div>
          <h3 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
            Outer Metadata Exposure (Observable Wire Surface)
          </h3>
          <p className="mt-0.5 text-xs text-[#707070]">
            Even with ESP encryption, on-path observers inspect outer endpoint addresses, SPIs,
            ports, and timing
          </p>
        </div>

        <div className="space-y-2 text-xs">
          <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3 flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-[#1d1d1f]">Outer endpoints:</span>
            {endpoints !== undefined ? (
              <span className="font-mono text-[#0066cc]">
                {JSON.stringify(endpoints.fact_value)}
              </span>
            ) : (
              <UnknownValue reason="Endpoint fact not reported." />
            )}
          </div>
          <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3 flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-[#1d1d1f]">ESP SPI:</span>
            {espSpi !== undefined ? (
              <span className="font-mono text-[#0066cc]">{hexSpi(espSpi.fact_value)}</span>
            ) : (
              <UnknownValue reason="No ESP SPI observed." />
            )}
          </div>
          <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3 flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-[#1d1d1f]">NAT-T (UDP/4500):</span>
            <span className="font-medium text-[#1d1d1f]">
              {natT !== undefined
                ? natT.fact_value === true
                  ? "observed"
                  : "not observed"
                : "Unknown"}
            </span>
          </div>
          <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3">
            <span className="font-medium text-[#1d1d1f] block mb-1">
              Duration / volume / timing bursts:
            </span>
            <UnknownValue reason="Derived exposure aggregates are computed worker-side; open the Evidence tab for packet counts and rekey intervals. No values are invented here." />
          </div>
        </div>
      </div>
    </div>
  );
}
