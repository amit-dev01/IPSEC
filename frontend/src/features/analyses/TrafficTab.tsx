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
    <div>
      <h2 className="text-lg font-medium">AI traffic inference (metadata only)</h2>
      <div role="note" className="mt-2 rounded border border-line bg-surface-sunken p-3 text-sm">
        <strong>Methodological notice:</strong> this classifier uses flow metadata only — packet
        lengths, timing, burstiness, and direction. It does <strong>not</strong> decrypt payloads
        and does not inspect application content. Predicted categories are probabilistic; real
        application/vendor identity is knowable only from lab ground truth (a manifest), never from
        this model. The backend abstains below its configured confidence threshold.
      </div>

      <div className="mt-4 space-y-3">
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
          <p className="text-sm">
            Predicted traffic category: <strong>{category}</strong>
            {(prediction?.model_version ?? detail.model_version) != null && (
              <>
                {" "}
                · model{" "}
                <span className="mono">{prediction?.model_version ?? detail.model_version}</span>
              </>
            )}
          </p>
        )}
        <ConfidenceMeter
          value={abstained || mlItem === undefined ? null : confidence}
          kind="ml_traffic"
        />
        {prediction?.limitations !== undefined && prediction.limitations.length > 0 && (
          <ul className="list-disc pl-5 text-sm text-ink-muted">
            {prediction.limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        )}
      </div>

      <h3 className="mt-6 font-medium">Flow-feature summary (sanitized)</h3>
      <dl className="mt-2 grid gap-2 text-sm md:grid-cols-3">
        <div className="rounded border border-line p-3">
          <dt className="text-ink-muted">Packets observed</dt>
          <dd className="tnum text-lg">
            {packetCount !== undefined ? String(packetCount.fact_value) : "Unknown"}
          </dd>
        </div>
        <div className="rounded border border-line p-3">
          <dt className="text-ink-muted">Predicted category</dt>
          <dd className="text-lg">{category ?? "Unknown (abstained/unavailable)"}</dd>
        </div>
        <div className="rounded border border-line p-3">
          <dt className="text-ink-muted">ESP SPI observed</dt>
          <dd className="mono text-lg">
            {espSpi !== undefined ? hexSpi(espSpi.fact_value) : "Unknown"}
          </dd>
        </div>
      </dl>
      <p className="mt-2 max-w-3xl text-sm text-ink-muted">
        Per-flow length/timing distributions are computed inside the worker from capture metadata.
        Where the API does not expose an aggregate, this view shows the underlying packet-observed
        facts above instead of inventing chart values.
      </p>

      <h3 className="mt-6 font-medium">Outer metadata exposure (visible without decryption)</h3>
      <p className="max-w-3xl text-sm text-ink-muted">
        Even with ESP, an on-path observer sees outer endpoint addresses (privacy-hashed by the
        backend unless plaintext endpoint exposure is explicitly enabled), SPIs, NAT-T ports, packet
        sizes, timing, and total volume. This is metadata exposure — not payload access.
      </p>
      <ul className="mt-2 space-y-2 text-sm">
        <li>
          Outer endpoints:{" "}
          {endpoints !== undefined ? (
            <span className="mono">{JSON.stringify(endpoints.fact_value)}</span>
          ) : (
            <UnknownValue reason="Endpoint fact not reported." />
          )}
        </li>
        <li>
          ESP SPI:{" "}
          {espSpi !== undefined ? (
            <span className="mono">{hexSpi(espSpi.fact_value)}</span>
          ) : (
            <UnknownValue reason="No ESP SPI observed." />
          )}
        </li>
        <li>
          NAT-T (UDP/4500):{" "}
          {natT !== undefined
            ? natT.fact_value === true
              ? "observed"
              : "not observed"
            : "Unknown"}
        </li>
        <li>
          Duration / volume / timing bursts:{" "}
          <UnknownValue reason="Derived exposure aggregates are computed worker-side; open the Evidence tab for packet counts and rekey intervals. No values are invented here." />
        </li>
      </ul>
    </div>
  );
}
