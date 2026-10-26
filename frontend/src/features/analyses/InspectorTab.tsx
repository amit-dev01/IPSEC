import type { ReactNode } from "react";

import type { AnalysisDetail } from "@/api/client";
import { FrameReferenceList, ProvenanceBadge, UnknownValue } from "@/components/epistemic";

import { asSource, factMap, isUnknown } from "./evidence-lib";
import type { Evidence } from "./evidence-lib";

function FactRow({
  label,
  item,
  renderValue,
}: {
  label: string;
  item: Evidence | undefined;
  renderValue?: (value: unknown) => ReactNode;
}): ReactNode {
  return (
    <div className="border-b border-[#e6e6e8] py-3 last:border-none">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-xs text-[#1d1d1f]">{label}</span>
        {item !== undefined ? (
          <ProvenanceBadge source={asSource(item.source)} />
        ) : (
          <UnknownValue reason="This fact was not reported for this capture." />
        )}
        {item !== undefined && isUnknown(item) && (
          <span className="text-[11px] font-medium text-[#707070]">
            status: unknown (not observable)
          </span>
        )}
      </div>
      {item !== undefined && (
        <>
          <div className="font-mono mt-1.5 whitespace-pre-wrap text-xs text-[#1d1d1f]">
            {renderValue !== undefined
              ? renderValue(item.fact_value)
              : JSON.stringify(item.fact_value)}
          </div>
          {item.limitation !== null && (
            <p className="mt-1 text-xs text-[#ff9500]">Limitation: {item.limitation}</p>
          )}
          <div className="mt-1.5">
            <FrameReferenceList frames={(item.packet_refs ?? []) as never[]} />
          </div>
        </>
      )}
    </div>
  );
}

function endpointText(value: unknown): string {
  if (value !== null && typeof value === "object") {
    const e = value as { address?: unknown; port?: unknown };
    const addr = typeof e.address === "string" ? e.address : "?";
    const port = typeof e.port === "number" ? e.port : null;
    return port !== null ? `${addr}:${port}` : addr;
  }
  return "?";
}

function endpointsText(value: unknown): string {
  if (value !== null && typeof value === "object") {
    const v = value as { initiator?: unknown; responder?: unknown };
    if (v.initiator !== undefined || v.responder !== undefined) {
      return `initiator ${endpointText(v.initiator)} → responder ${endpointText(v.responder)}`;
    }
  }
  return JSON.stringify(value);
}

export default function InspectorTab({ detail }: { detail: AnalysisDetail }): ReactNode {
  const facts = factMap(detail);
  const supplied = detail.supplied_facts;
  const discrepancies = detail.findings.filter((f) => f.rule_id.includes("discrepancy"));
  const childUnknown =
    isUnknown(facts.get("child_sa.proposals") ?? ({} as Evidence)) ||
    isUnknown(facts.get("esp.encryption_algorithm") ?? ({} as Evidence));

  return (
    <div className="space-y-6">
      {/* Session & encapsulation */}
      <div className="apple-card p-6 space-y-4">
        <h2 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
          Session &amp; Encapsulation Architecture
        </h2>
        <div>
          <FactRow
            label="Outer endpoints (may be privacy-hashed)"
            item={facts.get("network.outer_endpoints")}
            renderValue={endpointsText}
          />
          <FactRow label="Protocols observed" item={facts.get("ipsec.protocols_observed")} />
          <FactRow
            label="IKE version"
            item={facts.get("ike.version")}
            renderValue={(v) => (typeof v === "number" ? `IKEv${v}` : JSON.stringify(v))}
          />
          <FactRow label="IKE exchanges observed" item={facts.get("ike.exchange_types_observed")} />
          <FactRow
            label="NAT traversal (UDP/4500)"
            item={facts.get("ike.nat_traversal_observed")}
            renderValue={(v) =>
              v === true ? "observed" : v === false ? "not observed" : JSON.stringify(v)
            }
          />
          <FactRow
            label="Packet count observed"
            item={facts.get("capture.packet_count_observed")}
          />
        </div>
      </div>

      {/* VPN mode (inference-limited) */}
      <div className="apple-card p-6 space-y-4">
        <h2 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
          VPN Mode (Inference-Limited Boundary)
        </h2>
        <div className="rounded-[20px] border border-[#e6e6e8] bg-[#fafafc] p-4">
          <FactRow label="VPN mode (tunnel / transport)" item={facts.get("vpn.mode")} />
          <p className="mt-2 text-xs text-[#707070] leading-relaxed">
            Mode is only provable when inner packet structure is visible or supplied by a lab
            manifest. ESP payload structure alone does not prove tunnel vs transport mode — when
            unproven, this stays <strong className="text-[#1d1d1f]">unknown</strong> rather than a
            heuristic guess presented as fact.
          </p>
        </div>
      </div>

      {/* IKE SA — offered vs selected */}
      <div className="apple-card p-6 space-y-4">
        <h2 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
          IKE SA — offered vs selected (never conflated)
        </h2>
        <div className="space-y-4">
          <div className="space-y-1">
            <FactRow
              label="Proposals offered by initiator"
              item={facts.get("ike_sa.proposals_offered")}
            />
            <FactRow
              label="Offered encryption algorithms"
              item={facts.get("ike_sa.offered.encryption")}
            />
            <FactRow
              label="Offered integrity algorithms"
              item={facts.get("ike_sa.offered.integrity")}
            />
            <FactRow label="Offered PRFs" item={facts.get("ike_sa.offered.prf")} />
            <FactRow label="Offered DH groups" item={facts.get("ike_sa.offered.dh_groups")} />
            <FactRow label="Offered key lengths" item={facts.get("ike_sa.offered.key_lengths")} />
          </div>

          <div className="rounded-[20px] border border-[#0071e3]/30 bg-[#fafafc] p-5 space-y-2">
            <FactRow
              label="Proposal selected by responder"
              item={facts.get("ike_sa.proposal_selected")}
            />
            <FactRow label="Selected transforms" item={facts.get("ike_sa.selected_transforms")} />
            <FactRow label="Selected encryption" item={facts.get("ike_sa.selected.encryption")} />
            <FactRow label="Selected integrity" item={facts.get("ike_sa.selected.integrity")} />
            <FactRow label="Selected PRF" item={facts.get("ike_sa.selected.prf")} />
            <FactRow label="Selected DH group" item={facts.get("ike_sa.selected.dh_group")} />
            <FactRow label="Selected key length" item={facts.get("ike_sa.selected.key_length")} />
            <p className="mt-2 text-xs text-[#707070]">
              Only the responder-selected proposal is active. Offered-but-unselected transforms are
              never highlighted as active.
            </p>
          </div>
        </div>
      </div>

      {/* Child SA / ESP */}
      <div className="apple-card p-6 space-y-4">
        <h2 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
          Child SA / ESP — strictly separate from IKE SA
        </h2>
        {childUnknown && (
          <div
            role="note"
            className="rounded-[20px] border border-[#ff9500]/30 bg-[#ff9500]/5 p-4 text-xs text-[#1d1d1f] leading-relaxed"
          >
            <strong>Visibility boundary:</strong> after IKE_SA_INIT, subsequent IKE payloads and ESP
            parameters are encrypted. Child SA proposals, the negotiated ESP cipher, PFS, configured
            lifetimes, and replay windows are therefore <strong>unknown from the wire</strong>{" "}
            unless a lab manifest supplies them. SPIs and ESP sequence metadata remain visible on
            outer headers.
          </div>
        )}
        <div>
          <FactRow label="ESP SPIs (outer header)" item={facts.get("esp.spi_observed")} />
          <FactRow label="AH SPIs (outer header)" item={facts.get("ah.spi_observed")} />
          <FactRow
            label="ESP encryption algorithm (wire)"
            item={facts.get("esp.encryption_algorithm")}
          />
          <FactRow label="Child SA proposals" item={facts.get("child_sa.proposals")} />
          <FactRow label="Perfect forward secrecy" item={facts.get("security.pfs")} />
          <FactRow
            label="Replay window (configured)"
            item={facts.get("security.replay_window_configured")}
          />
          <FactRow
            label="Configured SA lifetime"
            item={facts.get("security.configured_sa_lifetime")}
          />
          <FactRow
            label="Observed rekey intervals (derived — NOT configured lifetime)"
            item={facts.get("ike.observed_rekey_intervals_seconds")}
          />
        </div>
      </div>

      {/* Lab Manifest reconciliation */}
      <div className="apple-card p-6 space-y-4">
        <div>
          <h2 className="font-display text-base font-semibold tracking-tight text-[#1d1d1f]">
            Lab Manifest Reconciliation
          </h2>
          <p className="mt-0.5 text-xs text-[#707070]">
            Manifest/analyst-supplied values sit beside wire observations; they never replace them.
            Discrepancies are flagged explicitly.
          </p>
        </div>

        {supplied.map((item) => (
          <FactRow key={item.id} label={item.fact_name} item={item} />
        ))}
        {supplied.length === 0 && (
          <p className="text-xs text-[#707070]">No lab-manifest facts attached to this analysis.</p>
        )}
        {discrepancies.length > 0 && (
          <div className="space-y-2 pt-2">
            {discrepancies.map((item, i) => (
              <div
                key={`${item.rule_id}-${i}`}
                className="rounded-[20px] border border-[#d70015]/30 bg-[#d70015]/5 p-4 text-xs"
                role="note"
                aria-label={`Discrepancy: ${item.rule_id}`}
              >
                <span className="font-semibold text-[#d70015]">⚠ Discrepancy — {item.rule_id}</span>
                <p className="font-mono mt-1 text-[11px] text-[#707070]">
                  observed{" "}
                  <strong className="text-[#1d1d1f]">{JSON.stringify(item.actual_value)}</strong> ·
                  expected{" "}
                  <strong className="text-[#1d1d1f]">{JSON.stringify(item.expected_value)}</strong>
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
