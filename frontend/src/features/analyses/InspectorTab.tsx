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
    <div className="border-b border-line py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{label}</span>
        {item !== undefined ? (
          <ProvenanceBadge source={asSource(item.source)} />
        ) : (
          <UnknownValue reason="This fact was not reported for this capture." />
        )}
        {item !== undefined && isUnknown(item) && (
          <span className="text-xs font-medium">status: unknown (not observable)</span>
        )}
      </div>
      {item !== undefined && (
        <>
          <div className="mono mt-1 whitespace-pre-wrap text-sm">
            {renderValue !== undefined
              ? renderValue(item.fact_value)
              : JSON.stringify(item.fact_value)}
          </div>
          {item.limitation !== null && (
            <p className="mt-1 text-xs text-sev-medium">Limitation: {item.limitation}</p>
          )}
          <div className="mt-1">
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
    <div>
      <h2 className="text-lg font-medium">Session &amp; encapsulation</h2>
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
      <FactRow label="Packet count observed" item={facts.get("capture.packet_count_observed")} />

      <h2 className="mt-6 text-lg font-medium">VPN mode (inference-limited)</h2>
      <div className="rounded border border-line p-3">
        <FactRow label="VPN mode (tunnel / transport)" item={facts.get("vpn.mode")} />
        <p className="mt-2 text-sm text-ink-muted">
          Mode is only provable when inner packet structure is visible or supplied by a lab
          manifest. ESP payload structure alone does not prove tunnel vs transport mode — when
          unproven, this stays <strong>unknown</strong> rather than a heuristic guess presented as
          fact.
        </p>
      </div>

      <h2 className="mt-6 text-lg font-medium">IKE SA — offered vs selected (never conflated)</h2>
      <FactRow
        label="Proposals offered by initiator"
        item={facts.get("ike_sa.proposals_offered")}
      />
      <FactRow
        label="Offered encryption algorithms"
        item={facts.get("ike_sa.offered.encryption")}
      />
      <FactRow label="Offered integrity algorithms" item={facts.get("ike_sa.offered.integrity")} />
      <FactRow label="Offered PRFs" item={facts.get("ike_sa.offered.prf")} />
      <FactRow label="Offered DH groups" item={facts.get("ike_sa.offered.dh_groups")} />
      <FactRow label="Offered key lengths" item={facts.get("ike_sa.offered.key_lengths")} />
      <div className="rounded border border-accent p-3">
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
        <p className="mt-2 text-sm text-ink-muted">
          Only the responder-selected proposal is active. Offered-but-unselected transforms are
          never highlighted as active.
        </p>
      </div>

      <h2 className="mt-6 text-lg font-medium">Child SA / ESP — strictly separate from IKE SA</h2>
      {childUnknown && (
        <div
          role="note"
          className="mb-3 rounded border border-sev-medium bg-surface-sunken p-3 text-sm"
        >
          <strong>Visibility boundary:</strong> after IKE_SA_INIT, subsequent IKE payloads and ESP
          parameters are encrypted. Child SA proposals, the negotiated ESP cipher, PFS, configured
          lifetimes, and replay windows are therefore <strong>unknown from the wire</strong> unless
          a lab manifest supplies them. SPIs and ESP sequence metadata remain visible on outer
          headers.
        </div>
      )}
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
      <FactRow label="Configured SA lifetime" item={facts.get("security.configured_sa_lifetime")} />
      <FactRow
        label="Observed rekey intervals (derived — NOT configured lifetime)"
        item={facts.get("ike.observed_rekey_intervals_seconds")}
      />

      <h2 className="mt-6 text-lg font-medium">Lab Manifest reconciliation</h2>
      <p className="text-sm text-ink-muted">
        Manifest/analyst-supplied values sit beside wire observations; they never replace them.
        Discrepancies are flagged explicitly.
      </p>
      {supplied.map((item) => (
        <FactRow key={item.id} label={item.fact_name} item={item} />
      ))}
      {supplied.length === 0 && (
        <p className="mt-2 text-sm text-ink-muted">
          No lab-manifest facts attached to this analysis.
        </p>
      )}
      {discrepancies.length === 0 ? (
        <p className="mt-2 text-sm text-ink-muted">
          No manifest-vs-wire discrepancies reported for this analysis.
        </p>
      ) : (
        <ul className="mt-2 space-y-2">
          {discrepancies.map((item, i) => (
            <li
              key={`${item.rule_id}-${i}`}
              className="rounded border border-sev-high p-3 text-sm"
              role="note"
              aria-label={`Discrepancy: ${item.rule_id}`}
            >
              <span className="font-medium">⚠ Discrepancy — {item.rule_id}</span>
              <p className="mono mt-1 text-xs">
                observed {JSON.stringify(item.actual_value)} · expected{" "}
                {JSON.stringify(item.expected_value)}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
