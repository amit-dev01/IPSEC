/**
 * timelineUtils.ts — derives an IKEv2 / ESP packet-flow sequence
 * from AnalysisDetail packet-observed facts.
 *
 * RFC 7296 (IKEv2) exchange sequence:
 *   IKE_SA_INIT (req/resp) → IKE_AUTH (req/resp) → [CREATE_CHILD_SA] → ESP data
 *
 * We reconstruct the most likely observed sequence from evidence facts.
 * Where evidence is missing, events are marked as "inferred" with a different style.
 */
import type { AnalysisDetail } from "@/api/client";

export type EventDir = "init_to_resp" | "resp_to_init" | "bidirectional";
export type EventKind =
  | "ike_sa_init"
  | "ike_auth"
  | "create_child_sa"
  | "informational"
  | "esp_data"
  | "nat_t"
  | "rekey"
  | "anomaly";

export interface TimelineEvent {
  id: string;
  label: string;
  sublabel?: string;
  kind: EventKind;
  direction: EventDir;
  /** true = inferred from evidence presence, false = directly observed timing */
  inferred: boolean;
  /** optional warning/anomaly annotation */
  warning?: string | undefined;
}

function hasFactWithValue(detail: AnalysisDetail, factName: string): boolean {
  const all = [
    ...detail.packet_observed_facts,
    ...detail.supplied_facts,
  ];
  const item = all.find((e) => e.fact_name === factName);
  if (!item) return false;
  return item.fact_value !== null && item.fact_value !== undefined && item.fact_value !== "unknown";
}

function getFactValue(detail: AnalysisDetail, factName: string): unknown | null {
  const all = [
    ...detail.packet_observed_facts,
    ...detail.supplied_facts,
    ...detail.model_inferred_facts,
  ];
  return all.find((e) => e.fact_name === factName)?.fact_value ?? null;
}

export function buildTimeline(detail: AnalysisDetail): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  const ikeVersion = getFactValue(detail, "ike.version");
  const hasIke = hasFactWithValue(detail, "ike.version");
  const hasTransforms = hasFactWithValue(detail, "ike_sa.selected_transforms");
  const hasEsp = hasFactWithValue(detail, "esp.spi_observed");
  const hasPfs = hasFactWithValue(detail, "security.pfs");
  const hasNatT = getFactValue(detail, "ike.nat_traversal_observed");
  const hasReplay = hasFactWithValue(detail, "security.replay_window_configured");
  const transforms = String(getFactValue(detail, "ike_sa.selected_transforms") ?? "");
  const isWeak = /3DES|SHA-?1|DH-[12]\b|RC4|NULL/i.test(transforms);
  const lifetimeFact = getFactValue(detail, "security.configured_sa_lifetime");

  // 1. IKE_SA_INIT — always inferred from IKE version fact presence
  events.push({
    id: "ike-sa-init-req",
    label: "IKE_SA_INIT",
    sublabel: `${String(ikeVersion ?? "IKEv2")} — DH exchange + nonces`,
    kind: "ike_sa_init",
    direction: "init_to_resp",
    inferred: !hasIke,
    warning: isWeak ? "Weak algorithm in proposal set" : undefined,
  });

  events.push({
    id: "ike-sa-init-resp",
    label: "IKE_SA_INIT reply",
    sublabel: hasTransforms ? `Transforms: ${transforms.slice(0, 50)}` : "Transform selection unknown",
    kind: "ike_sa_init",
    direction: "resp_to_init",
    inferred: !hasTransforms,
    warning: isWeak ? "⚠ Weak algorithm accepted" : undefined,
  });

  // 2. NAT-T detection (if observed between INIT and AUTH)
  if (hasNatT === true) {
    events.push({
      id: "nat-t-detect",
      label: "NAT-T Detected",
      sublabel: "UDP/4500 encapsulation will be used",
      kind: "nat_t",
      direction: "bidirectional",
      inferred: true,
    });
  }

  // 3. IKE_AUTH
  events.push({
    id: "ike-auth-req",
    label: "IKE_AUTH",
    sublabel: "Identity + auth payload + Child SA proposal",
    kind: "ike_auth",
    direction: "init_to_resp",
    inferred: !hasIke,
  });

  events.push({
    id: "ike-auth-resp",
    label: "IKE_AUTH reply",
    sublabel: hasEsp ? "SA established ✓ — ESP SPI assigned" : "Auth complete (ESP SPI not observed)",
    kind: "ike_auth",
    direction: "resp_to_init",
    inferred: !hasEsp,
    warning: !hasEsp ? "ESP SPI not observed — capture may be partial" : undefined,
  });

  // 4. CREATE_CHILD_SA (if PFS or lifetime observed)
  if (hasPfs || lifetimeFact !== null) {
    events.push({
      id: "create-child-sa",
      label: "CREATE_CHILD_SA",
      sublabel: [
        hasPfs ? "PFS enabled" : null,
        lifetimeFact !== null ? `Lifetime: ${String(lifetimeFact)}` : null,
      ].filter(Boolean).join(" · "),
      kind: "create_child_sa",
      direction: "init_to_resp",
      inferred: true,
    });
  }

  // 5. Replay window configured → informational
  if (hasReplay) {
    events.push({
      id: "replay-config",
      label: "Anti-Replay Window",
      sublabel: "Configured on ESP SA",
      kind: "informational",
      direction: "bidirectional",
      inferred: true,
    });
  }

  // 6. ESP data tunnel
  if (hasEsp) {
    events.push({
      id: "esp-data",
      label: "ESP Data Tunnel",
      sublabel: "Encrypted traffic observed (payload opaque)",
      kind: "esp_data",
      direction: "bidirectional",
      inferred: false,
    });
  }

  // 7. Anomaly events from findings
  const criticalFindings = detail.findings.filter(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  for (const finding of criticalFindings.slice(0, 2)) {
    events.push({
      id: `anomaly-${finding.rule_id}`,
      label: "Security Anomaly",
      sublabel: finding.rule_id,
      kind: "anomaly",
      direction: "bidirectional",
      inferred: false,
      warning: finding.recommendation ?? finding.rule_id,
    });
  }

  return events;
}
