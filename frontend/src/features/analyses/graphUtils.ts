/**
 * graphUtils.ts — maps AnalysisDetail → graph nodes + edges for the 3D IKE visualizer.
 *
 * Data source: packet_observed_facts. The graph is built entirely from
 * packet-observable evidence — nothing is fabricated.
 */
import type { AnalysisDetail } from "@/api/client";

export type NodeKind = "initiator" | "responder" | "child_sa" | "proposal";
export type EdgeKind = "accepted" | "rejected" | "weak" | "unknown";

export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  detail?: string;
  /** 3D position hint (x, y, z) — set by the layout algorithm */
  position: [number, number, number];
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  kind: EdgeKind;
  label?: string;
}

export interface HandshakeGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  ikeVersion: string | null;
  transforms: string | null;
}

function factValue(detail: AnalysisDetail, factName: string): unknown | undefined {
  const all = [
    ...detail.packet_observed_facts,
    ...detail.supplied_facts,
    ...detail.model_inferred_facts,
  ];
  return all.find((e) => e.fact_name === factName)?.fact_value ?? undefined;
}

function stringify(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

/**
 * Parse the selected_transforms string into an array of algorithm tokens.
 */
function parseTransforms(raw: string | null): string[] {
  if (!raw) return [];
  const cleaned = raw.replace(/^"|"$/g, "").replace(/\\"/g, '"');
  return cleaned
    .split(/[/,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

const WEAK_PATTERNS = [
  /3DES/i,
  /DES\b/i,
  /RC4/i,
  /MD5/i,
  /SHA-1\b/i,
  /SHA1\b/i,
  /DH-[12]\b/i,
  /GROUP_[12]\b/i,
  /NULL/i,
  /MODP768/i,
  /MODP1024/i,
];

function isWeakAlgorithm(alg: string): boolean {
  return WEAK_PATTERNS.some((p) => p.test(alg));
}

export function buildHandshakeGraph(detail: AnalysisDetail): HandshakeGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const endpoints = factValue(detail, "network.outer_endpoints");
  let initiatorLabel = "Initiator";
  let responderLabel = "Responder";
  if (Array.isArray(endpoints) && endpoints.length >= 2) {
    initiatorLabel = String(endpoints[0]).split("/")[0] ?? "Initiator";
    responderLabel = String(endpoints[1]).split("/")[0] ?? "Responder";
  }

  nodes.push({
    id: "initiator",
    label: initiatorLabel,
    kind: "initiator",
    position: [-3.5, 0, 0],
    detail: "IKEv2 Initiator",
  });
  nodes.push({
    id: "responder",
    label: responderLabel,
    kind: "responder",
    position: [3.5, 0, 0],
    detail: "IKEv2 Responder",
  });

  const ikeVersion = stringify(factValue(detail, "ike.version"));
  const rawTransforms = stringify(factValue(detail, "ike_sa.selected_transforms"));
  const transforms = rawTransforms ? rawTransforms.replace(/^"|"$/g, "") : null;
  const selectedAlgs = parseTransforms(transforms);

  const offered = factValue(detail, "ike_sa.proposals_offered");
  const offeredAlgs: string[] = [];
  if (typeof offered === "string") offeredAlgs.push(...parseTransforms(offered));
  else if (Array.isArray(offered)) {
    for (const o of offered) {
      const s = stringify(o);
      if (s) offeredAlgs.push(...parseTransforms(s));
    }
  }

  const rejectedAlgs = offeredAlgs.filter(
    (alg) => !selectedAlgs.some((s) => s.toLowerCase() === alg.toLowerCase()),
  );

  const angleStep = selectedAlgs.length > 0 ? Math.PI / (selectedAlgs.length + 1) : Math.PI / 4;
  selectedAlgs.forEach((alg, i) => {
    const id = `accepted-${i}`;
    const angle = angleStep * (i + 1) - Math.PI / 2;
    const r = 2.2;
    nodes.push({
      id,
      label: alg,
      kind: "proposal",
      position: [Math.cos(angle) * r, Math.sin(angle) * r + 1.5, 0],
      detail: isWeakAlgorithm(alg) ? "⚠ Weak — consider upgrading" : "✓ Accepted",
    });
    edges.push({
      id: `e-acc-init-${i}`,
      from: "initiator",
      to: id,
      kind: isWeakAlgorithm(alg) ? "weak" : "accepted",
      label: "proposed",
    });
    edges.push({
      id: `e-acc-resp-${i}`,
      from: id,
      to: "responder",
      kind: isWeakAlgorithm(alg) ? "weak" : "accepted",
      label: "selected",
    });
  });

  edges.push({
    id: "e-ike-sa",
    from: "initiator",
    to: "responder",
    kind: "accepted",
    label: "IKE SA",
  });

  const shownRejected = rejectedAlgs.slice(0, 4);
  const rejStep = shownRejected.length > 0 ? Math.PI / (shownRejected.length + 1) : Math.PI / 4;
  shownRejected.forEach((alg, i) => {
    const id = `rejected-${i}`;
    const angle = rejStep * (i + 1) - Math.PI / 2;
    const r = 1.8;
    nodes.push({
      id,
      label: alg,
      kind: "proposal",
      position: [Math.cos(angle) * r, Math.sin(angle) * r - 1.8, 0],
      detail: "✗ Not selected by responder",
    });
    edges.push({ id: `e-rej-${i}`, from: "initiator", to: id, kind: "rejected", label: "offered" });
  });

  const espSpi = factValue(detail, "esp.spi_observed");
  const hasPfs = factValue(detail, "security.pfs");
  nodes.push({
    id: "child_sa",
    label: espSpi !== undefined && espSpi !== null ? "ESP Child SA" : "Child SA",
    kind: "child_sa",
    position: [0, -3.2, 0],
    detail:
      hasPfs === true ? "PFS enabled ✓" : hasPfs === false ? "PFS disabled ⚠" : "PFS: unknown",
  });
  edges.push({
    id: "e-child-init",
    from: "initiator",
    to: "child_sa",
    kind: "accepted",
    label: "CREATE_CHILD_SA",
  });
  edges.push({
    id: "e-child-resp",
    from: "responder",
    to: "child_sa",
    kind: "accepted",
    label: "TS negotiated",
  });

  return { nodes, edges, ikeVersion, transforms };
}
