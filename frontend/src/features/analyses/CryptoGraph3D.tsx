/**
 * CryptoGraph3D.tsx — Feature 1
 *
 * Interactive 3D IKE SA / cryptographic handshake visualizer.
 * Uses @react-three/fiber + @react-three/drei.
 *
 * Renders the IKEv2 negotiation as an orbiting 3D node graph:
 *   - Initiator ↔ Responder endpoint spheres
 *   - Accepted proposal nodes (green = strong, amber = moderate)
 *   - Rejected/not-selected proposals (red, below center plane)
 *   - Child SA / ESP node (blue)
 *   - Animated glowing edges
 *
 * Click a node to open its detail panel.
 * The camera orbits continuously; the user can drag/rotate/zoom.
 */
import type { ReactNode, MutableRefObject } from "react";
import { Suspense, useRef, useState, useMemo } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Text, Sphere, Line } from "@react-three/drei";
import type * as THREE from "three";

import type { AnalysisDetail } from "@/api/client";
import { buildHandshakeGraph } from "./graphUtils";
import type { GraphNode, GraphEdge } from "./graphUtils";

// ─── Color mapping ────────────────────────────────────────────────────────────
const KIND_COLOR: Record<string, string> = {
  initiator: "#0071e3", // Pricing Blue
  responder: "#0066cc", // Apple Blue
  proposal: "#34c759", // Apple Green
  child_sa: "#0071e3", // Pricing Blue
};

const EDGE_COLOR: Record<string, string> = {
  accepted: "#34c759",
  rejected: "#d70015",
  weak: "#ff9500",
  unknown: "#86868b",
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function NodeMesh({
  node,
  isSelected,
  onClick,
}: {
  node: GraphNode;
  isSelected: boolean;
  onClick: () => void;
}): ReactNode {
  const meshRef = useRef<THREE.Mesh>(null!);

  const isWeak = node.detail?.startsWith("⚠");
  const color =
    node.kind === "proposal"
      ? isWeak
        ? "#ff9500"
        : "#34c759"
      : (KIND_COLOR[node.kind] ?? "#0071e3");

  const size =
    node.kind === "initiator" || node.kind === "responder"
      ? 0.38
      : node.kind === "child_sa"
        ? 0.3
        : 0.22;

  // Gentle float animation
  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.position.y =
        node.position[1] + Math.sin(state.clock.elapsedTime * 0.6 + node.position[0]) * 0.06;
    }
  });

  return (
    <group position={node.position}>
      {/* Outer glow sphere */}
      <Sphere ref={meshRef} args={[size * 1.35, 16, 16]}>
        <meshBasicMaterial color={color} transparent opacity={isSelected ? 0.3 : 0.08} />
      </Sphere>

      {/* Core sphere */}
      <Sphere
        args={[size, 24, 24]}
        onClick={(e) => {
          e.stopPropagation();
          onClick();
        }}
      >
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={isSelected ? 0.6 : 0.2}
          metalness={0.15}
          roughness={0.3}
        />
      </Sphere>

      {/* Label */}
      <Text
        position={[0, size + 0.22, 0]}
        fontSize={0.16}
        color="#1d1d1f"
        anchorX="center"
        anchorY="bottom"
        maxWidth={2.4}
      >
        {node.label}
      </Text>
    </group>
  );
}

function EdgeLine({
  from,
  to,
  kind,
}: {
  from: [number, number, number];
  to: [number, number, number];
  kind: GraphEdge["kind"];
}): ReactNode {
  const color = EDGE_COLOR[kind] ?? "#86868b";
  const lineRef = useRef<THREE.Line>(null!);

  // Subtle pulse on accepted edges
  useFrame((state) => {
    if (lineRef.current && kind === "accepted") {
      (lineRef.current.material as THREE.LineBasicMaterial).opacity =
        0.6 + Math.sin(state.clock.elapsedTime * 1.5) * 0.25;
    }
  });

  const points: [number, number, number][] = [from, to];

  return (
    <Line
      ref={lineRef as MutableRefObject<never>}
      points={points}
      color={color}
      lineWidth={kind === "accepted" ? 2 : 1}
      transparent
      opacity={kind === "rejected" ? 0.35 : 0.75}
      dashed={kind === "rejected"}
      dashSize={0.15}
      gapSize={0.08}
    />
  );
}

function Scene({
  nodes,
  edges,
  selectedId,
  onSelect,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}): ReactNode {
  const nodeMap = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  return (
    <>
      <ambientLight intensity={0.85} />
      <directionalLight position={[10, 10, 5]} intensity={1.1} color="#ffffff" />
      <pointLight position={[-6, -6, -3]} intensity={0.5} color="#0071e3" />

      {edges.map((edge) => {
        const fromNode = nodeMap.get(edge.from);
        const toNode = nodeMap.get(edge.to);
        if (!fromNode || !toNode) return null;
        return (
          <EdgeLine key={edge.id} from={fromNode.position} to={toNode.position} kind={edge.kind} />
        );
      })}

      {nodes.map((node) => (
        <NodeMesh
          key={node.id}
          node={node}
          isSelected={selectedId === node.id}
          onClick={() => onSelect(node.id)}
        />
      ))}

      <OrbitControls
        autoRotate
        autoRotateSpeed={0.4}
        enableDamping
        dampingFactor={0.08}
        minDistance={4}
        maxDistance={16}
      />
    </>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

export default function CryptoGraph3D({ detail }: { detail: AnalysisDetail }): ReactNode {
  const graph = useMemo(() => buildHandshakeGraph(detail), [detail]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedNode = graph.nodes.find((n) => n.id === selectedId) ?? null;

  const isWeak = (node: GraphNode) => node.kind === "proposal" && node.detail?.startsWith("⚠");

  return (
    <div
      role="region"
      aria-label="3D IKE cryptographic handshake visualizer"
      className="apple-card p-6 space-y-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
            IKE SA Crypto Negotiation Graph
          </h3>
          <p className="mt-0.5 text-xs text-[#707070]">
            Drag to rotate · Scroll to zoom · Click a node to inspect parameters
          </p>
        </div>
        <div className="flex items-center gap-2">
          {graph.ikeVersion !== null && (
            <span className="rounded-full border border-[#e6e6e8] bg-[#fafafc] px-3 py-1 font-mono text-xs text-[#1d1d1f]">
              {graph.ikeVersion}
            </span>
          )}
          {graph.transforms !== null && (
            <span className="rounded-full border border-[#0071e3]/30 bg-[#0071e3]/10 px-3 py-1 font-mono text-xs text-[#0071e3]">
              {graph.transforms}
            </span>
          )}
        </div>
      </div>

      {/* 3D Canvas */}
      <div
        className="overflow-hidden rounded-[24px] border border-[#e6e6e8]"
        style={{ height: 420, background: "#fafafc" }}
      >
        <Canvas camera={{ position: [0, 1.5, 9], fov: 50 }} gl={{ antialias: true, alpha: true }}>
          <Suspense fallback={null}>
            <Scene
              nodes={graph.nodes}
              edges={graph.edges}
              selectedId={selectedId}
              onSelect={(id) => setSelectedId((prev) => (prev === id ? null : id))}
            />
          </Suspense>
        </Canvas>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-2 text-xs" aria-label="Graph legend">
        {[
          { color: "#0071e3", label: "IKE Endpoint" },
          { color: "#34c759", label: "Accepted algorithm" },
          { color: "#ff9500", label: "Weak / deprecated algorithm" },
          { color: "#d70015", label: "Rejected proposal" },
          { color: "#0066cc", label: "Child SA / ESP" },
        ].map(({ color, label }) => (
          <span
            key={label}
            className="inline-flex items-center gap-1.5 rounded-full border border-[#e6e6e8] bg-[#fafafc] px-3 py-1 text-xs text-[#1d1d1f]"
          >
            <span
              aria-hidden="true"
              className="inline-block h-2 w-2 rounded-full"
              style={{ background: color }}
            />
            <span>{label}</span>
          </span>
        ))}
      </div>

      {/* Node detail panel */}
      {selectedNode !== null && (
        <div
          className="rounded-[20px] border border-[#e6e6e8] bg-[#ffffff] p-4"
          role="region"
          aria-label={`Node detail: ${selectedNode.label}`}
        >
          <p className="font-display text-sm font-semibold text-[#1d1d1f]">{selectedNode.label}</p>
          <p className="text-xs text-[#707070]">
            Type: <strong className="text-[#1d1d1f]">{selectedNode.kind.replace(/_/g, " ")}</strong>
          </p>
          {selectedNode.detail !== undefined && (
            <p
              className="mt-1 text-sm font-mono"
              style={{
                color: isWeak(selectedNode)
                  ? "#ff9500"
                  : selectedNode.detail.startsWith("✗")
                    ? "#d70015"
                    : "#34c759",
              }}
            >
              {selectedNode.detail}
            </p>
          )}
        </div>
      )}

      {graph.nodes.length <= 2 && (
        <p className="text-sm text-[#707070]" role="note">
          Insufficient IKE transform evidence in this capture to build a full graph. The graph shows
          only the observed endpoints.
        </p>
      )}
    </div>
  );
}
